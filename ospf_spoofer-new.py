#!/usr/bin/python3

"""
A receives B's Hello.
A marks B as Init if B does not list A yet.

A sends Hello listing B as a neighbor.
B later sends Hello listing A.
A marks B as 2-Way.

If adjacency should form, A and B enter ExStart.
They negotiate DBD master/slave and sequence numbers.

In Exchange, they send DBD packets.
DBD packets contain LSA headers, not full metrics.

If A is missing LSAs, A sends LSReq.

B sends LSUpd containing full LSAs.

A acknowledges with LSAck.

A reaches Full once LSDB sync is complete.

Only after LSAs are accepted into the LSDB does SPF use their metrics.
"""
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Any

from scapy.all import Packet, get_if_hwaddr, get_if_addr, sendp, sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.contrib.ospf import (
        OSPF_Hdr,
        OSPF_Hello,
        OSPF_DBDesc,
        OSPF_LSReq,
        OSPF_LSReq_Item,
        OSPF_LSUpd,
        OSPF_LSAck,
        OSPF_LSA_Hdr,
        )

LOG = logging.getLogger("ospf-session")

ALL_SPF_ROUTERS = "224.0.0.5"
ALL_SPF_ROUTERS_MAC = "01:00:5e:00:00:05"


class NeighbourState(Enum):
    DOWN = auto()
    INIT = auto()
    TWO_WAY = auto()
    EXSTART = auto()
    EXCHANGE = auto()
    LOADING = auto()
    FULL = auto()


class OSPFType(IntEnum):
    # OSPF Hello
    HELLO = 1
    # OSPF Database Description
    DBD = 2
    # OSPF Link State Request
    LSR = 3
    # OSPF Link State Update
    LSU = 4
    # OSPF Link State Acknowledge
    LSACK = 5


@dataclass
class OSPFConfig:
    iface: str
    area: str
    int_ip: str
    router_id: str
    authtype: int
    mask: str = "255.255.255.0"
    hello_interval: int = 10
    dead_interval: int = 40
    priority: int = 0 #TODO: MUST CHANGE PRIORITY - 0 means not participating in OSPF election
    options: int = 0x02
    mtu: int = 1500


@dataclass
class Neighbour:
    router_id: str
    ip: str
    mac: str | None = None

    state: NeighbourState = NeighbourState.DOWN

    master: bool | None = None
    dd_seq: int | None = None

    pending_requests: list = field(default_factory=list)
    neighbour_headers: list = field(default_factory=list)

    last_seen: float = field(default_factory=time.time)

    def is_dead(self, now: float, dead_interval: int) -> bool:
        return now - self.last_seen > dead_interval

    def set_state(self, new_state: NeighbourState) -> None:
        if self.state != new_state:
            LOG.info(
                "Neighbor %s: %s -> %s",
                self.router_id,
                self.state.name,
                new_state.name,
            )
            self.state = new_state

# Main Class
class OSPFSession:
    def __init__(self, config: OSPFConfig) -> None:
        self.config = config

        self.src_ip = get_if_addr(config.iface)
        self.src_mac = get_if_hwaddr(config.iface)

        self.neighbours:dict[str, Neighbour] = {}
        
        # Key: {lsa_type, link_state_id, advertising_router}
        self.lsdb: dict[tuple[int, str, str], Any] = {}

        self.running = False
        self.lock = threading.Lock()

    def run(self):
        self.running = True

        LOG.info(
"""
[*] Starting OSPF session [*]
Interface = %s
Src IP = %s
Router ID = %s
area = %s
""",
self.config.iface,
self.src_ip,
self.config.router_id,
self.config.area,
                )

        self.start_hello_loop()

        try:
            self.start_sniffer()
        finally:
            self.running = False

    ### ------ OSPF HELLO ------ ###
    def start_hello_loop(self) -> threading.Thread:
        """Starts threads for heartbeat/polling"""
        thread = threading.Thread(target=self._hello_loop, daemon=True)
        thread.start()
        return thread

    def _hello_loop(self) -> None:
        """Keeps device visible to OSPF"""
        while self.running:
            now = time.time()

            with self.lock:
                self.expire_dead_neighbours(now)
                neighbour_ids = self.get_active_neighbour_ids(now)

            hello = self.build_hello_packet(neighbour_ids)

            self._send_ospf(
                    dst_ip=ALL_SPF_ROUTERS,
                    dst_mac=ALL_SPF_ROUTERS_MAC,
                    ospf_type=OSPFType.HELLO,
                    payload=hello,
                    )

    def expire_dead_neighbours(self, now: float) -> None:
        """Checks if neighbour links are dead, then removes them from neighbours list"""
        dead = [
            rid
            for rid, nb in self.neighbours.items()
            if nb.is_dead(now, self.config.dead_interval)
        ]

        for rid in dead:
            LOG.warning("Neighbor %s expired", rid)
            del self.neighbours[rid]
            
    def get_active_neighbour_ids(self, now: float) -> list[str]:
        """Retrieves active neighbours links"""
        return [
            nb.router_id
            for nb in self.neighbours.values()
            if not nb.is_dead(now, self.config.dead_interval)
        ]

    def build_hello_packet(self, neighbour_ids: list[str]) -> Packet:
        """OSPF Hello Packet Builder, returns scapy packet"""
        return OSPF_Hello(
            mask=self.config.mask,
            hellointerval=self.config.hello_interval,
            options=self.config.options,
            prio=self.config.priority,
            deadinterval=self.config.dead_interval,
            router=self.src_ip,   # DR
            backup="0.0.0.0",   # BDR TODO: need backup? if so what value to use?
            neighbours=neighbour_ids,
        )
    ### ------ OSPF HELLO ENDS ------ ###

    ### ------ OSPF SNIFFER ------ ###
    def start_sniffer(self) -> None:
        sniff(
            iface=self.config.iface,
            filter="ip proto 89",
            prn=self.handle_packets,
            store=False,
            stop_filter=lambda _: not self.running,
        )
    ### ------ OSPF SNIFFER END ------ ###

    ### ------ OSPF PACKET HANDLERS ------ ###
    def handle_packets(self, pkt: Any) -> None:
        if IP not in pkt or OSPF_Hdr not in pkt:
            return

        ospf = pkt[OSPF_Hdr]

        # Own OSPF Packet - Drop
        if ospf.src == self.config.router_id:
            return

        # Different OSPF Area - Drop
        if ospf.area != self.config.area:
            return

        # Otherwise Determine OSPF Packet Type
        with self.lock:
            nb = self.get_or_create_neighbour(ospf)

            if ospf.type == OSPFType.HELLO:
                self.handle_hello(nb, ospf)

    def get_or_create_neighbour(self, pkt: Any) -> Neighbour:
        ospf = pkt[OSPF_Hdr]
        router_id = str(ospf.src)
        ip = pkt[IP].src

        nb = self.neighbours.get(router_id)

        if nb is None:
            # Create neighbour packet
            nb = Neighbour(
                    router_id=router_id,
                    ip=ip,
                    )
            self.neighbours[router_id] = nb
            LOG.info("[+] New Neighbour Detected: %s at %s", router_id, ip)

        nb.last_seen = time.time()

        if Ether in pkt:
            nb.mac = pkt[Ether].src

        return nb

    def handle_hello(self, nb: Neighbour, ospf: Any) -> None:
        ospf_hello = ospf[OSPF_Hello]

        # Update OSPF Hello state from DOWN to INIT
        if nb.state == NeighbourState.DOWN:
            nb.set_state(NeighbourState.INIT)

        neighbour_list = [str(x) for x in ospf_hello.neighbors]

        # Check if my Router ID in Neighbour's OSPF Hello list
        if self.config.router_id in neighbour_list:
            if nb.state in {NeighbourState.DOWN, NeighbourState.INIT}:
                nb.set_state(NeighbourState.TWO_WAY)

        # Form adjacency if neighbour state is two way & my router id is in neighbour OSPF Hello
        if nb.state == NeighbourState.TWO_WAY and self.should_form_adjacency(nb, ospf_hello):
            self.start_exstart(nb)

    def should_form_adjacency(self, nb: Neighbour, ospf_hello: OSPF_Hello) -> bool:
        # if self.config.
        pass

    def start_exstart(self):
        pass


    def _send_ospf(self, dst_ip: str, dst_mac: str, ospf_type: int, payload: Any) -> None:
        pkt = (
                Ether(src=self.src_mac, dst=dst_mac) /
                IP(src=self.src_ip, dst=dst_ip, proto=89, ttl=1) /
                OSPF_Hdr(
                    version=2, # TODO: Check what version means and if needa use 1
                    type=ospf_type,
                    src=self.config.router_id,
                    area=self.config.area,
                    authtype=self.config.authtype, # TODO: Determine authtype and add to OSPFConfig
                    ) /
                payload
            )

        sendp(pkt, iface=self.config.iface, verbose=False)


