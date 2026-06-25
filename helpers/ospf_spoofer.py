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
from curses import keyname
from scapy.contrib.gtp import TrueFalse_value
import typing
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto, StrEnum
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


class DBDFlags(StrEnum):
    INIT = "I"
    MORE = "M"
    MASTER = "MS"


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
    rxmt_interval: int = 5 # retransmission interval
    max_retries: int = 3


@dataclass
class Neighbour:
    router_id: str
    ip: str
    mac: str | None = None

    state: NeighbourState = NeighbourState.DOWN

    master: bool | None = None
    dd_seq: int | None = None

    pending_requests: list[tuple[int, str, str]] = field(default_factory=list)
    pending_acks: dict[tuple[int, str, str], dict[str, Any]] = field(default_factory=dict)

    neighbour_headers: list[Any] = field(default_factory=list)

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
        self.start_retransmission_loop()

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

            time.sleep(self.config.hello_interval)

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
            neighbors=neighbour_ids,
        )
    ### ------ OSPF HELLO ENDS ------ ###

    ### ----- Retransmission Loop ------ ###
    def start_retransmission_loop(self) -> threading.Thread:
        thread = threading.Thread(target=self._retransmission_loop, daemon=True)
        thread.start()
        return thread

    def _retransmission_loop(self) -> None:
        while self.running:
            now = time.time()

            with self.lock:
                for nb in self.neighbours.values():
                    for key, entry in list(nb.pending_acks.items()):
                        # Skip if retransmission interval not reached
                        if now - entry["sent_at"] < self.config.rxmt_interval:
                            continue

                        if entry["retries"] >= self.config.max_retries:
                            LOG.warning("Max retransmission retires reached for %s, stopping retransmission...", nb.router_id)
                            del nb.pending_acks[key]
                            continue

                        LOG.debug("Retransmitting %s to %s...", key, nb.router_id)
                        self.send_lsupd(nb, [entry["lsa"]], track_ack=False)
                        entry["sent_at"] = now
                        entry["retries"] += 1
            time.sleep(1)

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
            nb = self.get_or_create_neighbour(pkt)

            if ospf.type == OSPFType.HELLO:
                self.handle_hello(nb, ospf)
            elif ospf.type == OSPFType.DBD:
                self.handle_dbd(nb, ospf)
            elif ospf.type == OSPFType.LSR:
                self.handle_lsreq(nb, ospf)
            elif ospf.type == OSPFType.LSU:
                self.handle_lsupd(nb, ospf)
            elif ospf.type == OSPFType.LSACK:
                self.handle_lsack(nb, ospf)

    def get_or_create_neighbour(self, pkt: Any) -> Neighbour:
        """Get Neighbour List and Adds Neighbour to List if not already added"""
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
        """OSPF HELLO Packet Handler"""
        ospf_hello = ospf[OSPF_Hello]

        # Update OSPF Hello state from DOWN to INIT
        if nb.state == NeighbourState.DOWN:
            nb.set_state(NeighbourState.INIT)

        neighbour_list = [str(x) for x in ospf_hello.neighbors]

        # Check if my Router ID in Neighbour's OSPF Hello list
        if self.config.router_id in neighbour_list:
            if nb.state in {NeighbourState.DOWN, NeighbourState.INIT}:
                nb.set_state(NeighbourState.TWO_WAY)

        # Form adjacency if 
        if nb.state == NeighbourState.TWO_WAY and self.should_form_adjacency(nb, ospf_hello):
            self.start_exstart(nb)

    def should_form_adjacency(self, nb: Neighbour, ospf_hello: OSPF_Hello) -> bool:
        """Form adjacency only if router is DR/BDR"""
        nb_is_dr = str(ospf_hello.router) == nb.ip
        nb_is_bdr = str(ospf_hello.backup) == nb.ip
        # Initialising - No DR set yet
        no_dr_declared = str(ospf_hello.router) == "0.0.0.0"

        return nb_is_dr or nb_is_bdr or no_dr_declared

    ### ------ DBD NEGOTIATION ------ ###
    def start_exstart(self, nb: Neighbour) -> None:
        """Begins DBD Negotiation - Decide DBD master slave"""
        if nb.mac is None:
            LOG.warning("[!] Cannot start ExStart with %s: no MAC address.", nb.router_id)
            return

        nb.set_state(NeighbourState.EXSTART)
        nb.master = None
        nb.dd_seq = int(time.time()) & 0xFFFF

        dbd_packet = self.build_dbd_packet(
                master=True,
                init=True,
                more=True,
                dd_seq=nb.dd_seq,
                lsa_headers=[],
                )

        self._send_ospf(
                dst_ip=nb.ip,
                dst_mac=nb.mac,
                ospf_type=OSPFType.DBD,
                payload=dbd_packet,
                )

    def build_dbd_packet(
            self,
            master: bool,
            init: bool,
            more: bool,
            dd_seq: int,
            lsa_headers: list[Any]
            ) -> Packet:
        """DBD Packet Builder"""
        flags = []

        if init:
            flags.append(DBDFlags.INIT)
        if more:
            flags.append(DBDFlags.MORE)
        if master:
            flags.append(DBDFlags.MASTER)

        return OSPF_DBDesc(
                mtu=self.config.mtu,
                options=self.config.options,
                dbdescr=flags,
                ddseq=dd_seq,
                lsaheaders=lsa_headers,
                )
    
    def handle_dbd(self, nb: Neighbour, ospf: Any) -> None:
        """Handler for received OSPF DBD Type Packet"""
        dbd_packet = ospf[OSPF_DBDesc]
        # Retrieve flags field from `OSPF_DBDesc` type
        flags = set(dbd_packet.dbdescr)

        # Ensure neighbour state not DOWN, INIT or TWO_WAY
        if nb.state in {NeighbourState.DOWN, NeighbourState.INIT, NeighbourState.TWO_WAY}:
            return

        # Establish master/slave relationship (router with highest id)
        if nb.state == NeighbourState.EXSTART:
            self.handle_exstart_dbd(nb, dbd_packet, flags)
            return

        # Exchange headers/summaries of Link State Database
        if nb.state == NeighbourState.EXCHANGE:
            self.handle_exchange_dbd(nb, dbd_packet, flags)

        # Get full details of missing/outdated routes
        if nb.state == NeighbourState.LOADING:
            self.handle_loading_dbd(nb, dbd_packet, flags)

    def handle_exstart_dbd(self, nb: Neighbour, dbd_packet: OSPF_DBDesc, flags: set[str]) -> None:
        """Handler to establish master/slave relationship"""
        # Neighbour proposes itself as master
        nb_proposes_master = { DBDFlags.INIT, DBDFlags.MORE, DBDFlags.MASTER } <= flags and not dbd_packet.lsaheaders

        if nb_proposes_master and nb.master is None:
            # Neighbour has larger router id - wins master role
            if nb.router_id > self.config.router_id:
                nb.master = False
                nb.dd_seq = dbd_packet.ddseq

                reply_packet = self.build_dbd_packet(
                        master=False,
                        init=False,
                        more=False,
                        dd_seq=typing.cast(int, nb.dd_seq),
                        lsa_headers=[],
                        )

                self._send_ospf(
                        dst_ip=nb.ip,
                        dst_mac=typing.cast(str, nb.mac), 
                        ospf_type=OSPFType.DBD,
                        payload=reply_packet,
                        )
                nb.set_state(NeighbourState.EXCHANGE)

            # Otherwise drop packet
            return

        # Neighbour accepts us as master - confirm ddseq number same as our tracked dd_seq number
        nb_yeilded = DBDFlags.MASTER not in flags and dbd_packet.ddseq == nb.dd_seq

        if nb_yeilded:
            nb.master = True
            self.collect_lsa_headers(nb, dbd_packet.lsaheaders)
            nb.set_state(NeighbourState.EXCHANGE)

            self.continue_dbd_exchange(nb, more=(DBDFlags.MORE in flags))
    
    def handle_exchange_dbd(self, nb: Neighbour, dbd_packet: OSPF_DBDesc, flags: set[str]) -> None:
        """Handler for OSPF DBD EXCHANGE STATE packet exchange"""
        self.collect_lsa_headers(nb, dbd_packet.lsaheaders)

        if nb.master is False:
            # Update neighbour tracker to received seq num
            nb.dd_seq = dbd_packet.ddseq

            reply = self.build_dbd_packet(
                    master=False,
                    init=False,
                    more=False,
                    dd_seq=typing.cast(int, nb.dd_seq),
                    lsa_headers=[],
                    )

            self._send_ospf(
                    dst_ip=nb.ip,
                    dst_mac=typing.cast(str, nb.mac),
                    ospf_type=OSPFType.DBD,
                    payload=reply,
                    )
            
            # More data waiting to be sent?
            if DBDFlags.MORE not in flags:
                self.exchange_complete(nb)

        elif nb.master is True:
            if dbd_packet.ddseq != nb.dd_seq:
                return

            self.continue_dbd_exchange(nb, more=(DBDFlags.MORE in flags))

    def continue_dbd_exchange(self, nb: Neighbour, more: bool) -> None:
        if more:
            nb.dd_seq = typing.cast(int, nb.dd_seq) + 1

            dbd_packet = self.build_dbd_packet(
                    master=True,
                    init=False,
                    more=False,
                    dd_seq=nb.dd_seq,
                    lsa_headers=[],
                    )
            self._send_ospf(nb.ip, typing.cast(str, nb.mac), OSPFType.DBD, dbd_packet)
        else:
            self.exchange_complete(nb)

    def collect_lsa_headers(self, nb: Neighbour, lsaheaders: list[Any]) -> None:
        """Collects DBD LSA Headers and append to Unknown LSA's to Neighbour's `neighbour_headers` list"""
        for header in lsaheaders:
            key = (header.type, str(header.id), str(header.adrouter))

            if key in self.lsdb:
                continue

            already_known = any(
                    (hdr.type, str(hdr.id), str(hdr.adrouter)) == key
                    for hdr in nb.neighbour_headers
                    )

            if not already_known:
                nb.neighbour_headers.append(header)
    ### ------ END DBD NEGOIATION ------ ###

    ### ------ REQUEST MISSING LSAs ------ ###
    def exchange_complete(self, nb: Neighbour) -> None:
        """Requests missing LSAs, after DBD exchange is done"""
        if nb.neighbour_headers:
            nb.set_state(NeighbourState.LOADING)
            self.send_next_lsreq_batch(nb)
        else:
            nb.set_state(NeighbourState.FULL)
            LOG.info("Neighbour %s state set to FULL", nb.router_id)

    def send_next_lsreq_batch(self, nb:Neighbour) -> None:
        # No LSA to send - Proceed to FULL state
        if not nb.neighbour_headers:
            nb.set_state(NeighbourState.FULL)
            LOG.info("Reached FULL state with neighbour %s", nb.router_id)
            return

        lsreq_items = []

        for hdr in nb.neighbour_headers:
            lsreq = OSPF_LSReq_Item(
                    type=hdr.type,
                    id=hdr.id,
                    adrouter=hdr.adrouter,
                    )
            
            lsreq_items.append(lsreq)

        nb.pending_requests = []

        for hdr in nb.neighbour_headers:
            key = (hdr.type, str(hdr.id), str(hdr.adrouter))
            nb.pending_requests.append(key)

        # Craft LSR payload
        lsreq = OSPF_LSReq(requests=lsreq_items)

        self._send_ospf(
                dst_ip=nb.ip,
                dst_mac=typing.cast(str, nb.mac),
                ospf_type=OSPFType.LSR,
                payload=lsreq
                )

    def handle_lsupd(self, nb:Neighbour, ospf_packet: Any) -> None:
        """Received full LSA and stores them"""
        lsupd = ospf_packet[OSPF_LSUpd]
        received_lsas = []

        for lsa in lsupd.lsalist:
            key = self.lsa_key(lsa)
            current = self.lsdb.get(key)

            if current is None or self.is_newer_lsa(lsa, current):
                self.lsdb[key] = lsa
                received_lsas.append(lsa)

            # Repopulate neighbour_headers list without received key
            nb.neighbour_headers = [
                    hdr for hdr in nb.neighbour_headers
                    if (hdr.type, str(hdr.id), str(hdr.adrouter)) != key
                    ]

            # Repopulate pending_requests list without received req
            nb.pending_requests = [
                    req for req in nb.pending_requests
                    if req != key
                    ]
        if received_lsas:
            self.send_lsa_ack(nb, received_lsas)

        if nb.state == NeighbourState.LOADING and not nb.pending_requests:
            self.send_next_lsreq_batch(nb)

    def is_newer_lsa(self, incoming: Any, current: Any) -> bool:
        """Helper function to determine if incoming LSDB is newer that current"""
        if incoming.seq != current.seq:
            return incoming.seq > current.seq

        if incoming.chksum != current.chksum:
            return incoming.chksum > current.chksum

        return incoming.age < current.age

    def send_lsa_ack(self, nb: Neighbour, lsas: list[Any]) -> None:
        """Send LSA Ack"""
        headers = [
                OSPF_LSA_Hdr(
                    age=lsa.age,
                    options=lsa.options,
                    type=lsa.type,
                    id=lsa.id,
                    adrouter=lsa.adrouter,
                    seq=lsa.seq,
                    chksum=lsa.chksum,
                    len=lsa.len,
                    )
                for lsa in lsas
                ]

        ack = OSPF_LSAck(lsaheaders=headers)

        self._send_ospf(
                dst_ip=nb.ip,
                dst_mac=typing.cast(str, nb.mac),
                ospf_type=OSPFType.LSACK,
                payload=ack,
                )

    def handle_lsreq(self, nb: Neighbour, ospf: Any) -> None:
        """Handles neighbour's request for full LSAs"""
        req = ospf[OSPF_LSReq]
        lsas_to_send = []

        for item in req.requests:
            key = self.lsa_key(item)
            lsa = self.lsdb.get(key)

            if lsa is None:
                LOG.warning("Neighbour %s requested unknown LSA %s, skipping...", nb.router_id, key)
                continue

            lsas_to_send.append(lsa)

        if lsas_to_send:
            self.send_lsupd(nb, lsas_to_send, track_ack=True)

    def handle_lsack(self, nb: Neighbour, ospf: Any) -> None:
        """Handles Acknowledgement for LSAs sent - Remove entry from pending_ack list"""
        ack = ospf[OSPF_LSAck]

        for hdr in ack.lsaheaders:
            key = self.lsa_key(hdr)

            if key in nb.pending_acks:
                del nb.pending_acks[key]
                LOG.debug("Neighbour %s acknowledged LSA %s", nb.router_id, key)

    def handle_loading_dbd(self, nb: Neighbour, dbd_packet: OSPF_DBDesc, flags: set[str]) -> None:
        """Handles incoming DBD packets while waiting for requested LSAs"""
        self.collect_lsa_headers(nb, dbd_packet.lsaheaders)

        if nb.neighbour_headers and not nb.pending_requests:
            self.send_next_lsreq_batch(nb)

    def send_lsupd(self, nb: Neighbour, lsas: list[Any], track_ack: bool):
        """Send full LSAs to neighbour"""
        if nb.mac is None:
            LOG.warning("Missing MAC, unable to send LSU to %s", nb.router_id)
            return

        lsu_payload = OSPF_LSUpd(lsalist=lsas)

        self._send_ospf(
                dst_ip=nb.ip,
                dst_mac=nb.mac,
                ospf_type=OSPFType.LSU,
                payload=lsu_payload,
                )

        if track_ack:
            for lsa in lsas:
                key = self.lsa_key(lsa)
                nb.pending_acks[key] = {
                        "lsa": lsa,
                        "sent_at": time.time(),
                        "retries": 0,
                        }

    def _send_ospf(self, dst_ip: str, dst_mac: str, ospf_type: int, payload: Any) -> None:
        """Sends OSPF Packets"""
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

    def lsa_key(self, lsa_or_hdr: Any) -> tuple[int, str, str]:
        """Small Reusable lsa key helper"""
        return (
                int(lsa_or_hdr.type),
                str(lsa_or_hdr.id),
                str(lsa_or_hdr.adrouter),
                )
