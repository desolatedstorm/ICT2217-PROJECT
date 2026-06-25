#!/usr/bin/env python3
"""
ospf_recon.py — OSPFv2 active reconnaissance / topology mapper
================================================================

Forms a REAL OSPFv2 adjacency with neighboring router(s) on a broadcast
segment, walking the full state machine:

    Down -> Init -> 2-Way -> ExStart -> Exchange -> Loading -> Full

Once Full, it has received the area's complete Link State Database (LSDB)
flood and reconstructs the topology from it: every router, every
point-to-point/transit link and its cost, every transit (multi-access)
network and its attached routers, and any inter-area / external routes.
It then prints a clean report (and optionally a JSON dump) and exits.

READ BEFORE RUNNING — THIS IS NOT PASSIVE
------------------------------------------
* Only run this against networks you own or are explicitly authorized to
  test. Forming an adjacency is an active interaction with the live
  control plane, not a sniff.
* Reaching the Full state puts your ROUTER_ID into every real router's
  neighbor table on the segment and is fully visible in
  `show ip ospf neighbor` / syslog. It also triggers an SPF recalculation
  area-wide (a normal, expected OSPF event, but a real one).
* This script deliberately never originates a Router-LSA of its own back
  into the area — it only collects what's flooded to it — to minimize
  footprint, but the bidirectional Hello/DBD/LSA exchange itself cannot be
  hidden from the routers you peer with.
* It does not attempt to bypass OSPF authentication. If the area enforces
  plaintext/MD5/cryptographic auth, you'll see Hellos but stay stuck below
  2-Way — that's the protocol working as intended, not a bug to route
  around.
* Needs root (raw sockets) and Scapy >= 2.4.
* DR/BDR handling is simplified (priority is fixed at 0 so this host never
  becomes DR/BDR, and it only proceeds past 2-Way with neighbors that
  identify themselves as DR/BDR, or on networks with no DR concept). Good
  enough for a single segment with 1-3 real routers; not a substitute for
  a production-grade OSPF stack.

Usage
-----
    sudo python3 ospf_recon.py --iface eth0 --area 0.0.0.0 \\
        --router-id 10.255.255.254 --json-out topology.json

Run `python3 ospf_recon.py --help` for all options.
"""

import argparse
import json
import logging
import sys
import threading
import time

try:
    from scapy.all import sniff, sendp, get_if_hwaddr, get_if_addr, conf
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP
    from scapy.contrib.ospf import (
        OSPF_Hdr, OSPF_Hello, OSPF_DBDesc, OSPF_LSReq, OSPF_LSReq_Item,
        OSPF_LSUpd, OSPF_LSAck, OSPF_LSA_Hdr,
    )
except ImportError:
    sys.exit("This script requires Scapy >= 2.4: pip install scapy")

ALL_SPF_ROUTERS = "224.0.0.5"
ALL_SPF_ROUTERS_MAC = "01:00:5e:00:00:05"

STATE_DOWN, STATE_INIT, STATE_2WAY, STATE_EXSTART, STATE_EXCHANGE, \
    STATE_LOADING, STATE_FULL = range(7)
STATE_NAMES = ["Down", "Init", "2-Way", "ExStart", "Exchange", "Loading", "Full"]

LOG = logging.getLogger("ospf-recon")


class Neighbor:
    """Per-neighbor OSPF adjacency state machine."""

    def __init__(self, router_id, ip):
        self.router_id = router_id
        self.ip = ip
        self.mac = None
        self.state = STATE_DOWN
        self.master = None            # True / False / None (undetermined)
        self.dd_seq = None
        self.their_headers = []       # LSA headers advertised, not yet fetched
        self.pending_requests = []    # (type, id, adrouter) outstanding LSReq
        self.last_seen = time.time()

    def set_state(self, new_state):
        if new_state != self.state:
            LOG.info("Neighbor %-15s %-8s -> %-8s",
                      self.router_id, STATE_NAMES[self.state], STATE_NAMES[new_state])
            self.state = new_state


class OSPFRecon:
    def __init__(self, iface, area, router_id, mask="255.255.255.0",
                 hello_interval=10, dead_interval=40,
                 idle_timeout=8, overall_timeout=120):
        self.iface = iface
        self.area = area
        self.router_id = router_id
        self.mask = mask
        self.hello_interval = hello_interval
        self.dead_interval = dead_interval
        self.idle_timeout = idle_timeout
        self.overall_timeout = overall_timeout

        self.src_ip = get_if_addr(iface)
        self.my_mac = get_if_hwaddr(iface)

        self.neighbors = {}     # router_id -> Neighbor
        self.lsdb = {}          # (type, id, adrouter) -> LSA packet
        self.lock = threading.Lock()
        self.running = False
        self.last_update = time.time()
        self.start_time = time.time()

    # ------------------------------------------------------------------
    # low-level send helpers
    # ------------------------------------------------------------------

    def _send_ospf(self, dst_ip, dst_mac, ospf_type, payload):
        pkt = (
            Ether(src=self.my_mac, dst=dst_mac) /
            IP(src=self.src_ip, dst=dst_ip, proto=89, ttl=1) /
            OSPF_Hdr(version=2, type=ospf_type, src=self.router_id,
                     area=self.area, authtype=0) /
            payload
        )
        sendp(pkt, iface=self.iface, verbose=False)

    def _dbd_packet(self, ms, i, more, ddseq):
        flags = []
        if i:
            flags.append('I')
        if more:
            flags.append('M')
        if ms:
            flags.append('MS')
        return OSPF_DBDesc(mtu=1500, options=0x02, dbdescr=flags,
                            ddseq=ddseq, lsaheaders=[])

    def send_hello(self, neighbor_ids):
        hello = OSPF_Hello(
            mask=self.mask, hellointerval=self.hello_interval,
            options=0x02, prio=0, deadinterval=self.dead_interval,
            router="0.0.0.0", backup="0.0.0.0", neighbors=neighbor_ids,
        )
        self._send_ospf(ALL_SPF_ROUTERS, ALL_SPF_ROUTERS_MAC, 1, hello)

    # ------------------------------------------------------------------
    # background loops
    # ------------------------------------------------------------------

    def hello_loop(self):
        while self.running:
            with self.lock:
                ids = [nb.router_id for nb in self.neighbors.values()]
            self.send_hello(ids)
            time.sleep(self.hello_interval)

    def maintenance_loop(self):
        while self.running:
            time.sleep(2)
            with self.lock:
                now = time.time()
                dead = [rid for rid, nb in self.neighbors.items()
                        if now - nb.last_seen > self.dead_interval]
                for rid in dead:
                    LOG.warning("Neighbor %s timed out (dead interval exceeded)", rid)
                    del self.neighbors[rid]

    # ------------------------------------------------------------------
    # packet dispatch
    # ------------------------------------------------------------------

    def handle_packet(self, pkt):
        if IP not in pkt or pkt[IP].proto != 89 or OSPF_Hdr not in pkt:
            return
        ospf = pkt[OSPF_Hdr]
        if ospf.src == self.router_id or ospf.area != self.area:
            return

        with self.lock:
            nb = self.neighbors.get(ospf.src)
            if nb is None:
                nb = Neighbor(ospf.src, pkt[IP].src)
                self.neighbors[ospf.src] = nb
                LOG.info("New neighbor seen: %s (%s)", ospf.src, pkt[IP].src)
            nb.last_seen = time.time()
            if Ether in pkt:
                nb.mac = pkt[Ether].src

            if ospf.type == 1:
                self._handle_hello(nb, ospf)
            elif ospf.type == 2:
                self._handle_dbd(nb, ospf)
            elif ospf.type == 4:
                self._handle_lsupd(nb, ospf)
            # type 3 (LSReq) / type 5 (LSAck) addressed to us: nothing to do,
            # since we never originate LSAs of our own.

    def _handle_hello(self, nb, ospf):
        hello = ospf[OSPF_Hello]
        if nb.state == STATE_DOWN:
            nb.set_state(STATE_INIT)

        is_dr_or_bdr = hello.router == nb.router_id or hello.backup == nb.router_id
        no_dr_concept = hello.router == "0.0.0.0"

        if self.router_id in hello.neighbors and nb.state < STATE_2WAY:
            nb.set_state(STATE_2WAY)

        if nb.state == STATE_2WAY and (is_dr_or_bdr or no_dr_concept):
            self._start_exstart(nb)

    def _start_exstart(self, nb):
        nb.set_state(STATE_EXSTART)
        nb.master = None
        nb.dd_seq = int(time.time()) & 0xFFFF
        self._send_ospf(nb.ip, nb.mac, 2, self._dbd_packet(
            ms=True, i=True, more=True, ddseq=nb.dd_seq))

    def _collect_headers(self, nb, headers):
        for hdr in headers:
            key = (hdr.type, hdr.id, hdr.adrouter)
            if key in self.lsdb:
                continue
            if any((h.type, h.id, h.adrouter) == key for h in nb.their_headers):
                continue
            nb.their_headers.append(hdr)
            self.last_update = time.time()

    def _handle_dbd(self, nb, ospf):
        dbd = ospf[OSPF_DBDesc]
        flags = set(dbd.dbdescr)

        if nb.state in (STATE_DOWN, STATE_INIT, STATE_2WAY):
            return

        # --- Negotiation: they sent an Init/Master proposal ---
        if nb.state == STATE_EXSTART and {'I', 'M', 'MS'} <= flags and not dbd.lsaheaders \
                and nb.master is None:
            if nb.router_id > self.router_id:
                nb.master = False
                nb.dd_seq = dbd.ddseq
                self._send_ospf(nb.ip, nb.mac, 2, self._dbd_packet(
                    ms=False, i=False, more=False, ddseq=nb.dd_seq))
                nb.set_state(STATE_EXCHANGE)
            # else: our router-id is higher, we stay master and wait for them
            # to yield (handled below); keep re-advertising on Hello retransmit.
            return

        # --- They yielded to us as master ---
        if nb.state == STATE_EXSTART and nb.master is None and 'MS' not in flags \
                and dbd.ddseq == nb.dd_seq:
            nb.master = True
            nb.set_state(STATE_EXCHANGE)
            self._collect_headers(nb, dbd.lsaheaders)
            if 'M' in flags:
                nb.dd_seq += 1
                self._send_ospf(nb.ip, nb.mac, 2, self._dbd_packet(
                    ms=True, i=False, more=False, ddseq=nb.dd_seq))
            else:
                self._exchange_complete(nb)
            return

        if nb.state not in (STATE_EXCHANGE, STATE_LOADING) or nb.master is None:
            return

        self._collect_headers(nb, dbd.lsaheaders)

        if nb.master is False:
            nb.dd_seq = dbd.ddseq
            self._send_ospf(nb.ip, nb.mac, 2, self._dbd_packet(
                ms=False, i=False, more=False, ddseq=nb.dd_seq))
            if 'M' not in flags:
                self._exchange_complete(nb)
        else:
            if dbd.ddseq != nb.dd_seq:
                return
            if 'M' in flags:
                nb.dd_seq += 1
                self._send_ospf(nb.ip, nb.mac, 2, self._dbd_packet(
                    ms=True, i=False, more=False, ddseq=nb.dd_seq))
            else:
                self._exchange_complete(nb)

    def _exchange_complete(self, nb):
        if nb.their_headers:
            nb.set_state(STATE_LOADING)
            self._send_next_lsreq_batch(nb)
        else:
            nb.set_state(STATE_FULL)
            LOG.info("Adjacency with %s reached FULL — LSDB synchronized", nb.router_id)

    def _send_next_lsreq_batch(self, nb):
        if not nb.their_headers:
            nb.set_state(STATE_FULL)
            LOG.info("Adjacency with %s reached FULL — LSDB synchronized", nb.router_id)
            return
        items = [OSPF_LSReq_Item(type=h.type, id=h.id, adrouter=h.adrouter)
                 for h in nb.their_headers]
        nb.pending_requests = [(h.type, h.id, h.adrouter) for h in nb.their_headers]
        self._send_ospf(nb.ip, nb.mac, 3, OSPF_LSReq(requests=items))

    def _handle_lsupd(self, nb, ospf):
        lsupd = ospf[OSPF_LSUpd]
        received = []
        for lsa in lsupd.lsalist:
            key = (lsa.type, lsa.id, lsa.adrouter)
            self.lsdb[key] = lsa
            self.last_update = time.time()
            received.append(lsa)
            nb.their_headers = [h for h in nb.their_headers
                                 if (h.type, h.id, h.adrouter) != key]
            nb.pending_requests = [r for r in nb.pending_requests if r != key]

        if received:
            ack_hdrs = [OSPF_LSA_Hdr(age=l.age, options=l.options, type=l.type,
                                      id=l.id, adrouter=l.adrouter, seq=l.seq,
                                      chksum=l.chksum, len=l.len) for l in received]
            self._send_ospf(nb.ip, nb.mac, 5, OSPF_LSAck(lsaheaders=ack_hdrs))

        if nb.state == STATE_LOADING and not nb.pending_requests:
            self._send_next_lsreq_batch(nb)

    # ------------------------------------------------------------------
    # run loop
    # ------------------------------------------------------------------

    def _stop_condition(self, pkt):
        if not self.running:
            return True
        with self.lock:
            any_full = any(nb.state == STATE_FULL for nb in self.neighbors.values())
        now = time.time()
        if any_full and (now - self.last_update) > self.idle_timeout:
            return True
        if (now - self.start_time) > self.overall_timeout:
            LOG.warning("Timed out after %ss waiting for a Full adjacency.",
                        self.overall_timeout)
            return True
        return False

    def run(self):
        self.running = True
        LOG.info("Interface %s  src-ip=%s  router-id=%s  area=%s",
                  self.iface, self.src_ip, self.router_id, self.area)
        LOG.info("Sending Hellos every %ss, dead interval %ss ...",
                  self.hello_interval, self.dead_interval)
        threading.Thread(target=self.hello_loop, daemon=True).start()
        threading.Thread(target=self.maintenance_loop, daemon=True).start()
        sniff(iface=self.iface, filter="ip proto 89", prn=self.handle_packet,
              store=False, stop_filter=self._stop_condition)
        self.running = False

    # ------------------------------------------------------------------
    # topology extraction / reporting
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_to_cidr(mask):
        try:
            return sum(bin(int(o)).count('1') for o in mask.split('.'))
        except Exception:
            return '?'

    def build_topology(self):
        routers = {}
        networks = {}
        summaries = []
        externals = []

        for (ltype, lid, ladv), lsa in self.lsdb.items():
            if ltype == 1:  # Router-LSA
                entry = routers.setdefault(
                    ladv, {'links': [], 'stubs': [], 'flags': lsa.flags})
                for link in lsa.linklist:
                    if link.type == 3:
                        entry['stubs'].append(
                            {'network': link.id, 'mask': link.data, 'cost': link.metric})
                    else:
                        entry['links'].append(
                            {'type': link.type, 'id': link.id,
                             'iface': link.data, 'cost': link.metric})
            elif ltype == 2:  # Network-LSA
                networks[lid] = {'mask': lsa.mask, 'dr_adv': ladv,
                                  'attached': [str(r) for r in lsa.routerlist]}
            elif ltype in (3, 4):  # Summary / ASBR-Summary
                summaries.append({
                    'adv_router': ladv, 'id': lid,
                    'mask': getattr(lsa, 'mask', None), 'metric': lsa.metric,
                    'kind': 'ASBR-summary' if ltype == 4 else 'summary'})
            elif ltype == 5:  # External-LSA
                externals.append({
                    'adv_router': ladv, 'network': lid, 'mask': lsa.mask,
                    'metric': lsa.metric, 'fwdaddr': lsa.fwdaddr})

        return routers, networks, summaries, externals

    def print_topology(self):
        routers, networks, summaries, externals = self.build_topology()
        link_kind = {1: 'point-to-point ->', 2: 'transit network  ->', 4: 'virtual link     ->'}

        print("\n" + "=" * 72)
        print(f" OSPF AREA {self.area} — TOPOLOGY  ({len(self.lsdb)} LSAs in LSDB)")
        print("=" * 72)

        print(f"\nRouters discovered: {len(routers)}")
        for rid, info in sorted(routers.items()):
            tags = []
            if 'B' in info['flags']:
                tags.append("ABR")
            if 'E' in info['flags']:
                tags.append("ASBR")
            tag_str = f"  [{', '.join(tags)}]" if tags else ""
            print(f"\n  Router {rid}{tag_str}")
            for link in info['links']:
                kind = link_kind.get(link['type'], f"type {link['type']}        ->")
                print(f"      {kind} {link['id']:<16} via {link['iface']:<16} cost {link['cost']}")
            for stub in info['stubs']:
                cidr = self._mask_to_cidr(stub['mask'])
                print(f"      stub network      -> {stub['network']}/{cidr:<13} cost {stub['cost']}")

        print(f"\nTransit (multi-access) networks: {len(networks)}")
        for dr_ip, info in sorted(networks.items()):
            cidr = self._mask_to_cidr(info['mask'])
            print(f"\n  Network {dr_ip}/{cidr}   (DR: {info['dr_adv']})")
            for r in info['attached']:
                print(f"      attached router -> {r}")

        if summaries:
            print(f"\nInter-area summary routes: {len(summaries)}")
            for s in summaries:
                target = f"{s['id']}/{self._mask_to_cidr(s['mask'])}" if s['mask'] else s['id']
                print(f"  via {s['kind']:<14} ABR/ASBR {s['adv_router']:<16} -> {target:<20} cost {s['metric']}")

        if externals:
            print(f"\nExternal (redistributed) routes: {len(externals)}")
            for e in externals:
                print(f"  via ASBR {e['adv_router']:<16} -> {e['network']}/{self._mask_to_cidr(e['mask'])}"
                      f"   cost {e['metric']}  fwd={e['fwdaddr']}")

        print()

    def to_json(self):
        routers, networks, summaries, externals = self.build_topology()
        return json.dumps({
            'area': self.area,
            'lsa_count': len(self.lsdb),
            'routers': routers,
            'networks': networks,
            'summaries': summaries,
            'externals': externals,
        }, indent=2, default=str)


def main():
    p = argparse.ArgumentParser(
        description="OSPFv2 active reconnaissance — form a full adjacency and dump the area topology.")
    p.add_argument("--iface", required=True, help="Network interface on the OSPF segment, e.g. eth0")
    p.add_argument("--area", default="0.0.0.0", help="OSPF area ID (default: 0.0.0.0 / backbone)")
    p.add_argument("--router-id", required=True,
                   help="Router ID to advertise as. Pick something unlikely to collide with a real router.")
    p.add_argument("--mask", default="255.255.255.0", help="Subnet mask of the segment (must match neighbors')")
    p.add_argument("--hello-interval", type=int, default=10)
    p.add_argument("--dead-interval", type=int, default=40)
    p.add_argument("--idle-timeout", type=int, default=8,
                   help="Seconds of LSDB inactivity after Full before declaring sync complete")
    p.add_argument("--timeout", type=int, default=120, help="Overall timeout in seconds")
    p.add_argument("--json-out", help="Optional path to also write the topology as JSON")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")

    print(__doc__.split("Usage")[0])  # print the safety banner once at startup

    recon = OSPFRecon(
        iface=args.iface, area=args.area, router_id=args.router_id, mask=args.mask,
        hello_interval=args.hello_interval, dead_interval=args.dead_interval,
        idle_timeout=args.idle_timeout, overall_timeout=args.timeout,
    )

    try:
        recon.run()
    except PermissionError:
        sys.exit("Permission denied — raw sockets require root (try sudo).")
    except KeyboardInterrupt:
        LOG.info("Interrupted by user.")

    if recon.lsdb:
        recon.print_topology()
        if args.json_out:
            with open(args.json_out, "w") as f:
                f.write(recon.to_json())
            LOG.info("Wrote JSON topology to %s", args.json_out)
    else:
        LOG.warning("No LSAs collected — no neighbor reached Full state. "
                    "Check area ID, mask, authentication, and that you're on the right segment.")


if __name__ == "__main__":
    main()