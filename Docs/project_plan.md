# PROJECT PLAN

TODO:
- [X] Confirm Network Topology
- [X] Configure Working Network with OSPF
- [X] Confirm OSPF hijacking is possible
- [X] Add Internet Access to Network (ISP)
- [X] Confirm how to perform DNS/Web Spoofing to send captive portal after OSPF hijacking
- [X] Download CA Cert and capture victim web traffic
- [X] Perform TLS decryption to view captured web traffic in plaintext
- [ ] Add authentication method to OSPF configuration. (Try plaintext first, then MD5 hashing)
- [ ] Add vlan20 on ASW2 and test if traffic is passthrough kali

NOTE: 
- Redirect users to original destination after captive portal
- TLS decryption can only be done on websites that do not have HSTS implemented


# To add to scenario
```
Attacker uses a Wifi adapter to connect his PC to his hotspot which is then used as the internet facing gateway to direct traffic out
```
Null and simple auth found in OSPF_Hdr class under `authdata`
Crypto authentication found in OSPF_Hdr class under
`reserved`
`keyid` (identifies which preshared key is used)
`authdatalen` (16 exact byte length of crypto digest)
`seq` (strictly 32-bit increment counter for anti-replay protection)

Scapy has no direct support for extracting crypto authdata. 
Instead, authdata is 16 byte MD5 hash is appended to the end of the packet

OSPF uses Net-MD5 hashing algorithm
check if extracted hash (last 16 bytes starts with $netmd5...)

scapy OSPF_Hdr has a `key` macro that automatically calculates the hash from a provided plaintext key

# MD5 Hash generation

OSPF_Hdr chksum field set to 0

keyid use sniffed packet chosen keyid

`authdatalen` field set to 16 for MD5

`seq` must be at least as large as the last value send out of the interface


# MD5 auth configuration
password must not exceed 16 characters

MD5 always results in 128-bit hash value

# Not MD5
if using plaintext pw, password can be directly extracted from `authdata` field in OSPF_Hdr
