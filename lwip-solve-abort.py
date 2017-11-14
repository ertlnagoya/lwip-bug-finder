#!/usr/bin/python2
# encoding: utf-8
import angr #the main framework
import claripy #the solver engine
try:
    import emoviz # execution trace visualizer
except ImportError as e:
    print e
    print "[!] cannot load emoviz module. missing emoviz.py in current directory. exit."
    exit(1)
import os, signal
import pickle
import hexdump

angr.manager.l.setLevel("DEBUG")

TRACE_SAVE_DIR = "./trace/"
os.system("if [ ! -d %s ]; then mkdir %s; fi" % (TRACE_SAVE_DIR, TRACE_SAVE_DIR))
os.system("rm -f %s[a-zA-Z]*-[0-9]*.{png,dot,txt}" % (TRACE_SAVE_DIR))
def plot_trace():
    global proj, state

    def helper(proj, state, dot_file, plain_file=""):
        ev = emoviz.emoviz(proj)
        ev.add(state)
        ev.save_dot(dot_file)
        ev.save_png(dot_file)
        if plain_file:
            ev.save_plain(plain_file)

    for (i, act) in enumerate(simgr.active):
        dot_file = TRACE_SAVE_DIR + "active-%d.dot" % i
        helper(proj, act.state, dot_file,
            # plain_file=TRACE_SAVE_DIR + "active-%d.txt" % i
            )
        if i >= 9: break
    if hasattr(simgr, "found"):
        for (i, fnd) in enumerate(simgr.found):
            dot_file = TRACE_SAVE_DIR + "found-%d.dot" % i
            helper(proj, fnd.state, dot_file)
    if hasattr(simgr, "avoid"):
        for (i, avd) in enumerate(simgr.avoid):
            dot_file = TRACE_SAVE_DIR + "avoid-%d.dot" % i
            helper(proj, avd.state, dot_file,
                # plain_file=TRACE_SAVE_DIR + "avoid-%d.txt" % i
                )
            if i > 5: break
    for (i, ddd) in enumerate(simgr.deadended):
        dot_file = TRACE_SAVE_DIR + "deadended-%d.dot" % i
        helper(proj, ddd.state, dot_file)
        if i > 5: break
    for (i, err) in enumerate(simgr.errored):
        dot_file = TRACE_SAVE_DIR + "errored-%d.dot" % i
        helper(proj, err.state, dot_file)
        if i >= 14: break

def signal_handler(signal, frame):
    print('[*] received SIGNAL')
    plot_trace()
    exit(1)
signal.signal(signal.SIGINT, signal_handler) # Ctrl+C

def dump_regs(state, _exit=True):
    print "rax = %#x" % state.solver.eval(state.regs.rax)
    print "rdi = %#x" % state.solver.eval(state.regs.rdi)
    print "rsp = %#x" % state.solver.eval(state.regs.rsp)
    print "rbp = %#x" % state.solver.eval(state.regs.rbp)
    rbp = state.solver.eval(state.regs.rbp)
    for i in range(0, 0x48, 8):
        print "mem[rbp - %#x] = %#x" % (i, state.solver.eval(state.memory.load(rbp - i, 8)))
    for i in range(0x20000000, 0x20000000 + 0x200, 8):
        # v = state.solver.eval(state.memory.load(i, 8))
        try:
            v = state.mem[i].uint64_t.concrete
        except Exception, e:
            print "mem[%#x]: " % i + str(e)
            continue
        if v > 0:
            print "mem[%#x] = %#x" % (i, v)
    if _exit:
        exit()

def memory_dump(state, begin, length):
    ret = ""
    for i in range(0, length):
        val = state.solver.eval(state.memory.load(begin + i, 1))
        ret += chr(val)
    return ret

### === helper functions ===
rebased_addr = lambda x: proj.loader.find_symbol(x).rebased_addr
relative_addr = lambda x: proj.loader.find_symbol(x).relative_addr

### load binary
ELF_FILE = "./bin/simhost-STABLE-1_3_0"
proj = angr.Project(ELF_FILE, load_options={'auto_load_libs': False})
# start_addr = rebased_addr('tcp_input')
# start_addr = rebased_addr('udp_input')
start_addr = rebased_addr('etharp_arp_input')
print "[*] analysis start: %#x" % start_addr
### create blank state (initial state)
state = proj.factory.blank_state(addr=start_addr)

### helper boolean
tcp = (start_addr == rebased_addr('tcp_input'))
udp = (start_addr == rebased_addr('udp_input'))
etharp_arp = (start_addr == rebased_addr('etharp_arp_input'))
ip = tcp or udp

### load preprocessed data
from preprocess import Info, Symbol
INFO_FILE = ELF_FILE + ".info"
try:
    with open(INFO_FILE) as f:
        info = pickle.load(f)
except IOError as e:
    print e
    print "[!] run `./preprocess.py %s` first" % (ELF_FILE)
    exit()

### disables function calls. and sets return value 0
def handle_ret_0(state):
    state.regs.rax = 0

### hooks function calls
try:
    ### nop function x() calls
    funcs = [
    "tcp_debug_print_flags", "tcp_debug_print",
    "udp_debug_print", # debug output
    "tcp_process", # tcp state machine
    "inet_chksum_pseudo",
    "pbuf_free",
    ]
    for func_name in funcs:
        if func_name in info.call:
            for x in info.call[func_name]:
                proj.hook(0x400000 + x, handle_ret_0, length=5) # 5 bytes instruction
        else:
            print "[!] info.call has not key '%s'" % func_name
            exit(1)
except Exception as e:
    print e
    import ipdb; ipdb.set_trace()
    raise e

### specifies variables location
pbuf_ptr = 0x20000000
pbuf_payload_ptr = pbuf_ptr + 0x8
pbuf_tot_len = pbuf_ptr + 0x10
pbuf_len = pbuf_ptr + 0x12
pbuf_type = pbuf_ptr + 0x14
pbuf_payload = 0x20000100
state.mem[pbuf_payload_ptr].qword = pbuf_payload

### symbolize pbuf.tot_len
symvar_pbuf_tot_len = state.se.BVS('pbuf_tot_len', 16)
state.add_constraints(symvar_pbuf_tot_len > 0)
state.memory.store(pbuf_tot_len, symvar_pbuf_tot_len)

### symbolize pbuf.len
symvar_pbuf_len = state.se.BVS('pbuf_len', 16)
l4_min_len = 0
if tcp:
    l4_min_len = 20
elif udp:
    l4_min_len = 64 / 8
### limit `<= 256` avoids 'IP (len %d) is longer than pbuf (len 256), IP packet dropped.''
state.add_constraints(state.se.And(symvar_pbuf_len >= 20 + l4_min_len, symvar_pbuf_len <= 256))
# state.add_constraints(state.se.And(symvar_pbuf_len > 20 + 40, symvar_pbuf_len <= 256)) # minimum size of IP + TCP
state.memory.store(pbuf_len, state.se.Reverse(symvar_pbuf_len))
state.add_constraints(symvar_pbuf_tot_len == symvar_pbuf_len)

### symbolize pbuf.type
symvar_pbuf_type = state.se.BVS('pbuf_type', 8)
state.memory.store(pbuf_type, state.se.Reverse(symvar_pbuf_type))

### add constraints for a packet
L2_PAYLOAD_MAX_LEN = 1500 # 1518 (max Ether frame size) - 14 (address) - 4 (FCS)
symvar_pbuf_payload = state.se.BVS('pbuf_payload', L2_PAYLOAD_MAX_LEN * 8)
tcp_header_offset = 5 * 4 * 8
if ip:
    state.add_constraints(state.se.Extract(7, 0, symvar_pbuf_payload) == 0x45) # ip version & ip header size (IPHL)
    state.add_constraints(state.se.Reverse(state.se.Extract(31, 16, symvar_pbuf_payload)) == symvar_pbuf_len) # Total Length in IP header
    state.add_constraints(state.se.Extract(32 * 2 + 7, 32 * 2 + 0, symvar_pbuf_payload) > 0) # TTL
    symvar_ip_proto = state.se.Extract(32 * 2 + 15, 32 * 2 + 8, symvar_pbuf_payload)
    if tcp:
        state.add_constraints(symvar_ip_proto == 6) # ip proto (TCP = 6, UDP = 0x11)
    elif udp:
        state.add_constraints(symvar_ip_proto == 0x11) # ip proto (TCP = 6, UDP = 0x11)
    else:
        state.add_constraints(state.se.Or(symvar_ip_proto == 6, symvar_ip_proto == 0x11)) # ip proto (TCP = 6, UDP = 0x11)
    state.add_constraints(state.se.Reverse(state.se.Extract(32 * 3 + 31, 32 * 3 + 0, symvar_pbuf_payload)) == 0xc0a80001) # ip src (192.168.0.1)
    state.add_constraints(state.se.Reverse(state.se.Extract(32 * 4 + 31, 32 * 4 + 0, symvar_pbuf_payload)) == 0xc0a80002) # ip dest (192.168.0.2)
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0xf, tcp_header_offset + 0x0, symvar_pbuf_payload)) > 0) # src port
    if tcp:
        state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x1f, tcp_header_offset + 0x10, symvar_pbuf_payload)) == 80) # dst port
    elif udp:
        state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x1f, tcp_header_offset + 0x10, symvar_pbuf_payload)) == 7) # dst port
    fix_no = False
    symvar_seqno = state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x3f, tcp_header_offset + 0x20, symvar_pbuf_payload))
    symvar_ackno = state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x5f, tcp_header_offset + 0x40, symvar_pbuf_payload))
    if fix_no:
        state.add_constraints(symvar_seqno == 0x11223344) # seqno
        state.add_constraints(symvar_ackno == 0x55667788) # ackno
    else:
        state.add_constraints(symvar_seqno > 0) # seqno
        state.add_constraints(symvar_ackno > 0) # ackno
    if tcp:
        symvar_tcp_dataofs = state.solver.Extract(tcp_header_offset + 96 + 7, tcp_header_offset + 96 + 4, symvar_pbuf_payload)
        state.add_constraints(state.se.And(symvar_tcp_dataofs >= 5, symvar_tcp_dataofs <= 15)) # tcp length
elif etharp_arp:
    pass
state.memory.store(pbuf_payload, state.se.Reverse(symvar_pbuf_payload))

### symbolize netif variable (defined in simhost)
netif_ptr = rebased_addr('netif')
netif_size = info.symbols['netif'].size
print "[*] netif_size = %#x (%d)" % (netif_size, netif_size)
symvar_netif = state.se.BVS('netif', netif_size * 8)
"""
0x632de0 <netif>:   0x00000000  0x00000000  0x0200a8c0  0x00ffffff
0x632df0 <netif+16>:    0x0100a8c0  0x00000000  0x0041142d  0x00000000
0x632e00 <netif+32>:    0x0041687c  0x00000000  0x00418138  0x00000000
0x632e10 <netif+48>:    0x0062a7c8  0x00000000  0x03020106  0x00060504
0x632e20 <netif+64>:    0x740105dc  0x00000070  0x000000f8  0x00000000
"""
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 8 - 1, 0, symvar_netif)) == 0) # next
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_netif)) == 0xc0a80002) # ip_addr
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_netif)) == 0xffffff) # netmask
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 20 - 1, 8 * 16, symvar_netif)) == 0x0100a8c0) # gw
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 24 - 1, 8 * 20, symvar_netif)) == 0x00000000) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 28 - 1, 8 * 24, symvar_netif)) == 0x00418138) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 32 - 1, 8 * 28, symvar_netif)) == 0x00000000) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 36 - 1, 8 * 32, symvar_netif)) == 0x0041687c) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 40 - 1, 8 * 36, symvar_netif)) == 0x00000000) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 44 - 1, 8 * 40, symvar_netif)) == 0x00418138) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 48 - 1, 8 * 44, symvar_netif)) == 0x00000000) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 52 - 1, 8 * 48, symvar_netif)) == 0x0062a7c8) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 56 - 1, 8 * 52, symvar_netif)) == 0x00000000) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 60 - 1, 8 * 56, symvar_netif)) == 0x03020106) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 64 - 1, 8 * 60, symvar_netif)) == 0x00060504) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 68 - 1, 8 * 64, symvar_netif)) == 0x740105dc) #
state.add_constraints(state.se.Reverse(state.se.Extract(8 * 72 - 1, 8 * 70, symvar_netif)) == 0x00000070) #
# state.add_constraints(state.se.Reverse(state.se.Extract(8 * 76 - 1, 8 * 74, symvar_netif)) == 0x000000f8) #
# state.add_constraints(state.se.Reverse(state.se.Extract(8 * 82 - 1, 8 * 78, symvar_netif)) == 0x00000000) #
state.memory.store(netif_ptr, state.se.Reverse(symvar_netif))

### symbolize ethaddr
ethaddr_ptr = 0x201000
symvar_ethaddr = state.se.BVS('ethaddr', 6 * 8)
state.add_constraints(state.se.Reverse(state.se.Extract(6 * 8 - 1, 0, symvar_ethaddr)) > 0)
state.memory.store(netif_ptr, state.se.Reverse(symvar_netif))

### debugging
dump_regs(state, _exit=False)

# RSP = 0x7fff1000
if ip:
    state.regs.rdi = pbuf_ptr
    state.regs.rsi = netif_ptr # inp_ptr
elif etharp_arp:
    # etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr, struct pbuf *p)
    state.regs.rdi = netif_ptr
    state.regs.rsi = ethaddr_ptr
    state.regs.rdx = pbuf_ptr

### load initial state to engine (Simulation Manager)
simgr = proj.factory.simgr(state)

### setup finds / avoids
find, avoid = [], []
### (1) bug #24596; LWIP_ERROR("increment_magnitude <= p->len", (increment_magnitude <= p->len), return 1;);
if tcp:
    avoid += [rebased_addr('pbuf_header') + 0x9513 - relative_addr('pbuf_header')] # (1)
elif udp:
    # find += [rebased_addr('pbuf_header') + 0x9513 - relative_addr('pbuf_header')] # (1)
    avoid += [rebased_addr('pbuf_header') + 0x9513 - relative_addr('pbuf_header')] # (1)
### (2) find other bugs
find += [rebased_addr('abort')] # (2)
# avoid += [rebased_addr('pbuf_free')]
avoid += [rebased_addr('tcp_rst')]
avoid += [rebased_addr('pbuf_header') + 0x9608 - relative_addr('pbuf_header')] # bad pbuf type (This is not bug)
### (2) Assertion "netif->hwaddr_len == ETHARP_HWADDR_LEN" failed at line 473 in ../../../../../lwip/src/netif/etharp.c
# avoid += [rebased_addr('update_arp_entry') + 0x198fa - relative_addr('update_arp_entry')] # (2); this is not bug
# avoid += [rebased_addr('tcp_input') + 0x1c9a4 - relative_addr('tcp_input')] # short packet
# avoid += [rebased_addr('tcp_input') + 0x1c7c9 - relative_addr('tcp_input')] # short packet .. discarded
# avoid += [rebased_addr('udp_input') + 0x202ad - relative_addr('udp_input')] # short udp diagram

### print finds / avoids
print "[*] find = %s" % str(map(lambda x: hex(x), find))
print "[*] avoid = %s" % str(map(lambda x: hex(x), avoid))

### debugging
# proj.hook(0x400000 + 0x1c730, dump_regs, length=4)

### explore bugs
simgr.explore(find=find, avoid=avoid)
print "[*] explore finished!!"

if len(simgr.found) > 0:
    plot_trace()
    ### save results
    result = open("result.py", "w")
    result.write("""
import sys
import pickle
try:
    from scapy.all import *
except ImportError:
    print("[!] `pip install scapy` first! exit.")
    exit(1)

def usage():
    cmd_name = sys.argv[0]
    print("usage: [sudo] %s [PACKET_NO]" % cmd_name)
    print("\\tto preview packet: %s" % cmd_name)
    print("\\tto send packet: sudo %s PACKET_NO" % cmd_name)
    print("")
    print("PACKET_NO of packets are indicated in this script.")
    exit()

def recalc_chksums(p):
    if p.haslayer(IP):
        p[IP].chksum = None # to recalculate checksum
    if p.haslayer(TCP):
        p[TCP].chksum = None # to recalculate checksum
    fnull = open(os.devnull, 'w')
    fout = sys.stdout
    sys.stdout = fnull # disable output
    p.show2() # recalculate checksum
    sys.stdout = fout # enable output

def eth_type(p):
    eth_type = 0
    if p.haslayer(IP):
        if p[IP].version == 4:
            eth_type = 0x0800 # IPv4
        elif p[IP].version == 6:
            eth_type = 0x0806 # IPv6
    elif p.haslayer(ARP):
        eth_type = 0x0806
    assert(eth_type > 0)
    return eth_type

IS_ROOT = (os.geteuid() == 0)
PACKET_NO = -1
if len(sys.argv) == 2:
    if sys.argv[1] in ["--help", "-h"]:
        usage()
    PACKET_NO = int(sys.argv[1])
if PACKET_NO > 0 and not IS_ROOT:
    print "[!] you must _root_ to send packet! exit."
    exit(1)
if IS_ROOT and PACKET_NO == -1:
    print "[!] specify packet no"
    usage()
""")
    for i, found in enumerate(simgr.found):
        print "found #%d: stdout:\n%r" % (i, found.posix.dumps(1))
        print "found #%d: stderr:\n%r" % (i, found.posix.dumps(2))
        v = found.se.eval(symvar_pbuf_tot_len)
        print "found #%d: pbuf.tot_len: %#x (%d)" % (i, v, v)
        v = found.se.eval(symvar_pbuf_len)
        print "found #%d: pbuf.len: %#x (%d)" % (i, v, v)
        l2_payload_len = v
        v = found.se.eval(symvar_pbuf_type)
        print "found #%d: pbuf.type: %#x (%d)" % (i, v, v)
        print "found #%d: pbuf.payload (= L2 Payload): " % (i)
        v = found.se.eval(found.se.Reverse(symvar_pbuf_payload), cast_to=str)
        hexdump.hexdump(v[:l2_payload_len])
        result.write("""\n
### this is Packet #{no:d}
print("[*] ==== [Packet #{no:d}] ====")
print("found #{no:d}: pbuf.payload:")
l2_payload_len = {len:}
v = pickle.loads({dump!r})
if {ip!r}: # is IP packet?
    p = IP(_pkt=v[:l2_payload_len])
elif {etharp!r}: # is Ether packet?
    p = Ether(_pkt=v[:l2_payload_len])
# p[IP].ttl = 64
# p[IP].window = 8192

recalc_chksums(p)
p.show()
b = bytes(p)[:l2_payload_len] # trim unused padding

if IS_ROOT and PACKET_NO == {no:d}: # send mode
    ### write your script here...
    ### send(p) trims padding automically, so I use this one
    if {ip!r}:
        sendp(Ether(dst="11:45:14:11:45:14", type=eth_type(p))/b, iface="tap0")
    if {etharp!r}:
        sendp(b, iface="tap0")
else: # preview mode
    ### write your script here...
    hexdump(b)
    pass
""".format(no=i, dump=pickle.dumps(v), len=l2_payload_len, ip=ip, etharp=etharp_arp))
        print "found #%d: pbuf:" % (i)
        v = memory_dump(found, pbuf_ptr, 0x20)
        hexdump.hexdump(v)
        tcphdr_val = found.mem[rebased_addr('tcphdr')].uint64_t.concrete
        iphdr_val = found.mem[rebased_addr('iphdr')].uint64_t.concrete
        print "found #%d: iphdr = %#x, tcphdr = %#x" % (i, iphdr_val, tcphdr_val)
        print "found #%d: *iphdr:" % (i)
        hexdump.hexdump(memory_dump(found, iphdr_val, 0x20))
        print "found #%d: *tcphdr:" % (i)
        hexdump.hexdump(memory_dump(found, tcphdr_val, 0x20))
    ### the end of iteration
    result.close()
    print ""
    print "[*] attack packets are saved to result.py."

    ### print final result (this can be comment outed)
    print ""
    print "[*] preview of attack packets"
    os.system("python2 result.py")
else:
    print "[!] no outcomes;("

### you can send generated packets with result.py. enjoy:)