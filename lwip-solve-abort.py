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
import os, sys, signal
import pickle
import hexdump

angr.manager.l.setLevel("DEBUG")

### ==================================================================
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
### ==================================================================

def dump_regs(state, _exit=True):
    global symvar_listen_pcbs, symbar_netif
    print "rax = %#x" % state.solver.eval(state.regs.rax)
    print "rdi = %#x" % state.solver.eval(state.regs.rdi)
    print "rsp = %#x" % state.solver.eval(state.regs.rsp)
    print "rbp = %#x" % state.solver.eval(state.regs.rbp)
    rbp = state.solver.eval(state.regs.rbp)
    for i in range(0, 0x48, 8):
        # print "mem[rbp - %#x] = %#x" % (i, state.solver.eval(state.memory.load(rbp - i, 8)))
        print "mem[rbp - %#x] = %#x" % (i, state.mem[rbp - i].uint64_t.concrete)
    for i in range(0x20000000, 0x20000000 + 0x200, 8):
        # v = state.solver.eval(state.memory.load(i, 8))
        try:
            v = state.mem[i].uint64_t.concrete
        except Exception, e:
            print "mem[%#x]: " % i + str(e)
            continue
        if v > 0:
            print "mem[%#x] = %#x" % (i, v)
    print "listen_pcbs:"
    v = state.se.eval(state.se.Reverse(symvar_listen_pcbs), cast_to=str)
    hexdump.hexdump(v)
    print "netif:"
    v = state.se.eval(state.se.Reverse(symvar_netif), cast_to=str)
    hexdump.hexdump(v)
    if _exit:
        exit()

def memory_dump(state, begin, length):
    ret = ""
    for i in range(0, length):
        val = state.solver.eval(state.memory.load(begin + i, 1))
        ret += chr(val)
    return ret

def usage():
    print "usage: %s START_FUNC_NAME" % (sys.argv[0])
    exit(1)

### === helper functions ===
rebased_addr = lambda x: proj.loader.find_symbol(x).rebased_addr
relative_addr = lambda x: proj.loader.find_symbol(x).relative_addr

### process argv
if len(sys.argv) == 1:
    usage()
START_FUNC = sys.argv[1]
if START_FUNC not in ['tcp_input', 'udp_input', 'etharp_arp_input', 'dns_recv']:
    print "[!] invalid function name"
    exit(1)

### load binary
ELF_FILE = "./bin/simhost-STABLE-1_3_0"
if START_FUNC == 'dns_recv':
    ELF_FILE = "./bin/echop-STABLE-1_3_0"
proj = angr.Project(ELF_FILE, load_options={'auto_load_libs': False})
start_addr = rebased_addr(START_FUNC)
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
    funcs = []
    if True:
        funcs += [
        "tcp_debug_print_flags", "tcp_debug_print",
        "udp_debug_print", # debug output
        "inet_chksum_pseudo", # checksum check
        "inet_chksum_pseudo_partial",
        "tcp_process", # tcp state machine
        # "pbuf_free",
        "sys_arch_protect", "sys_arch_unprotect", # SYS_ARCH_PROTECT, SYS_ARCH_UNPROTECT
        "sys_arch_sem_wait",
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

### enable debug flag
LWIP_DBG_ON = 0x80
LWIP_DBG_OFF = 0x0
state.mem[rebased_addr('debug_flags')].uint32_t = LWIP_DBG_OFF

### symbolize pbuf
"""
gdb-peda$ p (struct pbuf) *$rdi
$4 = {
  next = 0x0,
  payload = 0x560bea7cbe9e <memp_memory+19006>,
  tot_len = 0x30,
  len = 0x30,
  type = 0x3,
  flags = 0x0,
  ref = 0x1
}
gdb-peda$ x/8wx $rdi
0x560bea7cbe78 <memp_memory+18968>: 0x00000000  0x00000000  0xea7cbe9e  0x0000560b
0x560bea7cbe88 <memp_memory+18984>: 0x00300030  0x00010003  0x04030201  0xa6920605 // + 16
"""
pbuf_ptr = 0x20000000
pbuf_next = pbuf_ptr + 0x0
pbuf_payload_ptr = pbuf_ptr + 0x8
pbuf_tot_len = pbuf_ptr + 0x10
pbuf_len = pbuf_ptr + 0x12
pbuf_type = pbuf_ptr + 0x14
pbuf_flags = pbuf_ptr + 0x15
pbuf_ref = pbuf_ptr + 0x16
pbuf_payload = 0x20000100

state.mem[pbuf_next].qword = 0 # NULL
state.mem[pbuf_payload_ptr].qword = pbuf_payload # => p->payload == pbuf_payload

### symbolize pbuf.tot_len
symvar_pbuf_tot_len = state.se.BVS('pbuf_tot_len', 16) # u16_t
state.add_constraints(symvar_pbuf_tot_len > 0)
state.memory.store(pbuf_tot_len, state.se.Reverse(symvar_pbuf_tot_len))

### symbolize pbuf.len
symvar_pbuf_len = state.se.BVS('pbuf_len', 16) # u16_t
state.add_constraints(symvar_pbuf_tot_len == symvar_pbuf_len)
ip_min_len = 20
min_len = 0
if tcp:
    min_len = ip_min_len + 20
elif udp:
    min_len = ip_min_len + 64 / 8
### limit `<= 256` avoids 'IP (len %d) is longer than pbuf (len 256), IP packet dropped.''
state.add_constraints(state.se.And(symvar_pbuf_len >= min_len, symvar_pbuf_len <= 256))
state.memory.store(pbuf_len, state.se.Reverse(symvar_pbuf_len))

### symbolize pbuf.type
symvar_pbuf_type = state.se.BVS('pbuf_type', 8)
# state.add_constraints(symvar_pbuf_type == 0x3)
state.add_constraints(state.se.Or(symvar_pbuf_type == 0x0, symvar_pbuf_type == 0x3))
state.memory.store(pbuf_type, state.se.Reverse(symvar_pbuf_type))

### symbolize pbuf.ref
symvar_pbuf_ref = state.se.BVS('pbuf_ref', 16)
# state.add_constraints(symvar_pbuf_ref == 0) # reference count
# state.add_constraints(symvar_pbuf_ref == 1) # reference count
state.add_constraints(symvar_pbuf_ref == 0xffff) # reference count
state.memory.store(pbuf_ref, state.se.Reverse(symvar_pbuf_ref))

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
    state.add_constraints(state.se.Extract(8 * 6 - 1, 0, symvar_pbuf_payload) > 0) # eth dst addr
    state.add_constraints(state.se.Extract(8 * 12 - 1, 8 * 6, symvar_pbuf_payload) > 0) # eth src addr
    pass
state.memory.store(pbuf_payload, state.se.Reverse(symvar_pbuf_payload))

### symbolize netif variable (defined in simhost)
netif_ptr = rebased_addr('netif')
netif_size = info.symbols['netif'].size
print "[*] netif_size = %#x (%d)" % (netif_size, netif_size)
symvar_netif = state.se.BVS('netif', netif_size * 8)
"""
[bin/simhost-STABLE-1_3_0]
gdb-peda$ p netif
$1 = {
  next = 0x0,
  ip_addr = {
    addr = 0x200a8c0
  },
  netmask = {
    addr = 0xffffff
  },
  gw = {
    addr = 0x100a8c0
  },
  input = 0x560bea5aa836 <tcpip_input>,
  output = 0x560bea5affe8 <etharp_output>,
  linkoutput = 0x560bea5b191d <low_level_output>,
  state = 0x560bea7c47c8 <ram_heap+8>,
  hwaddr_len = 0x6,
  hwaddr = "\001\002\003\004\005\006",
  mtu = 0x5dc,
  flags = 0x1,
  name = "tp",
  num = 0x0
}

gdb-peda$ x/20xw &netif
0x560bea7cce00 <netif>: 0x00000000  0x00000000  0x0200a8c0  0x00ffffff
0x560bea7cce10 <netif+16>:  0x0100a8c0  0x00000000  0xea5aa836  0x0000560b
0x560bea7cce20 <netif+32>:  0xea5affe8  0x0000560b  0xea5b191d  0x0000560b
0x560bea7cce30 <netif+48>:  0xea7c47c8  0x0000560b  0x03020106  0x00060504
0x560bea7cce40 <netif+64>:  0x740105dc  0x00000070  0xea7cce00  0x0000560b
"""
NoReverse = lambda x: x
state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1, 0, symvar_netif)) == 0) # next
state.add_constraints(NoReverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_netif)) == 0x0200a8c0) # ip_addr
state.add_constraints(NoReverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_netif)) == 0xffffffff) # netmask
state.add_constraints(NoReverse(state.se.Extract(8 * 20 - 1, 8 * 16, symvar_netif)) == 0x0100a8c0) # gw
state.add_constraints(NoReverse(state.se.Extract(8 * 24 - 1, 8 * 20, symvar_netif)) == 0x00000000) # padding?
state.add_constraints(NoReverse(state.se.Extract(8 * 32 - 1, 8 * 24, symvar_netif)) == rebased_addr('tcpip_input')) # input
state.add_constraints(NoReverse(state.se.Extract(8 * 40 - 1, 8 * 32, symvar_netif)) == rebased_addr('etharp_output')) # output
state.add_constraints(NoReverse(state.se.Extract(8 * 48 - 1, 8 * 40, symvar_netif)) == rebased_addr('low_level_output')) # linkoutput
state.add_constraints(NoReverse(state.se.Extract(8 * 56 - 1, 8 * 48, symvar_netif)) == rebased_addr('ram_heap') + 8) # state
state.add_constraints(NoReverse(state.se.Extract(8 * 60 - 1, 8 * 56, symvar_netif)) == 0x03020106) #
state.add_constraints(NoReverse(state.se.Extract(8 * 64 - 1, 8 * 60, symvar_netif)) == 0x00060504) #
state.add_constraints(NoReverse(state.se.Extract(8 * 68 - 1, 8 * 64, symvar_netif)) == 0x740105dc) #
state.add_constraints(NoReverse(state.se.Extract(8 * 72 - 1, 8 * 70, symvar_netif)) == 0x00000070) #
state.memory.store(netif_ptr, state.se.Reverse(symvar_netif))
if False:
    v = state.se.eval(state.se.Reverse(symvar_netif), cast_to=str)
    hexdump.hexdump(v)
    exit()

### symbolize tcp/udp pcbs
"""
gdb-peda$ p tcp_listen_pcbs
$6 = {
  listen_pcbs = 0x560bea7c7b28 <memp_memory+1736>,
  pcbs = 0x560bea7c7b28 <memp_memory+1736>
}
gdb-peda$ p *(tcp_listen_pcbs->listen_pcbs)
$8 = {
  local_ip = {
    addr = 0x0
  },
  remote_ip = {
    addr = 0x560b
  },
  so_options = 0x2,
  tos = 0x0,
  ttl = 0xff,
  next = 0x560bea7c7b60 <memp_memory+1792>,
  state = LISTEN,
  prio = 0x0,
  callback_arg = 0x560bea7c8250 <memp_memory+3568>,
  local_port = 0x7,
  accept = 0x560bea5a9039 <accept_function>
}
gdb-peda$ x/20wx (tcp_listen_pcbs->listen_pcbs)
0x560bea7c7b28 <memp_memory+1736>:  0x00000000  0x0000560b  0xff000002  0x00000000
0x560bea7c7b38 <memp_memory+1752>:  0xea7c7b60  0x0000560b  0x00000001  0x00000000 // + 16
0x560bea7c7b48 <memp_memory+1768>:  0xea7c8250  0x0000560b  0x00000007  0x00000000 // + 32
0x560bea7c7b58 <memp_memory+1784>:  0xea5a9039  0x0000560b  0x00000000  0x0000560b // + 48
0x560bea7c7b68 <memp_memory+1800>:  0xff000002  0x00000000  0xea7c7b98  0x0000560b

gdb-peda$ x/20wx (tcp_listen_pcbs->listen_pcbs)->callback_arg
0x560bea7c8250 <memp_memory+3568>:  0x00000010  0x00000002  0xea7c7b28  0x0000560b
0x560bea7c8260 <memp_memory+3584>:  0x00000000  0x00000000  0xec000b10  0x00007fd4
0x560bea7c8270 <memp_memory+3600>:  0x00000000  0x00000000  0xe8000f40  0x00007fd4
0x560bea7c8280 <memp_memory+3616>:  0xffffffff  0x00000000  0x00000000  0x00000000
0x560bea7c8290 <memp_memory+3632>:  0x00000000  0x00000000  0x00000000  0x00000000
"""
listen_pcbs = 0x20010000
callback_arg = 0x560bea7c8250 # => 0x10
# state.mem[rebased_addr('tcp_listen_pcbs')].uint64_t = state.se.Reverse(state.se.BVV(listen_pcbs, 64))
state.mem[rebased_addr('tcp_listen_pcbs')].uint64_t = listen_pcbs
state.mem[callback_arg + 0].uint32_t = 0x00000010
state.mem[callback_arg + 4].uint32_t = 0x00000002
symvar_listen_pcbs = state.se.BVS('listen_pcbs', 56 * 8)
symvar_listen_pcbs_state = state.se.BVS('listen_pcbs', 4 * 8)
"""
include/lwip/tcpbase.h
enum tcp_state {
  CLOSED      = 0,
  LISTEN      = 1,
  SYN_SENT    = 2,
  SYN_RCVD    = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1  = 5,
  FIN_WAIT_2  = 6,
  CLOSE_WAIT  = 7,
  CLOSING     = 8,
  LAST_ACK    = 9,
  TIME_WAIT   = 10
};
"""
"""
  for(pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    LWIP_ASSERT("tcp_input: active pcb->state != CLOSED", pcb->state != CLOSED);
    LWIP_ASSERT("tcp_input: active pcb->state != TIME-WAIT", pcb->state != TIME_WAIT);
    LWIP_ASSERT("tcp_input: active pcb->state != LISTEN", pcb->state != LISTEN);
"""
state.add_constraints(state.se.And(symvar_listen_pcbs_state > 1, symvar_listen_pcbs_state < 10)) # to pass assertions
state.add_constraints(NoReverse(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_listen_pcbs)) == 0x0) # local ip
state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_listen_pcbs)) == 0x560b) # remote ip
state.add_constraints(NoReverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_listen_pcbs)) == 0xff000002) # so_options, tos, ttl
state.add_constraints(NoReverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_listen_pcbs)) == 0x0) # padding?
state.add_constraints(NoReverse(state.se.Extract(8 * 24 - 1, 8 * 16, symvar_listen_pcbs)) == 0) # next
state.add_constraints(NoReverse(state.se.Extract(8 * 28 - 1, 8 * 24, symvar_listen_pcbs)) == symvar_listen_pcbs_state) # state
# state.add_constraints(NoReverse(state.se.Extract(8 * 32 - 1, 8 * 28, symvar_listen_pcbs)) == 0) # prio?
state.add_constraints(NoReverse(state.se.Extract(8 * 40 - 1, 8 * 32, symvar_listen_pcbs)) == callback_arg) # callback_arg
# state.add_constraints(NoReverse(state.se.Extract(8 * 44 - 1, 8 * 40, symvar_listen_pcbs)) == 7) # local_port
state.add_constraints(NoReverse(state.se.Extract(8 * 56 - 1, 8 * 48, symvar_listen_pcbs)) == rebased_addr('accept_function')) # accept
state.memory.store(listen_pcbs, state.se.Reverse(symvar_listen_pcbs))
if False:
    v = state.se.eval(state.se.Reverse(symvar_listen_pcbs), cast_to=str)
    hexdump.hexdump(v)
    exit()

### symbolize tcp_active_pcbs
"""
gdb-peda$ p (struct tcp_pcb) pcb
$11 = {
  local_ip = {
    addr = 0xea7cbfa8
  },
  remote_ip = {
    addr = 0x560b
  },
  so_options = 0x0,
  tos = 0x0,
  ttl = 0x0,
  next = 0x7fd50530fdf0,
  state = 3931789480,
  prio = 0xb,
  callback_arg = 0x0,
  local_port = 0xfe50,
  remote_port = 0x530,
  flags = 0xd5,
  rcv_nxt = 0xea5a629c,
  rcv_wnd = 0x560b,
  rcv_ann_wnd = 0x0,
  tmr = 0xea7cce00,
  polltmr = 0xb,
  pollinterval = 0x56,
  rtime = 0x0,
  mss = 0xbfa8,
  rttest = 0x560b,
  rtseq = 0x530fe70,
  sa = 0x7fd5,
  sv = 0x0,
  rto = 0x14,
  nrtx = 0x30,
  lastack = 0x1,
  dupacks = 0xce,
  cwnd = 0xea7c,
  ssthresh = 0x560b,
  snd_nxt = 0xea7cce00,
  snd_max = 0x560b,
  snd_wnd = 0x0,
  snd_wl1 = 0x0,
  snd_wl2 = 0x5b10d6e,
  snd_lbb = 0x7fd5,
  acked = 0xd6f,
  snd_buf = 0x5b1,
  snd_queuelen = 0x7fd5,
  unsent = 0x7fd505310700,
  unacked = 0x7fd50530fe80,
  ooseq = 0x560bea5aa751 <tcpip_thread+344>,
  refused_data = 0x0,
  sent = 0x0,
  recv = 0x560bea7c86d8 <memp_memory+4728>,
  connected = 0x69cd72e63fead100,
  accept = 0x0,
  poll = 0x7fd50733c08a <start_thread+218>,
  errf = 0x0,
  keep_idle = 0x5310700,
  persist_cnt = 0x7fd5,
  persist_backoff = 0x0,
  keep_cnt_sent = 0x7
}
"""
pcb = 0x20016000
state.mem[rebased_addr('tcp_active_pcbs')].uint64_t = pcb
# state.mem[rebased_addr('tcp_active_pcbs') + 8].uint64_t = 0 # terminate with NULL
state.mem[rebased_addr('udp_pcbs')].uint64_t = pcb
symvar_pcb = state.se.BVS('pcb', 0xe0 * 8)
if tcp:
    state.add_constraints(NoReverse(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_pcb)) == 0x0) # local ip
    state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_pcb)) == 0x560b) # remote ip
    state.add_constraints(NoReverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_pcb)) == 0xff000002) # so_options, tos, ttl
    state.add_constraints(NoReverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_pcb)) == 0x0) # padding?
    state.add_constraints(NoReverse(state.se.Extract(8 * 24 - 1, 8 * 16, symvar_pcb)) == 0) # next
    state.add_constraints(NoReverse(state.se.Extract(8 * 28 - 1, 8 * 24, symvar_pcb)) == symvar_listen_pcbs_state) # state
elif udp:
    """
gdb-peda$ p *udp_pcbs
$2 = {
  local_ip = {
    addr = 0x0
  },
  remote_ip = {
    addr = 0x0
  },
  so_options = 0x0,
  tos = 0x0,
  ttl = 0xff,
  next = 0x0, // + 16
  flags = 0x0,
  local_port = 0x7, // + 24
  remote_port = 0x0, // + 26
  recv = 0x55b3c4ce893d <recv_udp>,
  recv_arg = 0x55b3c4f082a0 <memp_memory+3648>
}

gdb-peda$ x/20wx udp_pcbs
0x55b3c4f07580 <memp_memory+288>:   0x00000000  0x00000000  0xff000000  0x00000000
0x55b3c4f07590 <memp_memory+304>:   0x00000000  0x00000000  0x00070000  0x00000000
0x55b3c4f075a0 <memp_memory+320>:   0xc4ce893d  0x000055b3  0xc4f082a0  0x000055b3 // + 32
0x55b3c4f075b0 <memp_memory+336>:   0x00000000  0x00000000  0x00000000  0x00000000
0x55b3c4f075c0 <memp_memory+352>:   0x00000000  0x00000000  0x00000000  0x00000000
    """
    state.add_constraints(NoReverse(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_pcb)) == 0x0) # local ip
    state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_pcb)) == 0x0) # remote ip
    state.add_constraints(NoReverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_pcb)) == 0xff000000) # so_options, tos, ttl
    state.add_constraints(NoReverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_pcb)) == 0x0) # padding?
    state.add_constraints(NoReverse(state.se.Extract(8 * 24 - 1, 8 * 16, symvar_pcb)) == 0) # next
    state.add_constraints(NoReverse(state.se.Extract(8 * 26 - 1, 8 * 24, symvar_pcb)) == 0x7) # local_port
    state.add_constraints(NoReverse(state.se.Extract(8 * 28 - 1, 8 * 26, symvar_pcb)) == 0x0) # remote_port
    state.add_constraints(NoReverse(state.se.Extract(8 * 32 - 1, 8 * 28, symvar_pcb)) == 0x0) # padding?
    state.add_constraints(NoReverse(state.se.Extract(8 * 40 - 1, 8 * 32, symvar_pcb)) == rebased_addr('recv_udp')) # recv
state.memory.store(pcb, state.se.Reverse(symvar_pcb))

### symbolize ethaddr
ethaddr_ptr = 0x20020000
symvar_ethaddr = state.se.BVS('ethaddr', 6 * 8)
state.add_constraints(state.se.Reverse(state.se.Extract(6 * 8 - 1, 0, symvar_ethaddr)) > 0)
state.memory.store(netif_ptr, state.se.Reverse(symvar_netif))

### symbolize arp table
"""
gdb-peda$ print arp_table[0]
$4 = {
  q = 0x0,
  ipaddr = {
    addr = 0x100a8c0
  },
  ethaddr = {
    addr = "za\n\214.G"
  },
  state = ETHARP_STATE_EMPTY,
  ctime = 0x1c,
  netif = 0x55bbf9543e00 <netif>
}
gdb-peda$ x/12wx &arp_table[0]
0x55bbf953e1a0 <arp_table>: 0x00000000  0x00000000  0x0100a8c0  0x8c0a617a
0x55bbf953e1b0 <arp_table+16>:  0x0000472e  0x00000000  0x0000001c  0x00000000
0x55bbf953e1c0 <arp_table+32>:  0xf9543e00  0x000055bb  0x00000000  0x00000000
"""
symvar_arp_table = state.se.BVS('arp_table', 0x190 * 8)
for i in range(10):
    # state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1 + 8 * 0x28 * i, 8 * 0 + 8 * 0x28 * i, symvar_arp_table)) == 0) # q
    state.add_constraints(NoReverse(state.se.Extract(8 * 40 - 1 + 8 * 0x28 * i, 8 * 32 + 8 * 0x28 * i, symvar_arp_table)) == rebased_addr('netif'))
state.memory.store(rebased_addr('arp_table'), symvar_arp_table)


### debugging
# dump_regs(state, _exit=False)

if ip:
    """
    void    tcp_input(struct pbuf *p, struct netif *inp)
    void    udp_input(struct pbuf *p, struct netif *inp)
    """
    state.regs.rdi = pbuf_ptr
    state.regs.rsi = netif_ptr # inp_ptr
elif etharp_arp:
    """
    void    etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr, struct pbuf *p)
    """
    state.regs.rdi = netif_ptr
    state.regs.rsi = ethaddr_ptr
    state.regs.rdx = pbuf_ptr

### load initial state to engine (Simulation Manager)
simgr = proj.factory.simgr(state)

### setup finds / avoids
find, avoid = [], []
### (1) bug #24596; LWIP_ERROR("increment_magnitude <= p->len", (increment_magnitude <= p->len), return 1;);
if tcp:
    find += [rebased_addr('pbuf_header') + 0x9513 - relative_addr('pbuf_header')] # (1)
    # find += [rebased_addr('tcp_process')]
    # avoid += [rebased_addr('pbuf_header') + 0x9513 - relative_addr('pbuf_header')] # (1)
elif udp:
    # find += [rebased_addr('pbuf_header') + 0x9513 - relative_addr('pbuf_header')] # (1)
    # avoid += [rebased_addr('pbuf_header') + 0x9513 - relative_addr('pbuf_header')] # (1)
    pass
### (2) find other bugs
# find += [rebased_addr('abort')] # (2)
# find += [rebased_addr('exit')] # (2)
# find += [rebased_addr('__stack_chk_fail')] # (2)
# find += [rebased_addr('udp_input') + 0x20824 - relative_addr('udp_input')] # p->recv()
# # avoid += [rebased_addr('pbuf_free')]
# avoid += [rebased_addr('tcp_rst')]
# avoid += [0x400000 + 0x1d513] # "tcp_listen_input: could not allocate PCB\n"
# # avoid += [rebased_addr('pbuf_header') + 0x9601 - relative_addr('pbuf_header')] # pbuf_header() returns non-zero
# avoid += [rebased_addr('pbuf_header') + 0x9608 - relative_addr('pbuf_header')] # bad pbuf type (This is not bug)
# ### (3) 'Assertion "netif->hwaddr_len == ETHARP_HWADDR_LEN" failed at line 473 in ../../../../../lwip/src/netif/etharp.c'
# # avoid += [rebased_addr('update_arp_entry') + 0x198fa - relative_addr('update_arp_entry')] # (3); this is not bug
# # avoid += [rebased_addr('tcp_input') + 0x1c9a4 - relative_addr('tcp_input')] # short packet
# # avoid += [rebased_addr('tcp_input') + 0x1c7c9 - relative_addr('tcp_input')] # short packet .. discarded
# # avoid += [rebased_addr('udp_input') + 0x202ad - relative_addr('udp_input')] # short udp diagram
# avoid += [rebased_addr('tcp_input') + 0x1c85c - relative_addr('tcp_input')] # dropped
# # avoid += [rebased_addr('udp_input') + 0x2086f - relative_addr('udp_input')] # not for us

avoid += [rebased_addr('etharp_send_ip')]

### print finds / avoids
print "[*] find = %s" % str(map(lambda x: hex(x), find))
print "[*] avoid = %s" % str(map(lambda x: hex(x), avoid))

### debugging
# proj.hook(0x400000 + 0x1c730, dump_regs, length=4)
# proj.hook(0x400000 + 0x1cecf, dump_regs, length=5)

### explore bugs
assert(find is not [])
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
    elif p.haslayer(UDP):
        p[UDP].chksum = None # to recalculate checksum
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
        print "found #%d: stdout:\n%s" % (i, found.posix.dumps(1))
        print "found #%d: stderr:\n%r" % (i, found.posix.dumps(2))
        if ip:
            v = found.se.eval(symvar_listen_pcbs_state)
            print "found #%d: listen_pcbs->state: %#x (%d)" % (i, v, v)
            print "found #%d: pcb: " % (i)
            v = found.se.eval(found.se.Reverse(symvar_pcb), cast_to=str)
            hexdump.hexdump(v)
        if etharp_arp:
            print "found #%d: arp_table: " % (i)
            v = found.se.eval(found.se.Reverse(symvar_arp_table), cast_to=str)
            hexdump.hexdump(v)
        print "found #%d: netif: " % (i)
        v = found.se.eval(found.se.Reverse(symvar_netif), cast_to=str)
        hexdump.hexdump(v)
        v = found.se.eval(symvar_pbuf_tot_len)
        print "found #%d: pbuf.tot_len: %#x (%d)" % (i, v, v)
        v = found.se.eval(symvar_pbuf_len)
        print "found #%d: pbuf.len: %#x (%d)" % (i, v, v)
        l2_payload_len = v
        v = found.se.eval(symvar_pbuf_type)
        print "found #%d: pbuf.type: %#x (%d)" % (i, v, v)
        v = found.se.eval(symvar_pbuf_ref)
        print "found #%d: pbuf.ref: %#x (%d)" % (i, v, v)
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
        # tcphdr_val = found.mem[rebased_addr('tcphdr')].uint64_t.concrete
        # iphdr_val = found.mem[rebased_addr('iphdr')].uint64_t.concrete
        # print "found #%d: iphdr = %#x, tcphdr = %#x" % (i, iphdr_val, tcphdr_val)
        # if ip:
        #     print "found #%d: *iphdr:" % (i)
        #     hexdump.hexdump(memory_dump(found, iphdr_val, 0x20))
        # if tcp:
        #     print "found #%d: *tcphdr:" % (i)
        #     hexdump.hexdump(memory_dump(found, tcphdr_val, 0x20))
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
    if len(simgr.avoid) > 0 or len(simgr.deadended) > 0:
        plot_trace()

### you can send generated packets with result.py. enjoy:)