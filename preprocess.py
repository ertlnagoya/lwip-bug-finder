#!/usr/bin/python2
import os, sys
from subprocess import *
import pickle

ELF_FILE = None
OBJDUMP_FILE = None
PY_OBJ_FILE = None

def usage():
    print "usage: %s ELF_FILE" % (sys.argv[0])
    exit(1)

def caller_addr_list(inst_name, func_name):
    global OBJDUMP_FILE
    p1 = Popen(["egrep", "%s\s*.+<%s>" % (inst_name, func_name), "%s" % OBJDUMP_FILE], stdout=PIPE)
    p2 = Popen(["cut", "-d:", "-f1"], stdin=p1.stdout, stdout=PIPE)
    p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
    output = p2.communicate()[0]
    return map(lambda x: int(x, 16), output.split())

class Symbol():
    def __init__(self, addr, size):
        assert(addr is not None)
        assert(size is not None)
        self.addr = addr
        self.size = size

class Info():
    def __init__(self, symbols, disasm=None, jmp=None, call=None):
        assert(symbols is not None)
        self.symbols = symbols
        self.disasm = disasm
        self.jmp = jmp
        self.call = call

def main(argc, argv):
    global ELF_FILE, OBJDUMP_FILE, PY_OBJ_FILE

    if len(sys.argv) < 2:
        usage()

    ELF_FILE = argv[1]
    SYMS_FILE = ELF_FILE + ".syms"
    OBJDUMP_FILE = ELF_FILE + ".objdump"
    INFO_FILE = ELF_FILE + ".info"

    if argc > 2 and argv[2] == "l":
        with open(INFO_FILE) as f:
            info = pickle.load(f)
            import ipdb; ipdb.set_trace()

    ### symbols
    err = os.system("nm --print-size %s > %s" % (ELF_FILE, SYMS_FILE))
    if err:
        print "[!] dumping symbols error!"
        exit(1)

    ### translate symbols file to symbols object
    symbols = {}
    with open(SYMS_FILE) as f:
        for x in f.readlines():
            """
            1800e19c 00000160 T act_tsk
            """
            try:
                data = x.strip().split(' ')
                if len(data) == 4:
                    addr, size, _type, symname = data
                    addr = int(addr, 16)
                    size = int(size, 16)
                    symbols[symname] = Symbol(addr=addr, size=size)
            except Exception:
                import ipdb; ipdb.set_trace()

    ### objdump
    err = os.system("objdump -d %s > %s" % (ELF_FILE, OBJDUMP_FILE))
    if err:
        print "[!] objdump error!"
        exit(1)

    ### obtain function callers
    call = {}
    for x in symbols.keys():
        call[x] = caller_addr_list("call", x)

    ### disassembly
    disasm = {}
    with open(OBJDUMP_FILE) as f:
        for x in f.readlines():
            if "\t" in x and ":" in x and not x.endswith(":"):
                addr, last = x.split(":", 1)
                last = last.strip("\t\n")
                if last is not "" and addr.isalnum():
                    try:
                        raw_insn, asm = last.split("\t", 1)
                        # print asm
                    except Exception:
                        # print "omitting: %s" % last
                        pass
                    disasm[int(addr, 16)] = asm

    ### dump variables
    info = Info(symbols=symbols, disasm=disasm, call=call)
    with open(INFO_FILE, "w") as f:
        pickle.dump(info, f)

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)