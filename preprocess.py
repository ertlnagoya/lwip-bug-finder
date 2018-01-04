#!/usr/bin/python2
import os, sys
from subprocess import *
import pickle
import struct
import hashlib

ELF_FILE = None
OBJDUMP_FILE = None
PY_OBJ_FILE = None

def usage():
    print "usage: %s ELF_FILE" % (sys.argv[0])
    exit(1)

def arch(ELF_FILE):
    b = b''
    with open(ELF_FILE, 'rb') as f:
        b = f.read(32)
    assert(len(b) > 0)
    e_machine = struct.unpack('<H', b[0x12:0x14])[0]
    if e_machine in [3, 50]:
        return "intel"
    if e_machine == 40:
        return "arm"

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
    def __init__(self, symbols, disasm=None, jmp=None, call=None, filesum=None):
        assert(symbols is not None)
        self.symbols = symbols
        self.disasm = disasm
        self.jmp = jmp
        self.call = call
        self.filesum = filesum

def main(argc, argv):
    global ELF_FILE, OBJDUMP_FILE, PY_OBJ_FILE

    if len(sys.argv) < 2:
        usage()

    ELF_FILE = argv[1]
    if not os.path.exists(ELF_FILE):
        print("[!] File '%s' not exists" % (ELF_FILE))
        exit(1)
    ARCH = arch(ELF_FILE)
    SYMS_FILE = ELF_FILE + ".syms"
    if ARCH == "intel":
        OBJDUMP = "objdump"
    else:
        OBJDUMP = "%s-none-eabi-objdump" % (ARCH)
    OBJDUMP_FILE = ELF_FILE + ".objdump"
    INFO_FILE = ELF_FILE + ".info"

    ### debug option
    if argc > 2 and argv[2] == "l":
        with open(INFO_FILE) as f:
            info = pickle.load(f)
            import ipdb; ipdb.set_trace()

    print("""obtain symbols""")
    err = os.system("nm --print-size %s > %s" % (ELF_FILE, SYMS_FILE))
    if err:
        print "[!] dumping symbols error!"
        exit(1)

    print("""translate symbols file to symbols object""")
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

    print("""objdump""")
    err = os.system("%s -d %s > %s" % (OBJDUMP, ELF_FILE, OBJDUMP_FILE))
    if err:
        print "[!] objdump error!"
        exit(1)

    print("""obtain function callers""")
    call = {}
    for x in symbols.keys():
        if ARCH == "intel":
            inst_name = "call"
        elif ARCH == "arm":
            inst_name = "bl"
        else:
            print("[!] unkown arch. exit")
            exit(1)
        call[x] = caller_addr_list(inst_name, x)

    print("""disassembly""")
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

    print("""file hash""")
    with open(ELF_FILE, 'rb') as f:
        filesum = hashlib.md5(f.read()).hexdigest()

    print("""save result""")
    info = Info(symbols=symbols, disasm=disasm, call=call, filesum=filesum)
    with open(INFO_FILE, "w") as f:
        pickle.dump(info, f)

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)