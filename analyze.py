#!/usr/bin/python
import sys
import r2pipe

def usage():
    print("usage: {} BIN START_FUNCTION".format(sys.argv[0]))
    print("\tBIN is analysis target")
    print("\tSTART_FUNCTION is a function to start symbolic exection")
    exit(1)

if len(sys.argv) < 3:
    usage()

BIN = sys.argv[1]
bin_file_name = BIN.split('/')[-1]
START_FUNC = sys.argv[2]
if not START_FUNC.startswith('sym.'):
    START_FUNC = "sym." + START_FUNC

r2 = r2pipe.open(BIN)
r2.cmd("aaa")
cfg = r2.cmdj("agCj")
calee = set()
xrefs = {}

def add_calle(cfg, func):
    global calee
    for x in cfg:
        if x['name'] == func:
            for f in x['imports']:
                if 'sym.imp.' in f:
                    continue
                if f not in calee:
                    calee.add(f)
                    add_calle(cfg, f) # add callee functions of f

add_calle(cfg, START_FUNC)
print(calee)

###
dependent_objs = set()
res = r2.cmd("ax | grep 'data mem'")
for x in res.split('\n'):
    x = x.strip().split('->')
    ref_from, ref_to = x[0].strip(), x[2].strip()
    if 'str.' in ref_from:
        continue
    if 'reloc.' in ref_from:
        continue
    # if 'obj.' in ref_from:
    if True:
        for y in calee:
            if y in ref_to:
                objname = ref_from.split(' ')[0]
                dependent_objs.add(objname)
print(dependent_objs)

### gather dependent symbols information
symbols = {}
isj_ret = r2.cmdj("isj")
for x in isj_ret:
    flagname = x['flagname']
    if flagname in calee or flagname in dependent_objs:
        symbols[flagname] = x
# print(symbols)

fdump = open("dump.py", "w")
fdump.write("""### NOTE: run this script in gdb, not shell.
import gdb
import json

def do_dump(addr, size):
    if size % 4:
        size += 4 - (size % 4)
    addr = '\\'' + addr + '\\''
    if not addr.isdigit():
        addr = '&' + addr
    o = gdb.execute('x/{size:d}wx {addr!s}'.format(addr=addr, size=int(size / 4)), to_string=True)
    o = o.strip()
    vals = []
    for x in o.split('\\n'):
        v = x.split(':')[1].strip().split('\t')
        for y in v:
            vals.append(int(y, 16))
    return vals

dump = {}
""")
for x in dependent_objs:
    name = symbols[x]['name']
    addr = symbols[x]['name']
    size = symbols[x]['size']
    fdump.write("dump['{name}'] = do_dump('{addr}', {size})\n".format(name=name, addr=addr, size=size))
fdump.write("""
print(dump)

with open("{dump_name}.dump", "w") as f:
    json.dump(dump, f)
print('[*] memory dump done! Go on your analysis!')
""".format(dump_name=BIN))
fdump.close()