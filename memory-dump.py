#NOTE: run this script in gdb, not shell.
import gdb
import json
import zipfile
import os

DUMP_JSON = 'dump.json'

def usage():
    print("usage: python memory_dump(bin_name,[(begin,end), ...])")

def do_dump(begin, end):
    file_name = 'memory-{begin:x}-{end:x}'.format(begin=begin, end=end)
    o = gdb.execute('dump binary memory {file_name} {begin:#x} {end:#x}'.format(begin=begin, end=end, file_name=file_name), to_string=True)
    return (begin, end, file_name)

def memory_dump(bin_name, areas):
    dumps = []
    if bin_name == "" or len(areas) == 0:
        usage()
        return
    zip_name = bin_name + "-dump.zip"
    for x in areas:
        begin, end = x
        print("mem: {:#x} {:#x}".format(begin, end))
        dumps.append(do_dump(begin, end))
    print(json.dumps(dumps))
    with open(DUMP_JSON, 'w') as f:
        f.write(json.dumps(dumps))

    print("zip name: {}".format(zip_name))
    zf = zipfile.ZipFile(zip_name, mode='w')
    for d in dumps:
        file_name = d[2]
        zf.write(file_name)
        os.unlink(file_name)
    zf.write(DUMP_JSON)
    os.unlink(DUMP_JSON)
    zf.close()

    print('[*] memory dump done! Go on your analysis!')

usage()
