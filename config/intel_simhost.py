from .template import template

class config(template):
    arch = "intel"
    arch_bits = 64
    ELF_FILE = "./bin/simhost-STABLE-1_3_0"
    skip_funcs = []
    init_objs = []
    find = ['abort']
    ### pbuf_free() means return of dns_recv()]
    avoid = ['pbuf_free']
