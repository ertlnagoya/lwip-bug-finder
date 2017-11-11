import cxxfilt # to demangle

class emoviz():
    ENTRY_POINT = ""
    NO_SUCH_NODE = ""

    node_id = 0

    """
    angr project
    """
    proj = None
    """
    disasm is dictonary type and must be following format
    @key    address of instruction (type: int)
    @value  instruction (type: str)
    """
    disasm = {}

    def __init__(self, proj, disasm={}):
        self.debug = []
        self.trace = {} # dict
        self.node = {} # dict
        self.node_description_to_id = {} # dict

        self.proj = proj
        self.disasm = disasm

    def __del__(self):
        self.trace = {}

    def __enter__(self, proj):
        self.proj = proj

    def __exit__(self):
        pass

    def create_node(self, label, description, fillcolor="transparent"):
        node_name = "node%d" % (self.node_id)
        self.node_id += 1
        self.node[node_name] = (label, fillcolor)
        self.node_description_to_id[description] = node_name

    def get_node_name_by_description(self, description):
        if description in self.node_description_to_id:
            return self.node_description_to_id[description]
        else:
            return self.NO_SUCH_NODE

    def get_pc_from_description(self, x):
        if "_SYSCALL after " in x:
            return -1, True
        pc = -1
        try:
            if 'SimState' in x:
                pc = int(x.split(' ')[2], 16)
            else:
                pc = int(x.split('from')[1].split()[0].strip(':'), 16)
        except Exception:
            print "[!] Implement me correctly! (in get_pc_from_description)"
            print x
            exit(1)
        return pc, False

    def add(self, state):
        prev = ""
        for x in state.history.descriptions:
            self.debug.append(x)
            ### register relation
            if not prev == "":
                k = (prev, x)
                if k in self.trace:
                    self.trace[k] += 1
                else:
                    self.trace[k] = 1
            prev = str(x)
            ### create node if necessary
            if self.get_node_name_by_description(x) == self.NO_SUCH_NODE:
                pc, err = self.get_pc_from_description(x)
                if err:
                    self.create_node(label=x, description=x)
                else:
                    describe_addr = self.proj.loader.describe_addr(pc)
                    if "(offset" in describe_addr:
                        func = describe_addr.split()[0]
                        func = cxxfilt.demangle(func)
                        describe_addr = ' '.join([func] + describe_addr.split()[1:])
                    fillcolor = "transparent"
                    if describe_addr.startswith("_start"):
                        fillcolor = "gray"
                    elif "in main binary" in describe_addr:
                        fillcolor = "lightskyblue"
                    elif "_error(" in describe_addr or "_exception" in describe_addr: # unwanted result?
                        fillcolor = "salmon"
                    additional_line = ""
                    # if self.disasm is not {} and "UserHook" in x:
                    if self.disasm is not {}:
                        if pc in self.disasm:
                            additional_line = "\\n" + self.disasm[pc]
                    self.create_node(label=x + "\\n" + describe_addr + additional_line, description=x, fillcolor=fillcolor)

    def save_plain(self, file_name):
        with open(file_name, "w") as f:
            f.write('\n'.join(self.debug))

    def save_dot(self, file_name):
        with open(file_name, "w") as f:
            f.write("digraph {\n")
            ### plot nodes
            f.write('\tnode [shape="box", style="filled", fillcolor="transparent"]\n')
            for name, v in self.node.items():
                label, fillcolor = v
                f.write('\t%s [label="%s", fillcolor=%s]\n' % (name, label, fillcolor))
            f.write("\n")
            ### plot edges
            for k, v in self.trace.items():
                # import ipdb; ipdb.set_trace()
                _from, _to = k
                times = v
                node_name_from = self.get_node_name_by_description(_from)
                node_name_to = self.get_node_name_by_description(_to)
                additional = ""
                if times >= 20:
                    times = "<B>%s</B>" % times
                    additional += ', color=%s' % "crimson"
                    additional += ', fontcolor=%s' % "crimson"
                f.write('\t%s -> %s [label=<%s>%s]\n' % (node_name_from, node_name_to, times, additional))
            f.write("}\n")

    def save_png(self, dot_file):
        import os
        png_file, _ = os.path.splitext(dot_file)
        png_file += ".png"
        os.system("dot -Tpng " + dot_file + " -o " + png_file)