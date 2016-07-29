#!/usr/bin/python3

import argparse
import json
import sys


def warn(msg):
    sys.stderr.write('WARNING: {}\n'.format(msg))


class Node:
    def __init__(self, filename, section, offset, name, is_global):
        self.filename = filename
        self.section = section
        self.offset = offset
        self.name = name
        self.is_global = is_global
        self.calls = set()
        self.called_by = set()
        self.active = False
        self.highlighted = False
        self.nofollow = False
        self.callmap_info = None

    def add_call(self, target):
        self.calls.add(target)
        target.called_by.add(self)

    def remove_call(self, target):
        try:
            self.calls.remove(target)
        except KeyError:
            pass
        try:
            target.called_by.remove(self)
        except KeyError:
            pass

    def remove_links(self):
        for other in list(self.calls):
            self.remove_call(other)
        for other in list(self.called_by):
            other.remove_call(self)

    def id(self):
        if self.is_global:
            return self.name
        return '{}:{}'.format(self.filename, self.name)

    def label(self):
        if self.is_global:
            return self.name
        return '{}+0x{:x}'.format(self.section, self.offset)

    def __repr__(self):
        return '<Node: {}>'.format(self.id())


class Graph:
    cluster_attrs = {
        'style': 'filled',
        'fillcolor': 'lightgrey',
    }
    default_node_attrs = {
        'shape': 'box',
        'style': 'filled',
        'fillcolor': 'white',
    }
    global_node_attrs = {
    }
    local_node_attrs = {
        'color': 'grey',
        'fontcolor': 'grey',
    }
    extern_node_attrs = {
        'shape': 'ellipse',
        'color': 'blue',
        'fontcolor': 'blue',
    }
    highlighted_node_attrs = {
        'penwidth': 2.5,
        'fillcolor': 'green',
    }
    nofollow_node_attrs = {
        'peripheries': 2,
    }

    def __init__(self):
        self.files = {None: {}}
        self.global_nodes = {}
        self.group_by_file = False
        # Copy all the attr dicts so that if somebody changes their contents on
        # this instance, it only affects this instance and not the shared
        # dictionaries on the class object:
        self.default_node_attrs = dict(self.default_node_attrs)
        self.global_node_attrs = dict(self.global_node_attrs)
        self.local_node_attrs = dict(self.local_node_attrs)
        self.extern_node_attrs = dict(self.extern_node_attrs)
        self.highlighted_node_attrs = dict(self.highlighted_node_attrs)
        self.nofollow_node_attrs = dict(self.nofollow_node_attrs)

    def add_node(self, node):
        self.files.setdefault(node.filename, {})[node.name] = node
        if node.is_global:
            self.global_nodes[node.name] = node

    def load_files(self, filelist):
        for mapfile in filelist:
            with open(mapfile, 'r') as f:
                mapdata = json.load(f)
            if not isinstance(mapdata, list):
                self.load_mapdata(mapdata)
            else:
                for m in mapdata:
                    self.load_mapdata(m)

    def load_mapdata(self, mapdata):
        filename = mapdata['filename']
        for section, funcs in mapdata['functions'].items():
            for func, info in funcs.items():
                node = Node(filename, section, info['offset'], func, info['global_name'])
                node.callmap_info = info
                self.add_node(node)

    def resolve_calls(self):
        for nodes in self.files.values():
            for node in nodes.values():
                info = node.callmap_info
                if not info:
                    continue
                targets = set(c['target'] for c in info['calls'])
                for name in targets:
                    target = nodes.get(name)
                    if target is None:
                        target = self.global_nodes.get(name)
                    if target is None:
                        target = Node(None, None, None, name, True)
                        self.add_node(target)
                    node.add_call(target)

    def file_nodes(self, filename):
        return self.files[filename].values()

    def mark_active(self, nodelist):
        nodelist = set(nodelist)
        while nodelist:
            node = nodelist.pop()
            if node.active:
                continue
            node.active = True
            if not node.nofollow:
                nodelist.update(node.calls)

    def cull_nodes(self, nodes):
        for nodeset in self.files.values():
            for n in set(nodeset.values()).intersection(nodes):
                n.remove_links()
                del nodeset[n.name]

    def cull_inactive(self):
        for nodeset in self.files.values():
            for n in list(nodeset.values()):
                if not n.active:
                    n.remove_links()
                    del nodeset[n.name]

    def print_output(self):
        default_attr_text = '; '.join('{}="{}"'.format(k, v) for k, v in self.default_node_attrs.items())
        cluster_attr_text = '; '.join('{}="{}"'.format(k, v) for k, v in self.cluster_attrs.items())
        print('digraph {')
        print('  node [{}];'.format(default_attr_text))
        cluster_num = 0
        for filename, nodes in self.files.items():
            if filename is not None:
                if nodes:
                    print("# Functions in {}".format(filename))
                    print()
                    if self.group_by_file:
                        print('  subgraph cluster{} {{ label="{}";'.format(cluster_num, filename))
                        print('    {}'.format(cluster_attr_text))
                        for n in nodes.values():
                            print('    {};'.format(self.dot_text(n)))
                        print('  }')
                        cluster_num += 1
                    else:
                        for n in nodes.values():
                            print('    {};'.format(self.dot_text(n)))
                    print()

        print("# External functions")
        print()
        for n in self.files[None].values():
            print('  {};'.format(self.dot_text(n)))
        print()

        print("# Calls")
        print()
        for filename, nodes in self.files.items():
            for n in nodes.values():
                for c in n.calls:
                    print('  "{}" -> "{}";'.format(n.id(), c.id()))
        print('}')

    def get_node(self, name):
        #TODO: make this work for more than just names/IDs
        if ':' in name:
            filename, func = name.split(':', 1)
            return self.files[filename][func]
        else:
            return self.global_nodes[name]

    def dot_attrs(self, node):
        attrs = {}
        label = node.label()
        if label != node.id():
            attrs['label'] = label
        if node.filename is None:
            attrs.update(self.extern_node_attrs)
        elif node.is_global:
            attrs.update(self.global_node_attrs)
        else:
            attrs.update(self.local_node_attrs)
        if node.nofollow:
            attrs.update(self.nofollow_node_attrs)
        if node.highlighted:
            attrs.update(self.highlighted_node_attrs)
        return attrs

    def dot_text(self, node):
        dot_attrs = self.dot_attrs(node)
        attr_text = '; '.join('{}="{}"'.format(k, v) for k, v in dot_attrs.items())
        return '"{}" [{}]'.format(node.id(), attr_text)


def apply_attr_options(attr_specs, attr_dict):
    for spec in attr_specs:
        try:
            attr, value = spec.split('=', 1)
        except ValueError:
            warn('Attribute {!r} is not in a valid form (must be "<name>=<value>").  Ignored.'.format(spec))
            continue
        attr_dict[attr] = value


def nodeset_from_args(funclist, filelist, listfiles, msg_prefix):
    nodes = set()
    for func in funclist:
        try:
            nodes.add(graph.get_node(func))
        except KeyError:
            warn("{}: No function named {!r}.  Ignored.".format(msg_prefix, func))
    for filename in filelist:
        try:
            nodes.update(graph.file_nodes(filename))
        except KeyError:
            warn("{}: No file named {!r} found in callmap info.  Ignored.".format(msg_prefix, filename))
    for filename in listfiles:
        try:
            with open(filename, 'r') as f:
                for line in f:
                    func = line.strip()
                    if not func or func.startswith('#'):
                        continue
                    try:
                        nodes.add(graph.get_node(func))
                    except KeyError:
                        warn("{} (from {!r}): No function named {!r}.  Ignored.".format(msg_prefix, filename, func))
        except IOError as e:
            warn("{}: Error reading from {!r}: {}".format(msg_prefix, filename, e))
    return nodes


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='xtcm2gv', description='Convert xtobjdis-format function call map data to GraphViz input (.dot) file', add_help=False)
    parser.add_argument('filenames', metavar='MAPFILE', nargs='+', help='Input callmap file(s)')

    pgroup = parser.add_argument_group('Selecting Nodes')
    pgroup.add_argument('--include', metavar='FUNCTION', action='append', default=[], help='Include the specified function (recursively) in the output')
    pgroup.add_argument('--include-file', metavar='OBJFILE', action='append', default=[], help='Include all functions defined in the specified object file')
    pgroup.add_argument('--include-from', metavar='LISTFILE', action='append', default=[], help='Include all functions listed in the specified file (one per line)')
    pgroup.add_argument('--exclude', metavar='FUNCTION', action='append', default=[], help='Exclude the specified function from the output')
    pgroup.add_argument('--exclude-file', metavar='OBJFILE', action='append', default=[], help='Exclude all functions defined in the specified object file')
    pgroup.add_argument('--exclude-from', metavar='LISTFILE', action='append', default=[], help='Exclude all functions listed in the specified file (one per line)')
    pgroup.add_argument('--nofollow', metavar='FUNCTION', action='append', default=[], help='Do not follow calls from the specified function when processing includes')
    pgroup.add_argument('--nofollow-file', metavar='OBJFILE', action='append', default=[], help='Nofollow all functions defined in the specified object file')
    pgroup.add_argument('--nofollow-from', metavar='LISTFILE', action='append', default=[], help='Nofollow all functions listed in the specified file (one per line)')
    pgroup.add_argument('--follow', metavar='FUNCTION', action='append', default=[], help='Do follow calls from the specified function when processing includes (overrides nofollow)')
    pgroup.add_argument('--follow-file', metavar='OBJFILE', action='append', default=[], help='Follow all functions defined in the specified object file')
    pgroup.add_argument('--follow-from', metavar='LISTFILE', action='append', default=[], help='Follow all functions listed in the specified file (one per line)')

    pgroup = parser.add_argument_group('Configuring DOT Output')
    pgroup.add_argument('--group-by-file', '-g', action='store_true', help='Group functions defined in the same file together')
    pgroup.add_argument('--node-attr', '-D', metavar='NAME=VALUE', action='append', default=[], help='Set DOT attribute(s) to be applied to all nodes by default')
    pgroup.add_argument('--globalfunc-attr', '-G', metavar='NAME=VALUE', action='append', default=[], help='Set DOT attribute(s) to be applied to global (exported) function nodes')
    pgroup.add_argument('--localfunc-attr', '-L', metavar='NAME=VALUE', action='append', default=[], help='Set DOT attribute(s) to be applied to local (static) function nodes')
    pgroup.add_argument('--extern-attr', '-E', metavar='NAME=VALUE', action='append', default=[], help='Set DOT attribute(s) to be applied to external (not defined in call map) function nodes')
    pgroup.add_argument('--highlight-attr', '-H', metavar='NAME=VALUE', action='append', default=[], help='Set DOT attribute(s) to be applied to highlighted nodes')
    pgroup.add_argument('--nofollow-attr', '-N', metavar='NAME=VALUE', action='append', default=[], help='Set DOT attribute(s) to be applied to highlighted nodes')
    pgroup.add_argument('--filegroup-attr', '-F', metavar='NAME=VALUE', action='append', default=[], help='Set DOT attribute(s) to be applied to file-grouping boxes')

    pgroup = parser.add_argument_group('Miscellaneous')
    pgroup.add_argument('--highlight', metavar='FUNCTION', action='append', default=[], help='Highlight the specified function')
    pgroup.add_argument('--help', '-h', action='help', help='Show this help message and exit')

    args = parser.parse_args()

    graph = Graph()
    graph.load_files(args.filenames)
    graph.resolve_calls()

    graph.group_by_file = args.group_by_file

    include_nodes = nodeset_from_args(args.include, args.include_file, args.include_from, "Include")
    exclude_nodes = nodeset_from_args(args.exclude, args.exclude_file, args.exclude_from, "Exclude")
    nofollow_nodes = nodeset_from_args(args.nofollow, args.nofollow_file, args.nofollow_from, "Nofollow")
    follow_nodes = nodeset_from_args(args.follow, args.follow_file, args.follow_from, "Follow")
    nofollow_nodes -= follow_nodes

    for func in args.highlight:
        try:
            graph.get_node(func).highlighted = True
        except KeyError:
            warn("No function named {!r}.  Highlight ignored.".format(func))

    for node in nofollow_nodes:
        node.nofollow = True
    if exclude_nodes:
        graph.cull_nodes(exclude_nodes)
    if include_nodes:
        graph.mark_active(include_nodes)
        graph.cull_inactive()

    apply_attr_options(args.node_attr, graph.default_node_attrs)
    apply_attr_options(args.globalfunc_attr, graph.global_node_attrs)
    apply_attr_options(args.localfunc_attr, graph.local_node_attrs)
    apply_attr_options(args.extern_attr, graph.extern_node_attrs)
    apply_attr_options(args.highlight_attr, graph.highlighted_node_attrs)
    apply_attr_options(args.nofollow_attr, graph.nofollow_node_attrs)
    apply_attr_options(args.filegroup_attr, graph.cluster_attrs)

    graph.print_output()
