
from collections import defaultdict
from dataclasses import dataclass
from cptools import read_json, read_pickle
import networkx as nx
import re


@dataclass
class Anchor(object):
    ea: str
    value: str
    type: str

    def __eq__(self, other):
        return self.value == other.value and self.type == other.type

    def __hash__(self):
        return hash(f"{self.ea}@{self.value}@{self.type}")


class ContextGener(object):
    """
    Context generator
    """

    def __init__(self):
        self.import_ea2name = {}
        self.export_ea2name = {}
        self.libc_funcs = set(read_json("DBs/libc_functions.json"))
        self.useless_func = set(read_json("DBs/useless_functions.json"))
        self.func_sig_pattern = re.compile(r'^(\w+\s+)+(\*)*(?P<func_name>\w+)\(.+\)?$')


    def _string_process(self, string):
        if "./" in string:
            string = string.lstrip("./")
        elif string.startswith("/home/"):
            return None
        elif len(string) > 300:
            return None
        else:
            try:
                string = self.func_sig_pattern.search(string).groupdict()['func_name']
            except AttributeError:
                pass
        return string

    def _extract_dependency_only_import_str(self, reverse_dg, node, attr):
        anchor_value = None
        if attr['type'] == "str":
            anchor_value = self._string_process(attr['value'])
        elif attr['type'] == "func" and "FUNC_THUNK" in attr['tags']:
            func_name = attr['value'].strip('.')
            if func_name in self.useless_func:
                return None
            if func_name in self.libc_funcs:
                anchor_value = func_name
        if anchor_value is not None:
            dist = nx.single_source_dijkstra_path_length(reverse_dg, node)
            return {
                'ac': (anchor_value, attr['type']),
                'dist': dist
            }
        else:
            return None

    def _reverse_dist(self, ac2func_ea_dist):
        func_ea2ac_dist = defaultdict(dict)

        for (ref_value, ref_type), node2ac_dist in ac2func_ea_dist.items():
            if ref_value.startswith('LEAF'):
                key = ("LEAF", ref_type)
            else:
                key = (ref_value, ref_type)
            for func_ea, ac_dist in node2ac_dist.items():
                if key == ("LEAF", ref_type) and key in func_ea2ac_dist[func_ea].keys():
                    func_ea2ac_dist[func_ea][key] = min(func_ea2ac_dist[func_ea][key], ac_dist)
                else:
                    func_ea2ac_dist[func_ea][key] = ac_dist
        return func_ea2ac_dist

    def get_dist(self, dg):
        ac2func_ea_dist = {}
        reverse_dg = dg.reverse()
        for node, attr in reverse_dg.nodes.items():
            res = self._extract_dependency_only_import_str(reverse_dg, node, attr)
            if res is None:
                continue
            if res['ac'] in ac2func_ea_dist.keys():
                # It may already exist due to a duplicate string — the same string appearing at different addresses.
                ac2func_ea_dist[res['ac']].update(res['dist'])
            else:
                ac2func_ea_dist[res['ac']] = res['dist']
        func_ea2ac_dist = self._reverse_dist(ac2func_ea_dist)
        return func_ea2ac_dist

    def extract(self, dg_path, sources=None):
        dg = read_pickle(dg_path)
        func_ea2ref_dist = self.get_dist(dg)
        if sources is not None:
            func_ea2ref_dist = {k: v for k, v in func_ea2ref_dist.items() if k in sources}
        return func_ea2ref_dist


