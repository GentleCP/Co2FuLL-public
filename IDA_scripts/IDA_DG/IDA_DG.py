import idaapi
import idautils
import idc
import ida_pro
import time
import networkx as nx
from pathlib import Path
from loguru import logger
from cptools import write_pickle


def get_func_tags(func_ea):
    """
    A function may have multiple tag, such as NORET THUNK -> .ft_validator_error in freetype 2.4.0
    :param func_ea:
    :return:
    """
    flags = idc.get_func_attr(func_ea, idc.FUNCATTR_FLAGS)
    tags = []
    if flags & idc.FUNC_NORET:
        # This flag is used to identify functions that do not execute a return instruction.
        # Internally, it is represented as 1.
        tags.append("FUNC_NORET")
    if flags & idc.FUNC_FAR:
        # This flag is rarely seen unless the reversed software uses segmented memory.
        # Internally, it is represented as the integer 2.
        tags.append("FUNC_FAR")
    if flags & idc.FUNC_USERFAR:
        # This flag is rarely seen and is almost undocumented. Hex-Rays describes it as "user has specified far-ness
        # of the function." Its internal value is 32.
        tags.append("FUNC_USERFAR")
    if flags & idc.FUNC_LIB:
        # This flag is used to identify library code. Marking library code is useful because it can often be ignored
        # during analysis. Internally, it is represented as the integer value 4.
        tags.append("FUNC_LIB")
    if flags & idc.FUNC_STATIC:
        # This flag is used to identify functions that have been compiled as static functions. In C, static functions
        # are global by default. If the author defines a function as static, it can only be accessed by other functions
        # within the same file.
        tags.append("FUNC_STATIC")
    if flags & idc.FUNC_FRAME:
        # This flag is used to mark functions that use EBP as a stack frame pointer. Such functions typically
        # have a standard prologue.
        tags.append("FUNC_FRAME")
    if flags & idc.FUNC_HIDDEN:
        # Functions marked with the `FUNC_HIDDEN` flag are considered hidden and need to be expanded to view their
        # contents. If we access the address of a function marked as hidden, it will automatically expand.
        tags.append("FUNC_HIDDEN")
    if flags & idc.FUNC_THUNK:
        # This flag identifies a thunk function, which is a function that uses a `jmp` instruction.
        tags.append("FUNC_THUNK")
    if flags & idc.FUNC_BOTTOMBP:
        # Similar to `FUNC_FRAME`, this flag identifies functions where the base pointer points to the stack pointer.
        tags.append("FUNC_BOTTOMBP")
    return tags


class IEViewer(object):
    """
    generate import and export table list
    """

    def __init__(self):
        self._imports = []
        self._exports = []

    def imports_names_cb(self, ea, name, ord):
        tmp = name.split('@@')
        if len(tmp) == 1:
            self._imports.append([ord, ea, tmp[0], ''])
        else:
            self._imports.append([ord, ea, tmp[0], tmp[1]])
        return True

    def get_imports(self, only_name=False):
        if self._imports:
            return [item[2:] for item in self._imports] if only_name else self._imports

        nimps = idaapi.get_import_module_qty()
        for i in range(nimps):
            idaapi.enum_import_names(i, self.imports_names_cb)
        self._imports.sort(key=lambda x: x[2])
        return [item[2:] for item in self._imports] if only_name else self._imports

    def get_exports(self, only_name=False):
        if self._exports:
            return [item[3] for item in self._exports] if only_name else self._exports
        self._exports = list(idautils.Entries())
        return [item[3] for item in self._exports] if only_name else self._exports

def _add_node_edge(call_graph, callee_ea, called_ea):
    caller = idaapi.get_func(called_ea)
    if caller is not None and caller.ea != callee_ea:
        if hex(caller.start_ea) not in call_graph.nodes:
            call_graph.add_node(hex(caller.start_ea),
                                value=idaapi.get_func_name(caller.start_ea),
                                type="func",
                                tags=get_func_tags(caller.start_ea))
        edge = hex(caller.start_ea), hex(callee_ea)
        if edge not in call_graph.edges:
            call_graph.add_edge(edge[0], edge[1], called_ea=[hex(called_ea)])
        else:
            call_graph[edge[0]][edge[1]]['called_ea'].append(hex(called_ea))

def restore_functions():
    """
    In a stripped binary, some functions may be missing.
    Therefore, scan the .text section to identify unknown function addresses and add them as functions.
    :return:
    """
    text_seg = idaapi.get_segm_by_name('.text')
    logger.info(f"Scanning .text segment: {hex(text_seg.start_ea)} - {hex(text_seg.end_ea)}")

    # enumerate .text section
    start_func_eas = []
    ea = text_seg.start_ea
    while ea < text_seg.end_ea:
        # Check whether the address has been recognized as a function
        if not idaapi.get_func(ea):
            for ref_ea in list(idautils.CodeRefsTo(ea, 0)):
                if idaapi.print_insn_mnem(ref_ea) in {'B', 'BL'}:
                    logger.info(f"Found ea {hex(ea)} with code ref")
                    start_func_eas.append(ea)

        # move to the next address
        ea = idc.next_head(ea)
    logger.info(f"Total {len(start_func_eas)} being identified")
    return start_func_eas



def extract_call_graph(save_path):
    start = time.time()
    call_graph = nx.DiGraph()

    # call relationship
    ie_viewer = IEViewer()
    for func_ea in idautils.Functions():
        func_name = idaapi.get_func_name(func_ea)
        if func_name is None:
            continue
        func_tags = get_func_tags(func_ea)
        call_graph.add_node(hex(func_ea),
                            value=func_name,
                            type="func",
                            tags=func_tags)
        for called_ea in idautils.CodeRefsTo(func_ea, 1):
            # Note that called_ea is just the address where the function is called within another function
            _add_node_edge(call_graph, callee_ea=func_ea, called_ea=called_ea)

    for str_item in idautils.Strings():
        call_graph.add_node(hex(str_item.ea),
                            value=str(str_item),
                            type="str",
                            tags=[])
        for called_ea in idautils.DataRefsTo(str_item.ea):
            _add_node_edge(call_graph, callee_ea=str_item.ea, called_ea=called_ea)

    call_graph.imports = ie_viewer.get_imports(only_name=False)
    call_graph.exports = ie_viewer.get_exports(only_name=False)
    call_graph.time_cost = time.time() - start
    call_graph.name = idc.get_root_filename()
    write_pickle(call_graph, save_path)
    print(f'[+] Dependency graph saved in {save_path}')


if __name__ == '__main__':
    if not idaapi.get_plugin_options("DG"):
        print("[!] -ODG option is missing")
        ida_pro.qexit(1)

    plugin_options = idaapi.get_plugin_options("DG").split(':')
    print(plugin_options)
    save_path = Path(plugin_options[0])
    extract_call_graph(save_path)
    ida_pro.qexit(0)
