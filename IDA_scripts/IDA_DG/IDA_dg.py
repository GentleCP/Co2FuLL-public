# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     ida_extract_anchor_relationships
   Description :  生成用于减小函数检索空间的的锚点以及他和目标函数的关系
   Author :       GentleCP
   date：          2024/12/18
-------------------------------------------------
   Change Activity:

-------------------------------------------------
"""

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
        # 此标志用于标识不执行返回指令的函数。它内部表示为1
        tags.append("FUNC_NORET")
    if flags & idc.FUNC_FAR:
        # 除非逆向的软件使用分段的内存，否则很少看见这个标志，它在内部表示为2的整数
        tags.append("FUNC_FAR")
    if flags & idc.FUNC_USERFAR:
        # 这个标记很少被看到，并且几乎没有文档。HexRays将这个标志描述为user has specified far-ness of the function。它的内部值是32
        tags.append("FUNC_USERFAR")
    if flags & idc.FUNC_LIB:
        # 此标志用于查找库代码。标识库代码非常有用，因为在进行分析时通常可以忽略这些代码。其内部表示为一个整数值4。
        # 经实际测试，并没什么用，libc的函数无法正确识别
        tags.append("FUNC_LIB")
    if flags & idc.FUNC_STATIC:
        # 此标志用于标识已编译为静态函数的函数。在C语言中，静态函数默认是全局的。如果作者将函数定义为静态函数，则该函数只能被该文件中的其他函数访问。
        tags.append("FUNC_STATIC")
    if flags & idc.FUNC_FRAME:
        # 此函数用于标志用了ebp作为栈帧的函数，这个函数有典型的开头
        tags.append("FUNC_FRAME")
    if flags & idc.FUNC_HIDDEN:
        # 带有FUNC_HIDDEN标标志的函数意味着它们是隐藏的，需要展开才能查看。如果我们访问一个被标记为隐藏的函数的地址，它将自动展开
        tags.append("FUNC_HIDDEN")
    if flags & idc.FUNC_THUNK:
        # 此标志标识为thunk(中转)函数，即使用了一个jmp的函数
        tags.append("FUNC_THUNK")
    if flags & idc.FUNC_BOTTOMBP:
        # 与FUNC_FRAM类似，它标识栈底指针指向堆栈指针的函数
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
    在strip binary 中，函数可能被遗漏,因此扫描.text 找出未知函数地址，添加函数
    :return:
    """
    text_seg = idaapi.get_segm_by_name('.text')
    logger.info(f"Scanning .text segment: {hex(text_seg.start_ea)} - {hex(text_seg.end_ea)}")

    # 遍历 .text 段
    start_func_eas = []
    ea = text_seg.start_ea
    while ea < text_seg.end_ea:
        # 检查地址是否已被识别为函数
        if not idaapi.get_func(ea):
            for ref_ea in list(idautils.CodeRefsTo(ea, 0)):
                if idaapi.print_insn_mnem(ref_ea) in {'B', 'BL'}:
                    logger.info(f"Found ea {hex(ea)} with code ref")
                    start_func_eas.append(ea)

        # 移动到下一个地址
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
            # 注意called_ea只是函数中调用该函数的地址，而非对应函数地址
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
    print(f'[+] call graph saved in {save_path}')


if __name__ == '__main__':
    if not idaapi.get_plugin_options("callgraph"):
        print("[!] -Ocallgraph option is missing")
        ida_pro.qexit(1)

    plugin_options = idaapi.get_plugin_options("callgraph").split(':')
    print(plugin_options)
    save_path = Path(plugin_options[0])
    extract_call_graph(save_path)
    ida_pro.qexit(0)
