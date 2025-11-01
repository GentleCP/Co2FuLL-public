import ida_hexrays
import idaapi
import idautils
import idc
import ida_pro
import time
import re
from pathlib import Path
from loguru import logger
from cptools import read_json, write_json

cast_pattern = re.compile(r"\(\x02\t\x01\x17.+?\x02\x17\x01\t\)")

def get_pseudo(func_ea):
    start = time.time()
    try:
        cfunc = idaapi.decompile(func_ea)
    except ida_hexrays.DecompilationFailure:
        return "", time.time()-start
    sv = cfunc.get_pseudocode()
    code_lines = []
    for sline in sv:
        # 同时去除强制类型转换的内容，通常是 (\x02\t\x01\x17__int64\x02\x17\x01\t) 的形式
        code_lines.append(idaapi.tag_remove(cast_pattern.sub("", sline.line)))
    return "\n".join(code_lines), time.time() - start

def extract_code(save_path, select_functions=None):
    if select_functions is None:
        select_functions = set([hex(func) for func in idautils.Functions()])
    else:
        select_functions = set(select_functions)
    save_path = Path(save_path)
    if save_path.exists():
        logger.critical(f"{save_path} already exists, loading...")
        func_ea2code = read_json(save_path)
        select_functions = select_functions.difference(set(func_ea2code.keys()))
        if not select_functions:
            # all code have been extracted
            logger.success("All code already extracted, pass")
            return
    else:
        func_ea2code = {}

    for i, func_ea in enumerate(select_functions):
        logger.debug(func_ea, i, len(select_functions))
        func_ea = int(func_ea, 16)
        pseudo_code, pseudo_time = get_pseudo(func_ea)
        func_ea2code[hex(func_ea)] = {
            'pseudo_code': pseudo_code,
            'pseudo_time': pseudo_time,
        }
    write_json(func_ea2code, save_path)
    logger.info(f'[+] code saved in {save_path}')


if __name__ == '__main__':
    if not idaapi.get_plugin_options("code"):
        print("[!] -Ocode option is missing")
        ida_pro.qexit(1)

    try:
        plugin_options = idaapi.get_plugin_options("code").split(':')
    except AttributeError:
        plugin_options = []
    if len(plugin_options) > 1:
        extract_code(save_path=plugin_options[0], select_functions=read_json(plugin_options[1])[plugin_options[2]])
    else:
        extract_code(save_path=idc.get_root_filename() + '.json', select_functions=['0x8151470', '0x8057240', '0x809e3e0', '0x80a10a0'])
    ida_pro.qexit(0)
