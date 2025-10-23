#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
from pathlib import Path
from loguru import logger
from cptools import execute_cmd, read_json
from tqdm import tqdm

CUR_PATH = Path(__file__).parent
ROOT_PATH = CUR_PATH.parent.parent
sys.path.append(str(ROOT_PATH))
from settings import IDA_PATH, N_JOBS, IDA32_PATH
from utils.tool_function import execute_by_multi_process

IDA_PLUGIN = CUR_PATH.joinpath('IDA_code.py')
LOG_PATH = CUR_PATH.joinpath("IDA_code.log")
logger.info(f"IDA_PLUGIN: {IDA_PLUGIN}")
logger.info(f"Log saved in {LOG_PATH}")

def extract_code(idb_path, save_path, select_func_ea_path):
    cmd = " ".join([
        "TVHEADLESS=1",
        str(IDA_PATH if idb_path.suffix == ".i64" else IDA32_PATH),
        '-A',
        f'-L{LOG_PATH}',
        f'-S{IDA_PLUGIN}',
        f'-Ocode:{save_path}:{select_func_ea_path}:{idb_path}',
        str(idb_path)])
    exe_res = execute_cmd(cmd)
    if exe_res['errcode'] == 0:
        if save_path.exists():
            logger.success(f"{idb_path.name} code saved in {save_path.name}")
        else:
            logger.warning(f"{idb_path.name} code can not find but no execute error")
    else:
        logger.error(f"{idb_path.name} code failed, error: {exe_res['errmsg']}")
    return exe_res


def main(args):
    """Call IDA_code.py IDA script."""
    if not IDA_PATH.exists():
        logger.error(f"[!] Error: IDA_PATH:{IDA_PATH} not valid, Use 'export IDA_PATH=/full/path/to/idat64'")
        return

    idb_path2select_funcs = read_json(args.input)
    params = []
    for idb_path, func_eas in tqdm(idb_path2select_funcs.items()):
        idb_path = Path(idb_path)
        suffix = idb_path.suffix
        org_dataset = idb_path.parts[1]
        save_path = Path(
            str(idb_path).replace('IDBs', 'DBs').replace(org_dataset, f'{org_dataset}-top_k_code').replace(suffix, '.json'))
        save_path.parent.mkdir(parents=True, exist_ok=True)
        params.append({
            'idb_path': idb_path,
            'save_path': save_path,
            'select_func_ea_path': args.input
        })
    execute_by_multi_process(extract_code, params, n_jobs=N_JOBS)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Code extraction')
    ap.add_argument("-input", type=str, help="A json file include a list of idb path to function addresses")
    args = ap.parse_args()
    main(args)
