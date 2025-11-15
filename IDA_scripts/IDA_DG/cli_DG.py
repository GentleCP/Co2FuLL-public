#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
from pathlib import Path
from loguru import logger
from cptools import execute_cmd, read_json
import pandas as pd
from tqdm import tqdm

CUR_PATH = Path(__file__).parent
ROOT_PATH = CUR_PATH.parent.parent
sys.path.append(str(ROOT_PATH))
from settings import IDA_PATH, N_JOBS, IDA32_PATH
from utils.tool_function import execute_by_multi_process, load_bin_idb

IDA_PLUGIN = CUR_PATH.joinpath('IDA_DG.py')
LOG_PATH = CUR_PATH.joinpath("IDA_DG.log")
logger.info(f"IDA_PLUGIN: {IDA_PLUGIN}")
logger.info(f"Log saved in {LOG_PATH}")

def gen_dependency_graph(idb_path, save_path):
    cmd = " ".join([
        "TVHEADLESS=1",
        str(IDA_PATH if idb_path.suffix == ".i64" else IDA32_PATH),
        '-A',
        f'-L{LOG_PATH}',
        f'-S{IDA_PLUGIN}',
        f'-ODG:{save_path}',
        str(idb_path)])
    exe_res = execute_cmd(cmd)
    if exe_res['errcode'] == 0:
        if save_path.exists():
            logger.success(f"{idb_path.name} DG saved in {save_path.name}")
        else:
            logger.warning(f"{idb_path.name} DG can not find but no execute error")
    else:
        logger.error(f"{idb_path.name} DG failed, error: {exe_res['errmsg']}")
    return exe_res


def main(args):
    if not IDA_PATH.exists():
        logger.error(f"[!] Error: IDA_PATH:{IDA_PATH} not valid, Use 'export IDA_PATH=/full/path/to/idat64'")
        return
    params = []
    for item in tqdm(load_bin_idb(args.path)):
        idb_path = item['idb_path']
        suffix = idb_path.suffix
        org_dataset = idb_path.parts[1]
        save_path = Path(
            str(idb_path).replace('IDBs', 'DBs').replace(org_dataset, f'{org_dataset}-DGs').replace(suffix,
                                                                                                            '.dg'))
        if save_path.exists():
            continue
        save_path.parent.mkdir(parents=True, exist_ok=True)
        params.append({
            'idb_path': idb_path,
            'save_path': save_path,
        })
    execute_by_multi_process(gen_dependency_graph, params, n_jobs=N_JOBS)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description="Generate dependency graphs based on generated idbs.")
    ap.add_argument('-p', '--path', type=str, default="DBs/Binkit-1.0-normal-strip-binaries",
                    help="Path of directory to store the binary files")
    args = ap.parse_args()
    main(args)

