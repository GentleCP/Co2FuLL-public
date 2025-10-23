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
from settings import IDA_PATH, IDB_PATH, DB_PATH, N_JOBS, IDA32_PATH
from utils.tool_function import execute_by_multi_process, load_binaries

IDA_PLUGIN = CUR_PATH.joinpath('IDA_code.py')
LOG_PATH = CUR_PATH.joinpath("IDA_call_graph.log")
logger.info(f"IDA_PLUGIN: {IDA_PLUGIN}")
logger.info(f"Log saved in {LOG_PATH}")

def gen_call_graph(idb_path, save_path):
    cmd = " ".join([
        "TVHEADLESS=1",
        str(IDA_PATH if idb_path.suffix == ".i64" else IDA32_PATH),
        '-A',
        f'-L{LOG_PATH}',
        f'-S{IDA_PLUGIN}',
        f'-Ocallgraph:{save_path}',
        str(idb_path)])
    exe_res = execute_cmd(cmd)
    if exe_res['errcode'] == 0:
        if save_path.exists():
            logger.success(f"{idb_path.name} call graph saved in {save_path.name}")
        else:
            logger.warning(f"{idb_path.name} call graph can not find but no execute error")
    else:
        logger.error(f"{idb_path.name} call graph failed, error: {exe_res['errmsg']}")
    return exe_res


def main(args):
    """Call IDA_code.py IDA script."""
    if not IDA_PATH.exists():
        logger.error(f"[!] Error: IDA_PATH:{IDA_PATH} not valid, Use 'export IDA_PATH=/full/path/to/idat64'")
        return

    select_idb_paths = read_json(args.input).keys()
    params = []
    for idb_path in tqdm(select_idb_paths):
        idb_path = Path(idb_path)
        suffix = idb_path.suffix
        org_dataset = idb_path.parts[1]
        save_path = Path(
            str(idb_path).replace('IDBs', 'DBs').replace(org_dataset, f'{org_dataset}-call_graphs').replace(suffix, '.cg'))
        if save_path.exists():
            continue
        save_path.parent.mkdir(parents=True, exist_ok=True)
        params.append({
            'idb_path': idb_path,
            'save_path': save_path,
        })
    logger.critical(f"[extract call graph (process: {N_JOBS})] need/total:{len(params)}/{len(select_idb_paths)}")
    if params:
        results = []
        for res in execute_by_multi_process(gen_call_graph, params, n_jobs=1):
            results.append(res)
        logger.critical(pd.DataFrame(results)['errmsg'].value_counts())


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Call graph extraction')
    ap.add_argument("-input", type=str, help="A json file include a list of idb paths")
    args = ap.parse_args()
    main(args)
