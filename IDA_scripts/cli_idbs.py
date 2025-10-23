#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pathlib import Path
from loguru import logger
from cptools import execute_cmd

CUR_PATH = Path(__file__).parent
ROOT_PATH = CUR_PATH.parent
sys.path.append(str(ROOT_PATH))
from settings import IDA_PATH, N_JOBS, IDA32_PATH
from utils.tool_function import execute_by_multi_process, load_bin_idb

LOG_PATH = CUR_PATH.joinpath("cli_idbs.log")
logger.info(f"IDA Log saved in {LOG_PATH}")

def export_idb(bin_path, idb_path):
    """Launch IDA Pro and export the IDB. Inner function."""
    try:
        cmd = " ".join([
            str(IDA_PATH if idb_path.suffix == ".i64" else IDA32_PATH),
            f"-L{LOG_PATH}",  # name of the log file. "Append mode"
            "-a-",  # enables auto analysis
            "-B",  # batch mode. IDA will generate .IDB and .ASM files
            f"-o{idb_path}",
            str(bin_path)
        ])
        exe_res = execute_cmd(cmd, timeout=120000)
        if exe_res['errcode'] != 0:
            logger.error(f"{bin_path.name} export failed, error: {exe_res['errmsg']}")

        if not idb_path.exists():
            logger.error(f"export {bin_path.name} failed. {idb_path.name} can not find")
            return {
                'errcode': 404,
                'errmsg': f"[!] Error: file {idb_path} not found. IDA output: {exe_res['errmsg']}"
            }
        logger.success(f"{bin_path.name} exported to {idb_path.name}")
        return {
            'errcode': 0,
            'errmsg': ""
        }

    except Exception as e:
        logger.error(f"export {bin_path.name} faild. error: {e}")
        return {
            'errcode': 0,
            'errmsg': f"[!] Exception in export_idb\n{e}"
        }


def main():
    """Launch IDA Pro and export the IDBs."""
    if not IDA_PATH.exists():
        logger.error(f"[!] Error: IDA_PATH:{IDA_PATH} not valid, Use 'export IDA_PATH=/full/path/to/idat64'")
        return
    base_bin_path = Path(sys.argv[1])
    logger.critical(f"[export idb] base_bin_path:{base_bin_path}")
    params = load_bin_idb()
    execute_by_multi_process(export_idb, params, n_jobs=N_JOBS)

if __name__ == "__main__":
    main()
