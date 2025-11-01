from pathlib import Path
from os import getenv

ROOT_PATH = Path(__file__).parent

# Replace IDA path with your own
IDA_PATH = Path(getenv("IDA_PATH", "/data/Application/idapro-7.5/idat64"))
IDA32_PATH = Path(getenv("IDA32_PATH", "/data/Application/idapro-7.5/idat"))
IDB_PATH = ROOT_PATH.joinpath("IDBs").relative_to(ROOT_PATH)
DB_PATH = ROOT_PATH.joinpath("DBs").relative_to(ROOT_PATH)

SKIP_SUFFIX = {'.idb', '.idb64', '.id1', '.id0', '.id2', '.nam', '.til', '.i64', '.json', '.pkl', '.txt', '.py', '.csv',
               '.dict', '.BinExport', '.cfg', '.cg', '.png', '.dot'}

N_JOBS = 32
RANK_STRATEGY = "average"
