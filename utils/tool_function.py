import re
import tiktoken
from pathlib import Path
from cptools import execute_cmd

from Levenshtein import distance as levenshtein_distance
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from mpire import WorkerPool
from tqdm import tqdm
from difflib import SequenceMatcher
import transformers
from dashscope import get_tokenizer
from settings import ROOT_PATH

tqdm.pandas(desc="apply")


def strip_bin(bin_path, save_path, arch_bit=None):
    save_path.parent.mkdir(exist_ok=True, parents=True)
    if arch_bit == "arm32":
        cmd = f"arm-linux-gnueabi-strip -s {bin_path} -o {save_path}"
    elif arch_bit == "arm64":
        cmd = f"aarch64-linux-gnu-strip -s {bin_path} -o {save_path}"
    elif arch_bit == "mips32":
        cmd = f"mips-linux-gnu-strip -s {bin_path} -o {save_path}"
    elif arch_bit == "mips64":
        cmd = f"mips64-linux-gnuabi64-strip -s {bin_path} -o {save_path}"
    elif arch_bit in {'x86', 'x64'}:
        cmd = f"strip -s {bin_path} -o {save_path}"
    else:
        raise ValueError(f"not support {arch_bit}")
    execute_cmd(cmd)




def execute_by_multi_process(method, objects, n_jobs=1):
    if n_jobs == 1:
        for obj in tqdm(objects, desc=f'{method.__name__}, n_jobs:{n_jobs}'):
            res = method(**obj)
            yield res
    else:
        with WorkerPool(n_jobs=n_jobs) as pool:
            for res in pool.imap_unordered(method,
                                         objects,
                                         progress_bar=True,
                                         progress_bar_options={'desc': f'{method.__name__}, n_jobs:{n_jobs}'}):
                yield res


def execute_by_multi_threads(method, objects, n_jobs=1):
    if n_jobs == 1:
        for obj in tqdm(objects, f'{method.__name__}, n_jobs:{n_jobs}'):
            yield method(**obj)
    else:
        with ThreadPoolExecutor(max_workers=n_jobs) as executor:
            # 提交任务到线程池
            future_to_index = {
                executor.submit(method, **args): index
                for index, args in enumerate(objects)
            }

            # 获取任务结果
            for future in tqdm(as_completed(future_to_index),
                               total=len(objects), desc=f'{method.__name__}, n_jobs:{n_jobs}'):
                yield future.result()


def load_bin_idb():
    datas = []
    for proj_path in ROOT_PATH.joinpath("DBs/Binkit-1.0-normal-strip-binaries").iterdir():
        for bin_path in proj_path.iterdir():
            _, compiler, arch, bit, optim, *file = bin_path.stem.split("_")
            if bit == "32":
                suffix = ".idb"
            else:
                suffix = ".i64"
            idb_path = Path(str(bin_path).replace('DBs', 'IDBs') + suffix)
            idb_path.parent.mkdir(parents=True, exist_ok=True)
            datas.append({
                'bin_path': bin_path,
                'idb_path': idb_path,
            })
    return datas

def get_context_sim(func1_ac2dist, func2_ac2dist, select_feats=None, direct=False):
    if direct:
        func1_ac2dist = {ac:dist for ac, dist in func1_ac2dist.items() if dist == 1}
        func2_ac2dist = {ac:dist for ac, dist in func2_ac2dist.items() if dist == 1}
    if select_feats is not None:
        func1_ac2dist = {ac:dist for ac, dist in func1_ac2dist.items() if ac[1] in select_feats}
        func2_ac2dist = {ac:dist for ac, dist in func2_ac2dist.items() if ac[1] in select_feats}
    func1_acs = set(func1_ac2dist.keys())
    func2_acs = set(func2_ac2dist.keys())
    if not func1_acs:
        return 1 if not func2_acs else 0
    common_keys = func1_acs.intersection(func2_acs)

    total_score = 0.0
    for key in common_keys:
        distance1 = func1_ac2dist[key]
        distance2 = func2_ac2dist[key]
        total_score += 1 - abs(distance1 - distance2) / max(distance1, distance2)

    for key in func2_acs - func1_acs:
        total_score -= 1 / (func2_ac2dist[key])
    for key in func1_acs - func2_acs:
        total_score -= 1 / (func1_ac2dist[key])

    similarity = max(total_score, 0) / len(func1_acs)
    return similarity


def edit_sim(s1, s2):
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return 1 - (levenshtein_distance(s1, s2) / max_len)



func_pattern = re.compile(r"(?P<func_name>\w+)\((?P<param>.*)\)")
reg_pattern = re.compile(r"@<\w+?>")
int_pattern = re.compile(r"\_\_int\d+")

def clean_pseudo_code(pseudo_code):
    code_lines = []
    is_content = False
    for i, line in enumerate(pseudo_code.split('\n')):
        if "//" in line and i == 0:
            continue
        elif "(" in line and i <= 1:
            # 清理函数名中的返回类型和参数定义
            line = int_pattern.sub("int", reg_pattern.sub("", line))
            code_lines.append(line)
            continue
        elif line == "{":
            code_lines.append(line)
            continue
        elif line == "":
            is_content = True
        if not is_content:
            code_lines.append(int_pattern.sub("int", line).split('//')[0])
        else:
            code_lines.append(line)
    return "\n".join(code_lines)


def recover_func_call(call):
    call = call.lstrip('.')
    if call.startswith('j_'):
        return call[2:]

    if re.match('^(__)|(memset)|(memcpy)|(operator).*', call):
        return None

    if '.' in call:
        # pr_out_uint.isra.28
        return call.split('.')[0]

    call = re.sub(r'<.*?>|\(.*?\)', '', call)
    return call


def recover_call_list(call_list, is_sorted=False):
    results = []

    for call in call_list:
        if call is None:
            continue
        tmp = recover_func_call(call)
        if tmp:
            results.append(tmp)
    if is_sorted:
        return results
    else:
        return sorted(results)

def get_lcs_simi(seq1, seq2):
    sm = SequenceMatcher(None, seq1, seq2)
    return sm.ratio()

def get_match_num(src_callee, tgt_callee):
    if len(src_callee) == 0:
        return 0
    c1 = Counter(src_callee)
    c2 = Counter(tgt_callee)
    common_keys = set(c1.keys()).intersection(c2.keys())
    match_num = 0
    for key in common_keys:
        match_num += min(c1[key], c2[key])
    return match_num/len(src_callee)

def get_tokenizer_num(model, content):
    model = model.lower()
    if model.startswith("gpt"):
        encoding = tiktoken.encoding_for_model(model)
        result = encoding.encode(content)
    elif model.startswith("deepseek"):
        chat_tokenizer_dir = Path(__file__).parent
        tokenizer = transformers.AutoTokenizer.from_pretrained(
            chat_tokenizer_dir, trust_remote_code=True
        )
        result = tokenizer.encode(content)
    else:
        # default qwen
        tokenizer = get_tokenizer(model)
        # 将字符串切分成token并转换为token id
        result = tokenizer.encode(content)
    return len(result)
