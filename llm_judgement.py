import sys
import time
import os
from collections import defaultdict

import pandas as pd
from pathlib import Path
from loguru import logger
from cptools import read_json, write_json

from core.llm_model import LLM
from core.prompts import PROMPTS
from functools import wraps
from utils.tool_function import execute_by_multi_threads, clean_pseudo_code

# 禁用代理
os.environ["http_proxy"] = ""
os.environ["https_proxy"] = ""

logger.remove(0)
logger.add(sys.stdout, level="INFO")

MODEL2FORMAL = {
    "deepseek-chat": "deepseek-v3",
    "deepseek-reasoner": "deepseek-R1",
}

FUNC_KEY2CODE = {}
for proj_path in Path("DBs/Binkit-1.0-normal-strip-top_k_code/").iterdir():
    for file_path in proj_path.iterdir():
        if file_path.suffix != ".json":
            continue
        for ea, code_info in read_json(file_path).items():
            code_info['pseudo_code'] = clean_pseudo_code(code_info['pseudo_code'])
            FUNC_KEY2CODE[f"{file_path.stem}@{ea}"] = code_info


idx2data_num = defaultdict(int)

def get_query_func_pair_list(df_top, models, prompt_key="zero_shot", code_type="pseudo_code", save_dir="llm_for_pair"):
    params = []
    data_idx = 0
    for (bin_name_1, fva_1), gp in df_top.groupby(["bin_name_1", "fva_1"]):
        code_A = FUNC_KEY2CODE[f"{bin_name_1}@{fva_1}"][code_type]
        for j, data in gp.iterrows():
            bin_name_2, fva_2 = data['bin_name_2'], data['fva_2']
            code_B = FUNC_KEY2CODE[f"{bin_name_2}@{fva_2}"][code_type]
            content = []
            for i, prompt in enumerate(PROMPTS[prompt_key]):
                if "{code_type}" in prompt and "{code_A}" not in prompt:
                    content.append(
                        prompt.format(code_type=" ".join(code_type.split('_'))))
                elif "{code_A}" in prompt:
                    # provide code info
                    content.append(
                        prompt.format(code_type=" ".join(code_type.split('_')), code_A=code_A, code_B=code_B))
                else:
                    content.append(prompt)
            query = {
                "func_pair_info": {
                    "bin_name_1": data['bin_name_1'],
                    "func_name_1": data['func_name_1'],
                    "fva_1": data['fva_1'],
                    "bin_name_2": data['bin_name_2'],
                    "func_name_2": data['func_name_2'],
                    "fva_2": data['fva_2'],
                    "db_type": data['db_type'],
                    "label": data['label'],
                    "is_code_A_empty": code_A == "",
                    'is_code_B_empty': code_B == "",
                },
                "content": content,
            }
            query["func_pair_info"].update({col: data[col] for col in data.index if col.endswith("sim")})

            idx = data_idx % len(models)
            model = models[idx]
            model_name = MODEL2FORMAL.get(model.model_name, model.model_name)
            if model.top_p:
                model_name = f"{model_name}#{model.top_p}#{model.temperature}"
            save_path = Path(
                f"saved/Binkit-1.0-dataset/pairs/experiments/{save_dir}/{model_name}/{prompt_key}-{code_type}/{data['bin_name_1']}@{data['fva_1']}#{data['bin_name_2']}@{data['fva_2']}.json")
            if save_path.exists():
                continue
            params.append({
                "model": model,
                "query": query,
                "save_path": save_path
            })
            idx2data_num[idx] += 1
            data_idx += 1
    return params


def base_prompt(func):
    @wraps(func)
    def wrapper(model, query, save_path: Path, *args, **kwargs):
        # 前置检查：路径存在性
        if save_path.exists():
            return
        # 准备阶段
        logger.debug(f"[{func.__name__}] func_info: {query['func_pair_info']}, Waiting for output")
        # 执行核心逻辑（由被装饰函数实现）
        start = time.time()
        func(model, query, save_path, *args, **kwargs)
        query['time_cost'] = time.time() - start - query['time_sleep']
        # 后置处理：记录时间并保存
        save_path.parent.mkdir(exist_ok=True, parents=True)
        write_json(query, save_path)

    return wrapper


# 使用装饰器的函数
@base_prompt
def zero_shot(model, query, save_path):
    res = model.ask(query['content'][0])
    query.update(**res)


@base_prompt
def few_shot(model, query, save_path):
    history = []
    few_shot_example_path = query['content'][0]
    for few_shot_data in read_json(few_shot_example_path):
        if "cot" in few_shot_example_path:
            history.append((few_shot_data['content1'], few_shot_data['reply1']))
            history.append((few_shot_data['content2'], few_shot_data['reply2']))
        else:
            history.append((few_shot_data['content'], few_shot_data['reply']))
    if "cot" in few_shot_example_path:
        cot_res = model.ask(query['content'][1], history=history)
        query["cot_reply"], query["cot_think"] = cot_res['output'], cot_res['think']
        history.append((query['content'][1], query['cot_reply']))
        res = model.ask(query['content'][2],
                        history=history)
    else:
        res = model.ask(query['content'][1], history=history)
    query.update(**res)


@base_prompt
def cot(model, query, save_path):
    cot_res = model.ask(query['content'][0])
    query["cot_reply"], query["cot_think"] = cot_res['output'], cot_res['think']
    res = model.ask(query['content'][1],
                    history=[(query['content'][0], query['cot_reply'])])
    query.update(**res)
    query['time_sleep'] += cot_res['time_sleep']


@base_prompt
def critique(model, query, save_path):
    init_res = model.ask(query['content'][0])
    problem_res = model.ask(query['content'][1],
                            history=[(query['content'][0], init_res['output'])])
    query['problem_reply'] = problem_res['output']
    if "no problem" in problem_res['output']:
        query.update(**init_res)
        query['time_sleep'] += problem_res['time_sleep']
    else:
        logger.warning(f"Problem found, waiting for output")
        res = model.ask(query['content'][2],
                        history=[(query['content'][0], init_res['output']),
                                 (query['content'][1], problem_res['output'])])
        query.update(**res)
        query['time_sleep'] += init_res['time_sleep'] + problem_res['time_sleep']


def initialize(args, top_p=1.0, temperature=0.0, use_system=True):
    df_topk = pd.read_csv(args.data_path)
    # 输入多个api key用于并发
    models = [LLM(
        base_url=args.url,
        model_name=args.model,
        api_key=args.api_key,
        top_p=top_p,
        temperature=temperature,
        use_system=use_system
    )]
    n_jobs = args.n_jobs
    return {
        "models": models,
        "n_jobs": n_jobs,
        "df_topk": df_topk,
    }


def execute(prompt2params, n_jobs):
    for i, (prompt, params) in enumerate(prompt2params.items()):
        logger.critical(f"[{i + 1}/{len(prompt2params)}] <{prompt}>, pair num: {len(params)}")
        _ = list(execute_by_multi_threads(globals()[prompt], params, n_jobs=n_jobs))


def main(args):
    init_data = initialize(args, top_p=args.top_p, temperature=args.temperature)
    default_prompt = args.prompt
    prompt2params = {default_prompt.split('-')[0]: []}
    tmp_params = get_query_func_pair_list(df_top=init_data['df_topk'],
                                          models=init_data['models'],
                                          prompt_key=default_prompt,
                                          code_type=args.code_type,
                                          save_dir=args.save_dir)
    prompt2params[default_prompt.split('-')[0]].extend(tmp_params)
    execute(prompt2params, n_jobs=init_data['n_jobs'])

