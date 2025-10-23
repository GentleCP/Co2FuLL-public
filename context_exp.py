from pathlib import Path
import pandas as pd
import argparse

from IPython.core.display_functions import display
from loguru import logger
from cptools import read_pickle, read_json
from sklearn.metrics.pairwise import cosine_similarity
from core.context import ContextGener
from utils.tool_function import execute_by_multi_process
from utils.metric import *
from utils.model_sim_rank import calculate_model_sim_rank, calculate_context_sim_rank
from settings import N_JOBS, ROOT_PATH, RANK_STRATEGY

FULL_OR_PART = "full/"

BASE_FILE_NAME = "Binkit-1.0-normal-strip_{}_1000_10000_{}.csv"

BASE_EMBED_PATH = ROOT_PATH.joinpath(f"DBs/Binkit-1.0-normal-strip-embedding")
BASE_DATASET_PATH = ROOT_PATH.joinpath('DBs/Binkit-1.0-dataset/pairs/experiments/')
BASE_SAVE_PATH = ROOT_PATH.joinpath('saved/Binkit-1.0-dataset/pairs/experiments/')
BASE_SAVE_PATH.mkdir(exist_ok=True, parents=True)
CONTEXT_GENER = ContextGener()

MODEL2BEST_PROP = read_json("saved/Binkit-1.0-dataset/pairs/train/model2best_prop-250530.json")


def get_parameters_for_context(df_data):
    params = []
    for idb_path, fvas in df_data.groupby('strip_idb_path')['fva']:
        idb_path = Path(idb_path)
        suffix = idb_path.suffix
        org_dataset = idb_path.parts[1]
        dg_path = Path(
            str(idb_path).replace('IDBs', 'DBs').replace(org_dataset, f'{org_dataset}-DGs').replace(suffix, '.dg'))
        params.append({
            'dg_path': dg_path,
            'sources': set(fvas),
        })
    return params


def extract_context_wrap(dg_path, sources):
    return dg_path.stem, CONTEXT_GENER.extract(dg_path=dg_path, sources=sources)


def load_model_embeddings():
    model2embed_all = {}
    for file_path in BASE_EMBED_PATH.iterdir():
        if file_path.suffix != ".pkl":
            continue
        dataset, exp, model, _, date = file_path.stem.split('_')
        logger.info(f'[+] loading {model}, {dataset} from {file_path.stem}')
        model2embed_all[model] = read_pickle(file_path)
    return model2embed_all


def cal_metrics_from_local():
    datas = []
    for full_path in BASE_SAVE_PATH.iterdir():
        if not full_path.is_dir():
            continue
        for file_path in full_path.iterdir():
            if file_path.suffix != ".csv":
                continue
            dataset, exp, _, pool_size, homo_or_all = file_path.stem.split('_')
            exp += '-' + full_path.name
            df_homo = pd.read_csv(file_path)
            metrics = {
                'dataset': dataset,
                'exp': exp,
            }
            for col in df_homo.columns:
                if col.endswith('rank'):
                    try:
                        model, dist_type, _ = col.split('-')
                    except ValueError:
                        model, _ = col.split('-')
                        dist_type = ""

                    metrics['model'] = model
                    metrics['method'] = f"{model}-{dist_type}"
                    metrics['mrr'] = get_mrr(df_homo[col])
                    for k in [1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50]:
                        metrics[f"recall@{k}"] = get_recall_at_k(df_homo[col], top_k=k)
                    datas.append(metrics.copy())

    df_metrics = pd.DataFrame(datas).sort_values(by="mrr", ascending=False)
    return df_metrics

def cal_sim_rank_by_exp(exp, model2embed_all, bin2contexts):
    logger.info('-' * 10 + exp + '-' * 10)
    exp_prefix, full_or_part = exp.split('-')

    pos_path = BASE_DATASET_PATH.joinpath(full_or_part + '/' + BASE_FILE_NAME.format(exp_prefix, 'pos'))
    neg_path = BASE_DATASET_PATH.joinpath(full_or_part + '/' + BASE_FILE_NAME.format(exp_prefix, 'neg'))
    homo_save_path = BASE_SAVE_PATH.joinpath(
        full_or_part + '/' + BASE_FILE_NAME.format(exp_prefix, 'homo'))
    all_models = set(model2embed_all.keys())
    logger.info(f'[{exp}] Loading neg pos test pairs from {pos_path}, models left:{all_models}')
    df_pos = pd.read_csv(pos_path)
    df_neg = pd.read_csv(neg_path)

    # labeling
    df_pos['label'] = 1
    df_neg['label'] = 0
    df = pd.concat([df_pos, df_neg])

    # # gen func key
    df['func_key_1'] = df['bin_name_1'] + '@' + df['fva_1']
    df['func_key_2'] = df['bin_name_2'] + '@' + df['fva_2']
    df['key_pair'] = df['func_key_1'] + '#' + df['func_key_2']

    for model in all_models:
        logger.info(f'[{exp}] calculate sim for {model}')
        df = calculate_model_sim_rank(df, model, model2embed_all[model], rank_strategy=RANK_STRATEGY,
                                      sim_method=cosine_similarity)

    if exp == "xm-full":
        dist_options = ['full', 'direct_only', 'str_only', 'import_only']
    else:
        dist_options = ['full']

    for method in dist_options:
        logger.info(f'[{exp}] calculate context similarity for {method}')
        df = calculate_context_sim_rank(df, key=method, bin2contexts=bin2contexts)

        for model in all_models:
            logger.info(f'[{exp}] combine {model} and context {method}')
            prop = float(MODEL2BEST_PROP[model])
            key = f"{model}-{method}"
            df[f"{key}-sim"] = prop * df[f"{model}-sim"] + (1 - prop) * df[f"{method}-sim"]
            df[f'{key}-rank'] = df.groupby(['bin_name_1', 'fva_1'])[f'{key}-sim'].rank(method=RANK_STRATEGY,
                                                                                       ascending=False)

    df_homo = df.query('label == 1').copy()
    homo_save_path.parent.mkdir(exist_ok=True, parents=True)
    logger.info(f"[{exp}] save to {homo_save_path}")
    df_homo.to_csv(homo_save_path, index=False)
    return df


def main(args):
    df_test = pd.read_csv(args.data_path).reset_index()
    params = get_parameters_for_context(df_test)
    bin2contexts = {}
    for bin_name, contexts in execute_by_multi_process(extract_context_wrap, params, n_jobs=N_JOBS):
        bin2contexts[bin_name] = contexts
    cal_sim_rank_by_exp(exp=args.exp + '-full', bin2contexts=bin2contexts, model2embed_all=load_model_embeddings())
    df_metrics = cal_metrics_from_local()
    display(df_metrics[['exp', 'method', 'mrr', 'recall@1']])


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Function retrieval enhancement experiments')
    ap.add_argument("-data_path", type=str, default="DBs/Binkit-1.0-dataset/Binkit-1.0-normal-strip_testing.csv",
                    help="Testing dataset path")
    ap.add_argument("-exp", type=str, default="xm", help="Experiment name (xc, xa, xm)")
    args = ap.parse_args()
    main(args)
