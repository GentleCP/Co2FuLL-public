import pandas as pd
from cptools import read_pickle
import numpy as np
from utils.tool_function import get_context_sim

from settings import RANK_STRATEGY


def get_embeddings(embed_all, func_keys, embed_dim):
    pool_not_exists = []
    mat = []
    for i, key in enumerate(func_keys):
        try:
            embed = embed_all[key].squeeze()
        except KeyError:
            pool_not_exists.append(key)
            embed = np.zeros(embed_dim)
        mat.append(embed)
    return np.array(mat), len(pool_not_exists)


def query_model_sim(key_pair, sim_all, src_key2idx, tgt_key2idx):
    src_key, tgt_key = key_pair.split('#')
    src_idx, tgt_idx = src_key2idx[src_key], tgt_key2idx[tgt_key]
    return sim_all[src_idx, tgt_idx]


def calculate_model_sim_rank(df, model, embed_all, sim_method, rank_strategy):
    # gen func_key to index, 用于索引sim和对应pair_key
    src_key2idx = {key: i for i, key in enumerate(df['func_key_1'].unique())}
    tgt_key2idx = {key: i for i, key in enumerate(df['func_key_2'].unique())}
    embed_dim = next(iter(embed_all.values())).shape[-1]
    src_embeddings, src_not_exist_embed_num = get_embeddings(embed_all, func_keys=src_key2idx.keys(),
                                                             embed_dim=embed_dim)
    tgt_embeddings, tgt_not_exist_embed_num = get_embeddings(embed_all, func_keys=tgt_key2idx.keys(),
                                                             embed_dim=embed_dim)
    sim_all = sim_method(src_embeddings, tgt_embeddings)
    # query sim
    df[f'{model}-sim'] = df['key_pair'].progress_apply(
        lambda x: query_model_sim(x, sim_all=sim_all, src_key2idx=src_key2idx, tgt_key2idx=tgt_key2idx))
    df[f'{model}-rank'] = df.groupby(['func_key_1'])[f'{model}-sim'].rank(method=rank_strategy, ascending=False)
    return df


def get_context_sim_for_key(key, bin2contexts, **kwargs):
    func_key1, func_key2 = key.split('#')
    (src_bin, src_func_ea), (tgt_bin, tgt_func_ea) = (func_key1.split('@'), func_key2.split('@'))
    func1_feature = bin2contexts[src_bin].get(src_func_ea, {})
    func2_feature = bin2contexts[tgt_bin].get(tgt_func_ea, {})
    return get_context_sim(func1_feature, func2_feature, **kwargs)


def calculate_context_sim_rank(df, key, bin2contexts):
    if key == "full":
        df[f'{key}-sim'] = df['key_pair'].progress_apply(
            lambda x: get_context_sim_for_key(x, bin2contexts, select_feats=None, direct=False))
    elif key == "direct_only":
        df[f'{key}-sim'] = df['key_pair'].progress_apply(
            lambda x: get_context_sim_for_key(x, bin2contexts, select_feats=None, direct=True))
    elif key == "str_only":
        df[f'{key}-sim'] = df['key_pair'].progress_apply(
            lambda x: get_context_sim_for_key(x, bin2contexts, select_feats={"str"}, direct=False))
    elif key == "import_only":
        df[f'{key}-sim'] = df['key_pair'].progress_apply(
            lambda x: get_context_sim_for_key(x, bin2contexts, select_feats={"func"}, direct=False))
    df[f'{key}-rank'] = df.groupby(['func_key_1'])[f'{key}-sim'].rank(method=RANK_STRATEGY, ascending=False)
    return df
