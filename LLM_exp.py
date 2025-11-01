import argparse
from llm_judgement import *
from settings import N_JOBS


def prompt_exp(args):
    init_data = initialize(args)
    prompt2params = defaultdict(list)
    for prompt in ["zero_shot", "critique", "cot-self", "cot-lite", "cot-pro", "few_shot",]:
        tmp_params = get_query_func_pair_list(df_top=init_data['df_topk'],
                                              models=init_data['models'],
                                              prompt_key=prompt,
                                  save_dir=args.save_dir)
        prompt2params[prompt.split('-')[0]].extend(tmp_params)
    execute(prompt2params, n_jobs=init_data['n_jobs'])


def setting_exp(args):
    default_prompt = "few_shot"
    prompt2params = {"few_shot": []}
    for top_p in [0.5, 1.0]:
        for temperature in [0.5, 1.0]:
            init_data = initialize(args, top_p=top_p, temperature=temperature)
            tmp_params = get_query_func_pair_list(df_top=init_data['df_topk'],
                                                  models=init_data['models'],
                                                  prompt_key=default_prompt,
                                                  save_dir=args.save_dir)
            prompt2params["few_shot"].extend(tmp_params)
    execute(prompt2params, n_jobs=init_data['n_jobs'])


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='BCSD LLM experiments')
    ap.add_argument("-data_path", type=str, help="Path to top-K results",
                    default="DBs/Binkit-1.0-dataset/pairs/experiments/xm-full_top5-250515.csv")
    ap.add_argument("-api_key", type=str, help="api key", default="sk-null")
    ap.add_argument("-n_jobs", type=int, help="Number of threads", default=N_JOBS)
    ap.add_argument("-save_dir", type=str, help="Directory to save results", default="llm_for_pair")
    # these parameters should be specified
    ap.add_argument("-url", type=str, help="Url for request", default="https://api.openai.com/v1")
    ap.add_argument("-model", type=str, help="Name of LLM (Please specify the model name based on the vendor)")
    ap.add_argument("-exp", type=str, help="Experiment name (prmpt_exp or setting_exp)")

    args = ap.parse_args()
    globals()[args.exp](args)