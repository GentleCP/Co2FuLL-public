
def get_metric(df, beta=2):
    tp = df.query('pred_label == 1 and label == 1').shape[0]
    fp = df.query('pred_label == 1 and label != 1').shape[0]
    fn = df.query('pred_label != 1 and label == 1').shape[0]
    tn = df.query('pred_label != 1 and label != 1').shape[0]
    acc = df.query('pred_label == label').shape[0] / df.shape[0]
    supp_rate = df.query('pred_label in [0, 1]').shape[0] / df.shape[0]

    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    tpr = r
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    try:
        f_beta = (1 + beta**2) * p* r / (beta **2 * p + r)
    except ZeroDivisionError:
        f_beta = 0
    return {
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn,
        'total': tp + fp + tn + fn,
        'p': round(p*100, 1),
        'r': round(r*100, 1),
        'tpr': round(tpr*100, 1),
        'fpr': round(fpr*100, 1),
        'f_beta': round(f_beta*100, 1),
        'acc': round(acc*100, 1),
        'supp_rate':round(supp_rate*100, 1),
    }

def get_mrr(ranks):
    return float((1 / ranks).mean()) * 100

def get_recall_at_k(ranks, top_k=1):
    return (ranks <= top_k).mean() * 100
