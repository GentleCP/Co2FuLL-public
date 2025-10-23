# Co$^2$FuLL
This repository provides the **code** and **dataset** for our ASE 2025 paper:

> **Chaopeng Dong, Jingdong Guo, Shouguo Yang, Yi Li, Dongliang Fang, Yang Xiao, Yongle Chen, Limin Sun.**
> *Advancing Binary Code Similarity Detection via Context-Content Fusion and LLM Verification.*
> *In IEEE/ACM International Conference on Automated Software Engineering (ASE 2025).*

---

## 📁 Project Structure

The project is organized as follows:

* **`DBs/`**
  Contains dataset lists, stripped binaries, and other essential data files.
  You can download the dataset from [figshare](https://figshare.com/account/articles/30426451).

* **`core/`**
  Includes the core implementation, such as context construction, feature extraction, and LLM integration logic.

* **`IDA_scripts/`**
  Provides IDA-Pro scripts used to extract binary-level features and function representations from binaries.

* **`utils/`**
  Contains supporting utility functions (data preprocessing, evaluation, etc.).

* **`saved/`**
  Stores experimental results and intermediate files.

---

## ⚙️ Environment Setup

Before running Co$^2$FuLL, please ensure your environment meets the following requirements:

* **Operating System**
  The experiments were conducted on **Ubuntu 22.04 LTS**.
  While other systems may work, unexpected errors might occur due to environment differences.

  * **Python Environment**
    Python **3.9** is used. We recommend managing the environment via **conda**.
    A pre-configured environment file (`environment.yml`) is provided for convenience:

    ```bash
    conda env create -f environment.yml
    conda activate co2full-public
    ```

    Alternatively, you may create a clean environment manually and install required dependencies.
      - Apart from that, install the necessary packages under your **IDA python environment**
      ```shell
    pip install cptools networkx loguru --target="/path/to/IDA Python/DIR/"
    ```
* **IDA-Pro**
  We use **IDA-Pro v7.5** for binary feature extraction.
  Since IDA-Pro is commercial software, please install it manually and configure the following paths in `settings.py`:

  ```python
  # Replace IDA path with your own
  IDA_PATH = Path(getenv("IDA_PATH", "/data/Application/idapro-7.5/idat64"))
  IDA32_PATH = Path(getenv("IDA32_PATH", "/data/Application/idapro-7.5/idat"))
  ```

---

## 🔁 Reproducing the Experiments

To reproduce the experimental results presented in our paper, follow these **three major steps**:

1. **Feature Extraction**
2. **Candidate Retrieval**
3. **LLM Verification**

---

### 🧩 Step 1: Feature Extraction

Feature extraction involves generating various binary representations and metadata for downstream tasks.

1. **Generate `.idb` files** (IDA-Pro analysis results):

   ```bash
   python IDA_scripts/cli_idbs.py
   ```

2. **Generate dependency graphs (DGs):**

   ```bash
   python IDA_scripts/cli_DG.py
   ```

3. **Extract code snippets** (for top-5 candidate functions):

   ```bash
   python IDA_scripts/cli_code.py -input DBs/Binkit-1.0-dataset/top5_for_llm-idb_path2func_eas.json
   ```

4. **Generate model embeddings**
   Follow the corresponding repositories to generate embeddings for your test functions:

   * [GMN](https://github.com/google-deepmind/deepmind-research/blob/master/graph_matching_networks/graph_matching_networks.ipynb)
   * [Trex](https://github.com/CUMLSec/trex)
   * [Asteria](https://github.com/Asteria-BCSD/Asteria)
   * [HermesSim](https://github.com/NSSL-SJTU/HermesSim)

---

### 🧭 Step 2: Candidate Retrieval

In this stage, Co$^2$FuLL fuses **contextual** and **content-based** similarities to retrieve semantically equivalent functions from a large function pool.

We explore:

* **4 models**
* **3 sub-tasks:** `xc`, `xa`, `xm`
* **5 configurations:**
  `base`, `base+context`, `base+context(import)`, `base+context(string)`, `base+context(direct)`

Example usage:

```bash
python context_exp.py -h
```

Help output:

```
usage: context_exp.py [-h] [-data_path DATA_PATH] [-exp EXP]

Function retrieval enhancement experiments

options:
  -h, --help            show this help message and exit
  -data_path DATA_PATH  Testing dataset path
  -exp EXP              Experiment name (xc, xa, xm)
```

---

### 🤖 Step 3: LLM Verification

After retrieving top-K candidates, Co$^2$FuLL leverages **Large Language Models (LLMs)** to verify and confirm the true match.
This verification step improves precision and interpretability.

In our experiments, we evaluate:

* **7 LLMs**
  * Qwen-2.5-7B (14B, 72B)
  * Qwen2.5-Coder-14B
  * DeepSeek-V3, DeepSeek-R1
  * GPT-4o
* **6 prompt designs**
  * Zero-shot, Few-Shot, CoT-Lite, CoT-Pro, CoT-Self, Critique
* **5 LLM settings**
  * top_p/temperature: 1.0/0.5, 0.5/0.5, 0.5/1.0, 1.0/1.0, 1.0/0.0

Example usage:

```bash
python LLM_exp.py -h
```

Help output:

```
usage: LLM_exp.py [-h] [-data_path DATA_PATH] [-api_key API_KEY] [-n_jobs N_JOBS]
                  [-save_dir SAVE_DIR] [-url URL] [-model MODEL] [-exp EXP]

BCSD LLM experiments

options:
  -h, --help            Show this help message and exit
  -data_path DATA_PATH  Path to top-K results
  -api_key API_KEY      API key for LLM service
  -n_jobs N_JOBS        Number of parallel threads
  -save_dir SAVE_DIR    Directory to save results
  -url URL              API request endpoint
  -model MODEL          LLM model name
  -exp EXP              Experiment name
```
> **Note**:
Different API vendors may use different names for the same LLM model (for example, deepseek-v3 may appear as deepseek-chat).
Please make sure to adjust the LLM name according to the API naming convention of the service you are using.
---

## 📜 Citation

If you find this work useful, please cite our paper:

```bibtex
@inproceedings{dong2025co2full,
  title={Advancing Binary Code Similarity Detection via Context-Content Fusion and LLM Verification},
  author={Dong, Chaopeng and Guo, Jingdong and Yang, Shouguo and Li, Yi and Fang, Dongliang and Xiao, Yang and Chen, Yongle and Sun, Limin},
  booktitle={Proceedings of the IEEE/ACM International Conference on Automated Software Engineering (ASE)},
  year={2025}
}
```

---

## 📬 Contact

If you encounter any issues or have questions about the code or dataset, please feel free to contact:

* **Chaopeng Dong**: dongchaopeng@iie.ac.cn

---

