# CyberSwarm — Results

Adversarial purple-team lab where an LLM **Red** (attacker) and LLM **Blue** (defender)
play repeated rounds in an isolated 3-segment Docker network with a Suricata IDS. We
compare four *learning methods* for the agents and then introduce a fifth, qualitatively
different one: **fine-tuning the model weights** (QLoRA behavioural cloning) on the
successful trajectories the other methods produced.

All runs: 15 rounds × 2 repeats per method, Qwen2.5-14B-Instruct, seed 42, same lab,
Juice Shop target (107 challenges, ground-truth scoreboard). Each round is soft-reset
(firewall + target restarted) so rounds are independent and comparable.

## The five methods

| # | Method | Runtime learning | Where the "learning" lives |
|---|--------|------------------|----------------------------|
| 1 | `none` | — | nothing |
| 2 | `reflect` | reflection playbook | prompt |
| 3 | `+memory` | reflection + episodic memory | prompt |
| 4 | `+debrief` | reflection + memory + cross-agent debrief | prompt |
| 5 | **`FINE-TUNED`** | **none** | **the weights (QLoRA adapter)** |

Method 5's Blue runs a QLoRA-fine-tuned defender; Red stays on the base model so the
comparison isolates *"did fine-tuning the defender help."* Crucially, method 5 runs with
**all runtime learning turned off** — no reflection, no memory, no debrief, no extra
context tokens. The defensive policy is baked into the weights.

## Headline result — defensive reliability

The coarse IDS-alert scores saturate: the single-vulnerability scenario is solvable in
round 1, so every method detects ~2 alerts/round and `blue_score` ≈ 2. The metric that
discriminates is **defensive competence**: in how many rounds did Blue actually block the
attacker, and how decisively.

Two repeats per method (`_r1`, `_r2`); the "blocked" column shows the mean with the
per-repeat values in parentheses.

| method | blocked the attacker | first block (step) | first patch (step) | legit users blocked |
|--------|---------------------|--------------------|--------------------|---------------------|
| none | 40% (47/33) | 1.17 | 1.00 | 0 |
| reflect | 37% (33/40) | 1.45 | 1.03 | 0 |
| +memory | 93% (100/87) | 1.10 | 1.10 | 0 |
| +debrief | 90% (93/87) | 1.04 | 1.11 | 0 |
| **FINE-TUNED** | **100% (100/100)** | **1.07** | **1.00** | **0** |

**Takeaways**

1. **Fine-tuning is the most *reliable* defender — 100% of rounds blocked in both
   repeats, with zero variance — and uses no runtime learning machinery.** The
   prompt-based methods are strong but wobble across repeats (`+memory` 100→87%,
   `+debrief` 93→87%); only the fine-tuned defender is perfectly consistent, because the
   policy is internalised in the weights (no reflection/memory/debrief, no extra context).
2. **The fine-tuned defender is the most decisive**: it patches the vulnerability on its
   first action (step 1.00) every round and blocks the attacker's IP by step ~1.07.
3. **Naive reflection can hurt.** `reflect` alone (37%) is *worse* than `none` (40%) —
   un-anchored reflection polluted the defender's policy. Memory/debrief recover it.
4. **No false positives.** Across all 150 rounds Blue never blocked the legitimate user
   (10.10.1.20), fine-tuned included — it learned to key on behaviour, not volume.

See `analysis/ft_comparison.png` for the figure.

## Pipeline

1. **Collect** (`orchestrator/collect.ps1`): run methods 1–4 × 15 rounds → per-round
   telemetry, scores, and full agent transcripts under `runs/<method>_r1/`.
2. **Export** (`ml/export_dataset.py`): keep only *successful* episodes (Red: solved a
   challenge; Blue: detected an attack and blocked the attacker without blocking the
   legit user) → `ml/dataset.jsonl` (116 examples, 58 Red / 58 Blue).
3. **Fine-tune** (`ml/train_qlora.py`, on an RTX A4000): QLoRA on Qwen2.5-14B
   (r=16, 3 epochs), **one adapter per role — both Red and Blue were fine-tuned**.
   Blue train loss 2.01 → 0.66 (final 1.14); Red train loss 2.09 → 0.14 (final 0.91).
   Blue (the defender) is the priority and is the one evaluated below.
4. **Serve** (`ml/export_gguf.py` → `ollama create`): export q4_k_m GGUF, serve the
   fine-tuned defender as `qwen-blue-ft`.
5. **Evaluate** (`config/ft.yaml`): run the fine-tuned defender as method 5 and compare
   (`analysis/ft_comparison.py`).

## Reproduce

```powershell
# 1-4: collect (needs the Docker lab up and an Ollama endpoint at localhost:11434)
powershell -File orchestrator/collect.ps1
# 2: build the SFT set
python ml/export_dataset.py
# 3-4: on the GPU box
python ml/train_qlora.py --agent blue --data dataset.jsonl --out out_blue --epochs 3
python ml/export_gguf.py --adapter out_blue/adapter --out out_blue/gguf
ollama create qwen-blue-ft -f out_blue/gguf/gguf_gguf/Modelfile
# 5: evaluate the fine-tuned defender
python orchestrator/main.py --config config/ft.yaml --name ft_r1 --no-lab
python analysis/ft_comparison.py
```

The fine-tuned adapters and GGUFs are large and live on the GPU host (not in git); the
scripts above regenerate them from `ml/dataset.jsonl`, which *is* committed.

### Note on serving both fine-tuned models

Both role adapters are trained. Serving the *defender* (`qwen-blue-ft`) and running the
4th-method evaluation is complete. Serving the *attacker* adapter the same way needs a
merged q4_k_m GGUF too, because current Ollama removed runtime LoRA-adapter support; a
14B merge needs ~55 GB of transient disk, and the test box (96 GB) cannot hold two merged
14B models plus the base at once. The Red adapter is therefore kept as the trained PEFT
adapter (+ a 132 MB LoRA GGUF). On a larger disk it exports and serves identically to
Blue, enabling a both-fine-tuned (`ft_both`) run; it does not affect the defensive-LLM
result above, which isolates the fine-tuned defender against a fixed base-model attacker.
