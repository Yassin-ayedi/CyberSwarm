"""QLoRA fine-tune (Block 4), runs on the GPU VM. Behavioural cloning of successful agent
trajectories into a role-specialised adapter, then export a GGUF Ollama can serve.

    python train_qlora.py --agent blue --data dataset.jsonl --out out_blue --epochs 2

Honours the locked decision: try 14B first, auto-fall back to 7B on CUDA OOM.
"""
import argparse, json, os, gc
import torch
from unsloth import FastLanguageModel
from datasets import Dataset
from trl import SFTTrainer, SFTConfig

M14 = "unsloth/Qwen2.5-14B-Instruct-bnb-4bit"
M7 = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"


def load_examples(path, agent, tok):
    """Render each successful <agent> conversation to a single training string."""
    texts = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("agent") != agent:
            continue
        try:
            text = tok.apply_chat_template(rec["messages"], tools=rec.get("tools"),
                                           tokenize=False, add_generation_prompt=False)
        except Exception:
            try:  # some saved tool-call dicts may not satisfy the tools template; retry plain
                text = tok.apply_chat_template(rec["messages"], tokenize=False,
                                               add_generation_prompt=False)
            except Exception:
                continue
        if text and len(text) > 50:
            texts.append({"text": text})
    return texts


def train(model_name, agent, data, out, epochs, maxseq):
    model, tok = FastLanguageModel.from_pretrained(
        model_name=model_name, max_seq_length=maxseq, load_in_4bit=True, dtype=None)
    model = FastLanguageModel.get_peft_model(
        model, r=16, lora_alpha=16,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth", random_state=42)

    rows = load_examples(data, agent, tok)
    if not rows:
        raise SystemExit(f"no training examples for agent={agent} in {data}")
    print(f"[train] {agent}: {len(rows)} examples on {model_name}", flush=True)
    ds = Dataset.from_list(rows)

    trainer = SFTTrainer(model=model, tokenizer=tok, train_dataset=ds, args=SFTConfig(
        per_device_train_batch_size=1, gradient_accumulation_steps=8,
        num_train_epochs=epochs, warmup_ratio=0.05, learning_rate=2e-4,
        logging_steps=5, dataset_text_field="text", max_seq_length=maxseq,
        output_dir=os.path.join(out, "ckpt"), report_to="none", optim="adamw_8bit",
        save_strategy="no"))
    trainer.train()
    peak = torch.cuda.max_memory_reserved() / 1e9
    print(f"[train] done, peak VRAM {peak:.2f} GB", flush=True)

    adapter_dir = os.path.join(out, "adapter")
    model.save_pretrained(adapter_dir); tok.save_pretrained(adapter_dir)
    print(f"[train] saved adapter -> {adapter_dir}", flush=True)

    # Export a GGUF Ollama can serve (merged + q4_k_m). Best-effort: the adapter above is
    # the guaranteed artifact; GGUF needs llama.cpp which unsloth builds on first use.
    try:
        model.save_pretrained_gguf(os.path.join(out, "gguf"), tok, quantization_method="q4_k_m")
        print(f"[train] saved GGUF -> {os.path.join(out, 'gguf')}", flush=True)
    except Exception as e:
        print(f"[train] GGUF export failed (adapter still saved): {e}", flush=True)
    return model_name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True, choices=["red", "blue"])
    ap.add_argument("--data", default="dataset.jsonl")
    ap.add_argument("--out", default=None)
    ap.add_argument("--epochs", type=float, default=2)
    args = ap.parse_args()
    out = args.out or f"out_{args.agent}"
    os.makedirs(out, exist_ok=True)
    try:
        used = train(M14, args.agent, args.data, out, args.epochs, maxseq=1024)
    except torch.cuda.OutOfMemoryError:
        print("[train] 14B OOM -> falling back to 7B", flush=True)
        gc.collect(); torch.cuda.empty_cache()
        used = train(M7, args.agent, args.data, out, args.epochs, maxseq=2048)
    with open(os.path.join(out, "base_model.txt"), "w") as f:
        f.write(used + "\n")
    print(f"BASE_MODEL_USED {used}")
    print("TRAIN_OK")


if __name__ == "__main__":
    main()
