"""
QLoRA fine-tune of Qwen2.5-14B-Instruct on an arena dataset (runs on the GPU VM).

Fixes over the first pipeline (ml/train_qlora.py, problem P9 in the guide):
  - max_seq_length 4096 (examples are 1.5-3k tokens; nothing is cut off)
  - loss on the ASSISTANT turns only (train_on_responses_only), not on prompts / tool output
  - the tool schemas are rendered into the prompt exactly as at inference (chat template + tools)

    python train_arena_lora.py --data blue.jsonl --out out_blue --epochs 3
Then convert the adapter to GGUF and attach it to the Ollama base model (see serve step).
"""
import argparse
import json

from unsloth import FastLanguageModel
from unsloth.chat_templates import train_on_responses_only
from datasets import Dataset
from trl import SFTTrainer, SFTConfig


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--epochs", type=float, default=3)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--max_seq", type=int, default=4096)
    ap.add_argument("--base", default="unsloth/Qwen2.5-14B-Instruct-bnb-4bit")
    a = ap.parse_args()

    model, tok = FastLanguageModel.from_pretrained(a.base, max_seq_length=a.max_seq, load_in_4bit=True)
    model = FastLanguageModel.get_peft_model(
        model, r=16, lora_alpha=16, lora_dropout=0, bias="none",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth", random_state=42)

    rows = [json.loads(l) for l in open(a.data, encoding="utf-8")]
    texts, lens = [], []
    for r in rows:
        t = tok.apply_chat_template(r["messages"], tools=r["tools"], tokenize=False)
        texts.append(t)
        lens.append(len(tok(t).input_ids))
    print(f"{len(texts)} examples, tokens: min {min(lens)} / mean {sum(lens)//len(lens)} / max {max(lens)} "
          f"(max_seq {a.max_seq}; {sum(l > a.max_seq for l in lens)} would be truncated)", flush=True)
    ds = Dataset.from_dict({"text": texts})

    trainer = SFTTrainer(
        model=model, tokenizer=tok, train_dataset=ds,
        args=SFTConfig(dataset_text_field="text", max_seq_length=a.max_seq, per_device_train_batch_size=2,
                       gradient_accumulation_steps=4, num_train_epochs=a.epochs, learning_rate=a.lr,
                       warmup_ratio=0.05, lr_scheduler_type="cosine", logging_steps=2, optim="adamw_8bit",
                       weight_decay=0.01, seed=42, output_dir=a.out + "/ckpt", report_to="none",
                       save_strategy="no", bf16=True))
    # learn only the assistant turns (tool calls + reasoning), not the prompt or tool results
    trainer = train_on_responses_only(trainer, instruction_part="<|im_start|>user\n",
                                      response_part="<|im_start|>assistant\n")
    stats = trainer.train()
    model.save_pretrained(a.out + "/adapter")
    tok.save_pretrained(a.out + "/adapter")
    log = [h for h in trainer.state.log_history if "loss" in h]
    json.dump({"examples": len(texts), "epochs": a.epochs, "train_loss": stats.training_loss,
               "first_loss": log[0]["loss"] if log else None, "last_loss": log[-1]["loss"] if log else None,
               "log": log}, open(a.out + "/train_stats.json", "w"), indent=1)
    print(f"done: loss {log[0]['loss'] if log else '?'} -> {log[-1]['loss'] if log else '?'}; adapter in {a.out}/adapter",
          flush=True)


if __name__ == "__main__":
    main()
