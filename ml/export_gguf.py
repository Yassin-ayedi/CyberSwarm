"""Export a trained LoRA adapter to a q4_k_m GGUF Ollama can serve.

    python export_gguf.py --adapter out_blue/adapter --out out_blue/gguf

Loads the 4-bit base + the saved adapter, then writes a single q4_k_m GGUF.
Disk-lean: only q4_k_m is requested; intermediates are unsloth-managed. Run only
after freeing enough disk (the 14B merge needs ~57 GB transient).
"""
import argparse, os
from unsloth import FastLanguageModel

ap = argparse.ArgumentParser()
ap.add_argument("--adapter", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--maxseq", type=int, default=1024)
args = ap.parse_args()

# from_pretrained on a saved adapter dir reloads the base (read from adapter_config)
# and re-attaches the LoRA weights, so the export reflects the fine-tune.
model, tok = FastLanguageModel.from_pretrained(
    model_name=args.adapter, max_seq_length=args.maxseq, load_in_4bit=True, dtype=None)

os.makedirs(args.out, exist_ok=True)
model.save_pretrained_gguf(args.out, tok, quantization_method="q4_k_m")
print(f"GGUF_OK -> {args.out}")
