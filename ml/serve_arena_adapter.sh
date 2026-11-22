#!/bin/bash
# Serve a trained LoRA adapter through Ollama, on top of the base model already there.
#   bash serve_arena_adapter.sh out_blue qwen-blue-ft
# 1. convert the PEFT adapter to a GGUF LoRA (small file; only the base CONFIG is fetched)
# 2. Modelfile: FROM qwen2.5:14b + ADAPTER lora.gguf  ->  ollama create <name>
set -e
OUT="$1"; NAME="$2"
~/ftenv/bin/python ~/llama.cpp/convert_lora_to_gguf.py "$OUT/adapter" \
    --base-model-id Qwen/Qwen2.5-14B-Instruct --outtype f16 --outfile "$OUT/lora.gguf"
ls -la "$OUT/lora.gguf"
printf 'FROM qwen2.5:14b\nADAPTER %s\n' "$(realpath "$OUT/lora.gguf")" > "$OUT/Modelfile"
ollama create "$NAME" -f "$OUT/Modelfile"
ollama list | grep -E "^($NAME|qwen2.5)"
