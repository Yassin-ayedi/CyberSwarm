#!/bin/bash
# Current Ollama refuses LoRA adapters ("LoRA adapters are no longer supported"), so merge the
# adapter INTO the base GGUF Ollama already has, re-quantize to the same Q4_K_M as the base, and
# create an Ollama model with the base model's exact template (tool calling keeps working).
#   bash merge_serve_adapter.sh out_blue qwen-blue-ft
set -e
OUT="$1"; NAME="$2"; LC=~/llama.cpp
if [ ! -x $LC/build/bin/llama-export-lora ]; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential cmake >/dev/null
  cmake -S $LC -B $LC/build -DGGML_CUDA=OFF -DLLAMA_CURL=OFF >/dev/null
  cmake --build $LC/build --target llama-export-lora llama-quantize -j "$(nproc)" >/dev/null
fi
[ -f "$OUT/lora.gguf" ] || ~/ftenv/bin/python $LC/convert_lora_to_gguf.py "$OUT/adapter" \
    --base-model-id Qwen/Qwen2.5-14B-Instruct --outtype f16 --outfile "$OUT/lora.gguf"
BASE=$(ollama show qwen2.5:14b --modelfile | awk '/^FROM /{print $2; exit}')
echo "base GGUF: $BASE"
$LC/build/bin/llama-export-lora -m "$BASE" --lora "$OUT/lora.gguf" -o "$OUT/merged.gguf" -t "$(nproc)" 2>&1 | tail -2
$LC/build/bin/llama-quantize --allow-requantize "$OUT/merged.gguf" "$OUT/merged-q4km.gguf" Q4_K_M "$(nproc)" 2>&1 | tail -2
rm -f "$OUT/merged.gguf"
ollama show qwen2.5:14b --modelfile | sed "s#^FROM .*#FROM $(realpath "$OUT/merged-q4km.gguf")#" > "$OUT/Modelfile"
ollama create "$NAME" -f "$OUT/Modelfile" 2>&1 | tail -1
ollama list | grep -E "^($NAME|qwen2.5)"
