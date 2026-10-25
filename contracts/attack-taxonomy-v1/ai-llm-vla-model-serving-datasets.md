# AI/LLM Systems, VLA Model Serving (GGUF/ONNX/Pickle) & Commercial Datasets (`ai-llm-vla-model-serving-datasets`)

> **Group:** III. Enterprise, Data Lake & AI Systems
> **Product Archetypes:** AI_Model_Serving_Engine, Data_AI_Pipeline
> **Trigger Signals:** llm, vla, vlm, gguf, ggml, onnx, torch, pickle, safetensors, huggingface, prompt, mcp, dataset, asr, nlu, voice

## [ BLOCK: model-file-deserialization-and-binary-parsers ]
### Unsafe Model Loading (Pickle/Torch) & GGUF/ONNX Binary Parser Memory Safety
- Hunt for `torch.load(..., weights_only=False)`, `pickle.loads`, `joblib.load`, or `trust_remote_code=True` on external checkpoints.
- In C/C++ model loaders (`GGUF`, `ONNX`, tokenizer parsers like `vla.cpp`), check tensor dimension multiplication (`ne[0] * ne[1] * ...`), string length fields, and header offsets for integer overflow before memory allocation (`malloc`/`new`) leading to heap OOB read/write.

## [ BLOCK: ai-to-actuation-and-prompt-tool-boundaries ]
### Prompt/ASR-to-Physical Actuation & Tool/MCP Output Injection
- When ASR/NLU/LLM or VLA models connect to physical robot/vehicle controls or enterprise tools, verify whether a deterministic bounds/safety filter sits between model output and execution.
- Enforce instruction-data separation: treat all external documents, diagrams, and tool outputs as untrusted data, never executable instructions.
