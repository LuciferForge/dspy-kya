# dspy-kya

KYA (Know Your Agent) identity verification for DSPy modules.

## Install

```bash
pip install dspy-kya
```

## Quick Start

```python
from dspy_kya import KYAModule

module = KYAModule(
    name="my-module",
    version="1.0.0",
    capabilities=["classification", "generation"]
)

card = module.identity_card()
print(card)
```

## What is KYA?

Know Your Agent (KYA) is an identity standard for AI agents. It provides unique agent identity with Ed25519 signing, framework-native integration, and verifiable credentials.

See [kya-agent](https://github.com/LuciferForge/KYA) for the core library.

## Related

- [kya-agent](https://github.com/LuciferForge/KYA) — Core library
- [crewai-kya](https://github.com/LuciferForge/crewai-kya) — CrewAI
- [autogen-kya](https://github.com/LuciferForge/autogen-kya) — AutoGen
- [langchain-kya](https://github.com/LuciferForge/langchain-kya) — LangChain
- [llamaindex-kya](https://github.com/LuciferForge/llamaindex-kya) — LlamaIndex
- [smolagents-kya](https://github.com/LuciferForge/smolagents-kya) — smolagents

## License

MIT
