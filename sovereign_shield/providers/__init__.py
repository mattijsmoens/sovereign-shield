from sovereign_shield.providers.base import LLMProvider

# Lazy imports — providers require optional dependencies.
# Only import when explicitly accessed to avoid ImportError.

def __getattr__(name):
    if name == "GeminiProvider":
        from sovereign_shield.providers.gemini import GeminiProvider
        return GeminiProvider
    elif name == "OpenAIProvider":
        from sovereign_shield.providers.openai_provider import OpenAIProvider
        return OpenAIProvider
    elif name == "OllamaProvider":
        from sovereign_shield.providers.ollama import OllamaProvider
        return OllamaProvider
    raise AttributeError(f"module 'sovereign_shield.providers' has no attribute {name!r}")

__all__ = ["LLMProvider", "GeminiProvider", "OpenAIProvider", "OllamaProvider"]
