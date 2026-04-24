"""Native AI provider adapters for Sheshnaag V4."""

from app.services.ai_adapters.base import (
    NativeAIAdapter,
    collect_stream,
    format_grounding_system_prompt,
)
from app.services.ai_adapters.anthropic_adapter import AnthropicAdapter
from app.services.ai_adapters.openai_adapter import OpenAIAdapter
from app.services.ai_adapters.gemini_adapter import GeminiAdapter
from app.services.ai_adapters.azure_openai_adapter import AzureOpenAIAdapter
from app.services.ai_adapters.bedrock_adapter import BedrockAdapter
from app.services.ai_adapters.local_adapter import LocalOpenAICompatAdapter


__all__ = [
    "NativeAIAdapter",
    "collect_stream",
    "format_grounding_system_prompt",
    "AnthropicAdapter",
    "OpenAIAdapter",
    "GeminiAdapter",
    "AzureOpenAIAdapter",
    "BedrockAdapter",
    "LocalOpenAICompatAdapter",
]
