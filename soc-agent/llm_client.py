"""
LLM client abstraction — switches between local Ollama and cloud providers
based on LLM_MODE env var.

LLM_MODE=local  → uses Ollama (default)
LLM_MODE=cloud  → uses CLOUD_PROVIDER (openai or anthropic)
"""
import os
import json
import httpx

LLM_MODE = os.getenv("LLM_MODE", "local")
CLOUD_PROVIDER = os.getenv("CLOUD_PROVIDER", "openai")
CLOUD_MODEL = os.getenv("CLOUD_MODEL", "gpt-4o")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")


async def chat(model: str, messages: list) -> dict:
    """
    Unified chat interface. Returns dict with same shape as Ollama response:
    {"message": {"content": "..."}}
    """
    if LLM_MODE == "cloud":
        if CLOUD_PROVIDER == "anthropic":
            return await _anthropic_chat(messages)
        else:
            return await _openai_chat(messages)
    else:
        return await _ollama_chat(model, messages)


async def _ollama_chat(model: str, messages: list) -> dict:
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "think": False,
    }
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(f"{OLLAMA_HOST}/api/chat", json=payload)
        response.raise_for_status()
        return response.json()


async def _openai_chat(messages: list) -> dict:
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY is not set")

    payload = {
        "model": CLOUD_MODEL,
        "messages": messages,
        "temperature": 0.1,
    }
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        return {"message": {"content": content}}


async def _anthropic_chat(messages: list) -> dict:
    if not ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    # Anthropic separates system message from the messages list
    system_content = ""
    filtered_messages = []
    for m in messages:
        if m["role"] == "system":
            system_content = m["content"]
        else:
            filtered_messages.append(m)

    payload = {
        "model": CLOUD_MODEL,
        "max_tokens": 4096,
        "messages": filtered_messages,
        "temperature": 0.1,
    }
    if system_content:
        payload["system"] = system_content

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
        data = response.json()
        content = data["content"][0]["text"]
        return {"message": {"content": content}}


def get_reasoner_model() -> str:
    if LLM_MODE == "cloud":
        return CLOUD_MODEL
    return os.getenv("REASONER_MODEL", "qwen3:14b")


def get_router_model() -> str:
    if LLM_MODE == "cloud":
        return CLOUD_MODEL
    return os.getenv("ROUTER_MODEL", "qwen3:1.7b")


def is_cloud_mode() -> bool:
    return LLM_MODE == "cloud"