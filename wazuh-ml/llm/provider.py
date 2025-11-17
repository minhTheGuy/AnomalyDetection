"""
DeepSeek-R1 provider helper (single implementation).
"""
from __future__ import annotations

import json
from typing import Optional

import requests

from core.config import DEEPSEEK_API_BASE, DEEPSEEK_API_KEY, LLM_MAX_TOKENS, LLM_MODEL

DEFAULT_SYSTEM_PROMPT = "You are a helpful SOC analyst."


def call_llm(
    prompt: str,
    *,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
) -> str:
    if not DEEPSEEK_API_KEY:
        return "[LLM ERROR: Missing DEEPSEEK_API_KEY]"

    payload = {
        "model": LLM_MODEL or "deepseek-reasoner",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens or LLM_MAX_TOKENS,
    }
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            f"{DEEPSEEK_API_BASE.rstrip('/')}/chat/completions",
            headers=headers,
            data=json.dumps(payload),
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as exc:  # pragma: no cover
        return f"[LLM ERROR: {exc}]\n\nPROMPT (truncated):\n{prompt[:1500]}"
