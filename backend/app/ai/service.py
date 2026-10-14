"""Provider selection with honest fallback."""
from __future__ import annotations

from typing import Any

from app.ai.base import AnalysisResult, LLMOutputError, LLMUnavailable
from app.ai.fallback import DeterministicProvider
from app.ai.ollama import OllamaConfig, OllamaProvider


def analyze_incident(context: dict[str, Any], provider: str, ollama_cfg: OllamaConfig, default_provider: str = "fallback",
                     ollama_provider: OllamaProvider | None = None) -> AnalysisResult:
    """provider: 'auto' (use the configured default), 'fallback', or 'ollama'.

    If the local model fails, the deterministic result is returned and labelled as such, with the reason in
    `fallback_reason`. Output from a model is never fabricated or silently substituted.
    """
    chosen = default_provider if provider == "auto" else provider
    fallback = DeterministicProvider()
    if chosen != "ollama":
        return fallback.analyze(context)
    prov = ollama_provider or OllamaProvider(ollama_cfg)
    try:
        return prov.analyze(context)
    except (LLMUnavailable, LLMOutputError) as exc:
        res = fallback.analyze(context)
        res.fallback_reason = f"Local model analysis failed ({type(exc).__name__}): {exc}"
        res.warnings.insert(0, "The local model was requested but unavailable or invalid; this report uses the deterministic fallback.")
        return res
    except Exception as exc:  # noqa: BLE001
        res = fallback.analyze(context)
        res.fallback_reason = f"Unexpected local model failure ({type(exc).__name__})."
        res.warnings.insert(0, "The local model failed unexpectedly; this report uses the deterministic fallback.")
        return res
