"""LLM client interface, mock fake, and LiteLLM provider implementation."""

from collections.abc import Sequence
from typing import Any, Protocol

from phishguard.core.config import Settings, get_settings
from phishguard.core.errors import LLMError


class LLMClient(Protocol):
    """Protocol for asynchronous LLM completions."""

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Generate a completion for the provided prompt."""
        ...


class FakeLLMClient:
    """In-memory fake LLM client for deterministic testing and adversarial verification."""

    def __init__(
        self,
        canned_response: str | Sequence[str] = "{}",
        raise_error: Exception | None = None,
    ) -> None:
        """Initialize FakeLLMClient.

        Args:
            canned_response: Single response string or sequence of responses to yield in order.
            raise_error: Optional exception to raise instead of completing.
        """
        if isinstance(canned_response, str):
            self._repeat_single = True
            self._single_response = canned_response
            self._responses: list[str] = [canned_response]
        else:
            self._repeat_single = False
            self._single_response = "{}"
            self._responses = list(canned_response)
        self._raise_error = raise_error
        self.calls: list[dict[str, str | None]] = []

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Record the call and return the configured canned response or raise configured error."""
        self.calls.append({"prompt": prompt, "system_prompt": system_prompt})
        if self._raise_error is not None:
            raise self._raise_error

        if self._repeat_single:
            return self._single_response

        if not self._responses:
            return "{}"
        return self._responses.pop(0)


class LiteLLMClient:
    """LiteLLM-backed LLM completion client."""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        timeout: float = 15.0,
        settings: Settings | None = None,
    ) -> None:
        """Initialize LiteLLMClient.

        Args:
            model: LiteLLM model string (e.g. 'gemini/gemini-1.5-flash'). Defaults to config.
            api_key: Optional provider API key.
            timeout: Request timeout in seconds.
            settings: Optional Settings instance.
        """
        cfg = settings or get_settings()
        self.model = model or cfg.LLM_MODEL
        self.api_key = api_key or (
            cfg.GEMINI_API_KEY.get_secret_value() if cfg.GEMINI_API_KEY else None
        )
        self.timeout = timeout

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Generate completion using litellm.acompletion with strict temperature and timeout."""
        try:
            import litellm
        except ImportError as exc:
            raise LLMError("litellm is not installed. Install with `uv sync --extra llm`.") from exc

        messages: list[dict[str, Any]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 1000,
            "timeout": self.timeout,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key

        try:
            response = await litellm.acompletion(**kwargs)
            choice = response.choices[0]
            content = choice.message.content
            return str(content or "")
        except Exception as exc:
            raise LLMError(f"LiteLLM completion failed: {exc.__class__.__name__}") from exc
