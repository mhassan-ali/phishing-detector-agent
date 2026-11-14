"""Unit tests for LLM client abstractions: FakeLLMClient and LiteLLMClient."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from phishguard.core.errors import LLMError
from phishguard.core.llm import FakeLLMClient, LiteLLMClient


@pytest.mark.asyncio
async def test_fake_llm_client_single_and_sequence() -> None:
    """Verify FakeLLMClient returns canned responses and records calls."""
    client = FakeLLMClient(canned_response=["resp1", "resp2"])
    r1 = await client.complete("prompt1", "sys1")
    assert r1 == "resp1"
    assert len(client.calls) == 1
    assert client.calls[0]["prompt"] == "prompt1"
    assert client.calls[0]["system_prompt"] == "sys1"

    r2 = await client.complete("prompt2")
    assert r2 == "resp2"

    # Default fallback when exhausted
    r3 = await client.complete("prompt3")
    assert r3 == "{}"


@pytest.mark.asyncio
async def test_fake_llm_client_raises_error() -> None:
    """Verify FakeLLMClient raises configured exception."""
    client = FakeLLMClient(raise_error=RuntimeError("LLM downstream failure"))
    with pytest.raises(RuntimeError, match="LLM downstream failure"):
        await client.complete("test")


@pytest.mark.asyncio
async def test_litellm_client_success() -> None:
    """Verify LiteLLMClient prepares messages and executes completion."""
    mock_choice = MagicMock()
    mock_choice.message.content = '{"urgency": {"score": 0.9}}'
    mock_response = MagicMock(choices=[mock_choice])

    mock_litellm = MagicMock()
    mock_litellm.acompletion = AsyncMock(return_value=mock_response)

    with patch.dict("sys.modules", {"litellm": mock_litellm}):
        client = LiteLLMClient(model="gemini/gemini-flash", api_key="test-key")
        res = await client.complete("analyze this", system_prompt="be helpful")
        assert res == '{"urgency": {"score": 0.9}}'
        assert mock_litellm.acompletion.call_count == 1
        _, kwargs = mock_litellm.acompletion.call_args
        assert kwargs["model"] == "gemini/gemini-flash"
        assert kwargs["temperature"] == 0.0
        assert kwargs["messages"] == [
            {"role": "system", "content": "be helpful"},
            {"role": "user", "content": "analyze this"},
        ]


@pytest.mark.asyncio
async def test_litellm_client_missing_import() -> None:
    """Verify missing litellm package raises friendly LLMError."""
    with patch.dict("sys.modules", {"litellm": None}):
        client = LiteLLMClient(model="gemini/gemini-flash")
        with pytest.raises(LLMError, match="litellm is not installed"):
            await client.complete("test")


@pytest.mark.asyncio
async def test_litellm_client_error_wrapped() -> None:
    """Verify LiteLLM errors are caught and re-raised as LLMError."""
    mock_litellm = MagicMock()
    mock_litellm.acompletion = AsyncMock(side_effect=TimeoutError("Request timed out"))

    with patch.dict("sys.modules", {"litellm": mock_litellm}):
        client = LiteLLMClient(model="gemini/gemini-flash")
        with pytest.raises(LLMError, match="LiteLLM completion failed: TimeoutError"):
            await client.complete("test")
