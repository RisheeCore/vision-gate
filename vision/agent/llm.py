import json
import os
from typing import Any, Iterator, Optional
import requests
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from vision.contracts import EventType
from vision.events import emit

DEFAULT_MODEL = os.environ.get("VENICE_MODEL", "qwen-3-8-27b")


class ScriptedLLM(BaseChatModel):
    responses: list[str]
    idx: int = 0
    calls: list[list[Any]] = []

    @property
    def _llm_type(self) -> str:
        return "scripted_llm"

    def _next_text(self, messages: list[BaseMessage]) -> str:
        self.calls.append(messages)
        if not self.responses:
            return ""
        text = self.responses[min(self.idx, len(self.responses) - 1)]
        self.idx += 1
        return text

    def _generate(self, messages: list[BaseMessage], stop: Optional[list[str]] = None, run_manager: Any = None, **kwargs: Any) -> ChatResult:
        text = self._next_text(messages)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])

    def _stream(self, messages: list[BaseMessage], stop: Optional[list[str]] = None, run_manager: Any = None, **kwargs: Any) -> Iterator[ChatGenerationChunk]:
        text = self._next_text(messages)
        yield ChatGenerationChunk(message=AIMessageChunk(content=text))


class VeniceChatModel(BaseChatModel):
    api_key: str
    model: str = DEFAULT_MODEL
    base_url: str = "https://api.venice.ai/api/v1"
    temperature: float = 0.2

    @property
    def _llm_type(self) -> str:
        return "venice_chat"

    def _format_messages(self, messages: list[BaseMessage]) -> list[dict[str, str]]:
        out = []
        for m in messages:
            role = "user"
            mtype = getattr(m, "type", "human")
            if mtype == "system":
                role = "system"
            elif mtype in ("ai", "assistant"):
                role = "assistant"
            out.append({"role": role, "content": str(m.content)})
        return out

    def _stream(self, messages: list[BaseMessage], stop: Optional[list[str]] = None, run_manager: Any = None, **kwargs: Any) -> Iterator[ChatGenerationChunk]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": self._format_messages(messages),
            "temperature": self.temperature,
            "stream": True,
            "venice_parameters": {"include_venice_system_prompt": False},
        }
        with requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload, stream=True, timeout=90) as resp:
            if resp.status_code >= 400:
                raise RuntimeError(f"Venice API {resp.status_code}: {resp.text[:300]}")
            for raw in resp.iter_lines(decode_unicode=True):
                if not raw or not raw.startswith("data: "):
                    continue
                data = raw[6:].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                    delta = obj["choices"][0].get("delta", {}).get("content", "")
                    if delta:
                        yield ChatGenerationChunk(message=AIMessageChunk(content=delta))
                except Exception:
                    continue

    def _generate(self, messages: list[BaseMessage], stop: Optional[list[str]] = None, run_manager: Any = None, **kwargs: Any) -> ChatResult:
        text = "".join(c.message.content for c in self._stream(messages, stop=stop))
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])


def get_llm(role: str = "coder", config: Optional[dict] = None) -> BaseChatModel:
    cfg = config or {}
    if "llm_override" in cfg and cfg["llm_override"] is not None:
        override = cfg["llm_override"]
        if isinstance(override, dict):
            return override.get(role) or override["coder"]
        return override

    venice_key = (cfg.get("api_key") or os.environ.get("VENICE_API_KEY") or "").strip()
    temp = 0.2 if role == "coder" else 0.3
    if venice_key and venice_key != "PASTE_YOUR_KEY_HERE":
        model = cfg.get("model") or os.environ.get("VENICE_MODEL", DEFAULT_MODEL)
        return VeniceChatModel(api_key=venice_key, model=model, temperature=temp)

    from langchain_ollama import ChatOllama
    model = cfg.get("model") or os.environ.get("GC_LOCAL_MODEL", "qwen2.5-coder:1.5b")
    base_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    return ChatOllama(model=model, base_url=base_url, temperature=temp)


def stream_and_collect(run_id: str, role: str, llm: BaseChatModel, messages: list[tuple[str, str]]) -> str:
    emit(run_id, EventType.LLM_REQUEST, role=role)
    chunks: list[str] = []
    for chunk in llm.stream(messages):
        token = chunk.content if isinstance(chunk.content, str) else str(chunk.content)
        if token:
            chunks.append(token)
            emit(run_id, EventType.LLM_TOKEN, role=role, token=token)
    full = "".join(chunks)
    emit(run_id, EventType.LLM_RESPONSE, role=role, length=len(full))
    return full


def list_models(api_key: str, base_url: str = "https://api.venice.ai/api/v1") -> list[str]:
    r = requests.get(f"{base_url}/models",
                     headers={"Authorization": f"Bearer {api_key}"}, timeout=10)
    r.raise_for_status()
    return sorted(m["id"] for m in r.json().get("data", []) if isinstance(m, dict) and "id" in m)


def validate_model(api_key: str, model: str) -> None:
    try:
        ids = list_models(api_key)
    except Exception:
        return
    if ids and model not in ids:
        near = [i for i in ids if i.split("-")[0] in model][:4]
        raise RuntimeError(f"model '{model}' not available. Try: {near or ids[:4]}")
