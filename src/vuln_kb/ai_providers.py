"""Server-side adapters for OpenAI Chat Completions compatible providers."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx


@dataclass(frozen=True)
class ProviderFailure(Exception):
    category: str
    message: str
    retryable: bool = False

    def __str__(self) -> str:
        return self.message


def endpoint_for(base_url: str) -> str:
    parsed = urlparse((base_url or "").strip())
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ProviderFailure("invalid_url", "模型 URL 必须是无凭据、无查询参数的 HTTP(S) 地址")
    base = base_url.rstrip("/")
    return base if base.endswith("/chat/completions") else f"{base}/chat/completions"


def validate_provider_host(base_url: str, allowed_hosts: tuple[str, ...] | list[str]) -> str:
    endpoint_for(base_url)
    host = (urlparse(base_url.strip()).hostname or "").lower().rstrip(".")
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if host not in local_hosts and host not in {value.lower().rstrip(".") for value in allowed_hosts}:
        raise ProviderFailure("host_not_allowed", "模型主机不在 AI_ALLOWED_HOSTS 白名单中")
    return host


def _response_failure(response: httpx.Response) -> ProviderFailure:
    status = response.status_code
    text = response.text[:1000].lower()
    if status in {401, 403}:
        return ProviderFailure("authentication_failed", "Provider 拒绝鉴权，请检查 API Key 或账号权限")
    if status == 404 and any(term in text for term in ("model", "deployment")):
        return ProviderFailure("model_not_found", "Provider 未找到配置的模型或 API 路径")
    if status == 404:
        return ProviderFailure("endpoint_not_found", "Provider 未找到 Chat Completions API 路径")
    if status == 429:
        return ProviderFailure("rate_limited", "Provider 限流，请稍后重试", retryable=True)
    if status in {408, 504} or status >= 500:
        return ProviderFailure("provider_unavailable", f"Provider 暂不可用（HTTP {status}）", retryable=True)
    if status in {400, 422} and any(term in text for term in ("response_format", "json_object", "json mode")):
        return ProviderFailure("json_mode_unsupported", "模型服务不支持 JSON Object 输出模式")
    if status >= 400:
        return ProviderFailure("request_rejected", f"Provider 拒绝请求（HTTP {status}）")
    return ProviderFailure("provider_error", f"Provider 返回异常状态（HTTP {status}）", retryable=status >= 500)


class OpenAICompatibleProvider:
    def __init__(self, base_url: str, model: str, api_key: str, *, timeout: float = 30,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.endpoint = endpoint_for(base_url)
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.transport = transport

    async def complete_json(self, messages: list[dict[str, str]], *, max_tokens: int = 2048) -> tuple[dict[str, Any], dict[str, int]]:
        if not self.model or not self.api_key:
            raise ProviderFailure("configuration_incomplete", "模型名称或 API Key 未配置")
        payload = {"model": self.model, "temperature": 0,
                   "response_format": {"type": "json_object"}, "max_tokens": max_tokens,
                   "messages": messages}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False,
                                         transport=self.transport) as client:
                response = await client.post(self.endpoint,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderFailure("timeout", "连接模型服务超时", retryable=True) from exc
        except httpx.RequestError as exc:
            raise ProviderFailure("connection_error", f"无法连接模型服务（{type(exc).__name__}）", retryable=True) from exc
        if response.status_code >= 400:
            raise _response_failure(response)
        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            parsed = json.loads(content)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderFailure("json_mode_unsupported", "模型响应不是有效的 JSON Object") from exc
        if not isinstance(parsed, dict):
            raise ProviderFailure("json_mode_unsupported", "模型响应不是 JSON Object")
        usage = body.get("usage") or {}
        tokens = {"input": int(usage.get("prompt_tokens", 0) or 0),
                  "output": int(usage.get("completion_tokens", 0) or 0)}
        return parsed, tokens

    async def probe(self) -> dict[str, Any]:
        _, tokens = await self.complete_json([
            {"role": "system", "content": "Return one JSON object only."},
            {"role": "user", "content": "Return exactly {\"capability_test\": true}."},
        ], max_tokens=64)
        return {"model": self.model, "response_format": "json_object", "usage": tokens}
