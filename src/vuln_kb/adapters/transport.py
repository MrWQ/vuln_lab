from __future__ import annotations

from collections.abc import AsyncIterator

import httpx


async def stream_http_bytes(url: str, *, headers: dict[str, str] | None = None,
                           max_bytes: int, timeout: float = 45) -> AsyncIterator[bytes]:
    """Yield a bounded HTTPS response without retaining the complete body in memory."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        async with client.stream("GET", url, headers=headers or {}) as response:
            response.raise_for_status()
            content_length = response.headers.get("content-length")
            if content_length and content_length.isdigit() and int(content_length) > max_bytes:
                raise ValueError(f"source material exceeds the {max_bytes}-byte limit")
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"source material exceeds the {max_bytes}-byte limit")
                if chunk:
                    yield chunk
