"""读 HTTP 首部、搬运 body。hop-by-hop 头不转给上游。"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

MAX_HEADER_BYTES = 64 * 1024
CHUNK_SIZE = 64 * 1024

HOP_BY_HOP = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
}


def wants_keep_alive(version: str, headers: Headers) -> bool:
    """HTTP/1.1 默认 keep-alive，HTTP/1.0 默认 close。"""
    conn = (headers.get("connection") or "").lower()
    if "close" in conn:
        return False
    if "keep-alive" in conn:
        return True
    return version.upper().startswith("HTTP/1.1")


class Headers:
    """大小写不敏感，保序。"""

    def __init__(self, items=None):
        self._items: list[tuple[str, str]] = list(items or [])

    def get(self, name: str, default=None):
        target = name.lower()
        for key, value in self._items:
            if key.lower() == target:
                return value
        return default

    def remove(self, name: str) -> None:
        target = name.lower()
        self._items = [(k, v) for k, v in self._items if k.lower() != target]

    def set(self, name: str, value: str) -> None:
        """覆盖同名项。"""
        self.remove(name)
        self._items.append((name, value))

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def to_bytes(self) -> bytes:
        """每行 `Name: value\\r\\n`，不含结尾空行。"""
        return b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in self._items)


@dataclass
class RequestHead:
    method: str
    target: str
    version: str
    headers: Headers
    raw_line: str = ""


async def read_message_head(reader) -> tuple[str, Headers] | None:
    """读到空行结束的首部；EOF/超时返回 None。请求和响应都能用。"""
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=60)
    except (
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
        asyncio.TimeoutError,
        ConnectionError,
    ):
        return None

    text = raw.decode("latin-1")
    lines = text[:-4].split("\r\n")
    if not lines:
        return None

    start_line = lines[0]
    items: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t" and items:  # obs-fold
            key, value = items[-1]
            items[-1] = (key, value + " " + line.strip())
            continue
        name, _, value = line.partition(":")
        items.append((name.strip(), value.strip()))
    return start_line, Headers(items)


async def read_request_head(reader) -> RequestHead | None:
    """解析请求行 + 首部。"""
    result = await read_message_head(reader)
    if result is None:
        return None
    start_line, headers = result
    parts = start_line.split(" ")
    if len(parts) < 3:
        return None
    return RequestHead(
        method=parts[0],
        target=parts[1],
        version=parts[2],
        headers=headers,
        raw_line=start_line,
    )


async def relay_body(
    reader, writer, headers: Headers, *, until_eof: bool = False, on_bytes=None
) -> None:
    """按 Transfer-Encoding / Content-Length 搬 body；until_eof 用于无长度的响应。"""
    encoding = (headers.get("transfer-encoding") or "").lower()
    if "chunked" in encoding:
        await _relay_chunked(reader, writer, on_bytes=on_bytes)
        return

    length = headers.get("content-length")
    if length is not None:
        try:
            await _relay_n(reader, writer, int(length), on_bytes=on_bytes)
        except ValueError:
            return
        return

    if until_eof:
        await pump(reader, writer, on_bytes=on_bytes)


async def _relay_n(reader, writer, n: int, on_bytes=None) -> None:
    """精确搬运 n 字节。"""
    remaining = n
    while remaining > 0:
        chunk = await reader.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            break
        writer.write(chunk)
        if on_bytes is not None:
            await on_bytes(len(chunk))
        remaining -= len(chunk)
    await writer.drain()


async def _relay_chunked(reader, writer, on_bytes=None) -> None:
    """原样转发 chunked，不解码。"""
    while True:
        size_line = await reader.readline()
        if not size_line:
            break
        writer.write(size_line)
        try:
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            while True:  # trailer 直到空行
                line = await reader.readline()
                writer.write(line)
                if on_bytes is not None:
                    await on_bytes(len(line))
                if line in (b"\r\n", b"\n", b""):
                    break
            break
        data = await reader.readexactly(size + 2)
        writer.write(data)
        if on_bytes is not None:
            await on_bytes(len(data))
    await writer.drain()


async def pump(reader, writer, on_bytes=None) -> None:
    """单向搬运直到 EOF。CONNECT 隧道用；on_bytes 可选。"""
    try:
        while True:
            data = await reader.read(CHUNK_SIZE)
            if not data:
                break
            writer.write(data)
            if on_bytes is not None:
                await on_bytes(len(data))
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass


def text_response(status: str, text: str, extra_headers=None) -> bytes:
    """纯文本响应，status 形如 `403 Forbidden`。"""
    body = text.encode("utf-8")
    lines = [
        f"HTTP/1.1 {status}",
        "Content-Type: text/plain; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if extra_headers:
        lines.extend(extra_headers)
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body
