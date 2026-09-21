"""上游明文 HTTP 连接池。CONNECT 隧道不复用。"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class UpstreamPool:
    def __init__(self, max_per_host: int = 8, idle_seconds: float = 30.0, clock=None):
        self.max_per_host = max_per_host
        self.idle_seconds = idle_seconds
        self._clock = clock or time.monotonic
        self._idle: dict[tuple, list] = defaultdict(list)
        self.created = 0
        self.reused = 0

    async def acquire(self, host: str, port: int):
        key = (host, port)
        now = self._clock()
        idle = self._idle[key]
        while idle:
            reader, writer, put_at = idle.pop()
            if now - put_at > self.idle_seconds or writer.is_closing() or reader.at_eof():
                await self._close_one(writer)
                continue
            self.reused += 1
            return reader, writer
        self.created += 1
        return await asyncio.open_connection(host, port)

    async def release(self, host: str, port: int, reader, writer, *, reuse: bool) -> None:
        if not reuse or writer.is_closing() or reader.at_eof():
            await self._close_one(writer)
            return
        key = (host, port)
        if len(self._idle[key]) >= self.max_per_host:
            await self._close_one(writer)
            return
        self._idle[key].append((reader, writer, self._clock()))

    async def close(self) -> None:
        for conns in self._idle.values():
            for _r, writer, _t in conns:
                await self._close_one(writer)
        self._idle.clear()

    async def _close_one(self, writer) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
