"""审计事件先入队，后台协程再写 sqlite，避免挡在转发路径上。"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class AuditEvent:
    """一条审计记录。"""

    client_ip: str = ""
    user: str = "anonymous"
    role: str = "user"
    method: str = ""
    host: str = ""
    port: int = 0
    url: str | None = None
    action: str = ""
    rule_id: str = ""
    reason: str = ""
    ts: str = ""


class AuditLogger:
    def __init__(self, storage):
        self.storage = storage
        self.queue: asyncio.Queue[AuditEvent] = asyncio.Queue()

    async def log(self, event: AuditEvent) -> None:
        """非阻塞入队。"""
        if not event.ts:
            event.ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.queue.put_nowait(event)

    async def run(self) -> None:
        """把队列写入 sqlite，直到被取消。"""
        loop = asyncio.get_running_loop()
        while True:
            event = await self.queue.get()
            try:
                await loop.run_in_executor(None, self.storage.write, event)
            except Exception:
                pass
            finally:
                self.queue.task_done()
