"""审计日志器：把审计事件排队，由后台协程异步落库。

为什么要异步（本项目的关键设计点之一）：
落库是磁盘 IO。如果把写库直接放在转发链路上，每一次请求都要等磁盘，
并发一高就明显拖慢代理。这里用 asyncio.Queue 当缓冲：
- 转发路径只做一次 put_nowait（几乎零成本、不等待）；
- 后台协程 run() 不断把事件取出，丢给线程池真正写库。
这样就实现了"转发"与"存储"的解耦——即架构里说的"转发前判定、转发后异步存储"。
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class AuditEvent:
    """一条审计事件的字段（与 sqlite 表结构一一对应）。"""

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
        """登记一条审计事件（非阻塞：只入队，不等写库）。"""
        if not event.ts:
            event.ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.queue.put_nowait(event)

    async def run(self) -> None:
        """后台任务：不断把队列里的事件写进数据库，直到被取消。"""
        loop = asyncio.get_running_loop()
        while True:
            event = await self.queue.get()
            try:
                # 把阻塞的 sqlite 写入丢到线程池，避免卡住事件循环
                await loop.run_in_executor(None, self.storage.write, event)
            except Exception:  # 存储出错不应拖垮代理
                pass
            finally:
                self.queue.task_done()
