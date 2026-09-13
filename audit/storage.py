"""审计存储：sqlite3 的薄封装（建表 / 写入 / 查询）。

线程模型说明（这块最容易踩坑，值得讲清）：
- 写入由 asyncio 的线程池（run_in_executor）调用，可能来自不同的工作线程，
  所以创建连接时用 check_same_thread=False，并用一把锁把写操作串行化。
- 读取（管理端查日志）也复用同一个连接，用同一把锁保护，避免并发访问冲突。
- sqlite 适合本项目这种"单机、单文件、轻量查询"的场景，零额外依赖。
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

# 审计表结构：一行 = 一次被代理处理过的访问
_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL,   -- 时间
    client_ip TEXT,               -- 客户端 IP
    user      TEXT,               -- 认证用户名（未认证为 anonymous）
    role      TEXT,               -- 角色：admin / user
    method    TEXT,               -- HTTP 方法（CONNECT 隧道记为 CONNECT）
    host      TEXT,               -- 目标域名
    port      INTEGER,            -- 目标端口
    url       TEXT,               -- 完整 URL（CONNECT 隧道为空）
    action    TEXT,               -- 动作：allow / block / error
    rule_id   TEXT,               -- 命中的规则标识（未命中为空）
    reason    TEXT                -- 可读原因
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
"""


class AuditStorage:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def write(self, event) -> None:
        """写入一条审计记录（阻塞 IO，应在工作线程里调用）。"""
        row = {
            "ts": event.ts,
            "client_ip": event.client_ip,
            "user": event.user,
            "role": event.role,
            "method": event.method,
            "host": event.host,
            "port": event.port,
            "url": event.url,
            "action": event.action,
            "rule_id": event.rule_id,
            "reason": event.reason,
        }
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit "
                "(ts, client_ip, user, role, method, host, port, url, action, rule_id, reason) "
                "VALUES (:ts, :client_ip, :user, :role, :method, :host, :port, :url, "
                ":action, :rule_id, :reason)",
                row,
            )
            self._conn.commit()

    def query(
        self,
        limit: int = 100,
        host: str | None = None,
        role: str | None = None,
    ) -> list[dict[str, Any]]:
        """查询最近的审计记录（供管理端展示），支持按域名模糊、按角色过滤。"""
        sql = (
            "SELECT ts, client_ip, user, role, method, host, port, url, action, rule_id, reason "
            "FROM audit"
        )
        conds: list[str] = []
        params: list[Any] = []
        if host:
            conds.append("host LIKE ?")
            params.append(f"%{host}%")
        if role:
            conds.append("role = ?")
            params.append(role)
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))

        with self._lock:
            cur = self._conn.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
