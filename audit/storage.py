"""sqlite 存储。访问日志和管理操作日志分两张表。"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

# 表结构：一行 = 一次被代理处理过的访问
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

CREATE TABLE IF NOT EXISTS admin_audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,      -- 时间
    actor     TEXT,               -- 操作者后台账号；登录失败时记 "-"
    action    TEXT,               -- login.ok / login.failed / logout / rules.add
                                  -- / rules.remove / admin.create / admin.remove
                                  -- / admin.reset / policy.set / logs.purge
    target    TEXT,               -- 作用对象（规则模式、被操作的账号名等）
    detail    TEXT,               -- 补充说明（失败原因、角色变更前后等）
    client_ip TEXT                -- 操作来源 IP
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit(ts);
"""


class AuditStorage:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def write(self, event) -> None:
        """写入访问日志。阻塞，应在工作线程调用。"""
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
        """最近访问记录，可按域名模糊、按角色过滤。"""
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

    def write_admin(
        self,
        actor: str,
        action: str,
        target: str = "",
        detail: str = "",
        client_ip: str = "",
        ts: str | None = None,
    ) -> None:
        """写入管理操作日志。"""
        row = {
            "ts": ts or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "actor": actor,
            "action": action,
            "target": target,
            "detail": detail,
            "client_ip": client_ip,
        }
        with self._lock:
            self._conn.execute(
                "INSERT INTO admin_audit (ts, actor, action, target, detail, client_ip) "
                "VALUES (:ts, :actor, :action, :target, :detail, :client_ip)",
                row,
            )
            self._conn.commit()

    def query_admin(self, limit: int = 100, action: str | None = None) -> list[dict]:
        """最近管理操作，可按 action 过滤。"""
        sql = "SELECT ts, actor, action, target, detail, client_ip FROM admin_audit"
        params: list[Any] = []
        if action:
            sql += " WHERE action = ?"
            params.append(action)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))

        with self._lock:
            cur = self._conn.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def purge_audit(self) -> int:
        """只清访问日志，保留 admin_audit。"""
        with self._lock:
            cur = self._conn.execute("DELETE FROM audit")
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
