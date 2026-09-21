"""端到端：自建源站 + 代理，用原始 socket 拼 HTTP（不用 requests，才能看清线上字节）。"""

from __future__ import annotations

import asyncio
import base64
from types import SimpleNamespace

import pytest
from proxy.limits import LimitTracker
from proxy.pool import UpstreamPool
from audit.logger import AuditLogger
from audit.storage import AuditStorage
from auth.admins import AdminStore, hash_password
from auth.roles import RoleManager
from config.loader import Config
from filter.engine import FilterEngine
from proxy.context import ProxyContext
from proxy.main import build_server

ORIGIN_BODY = b"hello-from-origin"
_ADMIN_HASH = hash_password("admin123")
_ALICE_HASH = hash_password("alice123")


async def _origin_handler(reader, writer):
    """固定正文的 HTTP 源站。"""
    try:
        await reader.readuntil(b"\r\n\r\n")
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: " + str(len(ORIGIN_BODY)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + ORIGIN_BODY
        )
        writer.write(resp)
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


@pytest.fixture
async def env(tmp_path):
    """源站 + 代理。"""
    origin = await asyncio.start_server(_origin_handler, "127.0.0.1", 0)
    origin_port = origin.sockets[0].getsockname()[1]

    cfg = Config(
        listen_host="127.0.0.1",
        listen_port=0,
        db_path=str(tmp_path / "audit.db"),
        default_policy="allow",
        users={
            "admin": {"password_hash": _ADMIN_HASH, "role": "admin"},
            "alice": {"password_hash": _ALICE_HASH, "role": "user"},
        },
        rules={},
    )
    cfg.path = tmp_path / "config.json"

    pool = UpstreamPool(max_per_host=4, idle_seconds=30)
    limits = LimitTracker({})
    storage = AuditStorage(cfg.resolve_db_path())
    ctx = ProxyContext(
        config=cfg,
        engine=FilterEngine(cfg.rules, cfg.default_policy),
        storage=storage,
        logger=AuditLogger(storage),
        roles=RoleManager(cfg.users),
        admins=AdminStore(cfg.admins),
        pool=pool,
        limits=limits,
    )

    logger_task = asyncio.create_task(ctx.logger.run())
    server = await build_server(ctx)
    proxy_port = server.sockets[0].getsockname()[1]

    yield SimpleNamespace(
        ctx=ctx,
        engine=ctx.engine,
        storage=storage,
        proxy_port=proxy_port,
        origin_port=origin_port,
        pool=pool,
        limits=limits,
    )

    logger_task.cancel()
    server.close()
    await server.wait_closed()
    origin.close()
    await origin.wait_closed()
    storage.close()


async def _proxy_get(proxy_port, url, host_header, extra_headers=None, auth=("admin", "admin123")):
    """经代理发 HTTP 请求。auth=(user, password)；auth=None 不带头。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    lines = [f"GET {url} HTTP/1.1", f"Host: {host_header}", "Connection: close"]
    if auth:
        lines.append(_basic(*auth))
    lines.extend(extra_headers or [])
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return data


def _basic(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}"


async def _wait_rows(storage, count=1, timeout=5.0):
    """等审计记录落库（写库是异步的，所以要轮询等待）。"""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    rows = storage.query(limit=50)
    while len(rows) < count and loop.time() < deadline:
        await asyncio.sleep(0.05)
        rows = storage.query(limit=50)
    return rows


async def test_http_forward_allowed(env):
    url = f"http://127.0.0.1:{env.origin_port}/index.html"
    data = await _proxy_get(env.proxy_port, url, f"127.0.0.1:{env.origin_port}")
    assert b"200 OK" in data
    assert ORIGIN_BODY in data


async def test_http_forward_blocked_by_blacklist(env):
    env.engine.reload({"blacklist": ["127.0.0.1"]})
    url = f"http://127.0.0.1:{env.origin_port}/"
    data = await _proxy_get(env.proxy_port, url, f"127.0.0.1:{env.origin_port}")
    assert b"403 Forbidden" in data
    assert ORIGIN_BODY not in data          # 请求不应到达源站


async def test_whitelist_wins_over_blacklist_end_to_end(env):
    env.engine.reload({"whitelist": ["127.0.0.1"], "blacklist": ["127.0.0.1"]})
    url = f"http://127.0.0.1:{env.origin_port}/"
    data = await _proxy_get(env.proxy_port, url, f"127.0.0.1:{env.origin_port}")
    assert b"200 OK" in data


async def test_connect_tunnel_established_and_usable(env):
    reader, writer = await asyncio.open_connection("127.0.0.1", env.proxy_port)
    target = f"127.0.0.1:{env.origin_port}"
    writer.write(
        (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"{_basic('admin', 'admin123')}\r\n"
            f"\r\n"
        ).encode("latin-1")
    )
    await writer.drain()

    # 先读 CONNECT 的响应行
    status_line = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    assert b"200 Connection Established" in status_line

    # 隧道里不再带 Proxy-Authorization
    writer.write(
        f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode("latin-1")
    )
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), timeout=10)
    assert ORIGIN_BODY in data
    writer.close()


async def test_connect_tunnel_blocked(env):
    env.engine.reload({"blacklist": ["127.0.0.1"]})
    reader, writer = await asyncio.open_connection("127.0.0.1", env.proxy_port)
    target = f"127.0.0.1:{env.origin_port}"
    writer.write(
        (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"{_basic('admin', 'admin123')}\r\n"
            f"\r\n"
        ).encode("latin-1")
    )
    await writer.drain()
    data = await asyncio.wait_for(reader.read(2048), timeout=5)
    assert b"403 Forbidden" in data
    writer.close()


async def test_audit_record_written_on_allow(env):
    url = f"http://127.0.0.1:{env.origin_port}/"
    await _proxy_get(env.proxy_port, url, f"127.0.0.1:{env.origin_port}")

    rows = await _wait_rows(env.storage, count=1)
    assert rows, "审计记录没有落库"
    assert rows[0]["action"] == "allow"
    assert rows[0]["host"] == "127.0.0.1"
    assert rows[0]["method"] == "GET"


async def test_audit_record_written_on_block(env):
    env.engine.reload({"blacklist": ["127.0.0.1"]})
    url = f"http://127.0.0.1:{env.origin_port}/"
    await _proxy_get(env.proxy_port, url, f"127.0.0.1:{env.origin_port}")

    rows = await _wait_rows(env.storage, count=1)
    assert rows
    assert rows[0]["action"] == "block"
    assert rows[0]["rule_id"]


async def test_role_scoped_rule_only_hits_user(env):
    env.engine.reload({"blacklist": [{"pattern": "127.0.0.1", "role": "user"}]})
    url = f"http://127.0.0.1:{env.origin_port}/"

    # 未认证 -> 407，还没走到过滤引擎
    anon = await _proxy_get(
        env.proxy_port, url, f"127.0.0.1:{env.origin_port}", auth=None
    )
    assert b"407 Proxy Authentication Required" in anon

    # 普通用户 alice -> 角色为 user -> 被拦
    alice = await _proxy_get(
        env.proxy_port,
        url,
        f"127.0.0.1:{env.origin_port}",
        auth=("alice", "alice123"),
    )
    assert b"403 Forbidden" in alice

    # 以 admin 认证 -> 规则不适用 -> 放行
    admin = await _proxy_get(
        env.proxy_port, url, f"127.0.0.1:{env.origin_port}"
    )
    assert b"200 OK" in admin

async def test_http_without_auth_returns_407(env):
    """缺 Proxy-Authorization 回 407。"""
    url = f"http://127.0.0.1:{env.origin_port}/"
    data = await _proxy_get(
        env.proxy_port, url, f"127.0.0.1:{env.origin_port}", auth=None
    )
    assert b"407 Proxy Authentication Required" in data
    assert b"Proxy-Authenticate: Basic" in data
    assert ORIGIN_BODY not in data          # 请求不应到达源站


async def test_http_wrong_password_returns_407(env):
    """密码错误与未认证同等对待：回 407，而不是降级成匿名 user。"""
    url = f"http://127.0.0.1:{env.origin_port}/"
    data = await _proxy_get(
        env.proxy_port,
        url,
        f"127.0.0.1:{env.origin_port}",
        auth=("admin", "wrong"),
    )
    assert b"407 Proxy Authentication Required" in data
    assert ORIGIN_BODY not in data


async def test_connect_without_auth_returns_407(env):
    """CONNECT 缺认证回 407。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", env.proxy_port)
    target = f"127.0.0.1:{env.origin_port}"
    writer.write(
        f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("latin-1")
    )
    await writer.drain()
    data = await asyncio.wait_for(reader.read(2048), timeout=5)
    assert b"407 Proxy Authentication Required" in data
    assert b"Proxy-Authenticate: Basic" in data
    writer.close()

async def _read_one_response(reader):
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    text = head.decode("latin-1")
    length = 0
    for line in text.split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    body = await reader.readexactly(length) if length else b""
    return head + body


async def test_client_keepalive_two_requests_one_tcp(env):
    """同一条客户端 TCP 连续两个 GET，都应 200（源站仍可每请求一连）。"""
    url = f"http://127.0.0.1:{env.origin_port}/"
    host = f"127.0.0.1:{env.origin_port}"
    reader, writer = await asyncio.open_connection("127.0.0.1", env.proxy_port)
    for _ in range(2):
        lines = [
            f"GET {url} HTTP/1.1",
            f"Host: {host}",
            "Connection: keep-alive",
            _basic("admin", "admin123"),
        ]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        await writer.drain()
        data = await _read_one_response(reader)
        assert b"200 OK" in data
        assert ORIGIN_BODY in data
    writer.close()


async def test_quota_returns_429(env):
    env.ctx.limits = LimitTracker({"admin": {"quota_requests": 1}})
    url = f"http://127.0.0.1:{env.origin_port}/"
    host = f"127.0.0.1:{env.origin_port}"
    first = await _proxy_get(env.proxy_port, url, host)
    assert b"200 OK" in first
    second = await _proxy_get(env.proxy_port, url, host)
    assert b"429 Too Many Requests" in second
    assert ORIGIN_BODY not in second