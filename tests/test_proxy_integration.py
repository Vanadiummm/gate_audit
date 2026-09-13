"""端到端集成测试：真的起一个代理、一个源站，用原始 socket 走一遍。

为什么用原始 socket 而不是 requests？
因为 requests 会自动帮我们处理代理、重定向等细节，反而看不清"线路上到底发了什么"。
这里手动拼 HTTP 报文，能精确验证：

    ① 放行路径：HTTP 请求经代理转发后能拿到源站内容；
    ② 拦截路径：命中黑名单时代理返回 403；
    ③ CONNECT 隧道：能建立、能在隧道里正常收发；
    ④ 审计落库：请求结束后 sqlite 里确实多了一条记录；
    ⑤ 角色权限：只对 user 生效的规则不影响 admin。

注意本测试完全跑在 127.0.0.1 上，不依赖外网。
"""

from __future__ import annotations

import asyncio
import base64
from types import SimpleNamespace

import pytest

from audit.logger import AuditLogger
from audit.storage import AuditStorage
from auth.roles import RoleManager
from config.loader import Config
from filter.engine import FilterEngine
from proxy.context import ProxyContext
from proxy.main import build_server

ORIGIN_BODY = b"hello-from-origin"


# --------------------------- 本地"源站" --------------------------- #
async def _origin_handler(reader, writer):
    """一个极简 HTTP 源站：读掉请求头，回一段固定正文。"""
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


# --------------------------- 测试环境 --------------------------- #
@pytest.fixture
async def env(tmp_path):
    """起一个源站 + 一个代理，并把它们的依赖打包给测试用。"""
    # 1) 源站，端口交给系统随机分配
    origin = await asyncio.start_server(_origin_handler, "127.0.0.1", 0)
    origin_port = origin.sockets[0].getsockname()[1]

    # 2) 代理。监听端口也用 0（随机），避免和真实服务/其他测试抢端口。
    #    直接构造 Config 而不读 config.json，避免污染真实配置文件与数据库。
    cfg = Config(
        listen_host="127.0.0.1",
        listen_port=0,
        db_path=str(tmp_path / "audit.db"),
        default_policy="allow",
        users={"admin": {"password": "admin123", "role": "admin"}},
        rules={},
    )
    cfg.path = tmp_path / "config.json"

    storage = AuditStorage(cfg.resolve_db_path())
    ctx = ProxyContext(
        config=cfg,
        engine=FilterEngine(cfg.rules, cfg.default_policy),
        storage=storage,
        logger=AuditLogger(storage),
        roles=RoleManager(cfg.users),
    )

    # 3) 启动审计后台任务 + 代理服务
    logger_task = asyncio.create_task(ctx.logger.run())
    server = await build_server(ctx)
    proxy_port = server.sockets[0].getsockname()[1]

    yield SimpleNamespace(
        ctx=ctx,
        engine=ctx.engine,
        storage=storage,
        proxy_port=proxy_port,
        origin_port=origin_port,
    )

    # 4) 收尾
    logger_task.cancel()
    server.close()
    await server.wait_closed()
    origin.close()
    await origin.wait_closed()
    storage.close()


# --------------------------- 测试用客户端 --------------------------- #
async def _proxy_get(proxy_port, url, host_header, extra_headers=None):
    """向代理发一个普通 HTTP 请求，读回完整响应（代理会 Connection: close）。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    lines = [f"GET {url} HTTP/1.1", f"Host: {host_header}", "Connection: close"]
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


# --------------------------- ① 放行 --------------------------- #
async def test_http_forward_allowed(env):
    url = f"http://127.0.0.1:{env.origin_port}/index.html"
    data = await _proxy_get(env.proxy_port, url, f"127.0.0.1:{env.origin_port}")
    assert b"200 OK" in data
    assert ORIGIN_BODY in data


# --------------------------- ② 拦截 --------------------------- #
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


# --------------------------- ③ CONNECT 隧道 --------------------------- #
async def test_connect_tunnel_established_and_usable(env):
    reader, writer = await asyncio.open_connection("127.0.0.1", env.proxy_port)
    target = f"127.0.0.1:{env.origin_port}"
    writer.write(
        f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("latin-1")
    )
    await writer.drain()

    # 先读 CONNECT 的响应行
    status_line = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    assert b"200 Connection Established" in status_line

    # 隧道已通：在里面说 HTTP，应能拿到源站响应（正常 HTTPS 时这里是 TLS 字节流）
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
        f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("latin-1")
    )
    await writer.drain()
    data = await asyncio.wait_for(reader.read(2048), timeout=5)
    assert b"403 Forbidden" in data
    writer.close()


# --------------------------- ④ 审计落库 --------------------------- #
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
    assert rows[0]["rule_id"]          # 命中规则应被记录，便于追溯


# --------------------------- ⑤ 角色权限 --------------------------- #
async def test_role_scoped_rule_only_hits_user(env):
    # 该规则只对 user 生效
    env.engine.reload({"blacklist": [{"pattern": "127.0.0.1", "role": "user"}]})
    url = f"http://127.0.0.1:{env.origin_port}/"

    # 匿名 -> 角色为 user -> 被拦
    anon = await _proxy_get(env.proxy_port, url, f"127.0.0.1:{env.origin_port}")
    assert b"403 Forbidden" in anon

    # 以 admin 认证 -> 规则不适用 -> 放行
    admin = await _proxy_get(
        env.proxy_port,
        url,
        f"127.0.0.1:{env.origin_port}",
        extra_headers=[_basic("admin", "admin123")],
    )
    assert b"200 OK" in admin
