"""上游连接池 + 客户端长连接。"""

from __future__ import annotations

import asyncio

import pytest

from proxy.httpmsg import Headers, wants_keep_alive
from proxy.pool import UpstreamPool


def test_http11_defaults_to_keepalive():
    assert wants_keep_alive("HTTP/1.1", Headers()) is True
    assert wants_keep_alive("HTTP/1.1", Headers([("Connection", "close")])) is False


def test_http10_defaults_to_close():
    assert wants_keep_alive("HTTP/1.0", Headers()) is False
    assert wants_keep_alive("HTTP/1.0", Headers([("Connection", "keep-alive")])) is True


async def _keep_origin(reader, writer):
    """源站：同一条连接上可以连续回答多次。"""
    try:
        while True:
            await reader.readuntil(b"\r\n\r\n")
            body = b"ok"
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n" + body
            )
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_pool_reuses_idle_connection():
    hits = {"n": 0}

    async def on_client(reader, writer):
        hits["n"] += 1
        await _keep_origin(reader, writer)

    server = await asyncio.start_server(on_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    pool = UpstreamPool(max_per_host=4, idle_seconds=30)

    r1, w1 = await pool.acquire("127.0.0.1", port)
    await pool.release("127.0.0.1", port, r1, w1, reuse=True)
    r2, w2 = await pool.acquire("127.0.0.1", port)
    assert w2 is w1
    assert pool.reused == 1
    assert hits["n"] == 1
    await pool.release("127.0.0.1", port, r2, w2, reuse=False)
    await pool.close()
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_pool_opens_new_when_not_released_for_reuse():
    server = await asyncio.start_server(_keep_origin, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    pool = UpstreamPool(max_per_host=4, idle_seconds=30)

    r1, w1 = await pool.acquire("127.0.0.1", port)
    await pool.release("127.0.0.1", port, r1, w1, reuse=False)
    r2, w2 = await pool.acquire("127.0.0.1", port)
    assert w2 is not w1
    assert pool.created == 2
    await pool.release("127.0.0.1", port, r2, w2, reuse=False)
    await pool.close()
    server.close()
    await server.wait_closed()