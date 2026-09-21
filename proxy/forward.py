"""明文 HTTP 转发：判定、连上游、搬字节。返回值表示客户端连接是否还能接下一个请求。"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from filter.engine import RequestMeta
from filter.rules import Action
from proxy.audit_hook import record
from proxy.httpmsg import (
    HOP_BY_HOP,
    Headers,
    read_message_head,
    relay_body,
    text_response,
    wants_keep_alive,
)


async def handle_http(reader, writer, head, ctx, identity, client_ip: str) -> bool:
    """处理一次普通 HTTP 请求。返回是否保持客户端长连接。"""

    target = head.target
    absolute = target.startswith("http://") or target.startswith("https://")

    if absolute:
        parts = urlsplit(target)
        scheme = (parts.scheme or "http").lower()
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        netloc = parts.netloc or host
        url = target
    else:
        host_header = head.headers.get("host", "") or ""
        host_part, _, port_part = host_header.partition(":")
        host = host_part.lower()
        port = int(port_part) if port_part.isdigit() else 80
        path = target or "/"
        netloc = host_header or host
        url = f"http://{netloc}{path}"

    if not host:
        writer.write(text_response("400 Bad Request", "无法确定目标主机\n"))
        await writer.drain()
        return False

    decision = ctx.engine.evaluate(
        RequestMeta(host=host, role=identity.role.value, url=url, method=head.method)
    )

    client_keep = wants_keep_alive(head.version, head.headers) and ctx.config.keepalive

    async def on_bytes(n: int):
        if ctx.limits is not None:
            await ctx.limits.throttle_bytes(identity.user, identity.role.value, n)

    if decision.action is Action.BLOCK:
        await record(
            ctx,
            client_ip=client_ip,
            identity=identity,
            method=head.method,
            host=host,
            port=port,
            url=url,
            action="block",
            rule_id=decision.rule.rule_id if decision.rule else "",
            reason=decision.reason,
        )
        writer.write(
            text_response(
                "403 Forbidden",
                f"该请求被企业代理拦截\n目标：{host}\n原因：{decision.reason}\n",
            )
        )
        await writer.drain()
        return False

    pool = ctx.pool
    up_reader = up_writer = None
    reuse = False
    try:
        try:
            if pool is not None:
                up_reader, up_writer = await pool.acquire(host, port)
            else:
                up_reader, up_writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            await record(
                ctx,
                client_ip=client_ip,
                identity=identity,
                method=head.method,
                host=host,
                port=port,
                url=url,
                action="error",
                reason=f"连接上游失败：{exc}",
            )
            writer.write(
                text_response("502 Bad Gateway", f"无法连接目标主机 {host}:{port}\n")
            )
            await writer.drain()
            return False

        out = Headers()
        for key, value in head.headers.items():
            if key.lower() in HOP_BY_HOP:
                continue
            out.set(key, value)
        out.set("Host", netloc)
        origin_keep = pool is not None
        out.set("Connection", "keep-alive" if origin_keep else "close")

        up_writer.write(f"{head.method} {path} {head.version}\r\n".encode("latin-1"))
        up_writer.write(out.to_bytes())
        up_writer.write(b"\r\n")
        await up_writer.drain()

        await relay_body(reader, up_writer, head.headers, on_bytes=on_bytes)

        response = await read_message_head(up_reader)
        if response is None:
            return False
        status_line, resp_headers = response
        version = status_line.split(" ", 1)[0] if status_line else "HTTP/1.0"
        origin_replied_keep = wants_keep_alive(version, resp_headers)

        resp_out = Headers()
        for key, value in resp_headers.items():
            if key.lower() in HOP_BY_HOP:
                continue
            resp_out.set(key, value)
        resp_out.set("Connection", "keep-alive" if client_keep else "close")

        writer.write(f"{status_line}\r\n".encode("latin-1"))
        writer.write(resp_out.to_bytes())
        writer.write(b"\r\n")
        await writer.drain()

        await relay_body(
            up_reader,
            writer,
            resp_headers,
            until_eof=not origin_replied_keep,
            on_bytes=on_bytes,
        )
        await writer.drain()

        await record(
            ctx,
            client_ip=client_ip,
            identity=identity,
            method=head.method,
            host=host,
            port=port,
            url=url,
            action="allow",
            reason=decision.reason,
        )
        reuse = bool(origin_keep and origin_replied_keep)
        return client_keep
    finally:
        if up_writer is None:
            pass
        elif pool is not None:
            await pool.release(host, port, up_reader, up_writer, reuse=reuse)
        else:
            up_writer.close()
            try:
                await up_writer.wait_closed()
            except Exception:
                pass