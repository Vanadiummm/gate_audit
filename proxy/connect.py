"""HTTPS CONNECT：按域名判定后做字节对拷，不解密隧道内容。"""

from __future__ import annotations

import asyncio

from filter.engine import RequestMeta
from filter.rules import Action
from proxy.audit_hook import record
from proxy.httpmsg import pump, text_response

# CONNECT 未写端口时默认 443
_DEFAULT_PORT = 443


async def handle_connect(reader, writer, head, ctx, identity, client_ip: str) -> None:
    """处理一次 CONNECT。"""

    target = head.target
    host_part, _, port_part = target.rpartition(":")
    host = host_part.strip().strip("[]").lower()
    port = int(port_part) if port_part.isdigit() else _DEFAULT_PORT
    if not host:
        writer.write(text_response("400 Bad Request", "CONNECT 目标格式非法\n"))
        await writer.drain()
        return

    decision = ctx.engine.evaluate(
        RequestMeta(host=host, role=identity.role.value, url=None, method="CONNECT")
    )

    if decision.action is Action.BLOCK:
        await record(
            ctx,
            client_ip=client_ip,
            identity=identity,
            method="CONNECT",
            host=host,
            port=port,
            url=None,
            action="block",
            rule_id=decision.rule.rule_id if decision.rule else "",
            reason=decision.reason,
        )
        writer.write(
            text_response(
                "403 Forbidden",
                f"该 HTTPS 目标被企业代理拦截\n目标：{host}:{port}\n原因：{decision.reason}\n",
            )
        )
        await writer.drain()
        return

    try:
        up_reader, up_writer = await asyncio.open_connection(host, port)
    except OSError as exc:
        await record(
            ctx,
            client_ip=client_ip,
            identity=identity,
            method="CONNECT",
            host=host,
            port=port,
            url=None,
            action="error",
            reason=f"连接上游失败：{exc}",
        )
        writer.write(
            text_response("502 Bad Gateway", f"无法连接目标主机 {host}:{port}\n")
        )
        await writer.drain()
        return

    await record(
        ctx,
        client_ip=client_ip,
        identity=identity,
        method="CONNECT",
        host=host,
        port=port,
        url=None,
        action="allow",
        reason="CONNECT 隧道建立（域名级放行，内容不解密）",
    )

    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()

    to_upstream = asyncio.create_task(pump(reader, up_writer))
    to_client = asyncio.create_task(pump(up_reader, writer))
    done, pending = await asyncio.wait(
        {to_upstream, to_client}, return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()

    up_writer.close()
    try:
        await up_writer.wait_closed()
    except Exception:
        pass
