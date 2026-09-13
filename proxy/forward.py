"""普通 HTTP 请求的转发（代理的"正向代理"核心）。

一次成功转发的完整步骤（也是阅读本文件的路线图）：

    ① 解析目标：从请求行 target 里取出 域名/端口/路径/查询串
    ② 判定     ：engine.evaluate(...) —— 内联、同步、无 IO（快路径）
    ③ 拦截     ：命中黑名单等 -> 回 403，并记一条 block 审计
    ④ 连上游   ：asyncio.open_connection(host, port)，失败则回 502
    ⑤ 重写首部 ：删逐跳首部，请求行由 absolute-form 改回 origin-form，
                 补 Host，强制 Connection: close（这样不必做连接复用）
    ⑥ 搬请求体 ：按 Content-Length / chunked 转发
    ⑦ 搬响应   ：把上游响应首部+body 原样回给客户端

关于 ⑦ 为什么可以"原样回"：我们只做域名级审计，不解密也不改写内容，
所以响应体无需理解，直接字节搬运即可。
"""

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
)


async def handle_http(reader, writer, head, ctx, identity, client_ip: str) -> None:
    """处理一次普通 HTTP 请求。reader/writer 是客户端连接。"""

    # ------------------------------------------------------------------ ①
    # 解析目标。优先按 absolute-form（完整 URL）解析；若不是，则退回
    # origin-form（路径 + Host 头）——后者出现在少数客户端/透明代理场景。
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
        netloc = parts.netloc or host          # 原样保留客户端写的 host:port
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
        return

    # ------------------------------------------------------------------ ②
    # 快路径判定：只带域名和角色，纯内存比对，绝不做网络/磁盘操作。
    decision = ctx.engine.evaluate(
        RequestMeta(host=host, role=identity.role.value, url=url, method=head.method)
    )

    # ------------------------------------------------------------------ ③
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
        return

    # ------------------------------------------------------------------ ④
    try:
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
        return

    try:
        # -------------------------------------------------------------- ⑤
        # 重写请求首部：
        #   - 删掉逐跳首部（Connection/Proxy-* 等），避免把"客户端-代理"这条
        #     连接的语义泄漏给"代理-源站"那条连接；
        #   - Proxy-Authorization 必须删除：那是给代理认证用的，源站不需要也不该看到；
        #   - 请求行改回 origin-form（源站不认绝对 URL）；
        #   - 强制 Connection: close，图省事不做长连接复用（教学项目够用）。
        out = Headers()
        for key, value in head.headers.items():
            if key.lower() in HOP_BY_HOP:
                continue
            out.set(key, value)
        out.set("Host", netloc)
        out.set("Connection", "close")

        up_writer.write(f"{head.method} {path} {head.version}\r\n".encode("latin-1"))
        up_writer.write(out.to_bytes())
        up_writer.write(b"\r\n")
        await up_writer.drain()

        # -------------------------------------------------------------- ⑥
        await relay_body(reader, up_writer, head.headers)

        # -------------------------------------------------------------- ⑦
        # 读上游响应首部，去掉逐跳首部后回给客户端，再搬响应体。
        response = await read_message_head(up_reader)
        if response is None:
            return
        status_line, resp_headers = response

        resp_out = Headers()
        for key, value in resp_headers.items():
            if key.lower() in HOP_BY_HOP:
                continue
            resp_out.set(key, value)
        resp_out.set("Connection", "close")

        writer.write(f"{status_line}\r\n".encode("latin-1"))
        writer.write(resp_out.to_bytes())
        writer.write(b"\r\n")
        await writer.drain()

        # until_eof=True：响应没有 Content-Length 也没有 chunked 时，
        # 就一路读到上游关闭连接为止（因为我们已经告诉上游 Connection: close）。
        await relay_body(up_reader, writer, resp_headers, until_eof=True)
        await writer.drain()

        # 转发成功，记一条 allow 审计（异步入队，不阻塞）。
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
    finally:
        up_writer.close()
        try:
            await up_writer.wait_closed()
        except Exception:
            pass
