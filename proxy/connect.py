"""HTTPS 的 CONNECT 隧道。

为什么 HTTPS 需要一种特殊处理？
HTTPS 里，客户端和源站之间是 TLS 加密的。作为代理，我们只有两条路：

  A. 做中间人（MITM）：假冒源站给客户端签证书、解密后再转发。能审计到 URL 和内容，
     但需要给每台客户端装根证书，属于"解密式审计"，代价与合规风险都很高。
  B. 只做隧道（本项目采用）：代理仅根据 CONNECT 请求里的**域名**决定放不放行，
     放行后就当一根"水管"，把加密字节流对拷，不看不改。

本项目在需求里已明确"只做域名级审计、不解密"，所以选 B。这也带来一个必然结论：
一旦隧道建立，本次连接后续访问了哪些 URL、传了什么内容，代理是看不到的。
这是方案的边界，写在这里以免误解。

流程：
    CONNECT www.example.com:443 HTTP/1.1
    ① 从 target 里取 域名:端口，按域名判定（快路径）
    ② 命中拦截 -> 回 403
    ③ 放行     -> 连上游，回 "200 Connection Established"
    ④ 之后双向对拷字节（pump），任一方向结束就收摊
"""

from __future__ import annotations

import asyncio

from filter.engine import RequestMeta
from filter.rules import Action
from proxy.audit_hook import record
from proxy.httpmsg import pump, text_response

# CONNECT 的目标若没写端口，默认 443
_DEFAULT_PORT = 443


async def handle_connect(reader, writer, head, ctx, identity, client_ip: str) -> None:
    """处理一次 CONNECT。reader/writer 是客户端连接。"""

    # ------------------------------------------------------------------ ①
    target = head.target                      # 形如 "www.example.com:443"
    host_part, _, port_part = target.rpartition(":")
    host = host_part.strip().strip("[]").lower()      # 兼容 IPv6 的 [::1] 写法
    port = int(port_part) if port_part.isdigit() else _DEFAULT_PORT
    if not host:
        writer.write(text_response("400 Bad Request", "CONNECT 目标格式非法\n"))
        await writer.drain()
        return

    # 注意：CONNECT 没有 URL（隧道里的一切都还不存在），meta.url 传 None。
    decision = ctx.engine.evaluate(
        RequestMeta(host=host, role=identity.role.value, url=None, method="CONNECT")
    )

    # ------------------------------------------------------------------ ②
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

    # ------------------------------------------------------------------ ③
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

    # 隧道建立成功：记一条 allow 审计（记录"谁在什么时候连了哪个 HTTPS 站点"）。
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

    # 告诉客户端隧道通了。此后这条连接上跑的就是它和源站之间的原始字节流。
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()

    # ------------------------------------------------------------------ ④
    # 双向对拷。两个方向各开一个任务，哪个先结束就把另一个取消——
    # 这样不用处理 TCP 半关闭（half-close），在 Windows 上也足够稳。
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
