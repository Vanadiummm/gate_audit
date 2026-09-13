"""连接分派层：每个客户端连接进来后，先读首部，再决定走哪条路。

对代理来说，"一条 TCP 连接"的走向只有两种：
    - 首行是 CONNECT  -> HTTPS 隧道，交给 connect.handle_connect
    - 其他方法        -> 普通 HTTP 转发，交给 forward.handle_http

这一层同时负责：
    * 解析代理认证头（Proxy-Authorization）确定身份与角色；
    * 兜住"单条连接"的异常——一条连接出错不能让整个代理进程崩掉；
    * 统一关闭连接（finally）。

这就是所谓"错误隔离"：并发服务里，任何单个客户端的异常都应当被限制在它自己
那条连接里。
"""

from __future__ import annotations

from proxy.connect import handle_connect
from proxy.forward import handle_http
from proxy.httpmsg import read_request_head, text_response


async def serve_client(reader, writer, ctx) -> None:
    """处理一条客户端连接（asyncio.start_server 的回调会为每条连接调用一次）。"""

    # 客户端地址：peername 对 TCP 是 (ip, port)。取不到就留空。
    peer = writer.get_extra_info("peername") or ("", 0)
    client_ip = peer[0] if isinstance(peer, (tuple, list)) and peer else str(peer)

    try:
        # 1) 读请求首部。读到一半对端就关了（比如端口探测）会返回 None，直接收工。
        head = await read_request_head(reader)
        if head is None:
            return

        # 2) 认证与角色。未带代理认证头时按匿名 user 处理（方便用 curl 直接试）。
        identity = ctx.roles.authenticate(head.headers.get("proxy-authorization"))

        # 3) 按方法分派。
        if head.method.upper() == "CONNECT":
            await handle_connect(reader, writer, head, ctx, identity, client_ip)
        else:
            await handle_http(reader, writer, head, ctx, identity, client_ip)

    except Exception as exc:                      # noqa: BLE001 —— 兜底隔离
        # 单个连接出错只影响它自己：尽力回一个 502，然后由 finally 关闭。
        try:
            writer.write(text_response("502 Bad Gateway", f"代理内部错误：{exc}\n"))
            await writer.drain()
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
