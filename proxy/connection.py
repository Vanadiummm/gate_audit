"""把每条客户端连接分给 HTTP 转发或 CONNECT 隧道。"""

from __future__ import annotations

from proxy.connect import handle_connect
from proxy.forward import handle_http
from proxy.httpmsg import read_request_head, text_response, wants_keep_alive

_PROXY_AUTHENTICATE = 'Proxy-Authenticate: Basic realm="gate_audit"'


async def serve_client(reader, writer, ctx) -> None:
    peer = writer.get_extra_info("peername") or ("", 0)
    client_ip = peer[0] if isinstance(peer, (tuple, list)) and peer else str(peer)

    try:
        while True:
            head = await read_request_head(reader)
            if head is None:
                return

            identity = ctx.roles.authenticate(head.headers.get("proxy-authorization"))
            if identity is None:
                writer.write(
                    text_response(
                        "407 Proxy Authentication Required",
                        "需要代理认证（Proxy-Authorization: Basic）\n",
                        extra_headers=[_PROXY_AUTHENTICATE],
                    )
                )
                await writer.drain()
                return

            if ctx.limits is not None:
                ok, reason = ctx.limits.check(identity.user, identity.role.value)
                if not ok:
                    writer.write(
                        text_response(
                            "429 Too Many Requests",
                            f"超出限速或配额：{reason}\n",
                            extra_headers=["Retry-After: 1"],
                        )
                    )
                    await writer.drain()
                    return

            if head.method.upper() == "CONNECT":
                await handle_connect(reader, writer, head, ctx, identity, client_ip)
                return

            keep = await handle_http(reader, writer, head, ctx, identity, client_ip)
            if not ctx.config.keepalive or not keep:
                return
            if not wants_keep_alive(head.version, head.headers):
                return

    except Exception as exc:                      # noqa: BLE001
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
