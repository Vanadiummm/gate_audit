"""HTTP 转发和 CONNECT 共用的审计入队。"""

from __future__ import annotations

from audit.logger import AuditEvent


async def record(
    ctx,
    *,
    client_ip: str,
    identity,
    method: str,
    host: str,
    port: int,
    action: str,
    reason: str,
    url: str | None = None,
    rule_id: str = "",
) -> None:
    await ctx.logger.log(
        AuditEvent(
            client_ip=client_ip,
            user=getattr(identity, "user", "anonymous"),
            role=getattr(getattr(identity, "role", None), "value", "user"),
            method=method,
            host=host,
            port=port,
            url=url,
            action=action,
            rule_id=rule_id,
            reason=reason,
        )
    )
