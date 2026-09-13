"""审计登记的小工具（把"记一条审计"这件事收敛到一个函数）。

为什么要单独抽出来？
因为"普通 HTTP 转发"和"CONNECT 隧道"都要记审计，字段几乎一样。如果各写一遍，
很容易出现某一处漏字段、或者时间戳格式不一致的情况。收敛成一个函数后：

- 字段含义只有一处定义；
- 调用方只关心"这次是什么动作、命中什么规则、为什么"；
- 记审计是异步的（ctx.logger.log 只是入队），所以这个函数是 async 的，
  但开销极低，可以放心放在转发链路上。

注意它和"校验/判定"的区别：判定（engine.evaluate）是转发之前必须同步完成的快路径；
记审计（这里）是转发之后异步完成的慢路径。两者分离是本项目的核心设计。
"""

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
    """登记一条审计事件。

    client_ip / identity 来自连接层；action 取 "allow" / "block" / "error"。
    ts 由 AuditLogger 自动补上，这里不用管。
    """
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
