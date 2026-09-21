"""装配配置、过滤、审计、管理端后启动代理。"""

from __future__ import annotations

import asyncio

from audit.logger import AuditLogger
from audit.storage import AuditStorage
from auth.admin_web import create_app as create_admin_app
from auth.admin_web import start_admin
from auth.admins import AdminStore
from auth.roles import RoleManager
from config.loader import ensure_secret_key, load_config
from filter.engine import FilterEngine
from proxy.connection import serve_client
from proxy.context import ProxyContext
from proxy.limits import LimitTracker
from proxy.pool import UpstreamPool


def build_context() -> ProxyContext:
    """读配置并组装 ProxyContext。"""
    cfg = load_config()
    ensure_secret_key(cfg)
    storage = AuditStorage(cfg.resolve_db_path())
    engine = FilterEngine(cfg.rules, cfg.default_policy)
    roles = RoleManager(cfg.users)
    admins = AdminStore(cfg.admins)
    logger = AuditLogger(storage)
    pool = UpstreamPool(cfg.pool_max_per_host, cfg.pool_idle_seconds)
    limits = LimitTracker(cfg.limits)
    return ProxyContext(
        config=cfg,
        engine=engine,
        storage=storage,
        logger=logger,
        roles=roles,
        admins=admins,
        pool=pool,
        limits=limits,
    )


async def build_server(ctx: ProxyContext) -> asyncio.Server:
    """asyncio TCP 服务。"""

    async def on_client(reader, writer):
        await serve_client(reader, writer, ctx)

    return await asyncio.start_server(
        on_client, ctx.config.listen_host, ctx.config.listen_port
    )


async def amain() -> None:
    ctx = build_context()

    admin_app = create_admin_app(ctx)
    start_admin(admin_app, ctx.config.admin_host, ctx.config.admin_port)

    logger_task = asyncio.create_task(ctx.logger.run())

    server = await build_server(ctx)
    listen = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[gate_audit] 代理监听      : {listen}")
    print(
        f"[gate_audit] 管理端        : "
        f"http://{ctx.config.admin_host}:{ctx.config.admin_port}"
    )
    print(
        f"[gate_audit] 试用          : "
        f"curl -x http://{ctx.config.listen_host}:{ctx.config.listen_port} "
        f"-U alice:alice123 http://example.com"
    )
    print("[gate_audit] 按 Ctrl+C 停止")

    try:
        async with server:
            await server.serve_forever()
    finally:
        logger_task.cancel()
        if ctx.pool is not None:
            await ctx.pool.close()
        ctx.storage.close()


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("\n[gate_audit] 已停止")


if __name__ == "__main__":
    main()
