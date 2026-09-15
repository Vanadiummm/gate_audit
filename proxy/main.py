"""程序入口：装配各模块并启动。

装配顺序（也就是本项目的"架构图"）：

    config.json ──> Config
                     │
                     ├─ AuditStorage(sqlite)  <── AuditLogger(asyncio.Queue) <── 转发路径
                     ├─ FilterEngine(规则)     <── 管理端热更新
                     ├─ RoleManager(账号/角色)
                     └─ ProxyContext 把上面这些打包，传给代理核心与管理端
                                          │
                      asyncio.start_server ─┘  (代理核心，监听 8080)
                      Flask 守护线程           (管理端，监听 5000)

运行时序：
    1. 起 Flask 管理端线程（daemon，随主进程退出而结束）；
    2. 起 asyncio 任务 AuditLogger.run()，持续把审计队列写进 sqlite；
    3. 起 asyncio TCP 服务，每个连接交给 proxy.connection.serve_client；
    4. serve_forever() 阻塞运行，直到 Ctrl+C。

启动命令（务必在 gate_audit 目录下，Python 3.12）：
    uv run python -m proxy.main
"""

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


def build_context() -> ProxyContext:
    """读配置、建各组件，打包成 ProxyContext。"""
    cfg = load_config()
    # session 签名密钥缺失时自动生成并写回配置文件，避免重启后登录态全部失效。
    ensure_secret_key(cfg)
    storage = AuditStorage(cfg.resolve_db_path())
    engine = FilterEngine(cfg.rules, cfg.default_policy)
    roles = RoleManager(cfg.users)
    admins = AdminStore(cfg.admins)
    logger = AuditLogger(storage)
    return ProxyContext(
        config=cfg,
        engine=engine,
        storage=storage,
        logger=logger,
        roles=roles,
        admins=admins,
    )


async def build_server(ctx: ProxyContext) -> asyncio.Server:
    """创建监听中的 asyncio TCP 服务。"""

    async def on_client(reader, writer):
        # start_server 的回调：每条连接调用一次。直接交给连接分派层。
        await serve_client(reader, writer, ctx)

    return await asyncio.start_server(
        on_client, ctx.config.listen_host, ctx.config.listen_port
    )


async def amain() -> None:
    ctx = build_context()

    # 管理端：Flask 跑在守护线程里，和代理共享同一份 engine / storage，
    # 所以网页上改规则能立刻影响代理（engine 内部有锁保证线程安全）。
    admin_app = create_admin_app(ctx)
    start_admin(admin_app, ctx.config.admin_host, ctx.config.admin_port)

    # 审计后台任务：不断把队列里的事件写进 sqlite。
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
        f"curl -x http://{ctx.config.listen_host}:{ctx.config.listen_port} http://example.com"
    )
    print("[gate_audit] 按 Ctrl+C 停止")

    try:
        async with server:
            await server.serve_forever()
    finally:
        logger_task.cancel()
        ctx.storage.close()


def main() -> None:
    """同步入口：跑事件循环，并把 Ctrl+C 处理干净。"""
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        # Windows 上 Ctrl+C 会以 KeyboardInterrupt 形式打断事件循环，
        # 这里吞掉它，打印一个友好的停止提示。
        print("\n[gate_audit] 已停止")


if __name__ == "__main__":
    main()
