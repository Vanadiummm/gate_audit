"""运行期共享上下文。

为什么要把这些依赖打包成一个对象？
代理核心、管理端、审计后台任务都需要访问同一份"配置 / 过滤引擎 / 存储 / 日志器 /
角色管理器"。与其到处传 5 个参数、或者用全局单例（不易测试），不如显式打包成一个
轻量 dataclass 传递。好处：

1. 依赖一目了然：看到 ProxyContext 就知道系统由哪几块组成；
2. 便于测试：测试时可以塞入假的 engine / storage，而不用启动真实服务；
3. 保证"同一份"：管理端在网页上改规则，改的就是这里的 engine，代理立刻可见。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProxyContext:
    """一次运行的所有共享依赖。

    这里刻意不做类型标注的具体化（用 object），避免模块之间循环 import：
    context 被所有模块引用，若它再去 import 各具体类，就会成环。
    """

    config: object    # config.loader.Config        配置（含监听地址、规则、账号）
    engine: object    # filter.engine.FilterEngine  过滤引擎（快路径判定）
    storage: object   # audit.storage.AuditStorage   审计落库（sqlite）
    logger: object    # audit.logger.AuditLogger     审计异步缓冲（asyncio.Queue）
    roles: object     # auth.roles.RoleManager       代理认证与角色
    admins: object    # auth.admins.AdminStore       后台账号与权限（管理端登录用）
