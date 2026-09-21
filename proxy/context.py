"""运行期共享依赖，避免各模块各拿一份。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProxyContext:
    """一次运行的共享对象。用 object 避免循环 import。"""

    config: object    # config.loader.Config
    engine: object    # filter.engine.FilterEngine
    storage: object   # audit.storage.AuditStorage
    logger: object    # audit.logger.AuditLogger
    roles: object     # auth.roles.RoleManager
    admins: object    # auth.admins.AdminStore
    pool: object = None     # proxy.pool.UpstreamPool
    limits: object = None   # proxy.limits.LimitTracker
