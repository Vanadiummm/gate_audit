"""角色与代理认证。

角色只有两级（题目要求"根据角色分配权限"）：
- admin：管理员，规则更宽松（例如不受只针对 user 的限制约束）。
- user ：普通用户，受更严格的规则约束（规则可用 role_scope 只对 user 生效）。

认证方式：HTTP Basic，且用代理专用的请求头 Proxy-Authorization：
    Proxy-Authorization: Basic base64("用户名:密码")
未带该头时视为匿名 user（这样用 curl 直接测也不用先配账号）。
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"


@dataclass
class Identity:
    """一次请求的身份：用户名 + 角色。"""

    user: str
    role: Role


class RoleManager:
    def __init__(self, users: dict | None = None):
        # users: {用户名: {"password": ..., "role": "admin"/"user"}}
        self._users = users or {}

    def authenticate(self, header: str | None) -> Identity:
        """解析 Proxy-Authorization 头并返回身份。

        - 头缺失 / 格式非法 -> 匿名 user。
        - 用户名密码正确     -> 对应角色。
        - 用户名存在但密码错 -> 按匿名 user 处理（演示用的宽松策略）。
        """
        if not header or not header.lower().startswith("basic "):
            return Identity("anonymous", Role.USER)

        token = header.split(None, 1)[1].strip()
        try:
            raw = base64.b64decode(token).decode("utf-8", "ignore")
            username, _, password = raw.partition(":")
        except (binascii.Error, ValueError):
            return Identity("anonymous", Role.USER)

        record = self._users.get(username)
        if record and record.get("password") == password:
            return Identity(username, Role(record.get("role", "user")))
        return Identity("anonymous", Role.USER)
