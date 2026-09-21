"""代理认证：Proxy-Authorization Basic，校验 password_hash。失败返回 None。"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import Enum

from auth.admins import verify_password


class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"


@dataclass
class Identity:
    user: str
    role: Role


class RoleManager:
    def __init__(self, users: dict | None = None):
        self._users = users or {}

    def authenticate(self, header: str | None) -> Identity | None:
        if not header or not header.lower().startswith("basic "):
            return None

        token = header.split(None, 1)[1].strip()
        try:
            raw = base64.b64decode(token).decode("utf-8", "ignore")
            username, _, password = raw.partition(":")
        except (binascii.Error, ValueError):
            return None

        record = self._users.get(username)
        if record and verify_password(record.get("password_hash", ""), password):
            return Identity(username, Role(record.get("role", "user")))
        return None
