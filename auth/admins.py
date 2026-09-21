"""后台账号：superadmin / admin，权限由 ROLE_PERMS 决定。与代理账号 users 分开存。"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum

from werkzeug.security import check_password_hash, generate_password_hash

_MAX_FAILS = 5
_LOCK_SECONDS = 300


class AdminRole(str, Enum):
    SUPERADMIN = "superadmin"
    ADMIN = "admin"


class Perm(str, Enum):
    VIEW_LOGS = "view_logs"
    EDIT_RULES = "edit_rules"
    MANAGE_ADMINS = "manage_admins"
    DANGEROUS = "dangerous"


ROLE_PERMS: dict[AdminRole, frozenset[Perm]] = {
    AdminRole.SUPERADMIN: frozenset(
        {Perm.VIEW_LOGS, Perm.EDIT_RULES, Perm.MANAGE_ADMINS, Perm.DANGEROUS}
    ),
    AdminRole.ADMIN: frozenset({Perm.VIEW_LOGS, Perm.EDIT_RULES}),
}


@dataclass
class AdminIdentity:
    """已登录后台用户。"""

    name: str
    role: AdminRole


def hash_password(raw: str) -> str:
    """scrypt 哈希。串里有 `$`，不要在 PowerShell 里手工拼接，用 `python -m auth.admins`。"""
    return generate_password_hash(raw)


def verify_password(stored_hash: str, raw: str) -> bool:
    """对照 password_hash。格式坏了当校验失败，不抛异常。"""
    if not stored_hash:
        return False
    try:
        return check_password_hash(stored_hash, raw)
    except (ValueError, TypeError):
        return False


class AdminStore:
    """内存里的后台账号。落盘由调用方 save_admins。Flask 多线程，用 RLock。"""

    def __init__(self, admins: dict | None = None):
        self._lock = threading.RLock()
        self._admins: dict[str, dict] = {}
        for name, record in (admins or {}).items():
            self._admins[name] = {
                "password_hash": record.get("password_hash", ""),
                "role": str(record.get("role", AdminRole.ADMIN.value)),
            }
        self._fails: dict[tuple[str, str], list] = {}  # (name, ip) -> [fails, first_ts]

    def get(self, name: str | None) -> AdminIdentity | None:
        """账号不存在则返回 None。"""
        if not name:
            return None
        with self._lock:
            record = self._admins.get(name)
        if record is None:
            return None
        return AdminIdentity(name, self._role_of(record))

    def list(self) -> list[dict]:
        """账号列表，不含 password_hash。"""
        with self._lock:
            return [
                {"name": name, "role": record["role"]}
                for name, record in sorted(self._admins.items())
            ]

    def count_superadmins(self) -> int:
        with self._lock:
            return sum(
                1
                for record in self._admins.values()
                if record["role"] == AdminRole.SUPERADMIN.value
            )

    def allows(self, role: AdminRole, *perms: Perm) -> bool:
        """字符串权限名先转 Perm 再比（Enum 哈希按成员名，不能直接和 str 比）。"""
        try:
            role = role if isinstance(role, AdminRole) else AdminRole(role)
        except ValueError:
            return False

        owned = ROLE_PERMS.get(role, frozenset())
        for perm in perms:
            try:
                key = perm if isinstance(perm, Perm) else Perm(perm)
            except ValueError:
                return False
            if key not in owned:
                return False
        return True

    def verify(self, name: str, password: str) -> AdminIdentity | None:
        """校验用户名 + 密码。成功返回身份，失败返回 None。"""
        with self._lock:
            record = self._admins.get(name)
        if record is None:
            return None
        if not verify_password(record.get("password_hash", ""), password):
            return None
        return AdminIdentity(name, self._role_of(record))

    def create(self, name: str, password: str, role: AdminRole) -> None:
        name = (name or "").strip()
        if not name:
            raise ValueError("用户名不能为空")
        if not password:
            raise ValueError("密码不能为空")
        with self._lock:
            if name in self._admins:
                raise ValueError(f"账号 {name} 已存在")
            self._admins[name] = {
                "password_hash": hash_password(password),
                "role": role.value if isinstance(role, AdminRole) else str(role),
            }

    def remove(self, name: str) -> None:
        with self._lock:
            record = self._admins.get(name)
            if record is None:
                raise ValueError(f"账号 {name} 不存在")
            if (
                record["role"] == AdminRole.SUPERADMIN.value
                and self.count_superadmins() <= 1
            ):
                raise ValueError("必须至少保留一个超级管理员")
            del self._admins[name]

    def set_password(self, name: str, password: str) -> None:
        if not password:
            raise ValueError("密码不能为空")
        with self._lock:
            record = self._admins.get(name)
            if record is None:
                raise ValueError(f"账号 {name} 不存在")
            record["password_hash"] = hash_password(password)

    def set_role(self, name: str, role: AdminRole) -> None:
        new_role = role.value if isinstance(role, AdminRole) else str(role)
        with self._lock:
            record = self._admins.get(name)
            if record is None:
                raise ValueError(f"账号 {name} 不存在")
            if (
                record["role"] == AdminRole.SUPERADMIN.value
                and new_role != AdminRole.SUPERADMIN.value
                and self.count_superadmins() <= 1
            ):
                raise ValueError("必须至少保留一个超级管理员")
            record["role"] = new_role

    def is_locked(self, name: str, ip: str = "") -> bool:
        """按 (用户名, IP) 锁定，避免按用户名就能把 root 锁死。"""
        key = (name, ip)
        with self._lock:
            entry = self._fails.get(key)
            if not entry:
                return False
            fails, first_ts = entry
            if fails < _MAX_FAILS:
                return False
            if time.time() - first_ts > _LOCK_SECONDS:
                del self._fails[key]
                return False
            return True

    def record_failure(self, name: str, ip: str = "") -> None:
        key = (name, ip)
        now = time.time()
        with self._lock:
            entry = self._fails.get(key)
            if not entry or now - entry[1] > _LOCK_SECONDS:
                self._fails[key] = [1, now]
            else:
                entry[0] += 1

    def clear_failures(self, name: str, ip: str = "") -> None:
        with self._lock:
            self._fails.pop((name, ip), None)

    def snapshot(self) -> dict:
        """导出成可直接写回 config.json 的 admins 段。"""
        with self._lock:
            return {
                name: {"password_hash": r["password_hash"], "role": r["role"]}
                for name, r in sorted(self._admins.items())
            }

    @staticmethod
    def _role_of(record: dict) -> AdminRole:
        """无法识别的角色当 admin。"""
        try:
            return AdminRole(record.get("role", AdminRole.ADMIN.value))
        except ValueError:
            return AdminRole.ADMIN


def _main() -> None:
    """打印 scrypt 哈希。PowerShell 里不要手工拼带 `$` 的串。"""
    import sys

    if len(sys.argv) < 2:
        print("用法：uv run python -m auth.admins <密码>")
        raise SystemExit(2)
    print(hash_password(sys.argv[1]))


if __name__ == "__main__":
    _main()
