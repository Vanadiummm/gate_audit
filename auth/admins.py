"""后台账号与权限：企业常用的两级权限模型。

## 为什么后台账号要单独一套，而不复用 auth/roles.py 里的代理账号？

        代理账号（config.users）        后台账号（config.admins）
        ----------------------------    ----------------------------
身份    上网的员工                      管代理的运维
数量    可能几百个                      通常个位数
认证    Proxy-Authorization（Basic）    表单登录 + Session
存储    明文（本轮刻意不动）            哈希（scrypt）
角色    admin / user                    superadmin / admin

两套身份的字段语义、存储要求、角色含义都不同。混在一起会带来两个具体问题：
    1) 改后台密码时可能误伤上网账号（同名字段冲突）；
    2) 权限泄露面失控 —— 上网的人数和管代理的人数根本不是一个量级。
所以在 config.json 里它们是独立的两个段。

## 为什么权限用"权限点 + 角色矩阵"，而不是在路由里判断角色？

路由只声明"我需要 EDIT_RULES 这个权限"，至于哪些角色拥有它，由 ROLE_PERMS 决定。
将来要加第三种角色（比如"只读审计员"），只需在矩阵里加一行，
不用翻遍所有路由去改 `if role == "superadmin"`。这就是这张表存在的意义。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum

from werkzeug.security import check_password_hash, generate_password_hash

# 连续登录失败达到这个次数就锁定（与 _LOCK_SECONDS 配合）
_MAX_FAILS = 5
# 锁定时长（秒）
_LOCK_SECONDS = 300


class AdminRole(str, Enum):
    """后台角色。继承 str 便于直接写 JSON、比较、打印。"""

    SUPERADMIN = "superadmin"   # 超管：管人 + 管规则 + 危险操作
    ADMIN = "admin"             # 管理员：改规则 + 看日志


class Perm(str, Enum):
    """权限点。路由只声明"需要哪个权限点"，不关心调用者是什么角色。"""

    VIEW_LOGS = "view_logs"           # 查看审计日志
    EDIT_RULES = "edit_rules"         # 增删过滤规则
    MANAGE_ADMINS = "manage_admins"   # 增删后台账号 / 重置密码
    DANGEROUS = "dangerous"           # 清空日志、切换默认策略


# 角色 -> 权限集合。这张表是整个权限模型的"唯一事实来源"。
ROLE_PERMS: dict[AdminRole, frozenset[Perm]] = {
    AdminRole.SUPERADMIN: frozenset(
        {Perm.VIEW_LOGS, Perm.EDIT_RULES, Perm.MANAGE_ADMINS, Perm.DANGEROUS}
    ),
    AdminRole.ADMIN: frozenset({Perm.VIEW_LOGS, Perm.EDIT_RULES}),
}


@dataclass
class AdminIdentity:
    """一个已登录后台用户的身份（只含展示需要的信息，不含任何凭据）。"""

    name: str
    role: AdminRole


def hash_password(raw: str) -> str:
    """把明文密码转成可安全存储的哈希串。

    用 werkzeug 的 generate_password_hash：Werkzeug 3.x 的默认算法是 scrypt，
    会自动生成随机盐，产出形如 "scrypt:32768:8:1$<salt>$<hash>" 的字符串。
    校验时不需要我们自己记录算法，因为算法前缀就写在哈希串里。

    注意：哈希串里含 "$"。手工把它拼进 shell 命令时，PowerShell 会把 $salt
    当变量插值，结果生成一个"看起来正常但永远校验失败"的错哈希。
    所以本文件末尾提供了 __main__ 工具，别手工拼命令（见文件底部）。
    """
    return generate_password_hash(raw)


def verify_password(stored_hash: str, raw: str) -> bool:
    """校验明文密码是否与哈希匹配。

    check_password_hash 自己会从哈希串里读出算法与盐，所以不用我们操心，
    也能兼容将来换算法后留下的旧哈希。
    """
    if not stored_hash:
        return False
    try:
        return check_password_hash(stored_hash, raw)
    except (ValueError, TypeError):
        # 哈希串格式非法（例如配置里误填了明文），一律按"校验失败"处理，
        # 绝不能因此抛异常导致管理端 500。
        return False


class AdminStore:
    """后台账号的持有者（内存中的账号表）。

    线程安全：管理端是 Flask 的多线程服务器（start_admin 传了 threaded=True），
    会并发读写这张表，所以用 RLock 保护，风格与 filter/engine.py 的 FilterEngine 一致。

    职责边界：本类只管"内存里的账号表"，**不负责写磁盘**。
    变更后由调用方（auth/admin_web.py）调用 config.loader.save_admins() 持久化。
    这样 AdminStore 不依赖配置文件路径，单元测试可以直接构造。
    """

    def __init__(self, admins: dict | None = None):
        self._lock = threading.RLock()
        # 内部结构：{用户名: {"password_hash": "...", "role": "superadmin"|"admin"}}
        self._admins: dict[str, dict] = {}
        for name, record in (admins or {}).items():
            self._admins[name] = {
                "password_hash": record.get("password_hash", ""),
                "role": str(record.get("role", AdminRole.ADMIN.value)),
            }
        # 登录失败计数：{(用户名, IP): [失败次数, 首次失败时间戳]}
        self._fails: dict[tuple[str, str], list] = {}

    # ------------------------------------------------------------------ 查询
    def get(self, name: str | None) -> AdminIdentity | None:
        """按用户名取身份；不存在返回 None（不抛异常）。

        返回 None 而不是抛异常，是为了让"账号已被删除，但旧会话还在"这种情况
        自然退化成"未登录"——管理端每请求都会调它，于是被删账号立即失效。
        """
        if not name:
            return None
        with self._lock:
            record = self._admins.get(name)
        if record is None:
            return None
        return AdminIdentity(name, self._role_of(record))

    def list(self) -> list[dict]:
        """账号列表（供管理端展示）。**刻意不返回哈希**，避免凭据泄露。"""
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
        """该角色是否拥有全部指定权限（权限矩阵的唯一查询入口）。

        入参做了归一化，字符串也能传（模板里写 can('edit_rules') 更顺手）：

            ⚠️ 这里有个很容易踩的坑：Perm 虽然继承了 str，但 Enum 的 __hash__
            是基于**成员名**的（hash("MANAGE_ADMINS")），而字符串值是
            "manage_admins"。两者的 hash 不同，所以 `'manage_admins' in
            frozenset({Perm.MANAGE_ADMINS})` 会返回 False ——
            必须先把字符串转成枚举成员再比对，不能依赖 str 的相等性。
        """
        try:
            role = role if isinstance(role, AdminRole) else AdminRole(role)
        except ValueError:
            return False

        owned = ROLE_PERMS.get(role, frozenset())
        for perm in perms:
            try:
                key = perm if isinstance(perm, Perm) else Perm(perm)
            except ValueError:
                return False          # 传了不认识的权限名，一律视为无权限
            if key not in owned:
                return False
        return True

    # ------------------------------------------------------------------ 认证
    def verify(self, name: str, password: str) -> AdminIdentity | None:
        """校验用户名 + 密码。成功返回身份，失败返回 None。"""
        with self._lock:
            record = self._admins.get(name)
        if record is None:
            return None
        if not verify_password(record.get("password_hash", ""), password):
            return None
        return AdminIdentity(name, self._role_of(record))

    # ------------------------------------------------------------------ 变更
    # 注意：以下方法只做"数据是否正确"的校验，**不做权限校验**。
    # 谁能调用它们由 auth/admin_web.py 的 require() 装饰器负责。职责分离。
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
            # 防止把后台彻底锁死：必须至少留一个超管，
            # 否则一旦删掉最后一个超管，就再也没人能登录进来管账号了。
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
            # 与 remove 同理：不能把最后一个超管降级，否则后台一样会锁死。
            if (
                record["role"] == AdminRole.SUPERADMIN.value
                and new_role != AdminRole.SUPERADMIN.value
                and self.count_superadmins() <= 1
            ):
                raise ValueError("必须至少保留一个超级管理员")
            record["role"] = new_role

    # ------------------------------------------------------- 登录失败限制
    def is_locked(self, name: str, ip: str = "") -> bool:
        """该 (用户名, IP) 组合是否处于锁定状态。

        为什么按 (用户名, IP) 而不是只按用户名？
        只按用户名的话，任何人只要故意连输 5 次错密码，就能把 root 锁死
        ——这本身就是一种拒绝服务攻击。加上 IP 后，锁只影响攻击来源。
        代价是攻击者换 IP 可以继续尝试；对教学项目这个权衡是合算的。
        """
        key = (name, ip)
        with self._lock:
            entry = self._fails.get(key)
            if not entry:
                return False
            fails, first_ts = entry
            if fails < _MAX_FAILS:
                return False
            if time.time() - first_ts > _LOCK_SECONDS:
                del self._fails[key]     # 锁定期已过，顺手清掉，避免字典无限增长
                return False
            return True

    def record_failure(self, name: str, ip: str = "") -> None:
        key = (name, ip)
        now = time.time()
        with self._lock:
            entry = self._fails.get(key)
            if not entry or now - entry[1] > _LOCK_SECONDS:
                # 首次失败，或上一次失败已超出统计窗口 -> 重新开始计数
                self._fails[key] = [1, now]
            else:
                entry[0] += 1

    def clear_failures(self, name: str, ip: str = "") -> None:
        with self._lock:
            self._fails.pop((name, ip), None)

    # ------------------------------------------------------------------ 导出
    def snapshot(self) -> dict:
        """导出成可直接写回 config.json 的 admins 段。"""
        with self._lock:
            return {
                name: {"password_hash": r["password_hash"], "role": r["role"]}
                for name, r in sorted(self._admins.items())
            }

    # ------------------------------------------------------------------ 内部
    @staticmethod
    def _role_of(record: dict) -> AdminRole:
        """把配置里的字符串角色转成枚举。

        无法识别时降级为 ADMIN（权限最小的那个），这是"失败安全"原则：
        配置写错宁可少给权限，也不能误判成超管。
        """
        try:
            return AdminRole(record.get("role", AdminRole.ADMIN.value))
        except ValueError:
            return AdminRole.ADMIN


def _main() -> None:
    """命令行工具：生成密码哈希。

        uv run python -m auth.admins <密码>

    为什么要做成模块命令？因为 scrypt 哈希串里含 "$"，手工往 shell 里拼
    很容易被 PowerShell 当变量插值（$salt 会被展开成空串），
    生成一个看起来正常、但永远校验失败的错哈希。用这个命令可以完全避免。
    """
    import sys

    if len(sys.argv) < 2:
        print("用法：uv run python -m auth.admins <密码>")
        raise SystemExit(2)
    print(hash_password(sys.argv[1]))


if __name__ == "__main__":
    _main()
