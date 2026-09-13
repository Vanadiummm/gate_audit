"""角色认证的单元测试。

认证规则（见 auth/roles.py）：
- 没带 Proxy-Authorization      -> 匿名 user
- Basic 解析成功且账号密码正确   -> 对应角色
- 账号存在但密码错误 / 格式非法  -> 匿名 user
"""

import base64

from auth.roles import Role, RoleManager

USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "alice": {"password": "alice123", "role": "user"},
}


def _basic(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def test_missing_header_is_anonymous_user():
    identity = RoleManager(USERS).authenticate(None)
    assert identity.user == "anonymous"
    assert identity.role is Role.USER


def test_valid_admin_credentials():
    identity = RoleManager(USERS).authenticate(_basic("admin", "admin123"))
    assert identity.user == "admin"
    assert identity.role is Role.ADMIN


def test_valid_normal_user_credentials():
    identity = RoleManager(USERS).authenticate(_basic("alice", "alice123"))
    assert identity.user == "alice"
    assert identity.role is Role.USER


def test_wrong_password_falls_back_to_anonymous():
    identity = RoleManager(USERS).authenticate(_basic("admin", "wrong"))
    assert identity.user == "anonymous"
    assert identity.role is Role.USER


def test_malformed_base64_falls_back_to_anonymous():
    identity = RoleManager(USERS).authenticate("Basic !!!not-base64!!!")
    assert identity.user == "anonymous"
    assert identity.role is Role.USER


def test_non_basic_scheme_falls_back_to_anonymous():
    identity = RoleManager(USERS).authenticate("Bearer some-token")
    assert identity.user == "anonymous"
    assert identity.role is Role.USER
