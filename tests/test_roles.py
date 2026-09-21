"""代理 Basic 认证：成功返回 Identity，失败返回 None。"""

import base64

from auth.admins import hash_password
from auth.roles import Role, RoleManager

# scrypt 慢，模块导入时只算一次，后面所有用例复用。
_ADMIN_HASH = hash_password("admin123")
_ALICE_HASH = hash_password("alice123")

USERS = {
    "admin": {"password_hash": _ADMIN_HASH, "role": "admin"},
    "alice": {"password_hash": _ALICE_HASH, "role": "user"},
}


def _basic(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def test_missing_header_is_rejected():
    assert RoleManager(USERS).authenticate(None) is None


def test_valid_admin_credentials():
    identity = RoleManager(USERS).authenticate(_basic("admin", "admin123"))
    assert identity is not None
    assert identity.user == "admin"
    assert identity.role is Role.ADMIN


def test_valid_normal_user_credentials():
    identity = RoleManager(USERS).authenticate(_basic("alice", "alice123"))
    assert identity is not None
    assert identity.user == "alice"
    assert identity.role is Role.USER


def test_wrong_password_is_rejected():
    assert RoleManager(USERS).authenticate(_basic("admin", "wrong")) is None


def test_malformed_base64_is_rejected():
    assert RoleManager(USERS).authenticate("Basic !!!not-base64!!!") is None


def test_non_basic_scheme_is_rejected():
    assert RoleManager(USERS).authenticate("Bearer some-token") is None


def test_plaintext_password_field_is_ignored():
    leftover = {
        "bob": {"password": "bob123", "role": "user"},
    }
    assert RoleManager(leftover).authenticate(_basic("bob", "bob123")) is None


def test_malformed_hash_is_rejected():
    broken = {
        "carol": {"password_hash": "not-a-real-hash", "role": "admin"},
    }
    assert RoleManager(broken).authenticate(_basic("carol", "not-a-real-hash")) is None