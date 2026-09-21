"""管理端测试夹具：Flask + cookie 客户端（urllib 默认不带 cookie、会自动跟重定向）。"""

from __future__ import annotations

import http.cookiejar
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from audit.logger import AuditLogger
from audit.storage import AuditStorage
from auth.admin_web import create_app, start_admin
from auth.admins import AdminStore, hash_password
from auth.roles import RoleManager
from config.loader import Config
from filter.engine import FilterEngine
from proxy.context import ProxyContext

# 测试账号（与 admin_env fixture 里预置的一致）
ROOT = ("root", "root123")      # 超级管理员
OPS = ("ops", "ops123")         # 管理员

# scrypt 慢，模块导入时只算一次，避免每个用例都重新哈希。
_ROOT_HASH = hash_password(ROOT[1])
_OPS_HASH = hash_password(OPS[1])


def free_port() -> int:
    """向系统要一个当前空闲的端口。"""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@dataclass
class Resp:
    """统一的响应视图：状态码 + 正文 + Location 头。"""

    status: int
    text: str
    location: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁用自动重定向，这样 3xx 会以 HTTPError 抛出，便于断言跳转目标。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class AdminClient:
    """带 cookie、不自动跟随重定向的管理端测试客户端。"""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self._token_cache = ""
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            _NoRedirect(),
        )

    def _cookies(self) -> list:
        """当前持有的 cookie（供测试断言会话是否被轮换）。"""
        return list(self.jar)

    # ---------------------------------------------------------------- 底层请求
    def _open(self, url: str, data: bytes | None = None) -> Resp:
        req = urllib.request.Request(url, data=data)
        try:
            with self.opener.open(req, timeout=10) as resp:
                return Resp(
                    resp.status,
                    resp.read().decode("utf-8", "ignore"),
                    resp.headers.get("Location", "") or "",
                )
        except urllib.error.HTTPError as exc:
            # 3xx（被 _NoRedirect 拦下）、400、403 等都会走到这里
            body = exc.read().decode("utf-8", "ignore")
            return Resp(
                exc.code,
                body,
                (exc.headers.get("Location", "") if exc.headers else "") or "",
            )

    # ---------------------------------------------------------------- 便捷方法
    def get(self, path: str) -> Resp:
        return self._open(self.base + path)

    def post(self, path: str, fields: dict, csrf: bool = True) -> Resp:
        """发 POST。csrf=True 时自动带上会话里的 CSRF token。"""
        body = dict(fields)
        if csrf:
            body["_csrf"] = self.token()
        return self._open(self.base + path, urllib.parse.urlencode(body).encode())

    def token(self, page: str = "/") -> str:
        """登录成功会 session.clear()，缓存的 token 要丢掉。"""
        if not self._token_cache:
            html = self.get(page).text
            match = re.search(r'name="_csrf" value="([^"]+)"', html)
            self._token_cache = match.group(1) if match else ""
        return self._token_cache

    def login(self, username: str, password: str) -> Resp:
        self.token("/login")                     # 先 GET 登录页拿到 token
        resp = self.post("/login", {"username": username, "password": password})
        self._token_cache = ""                   # session.clear() 后旧 token 失效
        return resp

    def login_as_root(self) -> Resp:
        return self.login(*ROOT)

    def login_as_ops(self) -> Resp:
        return self.login(*OPS)


@pytest.fixture
def admin_env(tmp_path):
    """起一个真实的管理端，返回 base 地址、ctx、配置与数据库句柄。"""
    port = free_port()

    seed_admins = {
        "root": {"password_hash": _ROOT_HASH, "role": "superadmin"},
        "ops": {"password_hash": _OPS_HASH, "role": "admin"},
    }

    cfg = Config(
        listen_host="127.0.0.1",
        listen_port=0,
        admin_host="127.0.0.1",
        admin_port=port,
        db_path=str(tmp_path / "audit.db"),
        default_policy="allow",
        users={},
        admins=seed_admins,
        admin_secret_key="test-secret-key-only-for-tests",
        admin_session_minutes=30,
        rules={"blacklist": ["evil.com"]},
    )
    cfg.path = tmp_path / "config.json"
    cfg.path.write_text(
        json.dumps(
            {"users": {}, "admins": seed_admins, "rules": cfg.rules,
             "default_policy": "allow"},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    storage = AuditStorage(cfg.resolve_db_path())
    ctx = ProxyContext(
        config=cfg,
        engine=FilterEngine(cfg.rules, cfg.default_policy),
        storage=storage,
        logger=AuditLogger(storage),
        roles=RoleManager(cfg.users),
        admins=AdminStore(cfg.admins),
    )

    app = create_app(ctx)
    start_admin(app, "127.0.0.1", port)

    base = f"http://127.0.0.1:{port}"
    # 等端口就绪（守护线程启动 + 绑定端口有一点点延迟）
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/login", timeout=1).read()
            break
        except Exception:
            time.sleep(0.05)
    else:
        pytest.skip("管理端未能在预期时间内启动")

    yield SimpleNamespace(
        base=base,
        ctx=ctx,
        cfg=cfg,
        storage=storage,
        client=lambda: AdminClient(base),
    )
    storage.close()


@pytest.fixture
def root_client(admin_env):
    """已用超管登录的客户端。"""
    client = admin_env.client()
    resp = client.login_as_root()
    assert resp.status in (302, 303), f"超管登录失败：{resp.status}"
    return client


@pytest.fixture
def ops_client(admin_env):
    """已用管理员登录的客户端。"""
    client = admin_env.client()
    resp = client.login_as_ops()
    assert resp.status in (302, 303), f"管理员登录失败：{resp.status}"
    return client
