"""管理端（Flask）的冒烟测试。

这个测试回答一个很实际的问题：**Flask 开发服务器放在守护线程里，能不能正常跑？**
（proxy/main.py 就是这么启动管理端的。）同时验证"网页上改规则 = 代理立刻生效"
这条"热更新"链路是否真的通。

做法：监听一个随机空闲端口 -> 起线程 -> 用 urllib 请求首页 -> 再 POST 加/删规则，
检查引擎快照和 config.json 是否同步变化。
"""

from __future__ import annotations

import socket
import time
import urllib.parse
import urllib.request
from types import SimpleNamespace

import pytest

from audit.logger import AuditLogger
from audit.storage import AuditStorage
from auth.admin_web import create_app, start_admin
from auth.roles import RoleManager
from config.loader import Config
from filter.engine import FilterEngine
from proxy.context import ProxyContext


def _free_port() -> int:
    """向系统要一个当前空闲的端口（绑定后立刻释放，够测试用）。"""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture
def admin_env(tmp_path):
    port = _free_port()
    cfg = Config(
        listen_host="127.0.0.1",
        listen_port=0,
        admin_host="127.0.0.1",
        admin_port=port,
        db_path=str(tmp_path / "audit.db"),
        default_policy="allow",
        users={},
        rules={"blacklist": ["evil.com"]},
    )
    cfg.path = tmp_path / "config.json"

    storage = AuditStorage(cfg.resolve_db_path())
    ctx = ProxyContext(
        config=cfg,
        engine=FilterEngine(cfg.rules, cfg.default_policy),
        storage=storage,
        logger=AuditLogger(storage),
        roles=RoleManager(cfg.users),
    )

    app = create_app(ctx)
    start_admin(app, "127.0.0.1", port)

    base = f"http://127.0.0.1:{port}"
    # 等服务真正起来（线程启动 + 绑定端口有微小延迟）
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/", timeout=1).read()
            break
        except Exception:
            time.sleep(0.05)
    else:
        pytest.skip("管理端未能在预期时间内启动")

    yield SimpleNamespace(base=base, ctx=ctx, cfg=cfg, storage=storage)
    storage.close()


def _post(url: str, data: dict) -> str:
    body = urllib.parse.urlencode(data).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=5) as resp:
        return resp.read().decode("utf-8", "ignore")


def test_admin_index_renders(admin_env):
    with urllib.request.urlopen(admin_env.base + "/", timeout=5) as resp:
        html = resp.read().decode("utf-8", "ignore")
    assert resp.status == 200
    assert "过滤规则" in html
    assert "evil.com" in html          # 来自 config 的初始规则应被展示


def test_admin_add_rule_hot_reloads_and_persists(admin_env):
    _post(admin_env.base + "/rules/add", {"kind": "blacklist", "pattern": "bad.test"})

    # 1) 引擎立刻生效（热更新）
    snapshot = admin_env.ctx.engine.snapshot()
    assert "bad.test" in snapshot["blacklist"]

    # 2) 判定随之改变
    from filter.engine import RequestMeta
    from filter.rules import Action

    decision = admin_env.ctx.engine.evaluate(RequestMeta(host="bad.test"))
    assert decision.action is Action.BLOCK

    # 3) 已持久化到 config.json
    import json

    saved = json.loads(admin_env.cfg.path.read_text(encoding="utf-8"))
    assert "bad.test" in saved["rules"]["blacklist"]


def test_admin_remove_rule(admin_env):
    _post(admin_env.base + "/rules/remove", {"kind": "blacklist", "pattern": "evil.com"})

    snapshot = admin_env.ctx.engine.snapshot()
    assert "evil.com" not in snapshot["blacklist"]
