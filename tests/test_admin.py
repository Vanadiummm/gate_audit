"""管理端登录后的规则维护和落盘。鉴权见 test_admin_auth.py。"""

import json

from filter.engine import RequestMeta
from filter.rules import Action


def test_login_page_renders(admin_env):
    """登录页带 CSRF。"""
    resp = admin_env.client().get("/login")
    assert resp.status == 200
    assert "管理员登录" in resp.text
    assert 'name="_csrf"' in resp.text


def test_index_renders_rules_and_logs(root_client):
    """总览含规则、访问审计、管理操作日志。"""
    resp = root_client.get("/")
    assert resp.status == 200
    assert "过滤规则" in resp.text
    assert "evil.com" in resp.text
    assert "网络访问审计" in resp.text
    assert "管理操作日志" in resp.text


def test_add_rule_hot_reloads_and_persists(root_client, admin_env):
    """加规则后引擎、判定、config.json 同步更新。"""
    resp = root_client.post("/rules/add", {"kind": "blacklist", "pattern": "bad.test"})
    assert resp.status == 302

    assert "bad.test" in admin_env.ctx.engine.snapshot()["blacklist"]

    decision = admin_env.ctx.engine.evaluate(RequestMeta(host="bad.test"))
    assert decision.action is Action.BLOCK

    saved = json.loads(admin_env.cfg.path.read_text(encoding="utf-8"))
    assert "bad.test" in saved["rules"]["blacklist"]


def test_add_duplicate_rule_is_rejected(root_client, admin_env):
    """重复添加同一条规则应给出提示，而不是产生第二条重复规则。"""
    resp = root_client.post("/rules/add", {"kind": "blacklist", "pattern": "evil.com"})
    assert resp.status == 302

    rules = admin_env.ctx.engine.snapshot()["blacklist"]
    assert rules.count("evil.com") == 1             # 没有重复

    # 跟随一次首页，能看到错误提示
    page = root_client.get("/")
    assert "规则已存在" in page.text


def test_remove_rule(root_client, admin_env):
    """删规则应同时从引擎与配置文件里消失。"""
    resp = root_client.post("/rules/remove", {"kind": "blacklist", "pattern": "evil.com"})
    assert resp.status == 302
    assert "evil.com" not in admin_env.ctx.engine.snapshot()["blacklist"]

    saved = json.loads(admin_env.cfg.path.read_text(encoding="utf-8"))
    assert "evil.com" not in saved["rules"]["blacklist"]


def test_remove_missing_rule_reports_error(root_client):
    """删除不存在的规则应提示，而不是静默成功。"""
    resp = root_client.post("/rules/remove", {"kind": "blacklist", "pattern": "ghost.test"})
    assert resp.status == 302
    page = root_client.get("/")
    assert "未找到规则" in page.text


def test_admins_page_lists_accounts(root_client):
    """超管能看到账号管理页，并列出预置账号。"""
    resp = root_client.get("/admins")
    assert resp.status == 200
    assert "后台账号" in resp.text
    assert "root" in resp.text and "ops" in resp.text
    assert "superadmin" in resp.text


def test_admin_can_see_rules_but_not_accounts_nav(ops_client):
    """管理员登录后：能看总览，但导航里不应出现"账号管理"入口。"""
    index = ops_client.get("/")
    assert index.status == 200
    assert "过滤规则" in index.text
    assert "账号管理" not in index.text


def test_dangerous_card_hidden_for_admin(ops_client):
    """管理员不应看到危险操作卡片。"""
    page = ops_client.get("/")
    assert "危险操作" not in page.text


def test_dangerous_card_visible_for_superadmin(root_client):
    """超管应能看到危险操作卡片与默认策略。"""
    page = root_client.get("/")
    assert "危险操作" in page.text
    assert "allow" in page.text
