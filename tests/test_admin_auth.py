"""管理端：登录、权限边界、CSRF、开放重定向、最后超管保护。"""

import json

from audit.logger import AuditEvent
from auth.admins import AdminRole

from conftest import OPS, ROOT


def test_unauthenticated_index_redirects_to_login(admin_env):
    """未登录访问总览应被跳转到登录页，并记住原地址。"""
    resp = admin_env.client().get("/")
    assert resp.status == 302
    assert "/login" in resp.location
    assert "next=%2F" in resp.location or "next=/" in resp.location


def test_wrong_password_is_rejected_and_logged(admin_env):
    """错密码：不跳转、页面报错，并在 admin_audit 里留下 login.failed。"""
    client = admin_env.client()
    resp = client.login(ROOT[0], "wrong-password")
    assert resp.status == 200
    assert "用户名或密码错误" in resp.text

    failures = admin_env.storage.query_admin(action="login.failed")
    assert len(failures) == 1
    assert failures[0]["actor"] == "-"          # 未登录成功，操作者记为 "-"
    assert failures[0]["target"] == ROOT[0]


def test_correct_password_logs_in(admin_env):
    """正确密码：跳转回首页，且首页可访问。"""
    client = admin_env.client()
    resp = client.login(*ROOT)
    assert resp.status == 302
    assert client.get("/").status == 200

    ok = admin_env.storage.query_admin(action="login.ok")
    assert len(ok) == 1 and ok[0]["actor"] == ROOT[0]


def test_login_is_rate_limited(admin_env):
    """连续失败 5 次后，即使密码正确也会被锁定提示挡住。"""
    client = admin_env.client()
    for _ in range(5):
        client.login(ROOT[0], "bad")

    resp = client.login(*ROOT)                  # 这次密码是对的
    assert resp.status == 200
    assert "次数过多" in resp.text

    locked = admin_env.storage.query_admin(action="login.locked")
    assert len(locked) == 1


def test_lockout_is_scoped_to_client_ip(admin_env):
    """按 (用户名, IP) 计数：另一个 IP 不应被别人的失败连累。"""
    victim = admin_env.client()
    for _ in range(5):
        victim.login(ROOT[0], "bad")
    assert admin_env.ctx.admins.is_locked(ROOT[0], "127.0.0.1") is True
    assert admin_env.ctx.admins.is_locked(ROOT[0], "10.0.0.9") is False


def test_logout_invalidates_session(root_client):
    """登出后会话立即失效，再访问首页要重新登录。"""
    resp = root_client.post("/logout", {})
    assert resp.status == 302
    assert "/login" in resp.location
    assert root_client.get("/").status == 302


def test_post_without_csrf_token_is_rejected(ops_client, admin_env):
    """缺 CSRF 的 POST 回 400。"""
    resp = ops_client.post("/rules/add", {"kind": "blacklist", "pattern": "x.test"}, csrf=False)
    assert resp.status == 400
    assert "x.test" not in admin_env.ctx.engine.snapshot()["blacklist"]


def test_open_redirect_is_blocked(admin_env):
    """`next` 指向站外时回落到首页。"""
    for bad in ("http://evil.example/", "//evil.example/"):
        client = admin_env.client()
        client.token("/login")
        resp = client.post(
            f"/login?next={bad}",
            {"username": ROOT[0], "password": ROOT[1]},
        )
        assert resp.status == 302
        assert "evil.example" not in resp.location
        assert resp.location.endswith("/")


def test_session_is_rotated_after_login(admin_env):
    """登录应换一个全新的会话 cookie（防会话固定攻击）。

    登录成功后代码会 session.clear()，会话内容变了，签名后的 cookie 值自然不同。
    如果两者相同，就说明会话没被轮换，攻击者预先塞给受害者的 session id 会继续有效。
    """
    client = admin_env.client()
    client.get("/login")                              # 先拿一个匿名会话 cookie
    before = [c.value for c in client._cookies()]
    assert before, "匿名访问后应当已种下 session cookie"

    client.login(*ROOT)
    after = [c.value for c in client._cookies()]
    assert after, "登录后应当有新的 session cookie"
    assert before != after


def test_password_hash_is_never_rendered(root_client):
    """账号管理页绝不能回显密码哈希或明文密码。"""
    page = root_client.get("/admins").text
    assert "password_hash" not in page
    assert "scrypt:" not in page
    assert ROOT[1] not in page
    assert OPS[1] not in page


def test_admin_can_edit_rules_and_is_logged(ops_client, admin_env):
    """管理员能改规则，并写入操作日志。"""
    resp = ops_client.post("/rules/add", {"kind": "blacklist", "pattern": "bad2.test"})
    assert resp.status == 302
    assert "bad2.test" in admin_env.ctx.engine.snapshot()["blacklist"]

    added = admin_env.storage.query_admin(action="rules.add")
    assert len(added) == 1
    assert added[0]["actor"] == OPS[0]
    assert added[0]["target"] == "blacklist:bad2.test"


def test_admin_cannot_manage_accounts(ops_client, admin_env):
    """管理员没有 MANAGE_ADMINS：账号管理页与新建账号都应 403。"""
    assert ops_client.get("/admins").status == 403

    resp = ops_client.post(
        "/admins/create",
        {"name": "sneaky", "password": "p@ss1234", "role": "superadmin"},
    )
    assert resp.status == 403
    assert admin_env.ctx.admins.get("sneaky") is None    # 没有真的建出来


def test_admin_cannot_do_dangerous_actions(ops_client, admin_env):
    """管理员没有 DANGEROUS：清空日志与切换默认策略都应 403。"""
    admin_env.storage.write(AuditEvent(host="evil.com", port=80, action="block"))
    assert ops_client.post("/actions/purge-logs", {}).status == 403
    assert ops_client.post("/actions/policy", {"policy": "block"}).status == 403

    assert len(admin_env.storage.query(limit=10)) == 1
    assert admin_env.ctx.engine.default_policy.value == "allow"


def test_superadmin_can_create_account_and_persist(root_client, admin_env):
    """超管建账号：内存、config.json、操作日志一并更新。"""
    resp = root_client.post(
        "/admins/create",
        {"name": "newbie", "password": "p@ss1234", "role": "admin"},
    )
    assert resp.status == 302

    identity = admin_env.ctx.admins.get("newbie")
    assert identity is not None and identity.role is AdminRole.ADMIN

    saved = json.loads(admin_env.cfg.path.read_text(encoding="utf-8"))
    assert "newbie" in saved["admins"]
    assert saved["admins"]["newbie"]["role"] == "admin"
    assert saved["admins"]["newbie"]["password_hash"].startswith("scrypt:")
    # 明文密码绝不能出现在配置文件里
    assert "p@ss1234" not in admin_env.cfg.path.read_text(encoding="utf-8")

    created = admin_env.storage.query_admin(action="admin.create")
    assert len(created) == 1 and created[0]["target"] == "newbie"


def test_last_superadmin_cannot_be_removed(root_client, admin_env):
    """不能删掉最后一个超管。"""
    resp = root_client.post("/admins/remove", {"name": ROOT[0]})
    assert resp.status == 302

    assert admin_env.ctx.admins.get(ROOT[0]) is not None      # 账号仍在
    page = root_client.get("/admins")                        # flash 提示在下一页
    assert "至少保留一个超级管理员" in page.text


def test_last_superadmin_cannot_be_demoted(root_client, admin_env):
    """把最后一个超管降级同样要拒绝。"""
    root_client.post("/admins/role", {"name": ROOT[0], "role": "admin"})
    identity = admin_env.ctx.admins.get(ROOT[0])
    assert identity.role is AdminRole.SUPERADMIN


def test_password_reset_takes_effect(admin_env, root_client):
    """重置密码后：旧密码失效，新密码可登录。"""
    root_client.post("/admins/reset", {"name": OPS[0], "password": "brand-new-123"})

    old = admin_env.client().login(*OPS)
    assert old.status == 200 and "用户名或密码错误" in old.text

    new = admin_env.client().login(OPS[0], "brand-new-123")
    assert new.status == 302

    reset = admin_env.storage.query_admin(action="admin.reset")
    assert len(reset) == 1 and reset[0]["target"] == OPS[0]


def test_role_change_takes_effect_immediately(admin_env, root_client, ops_client):
    """把 ops 提升为超管后，它会立刻获得账号管理权限（无需重新登录）。"""
    assert ops_client.get("/admins").status == 403      # 提升之前无权限

    root_client.post("/admins/role", {"name": OPS[0], "role": "superadmin"})
    assert admin_env.ctx.admins.get(OPS[0]).role is AdminRole.SUPERADMIN

    # 同一个会话（没有重新登录）现在就能进账号管理页了 ——
    # 因为 current_admin() 每次请求都去查 AdminStore，而不是把角色缓存进 cookie。
    assert ops_client.get("/admins").status == 200


def test_removed_account_session_dies_immediately(admin_env, root_client):
    """账号被删除后，它的旧会话在下一次请求就失效。"""
    root_client.post("/admins/create", {"name": "temp1", "password": "temp-1234", "role": "admin"})
    victim = admin_env.client()
    assert victim.login("temp1", "temp-1234").status == 302
    assert victim.get("/").status == 200                # 现在能进

    root_client.post("/admins/remove", {"name": "temp1"})

    assert admin_env.ctx.admins.get("temp1") is None
    assert victim.get("/").status == 302                # 立刻被踢回登录页


def test_superadmin_purge_keeps_admin_audit(root_client, admin_env):
    """清访问日志，保留管理操作日志。"""
    for host in ("a.com", "b.com", "c.com"):
        admin_env.storage.write(AuditEvent(host=host, port=80, action="allow"))
    assert len(admin_env.storage.query(limit=10)) == 3

    resp = root_client.post("/actions/purge-logs", {})
    assert resp.status == 302

    assert admin_env.storage.query(limit=10) == []              # 访问日志清空
    kept = admin_env.storage.query_admin(limit=50)
    assert any(r["action"] == "logs.purge" for r in kept)       # 操作日志还在


def test_superadmin_switches_default_policy(root_client, admin_env):
    """切换默认策略应热更新到引擎并落盘。"""
    resp = root_client.post("/actions/policy", {"policy": "block"})
    assert resp.status == 302

    assert admin_env.ctx.engine.default_policy.value == "block"

    saved = json.loads(admin_env.cfg.path.read_text(encoding="utf-8"))
    assert saved["default_policy"] == "block"


def test_invalid_policy_value_is_rejected(root_client, admin_env):
    """非法策略值应被拒绝，不能污染配置。"""
    root_client.post("/actions/policy", {"policy": "whatever"})
    assert admin_env.ctx.engine.default_policy.value == "allow"
