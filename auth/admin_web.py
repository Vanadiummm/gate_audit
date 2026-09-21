"""Flask 管理端。代理用 Proxy-Authorization；后台用表单 + Session。权限看 ROLE_PERMS。"""

from __future__ import annotations

import functools
import secrets
from datetime import timedelta
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth.admins import AdminRole, Perm
from config.loader import save_admins, save_default_policy, save_rules
from filter.rules import Action

# 相对模板路径依赖启动时的 cwd，这里钉死到本文件旁边。
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def create_app(ctx) -> Flask:
    """创建 Flask 应用。"""

    app = Flask("gate_audit_admin", template_folder=str(_TEMPLATE_DIR))
    cfg = ctx.config

    app.secret_key = cfg.admin_secret_key or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=cfg.admin_session_minutes),
        # 本地是 http，开 SESSION_COOKIE_SECURE 会登不上。
    )

    # ------------------------------------------------------------------ 通用工具
    def current_admin():
        """当前后台用户；每次回查账号表。"""
        name = session.get("admin_user")
        return ctx.admins.get(name) if name else None

    def client_ip() -> str:
        """请求来源 IP。"""
        return request.remote_addr or ""

    def csrf_token() -> str:
        """会话 CSRF token。"""
        token = session.get("_csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf"] = token
        return token

    def check_csrf() -> None:
        """校验表单 CSRF。"""
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            abort(400, "CSRF 校验失败，请刷新页面后重试")

    def audit(action: str, target: str = "", detail: str = "", actor: str = "") -> None:
        """写 admin_audit。"""
        who = current_admin()
        ctx.storage.write_admin(
            actor=actor or (who.name if who else "-"),
            action=action,
            target=target,
            detail=detail,
            client_ip=client_ip(),
        )

    def can(*perms: Perm) -> bool:
        """当前用户是否拥有这些权限。"""
        who = current_admin()
        return bool(who) and ctx.admins.allows(who.role, *perms)

    def require(*perms: Perm):
        """未登录跳登录页；权限不足 403。"""

        def deco(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                who = current_admin()
                if who is None:
                    return redirect(url_for("login", next=request.path))
                if perms and not ctx.admins.allows(who.role, *perms):
                    abort(403, "当前账号没有该操作权限")
                return fn(*args, **kwargs)

            return wrapper

        return deco

    app.jinja_env.globals.update(can=can, csrf_token=csrf_token)

    @app.context_processor
    def _inject_identity():
        return {"who": current_admin()}

    # ------------------------------------------------------------------ 登录 / 登出
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_admin() is not None:
            return redirect(url_for("index"))

        error = None
        if request.method == "POST":
            check_csrf()
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            ip = client_ip()

            if ctx.admins.is_locked(username, ip):
                error = "登录失败次数过多，请 5 分钟后再试"
                audit("login.locked", target=username, detail="触发失败锁定", actor="-")
            else:
                who = ctx.admins.verify(username, password)
                if who is None:
                    ctx.admins.record_failure(username, ip)
                    audit("login.failed", target=username, detail="用户名或密码错误", actor="-")
                    error = "用户名或密码错误"
                else:
                    ctx.admins.clear_failures(username, ip)
                    session.clear()
                    session["admin_user"] = who.name
                    session.permanent = True
                    audit("login.ok", target=who.name, actor=who.name)

                    nxt = request.args.get("next") or ""
                    if not nxt.startswith("/") or nxt.startswith("//"):
                        nxt = url_for("index")
                    return redirect(nxt)

        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        who = current_admin()
        check_csrf()
        if who is not None:
            audit("logout", target=who.name, actor=who.name)
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------------------------------ 总览
    @app.get("/")
    @require(Perm.VIEW_LOGS)
    def index():
        return render_template(
            "index.html",
            rules=ctx.engine.snapshot(),
            logs=ctx.storage.query(limit=100),
            admin_logs=ctx.storage.query_admin(limit=50),
            default_policy=ctx.config.default_policy,
        )

    # ------------------------------------------------------------------ 规则维护
    @app.post("/rules/add")
    @require(Perm.EDIT_RULES)
    def add_rule():
        check_csrf()
        kind = (request.form.get("kind") or "").strip()
        pattern = (request.form.get("pattern") or "").strip()

        if not kind or not pattern:
            flash("类型和模式都不能为空", "error")
            return redirect(url_for("index"))

        rules = ctx.engine.snapshot()
        rules.setdefault(kind, [])
        existing = {p if isinstance(p, str) else p.get("pattern") for p in rules[kind]}
        if pattern in existing:
            flash(f"规则已存在：{pattern}", "error")
        else:
            rules[kind].append(pattern)
            ctx.engine.reload(rules)
            save_rules(ctx.config, rules)
            audit("rules.add", target=f"{kind}:{pattern}")
            flash(f"已添加规则 {kind} / {pattern}", "notice")
        return redirect(url_for("index"))

    @app.post("/rules/remove")
    @require(Perm.EDIT_RULES)
    def remove_rule():
        check_csrf()
        kind = (request.form.get("kind") or "").strip()
        pattern = (request.form.get("pattern") or "").strip()

        rules = ctx.engine.snapshot()
        items = rules.get(kind, [])
        kept = [p for p in items if (p if isinstance(p, str) else p.get("pattern")) != pattern]
        if len(kept) != len(items):
            rules[kind] = kept
            ctx.engine.reload(rules)
            save_rules(ctx.config, rules)
            audit("rules.remove", target=f"{kind}:{pattern}")
            flash(f"已删除规则 {kind} / {pattern}", "notice")
        else:
            flash(f"未找到规则 {pattern}", "error")
        return redirect(url_for("index"))

    @app.get("/admins")
    @require(Perm.MANAGE_ADMINS)
    def admins():
        return render_template(
            "admins.html",
            accounts=ctx.admins.list(),
            roles=[r.value for r in AdminRole],
        )

    @app.post("/admins/create")
    @require(Perm.MANAGE_ADMINS)
    def admin_create():
        check_csrf()
        name = (request.form.get("name") or "").strip()
        password = request.form.get("password") or ""
        role_raw = (request.form.get("role") or AdminRole.ADMIN.value).strip()
        try:
            role = AdminRole(role_raw)
            ctx.admins.create(name, password, role)
            save_admins(ctx.config, ctx.admins.snapshot())
            audit("admin.create", target=name, detail=f"角色 {role.value}")
            flash(f"已创建账号 {name}（{role.value}）", "notice")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("admins"))

    @app.post("/admins/remove")
    @require(Perm.MANAGE_ADMINS)
    def admin_remove():
        check_csrf()
        name = (request.form.get("name") or "").strip()
        try:
            ctx.admins.remove(name)
            save_admins(ctx.config, ctx.admins.snapshot())
            audit("admin.remove", target=name)
            flash(f"已删除账号 {name}", "notice")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("admins"))

    @app.post("/admins/reset")
    @require(Perm.MANAGE_ADMINS)
    def admin_reset():
        check_csrf()
        name = (request.form.get("name") or "").strip()
        password = request.form.get("password") or ""
        try:
            ctx.admins.set_password(name, password)
            save_admins(ctx.config, ctx.admins.snapshot())
            audit("admin.reset", target=name)
            flash(f"已重置 {name} 的密码", "notice")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("admins"))

    @app.post("/admins/role")
    @require(Perm.MANAGE_ADMINS)
    def admin_role():
        check_csrf()
        name = (request.form.get("name") or "").strip()
        role_raw = (request.form.get("role") or "").strip()
        try:
            role = AdminRole(role_raw)
            ctx.admins.set_role(name, role)
            save_admins(ctx.config, ctx.admins.snapshot())
            audit("admin.role", target=name, detail=f"新角色 {role.value}")
            flash(f"已把 {name} 的角色改为 {role.value}", "notice")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("admins"))

    # ------------------------------------------------------------------ 危险操作
    @app.post("/actions/purge-logs")
    @require(Perm.DANGEROUS)
    def purge_logs():
        check_csrf()
        deleted = ctx.storage.purge_audit()
        audit("logs.purge", detail=f"删除 {deleted} 条网络访问记录")
        flash(f"已清空网络访问日志（{deleted} 条）。管理操作日志已保留。", "notice")
        return redirect(url_for("index"))

    @app.post("/actions/policy")
    @require(Perm.DANGEROUS)
    def set_policy():
        check_csrf()
        policy = (request.form.get("policy") or "").strip().lower()
        if policy not in (Action.ALLOW.value, Action.BLOCK.value):
            flash("默认策略只能是 allow 或 block", "error")
            return redirect(url_for("index"))

        old = ctx.config.default_policy
        ctx.engine.default_policy = Action(policy)
        save_default_policy(ctx.config, policy)
        audit("policy.set", target=policy, detail=f"{old} -> {policy}")
        flash(f"默认策略已从 {old} 切换为 {policy}", "notice")
        return redirect(url_for("index"))

    return app


def start_admin(app: Flask, host: str, port: int) -> "threading.Thread":  # noqa: F821
    """在守护线程里跑 Flask（threaded=True）。"""
    import threading

    def _run() -> None:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)

    thread = threading.Thread(target=_run, name="admin-web", daemon=True)
    thread.start()
    return thread
