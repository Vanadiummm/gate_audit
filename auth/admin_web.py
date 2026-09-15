"""Flask 管理端：登录鉴权 + 两级权限（超管 / 管理员）。

## 认证方式为什么从 Basic 换成表单登录 + Session？

代理端必须用 Proxy-Authorization，那是代理协议规定的，没有替代方案。
但后台是网页，用 Basic 有三个硬伤：
    1) 无法"登出"——浏览器会一直带着凭据，除非关掉浏览器；
    2) 浏览器弹原生认证框，样式不可控、体验差；
    3) 无法做会话超时。
所以后台走 Flask 的签名 Session Cookie（itsdangerous 随 Flask 一并安装，无需新依赖）。

## 权限怎么落地？

路由上只写 @require(Perm.EDIT_RULES) 这样的"权限点声明"；
"哪些角色拥有哪些权限"完全由 auth/admins.py 的 ROLE_PERMS 决定。
将来新增一种角色（比如"只读审计员"），只需改矩阵一行，不用回来动任何路由。
模板里同理，用 {% if can('edit_rules') %} 控制按钮显隐。

## 安全措施清单（每条在对应代码处都有注释）

    - 密码以 scrypt 哈希存储，永不落明文、永不回显
    - 登录成功后 session.clear()  —— 防会话固定攻击
    - next 参数只允许站内相对路径 —— 防开放重定向
    - 所有改状态的 POST 都校验 CSRF token
    - 登录失败 5 次锁定 5 分钟（按 用户名 + IP 计数）
    - 删账号 / 降级时保护"最后一个超管" —— 防后台被永久锁死
    - 管理端自身操作也写审计（admin_audit）—— 做到"审计者被审计"

## 关于"改动即时生效"

管理端与代理跑在同一个进程里，共享同一份 FilterEngine / AuditStorage 对象
（见 proxy/main.py 的装配）。所以在网页上改规则，代理下一次请求就按新规则判定，
不需要重启——这就是热更新。引擎内部有锁，因此跨线程访问是安全的。

注意：Flask 自带的开发服务器只适合演示，不要用于生产。
"""

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

# 模板目录：必须用绝对路径。
# 若依赖 Flask 默认的相对路径（基于 app.root_path），一旦启动时的当前目录不同
# 就可能找不到模板，所以这里直接锚定到本文件所在目录。
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def create_app(ctx) -> Flask:
    """创建 Flask 应用。ctx 提供 config / engine / storage / admins 等依赖。"""

    app = Flask("gate_audit_admin", template_folder=str(_TEMPLATE_DIR))
    cfg = ctx.config

    # ------------------------------------------------------------------ 会话配置
    # secret_key 是用来签名 session cookie 的密钥，没有它 Flask 的 session 直接不可用。
    # 正常流程是 proxy/main.py 调 config.loader.ensure_secret_key() 在启动时生成并
    # 写回配置文件；这里再兜一层，避免测试或别的调用入口忘了生成时直接报错。
    app.secret_key = cfg.admin_secret_key or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,    # 禁止 JS 读取 cookie，缓解 XSS 窃取会话
        SESSION_COOKIE_SAMESITE="Lax",   # 跨站请求不携带 cookie，缓解 CSRF
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=cfg.admin_session_minutes),
        # 刻意【不】开启 SESSION_COOKIE_SECURE：本地是 http，开了浏览器就不回传
        # cookie，会导致"无论如何都登不上"。生产环境上了 HTTPS 才应该打开。
    )

    # ------------------------------------------------------------------ 通用工具
    def current_admin():
        """取当前登录的后台身份；未登录返回 None。

        每次都去查 AdminStore，而不是把角色塞进 cookie。好处是：
        超管删掉某个账号后，那个人的旧会话在下一次请求就立即失效，
        不需要额外写"踢下线"逻辑（因为 get() 查不到就返回 None）。
        """
        name = session.get("admin_user")
        return ctx.admins.get(name) if name else None

    def client_ip() -> str:
        """取请求来源 IP，写入审计日志用。"""
        return request.remote_addr or ""

    def csrf_token() -> str:
        """取（必要时生成）当前会话的 CSRF token。模板里用它填隐藏域。"""
        token = session.get("_csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf"] = token
        return token

    def check_csrf() -> None:
        """校验表单里的 CSRF token，不通过直接 400。

        为什么必须有：浏览器会自动带上本站 cookie 去发跨站请求。没有这道校验，
        别人只要诱导已登录的管理员打开一个恶意页面，那个页面上的隐藏表单
        就能"借用"管理员的身份把过滤规则改掉。
        """
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        # compare_digest 做常量时间比较，避免通过响应耗时差异反推 token
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            abort(400, "CSRF 校验失败，请刷新页面后重试")

    def audit(action: str, target: str = "", detail: str = "", actor: str = "") -> None:
        """记一条管理操作日志（写 admin_audit 表）。

        这是"审计者被审计"的落地：管理员自己改规则、删账号、登录失败，
        全都要留痕，否则后台就成了审计体系的盲区。
        """
        who = current_admin()
        ctx.storage.write_admin(
            actor=actor or (who.name if who else "-"),
            action=action,
            target=target,
            detail=detail,
            client_ip=client_ip(),
        )

    def can(*perms: Perm) -> bool:
        """当前登录者是否拥有全部指定权限（模板里用）。"""
        who = current_admin()
        return bool(who) and ctx.admins.allows(who.role, *perms)

    def require(*perms: Perm):
        """权限装饰器：在路由上声明"需要哪些权限点"。

        未登录 -> 跳登录页并记住原地址；已登录但权限不足 -> 403。
        """

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

    # 把 can() 和 csrf_token() 暴露给所有模板，省得每个 render_template 都传一遍。
    # 同时用 context_processor 注入 who，避免每个页面都忘记传当前身份。
    app.jinja_env.globals.update(can=can, csrf_token=csrf_token)

    @app.context_processor
    def _inject_identity():
        return {"who": current_admin()}

    # ------------------------------------------------------------------ 登录 / 登出
    @app.route("/login", methods=["GET", "POST"])
    def login():
        # 已登录就不必再看登录页
        if current_admin() is not None:
            return redirect(url_for("index"))

        error = None
        if request.method == "POST":
            check_csrf()
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            ip = client_ip()

            if ctx.admins.is_locked(username, ip):
                # 提示语刻意不区分"账号不存在/密码错误/被锁定"的真实原因，
                # 避免给攻击者提供"这个用户名存在"这类信息。
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
                    # 防会话固定攻击：登录成功后果断换一个全新会话。
                    # 否则攻击者可先诱导你用他掌握的 session id 访问站点，
                    # 你登录后那个 id 就变成了合法会话，他也就"顺带"登录了。
                    session.clear()
                    session["admin_user"] = who.name
                    session.permanent = True     # 启用 PERMANENT_SESSION_LIFETIME 超时
                    audit("login.ok", target=who.name, actor=who.name)

                    nxt = request.args.get("next") or ""
                    # 防开放重定向：只接受站内相对路径。
                    # 否则 /login?next=http://evil.com 会让我们的登录页
                    # 变成钓鱼跳板（用户看到的是可信域名，落地却是别人的站）。
                    # 额外排除 "//evil.com" 这种协议相对 URL。
                    if not nxt.startswith("/") or nxt.startswith("//"):
                        nxt = url_for("index")
                    return redirect(nxt)

        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        # 登出也用 POST 而不是 GET：GET 会被浏览器预取、被 <img> 引用，
        # 那样别人插一张图就能把你登出（一种很低成本的小骚扰）。
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
            ctx.engine.reload(rules)            # 热更新（引擎内部已加锁）
            save_rules(ctx.config, rules)       # 持久化到 config.json
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

    # ------------------------------------------------------------------ 账号管理
    # 以下四条都要求 MANAGE_ADMINS，即只有超管能用。
    @app.get("/admins")
    @require(Perm.MANAGE_ADMINS)
    def admins():
        return render_template(
            "admins.html",
            accounts=ctx.admins.list(),          # 注意：只含 name/role，不含哈希
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
            # "必须至少保留一个超级管理员"的兜底判断在 AdminStore.remove() 里，
            # 业务规则放在数据层可以保证"无论从哪个入口调用都不会破坏它"。
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
        # 注意：purge_audit 只清 audit（网络访问），不清 admin_audit，
        # 所以"谁清空了日志"这件事本身仍然留在管理操作日志里。
        audit("logs.purge", detail=f"删除 {deleted} 条网络访问记录")
        flash(f"已清空网络访问日志（{deleted} 条）。管理操作日志刻意保留。", "notice")
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
        ctx.engine.default_policy = Action(policy)   # 热更新到引擎
        save_default_policy(ctx.config, policy)      # 落盘，否则重启就还原
        audit("policy.set", target=policy, detail=f"{old} -> {policy}")
        flash(f"默认策略已从 {old} 切换为 {policy}", "notice")
        return redirect(url_for("index"))

    return app


def start_admin(app: Flask, host: str, port: int) -> "threading.Thread":  # noqa: F821
    """在守护线程里启动 Flask，避免和 asyncio 主循环抢线程。

    threaded=True 让 Flask 能并发处理请求；正因为是多线程，
    FilterEngine / AdminStore / AuditStorage 内部都用锁做了保护。
    """
    import threading

    def _run() -> None:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)

    thread = threading.Thread(target=_run, name="admin-web", daemon=True)
    thread.start()
    return thread
