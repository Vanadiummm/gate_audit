"""Flask 管理端：维护黑白名单、查看审计日志（演示用的最小实现）。

运行方式：在代理进程内用守护线程启动（见 proxy/main.py），因此它与代理核心
共享同一份 FilterEngine 和 AuditStorage 对象——在网页上改规则会立即对代理生效
（引擎内部有锁保护），这就是"热更新"。

注意：Flask 自带的开发服务器只适合演示，不要用于生产。
"""

from __future__ import annotations

import threading

from flask import Flask, redirect, render_template_string, request, url_for

from config.loader import save_rules

_PAGE = """
<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>gate_audit 管理端</title>
<style>
 body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#f6f7f9;color:#1f2937}
 header{background:#1f2937;color:#fff;padding:14px 22px;font-size:18px}
 main{max-width:980px;margin:22px auto;padding:0 16px}
 .card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px 18px;margin-bottom:18px}
 h2{font-size:15px;margin:0 0 12px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{border-bottom:1px solid #eee;padding:6px 8px;text-align:left}
 th{color:#555;font-weight:600}
 input,select{padding:5px 8px;border:1px solid #cbd5e1;border-radius:6px;font-size:13px}
 button{padding:5px 12px;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer;font-size:13px}
 .del{background:#dc2626}
 .tag{display:inline-block;padding:1px 7px;border-radius:10px;background:#eef2ff;color:#3730a3;font-size:12px}
</style></head><body>
<header>gate_audit · 管理端（规则维护 + 审计查询）</header>
<main>
  <div class="card">
    <h2>过滤规则</h2>
    <table>
      <tr><th style="width:120px">类型</th><th>模式</th><th style="width:90px"></th></tr>
      {% for kind, items in rules.items() %}{% for p in items %}
      <tr>
        <td><span class="tag">{{ kind }}</span></td>
        <td>{{ p.pattern if p is mapping else p }}</td>
        <td>
          {% set pat = p.pattern if p is mapping else p %}
          <form method="post" action="{{ url_for('remove_rule') }}">
            <input type="hidden" name="kind" value="{{ kind }}">
            <input type="hidden" name="pattern" value="{{ pat }}">
            <button class="del">删除</button>
          </form>
        </td>
      </tr>
      {% endfor %}{% endfor %}
    </table>
    <p></p>
    <form method="post" action="{{ url_for('add_rule') }}">
      <select name="kind">
        <option value="whitelist">whitelist</option>
        <option value="blacklist">blacklist</option>
        <option value="category">category</option>
        <option value="regex">regex</option>
      </select>
      <input name="pattern" placeholder="例如 evil.com / *.gov.cn / gambling" size="42">
      <button>添加</button>
    </form>
  </div>

  <div class="card">
    <h2>最近审计记录（最新 100 条）</h2>
    <table>
      <tr><th>时间</th><th>用户</th><th>角色</th><th>方法</th><th>目标</th><th>动作</th><th>原因</th></tr>
      {% for r in logs %}
      <tr>
        <td>{{ r.ts }}</td><td>{{ r.user }}</td><td>{{ r.role }}</td>
        <td>{{ r.method }}</td><td>{{ r.host }}:{{ r.port }}</td>
        <td>{{ r.action }}</td><td>{{ r.reason }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</main></body></html>
"""


def create_app(ctx) -> Flask:
    """创建 Flask 应用。ctx 提供 engine / storage / config 三个依赖。"""
    app = Flask("gate_audit_admin")

    @app.get("/")
    def index():
        return render_template_string(
            _PAGE,
            rules=ctx.engine.snapshot(),
            logs=ctx.storage.query(limit=100),
        )

    @app.post("/rules/add")
    def add_rule():
        kind = request.form.get("kind", "").strip()
        pattern = request.form.get("pattern", "").strip()
        if kind and pattern:
            rules = ctx.engine.snapshot()
            rules.setdefault(kind, [])
            existing = {p if isinstance(p, str) else p.get("pattern") for p in rules[kind]}
            if pattern not in existing:
                rules[kind].append(pattern)
            ctx.engine.reload(rules)          # 热更新（引擎内部已加锁）
            save_rules(ctx.config, rules)     # 持久化到 config.json
        return redirect(url_for("index"))

    @app.post("/rules/remove")
    def remove_rule():
        kind = request.form.get("kind", "").strip()
        pattern = request.form.get("pattern", "").strip()
        rules = ctx.engine.snapshot()
        items = rules.get(kind, [])
        kept = [p for p in items if (p if isinstance(p, str) else p.get("pattern")) != pattern]
        if len(kept) != len(items):
            rules[kind] = kept
            ctx.engine.reload(rules)
            save_rules(ctx.config, rules)
        return redirect(url_for("index"))

    return app


def start_admin(app: Flask, host: str, port: int) -> threading.Thread:
    """在守护线程里启动 Flask，避免和 asyncio 主循环抢线程。"""

    def _run() -> None:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)

    thread = threading.Thread(target=_run, name="admin-web", daemon=True)
    thread.start()
    return thread
