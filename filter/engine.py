"""过滤引擎：纯逻辑、同步、无 IO 的判定核心。

为什么必须是"同步、无 IO、纯逻辑"：
按本项目的架构决策（见 docs/topic4_parsing_decision.md），判定必须发生在
"转发之前、内联"完成，也就是所谓"快路径"。既然它在每一次请求的关键路径上，
就必须极快、且不引入任何等待（不发网络请求、不写磁盘）。审计落库这类慢操作
被刻意挪到"转发之后、异步"去做——这就是快慢路径分离。

判定优先级（命中即返回，越靠前越优先）：
    白名单(放行) -> 黑名单(拦截) -> 网站类型(拦截) -> 正则(拦截) -> 默认策略
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from filter.classifier import classify
from filter.rules import Action, Rule, RuleKind, normalize_host


@dataclass
class RequestMeta:
    """交给引擎判断的最小信息集（域名快路径只需要这些）。"""

    host: str
    role: str = "user"
    url: str | None = None       # 普通 HTTP 才有完整 URL；CONNECT 隧道只有 host
    method: str | None = None


@dataclass
class Decision:
    """判定结果：动作 + 命中的规则（若无）+ 可读原因。"""

    action: Action
    rule: Rule | None = None
    reason: str = ""


# 各类规则对应的默认动作
_KIND_ACTION: dict[RuleKind, Action] = {
    RuleKind.WHITELIST: Action.ALLOW,
    RuleKind.BLACKLIST: Action.BLOCK,
    RuleKind.CATEGORY: Action.BLOCK,
    RuleKind.REGEX: Action.BLOCK,
}


class FilterEngine:
    """规则集合的持有者与判定入口。

    线程安全：代理核心（事件循环线程）会读规则，Flask 管理端（另一个线程）
    会热更新规则，因此内部用可重入锁保护规则列表。
    """

    def __init__(self, rules: dict | None = None, default_policy: str = "allow"):
        self._lock = threading.RLock()
        self._rules: list[Rule] = []
        self.default_policy = Action(default_policy)
        self.reload(rules or {})

    # ---------------- 规则装载 / 热更新 ----------------
    def reload(self, rules: dict) -> None:
        """用一份新的规则字典重建规则列表（管理端改规则后调用）。"""
        built: list[Rule] = []
        for kind, action in _KIND_ACTION.items():
            items = rules.get(kind.value, []) or []
            for index, item in enumerate(items):
                # 规则项支持两种写法：
                #   "evil.com"                       —— 对所有角色生效
                #   {"pattern": "x.com", "role": "user"} —— 仅对该角色生效
                if isinstance(item, str):
                    pattern, scope = item, None
                else:
                    pattern, scope = item.get("pattern", ""), item.get("role")
                built.append(
                    Rule(
                        kind=kind,
                        pattern=pattern,
                        action=action,
                        role_scope=scope,
                        rule_id=f"{kind.value}:{index}:{pattern}",
                    ).compile()
                )
        with self._lock:
            self._rules = built

    def snapshot(self) -> dict:
        """导出当前规则（供管理端展示，保持“字符串 / 字典”两种形态）。"""
        with self._lock:
            out: dict[str, list] = {k.value: [] for k in RuleKind}
            for r in self._rules:
                out[r.kind.value].append(
                    r.pattern if r.role_scope is None
                    else {"pattern": r.pattern, "role": r.role_scope}
                )
            return out

    # ---------------- 判定 ----------------
    def evaluate(self, meta: RequestMeta) -> Decision:
        host = normalize_host(meta.host)
        with self._lock:
            rules = list(self._rules)   # 拷一份，避免判定期间规则被改

        # 1) 白名单命中 -> 放行（优先级最高，用于给特定站点开绿灯）
        for r in rules:
            if r.kind is RuleKind.WHITELIST and r.applies_to(meta.role) and r.matches(host):
                return Decision(Action.ALLOW, r, f"白名单命中 {r.pattern}")

        # 2) 黑名单命中 -> 拦截
        for r in rules:
            if r.kind is RuleKind.BLACKLIST and r.applies_to(meta.role) and r.matches(host):
                return Decision(Action.BLOCK, r, f"黑名单命中 {r.pattern}")

        # 3) 网站类型命中 -> 拦截（先分类，再比对 category 规则）
        category = classify(host)
        for r in rules:
            if r.kind is RuleKind.CATEGORY and r.applies_to(meta.role) and r.pattern == category:
                return Decision(Action.BLOCK, r, f"网站类型[{category}]被禁止")

        # 4) 正则命中 -> 拦截
        for r in rules:
            if r.kind is RuleKind.REGEX and r.applies_to(meta.role) and r.matches(host):
                return Decision(Action.BLOCK, r, f"正则命中 {r.pattern}")

        # 5) 都没命中 -> 默认策略
        return Decision(self.default_policy, None, "未命中规则，按默认策略处理")
