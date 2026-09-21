"""域名过滤：转发前同步判定。优先级 白名单 > 黑名单 > 类型 > 正则 > 默认策略。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from filter.classifier import classify
from filter.rules import Action, Rule, RuleKind, normalize_host


@dataclass
class RequestMeta:
    host: str
    role: str = "user"
    url: str | None = None
    method: str | None = None


@dataclass
class Decision:
    """动作、命中规则、原因。"""

    action: Action
    rule: Rule | None = None
    reason: str = ""


_KIND_ACTION: dict[RuleKind, Action] = {
    RuleKind.WHITELIST: Action.ALLOW,
    RuleKind.BLACKLIST: Action.BLOCK,
    RuleKind.CATEGORY: Action.BLOCK,
    RuleKind.REGEX: Action.BLOCK,
}


class FilterEngine:
    """规则列表。Flask 线程会 reload，代理线程会 evaluate，用 RLock。"""

    def __init__(self, rules: dict | None = None, default_policy: str = "allow"):
        self._lock = threading.RLock()
        self._rules: list[Rule] = []
        self.default_policy = Action(default_policy)
        self.reload(rules or {})

    def reload(self, rules: dict) -> None:
        """用新规则字典重建列表。"""
        built: list[Rule] = []
        for kind, action in _KIND_ACTION.items():
            items = rules.get(kind.value, []) or []
            for index, item in enumerate(items):
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
        """当前规则，形态与配置一致（字符串或 `{pattern, role}`）。"""
        with self._lock:
            out: dict[str, list] = {k.value: [] for k in RuleKind}
            for r in self._rules:
                out[r.kind.value].append(
                    r.pattern if r.role_scope is None
                    else {"pattern": r.pattern, "role": r.role_scope}
                )
            return out

    def evaluate(self, meta: RequestMeta) -> Decision:
        host = normalize_host(meta.host)
        with self._lock:
            rules = list(self._rules)

        for r in rules:
            if r.kind is RuleKind.WHITELIST and r.applies_to(meta.role) and r.matches(host):
                return Decision(Action.ALLOW, r, f"白名单命中 {r.pattern}")

        for r in rules:
            if r.kind is RuleKind.BLACKLIST and r.applies_to(meta.role) and r.matches(host):
                return Decision(Action.BLOCK, r, f"黑名单命中 {r.pattern}")

        category = classify(host)
        for r in rules:
            if r.kind is RuleKind.CATEGORY and r.applies_to(meta.role) and r.pattern == category:
                return Decision(Action.BLOCK, r, f"网站类型[{category}]被禁止")

        for r in rules:
            if r.kind is RuleKind.REGEX and r.applies_to(meta.role) and r.matches(host):
                return Decision(Action.BLOCK, r, f"正则命中 {r.pattern}")

        return Decision(self.default_policy, None, "未命中规则，按默认策略处理")
