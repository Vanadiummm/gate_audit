"""规则数据和域名匹配。

- `*.gov.cn` 命中 gov.cn 及其子域
- `evil.com` 同样命中子域，避免 a.evil.com 绕过
- 正则对域名做 re.search
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Action(str, Enum):
    """过滤动作。"""

    ALLOW = "allow"
    BLOCK = "block"


class RuleKind(str, Enum):
    """规则种类，声明顺序即优先级。"""

    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    CATEGORY = "category"
    REGEX = "regex"


def normalize_host(host: str) -> str:
    """统一大小写、去掉端口与结尾的点，便于比较。"""
    host = (host or "").strip().lower().rstrip(".")
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host


def domain_matches(host: str, pattern: str) -> bool:
    """域名/通配匹配（语义见模块 docstring）。"""
    host = normalize_host(host)
    pattern = normalize_host(pattern)
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern or host.endswith("." + pattern)


@dataclass
class Rule:
    """一条过滤规则。"""

    kind: RuleKind
    pattern: str
    action: Action
    role_scope: str | None = None
    rule_id: str = ""
    _regex: re.Pattern | None = field(default=None, repr=False, compare=False)

    def compile(self) -> "Rule":
        """REGEX 预编译。"""
        if self.kind is RuleKind.REGEX:
            self._regex = re.compile(self.pattern)
        return self

    def applies_to(self, role: str) -> bool:
        """本规则是否对给定角色生效。"""
        return self.role_scope is None or self.role_scope == role

    def matches(self, host: str) -> bool:
        """分类规则由引擎配合 classifier 处理。"""
        if self.kind is RuleKind.REGEX:
            return bool(self._regex and self._regex.search(normalize_host(host)))
        return domain_matches(host, self.pattern)
