"""规则模型与域名匹配工具。

本模块只做"数据 + 纯函数"，无任何 IO，便于单元测试。

匹配语义刻意保持直白（也是这类系统最容易出错、最该讲清楚的地方）：
- 通配 "*.gov.cn"   -> 命中 gov.cn 本身，以及它的任意子域（如 www.gov.cn）。
- 普通 "evil.com"   -> 命中 evil.com 本身，以及它的任意子域（如 a.evil.com）。
  之所以"子域也算命中"，是为了防止有人用 a.evil.com 绕过对 evil.com 的封锁。
- 正则              -> 直接对域名做 re.search。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Action(str, Enum):
    """过滤动作。继承 str 便于直接写库/写日志时无需再转换。"""

    ALLOW = "allow"
    BLOCK = "block"


class RuleKind(str, Enum):
    """规则种类。声明顺序即优先级（越靠前越优先）。"""

    WHITELIST = "whitelist"   # 白名单：命中即放行（最高优先级）
    BLACKLIST = "blacklist"   # 黑名单：命中即拦截
    CATEGORY = "category"     # 网站类型：按 classifier 的分类结果拦截
    REGEX = "regex"           # 正则：对域名做正则匹配后拦截


def normalize_host(host: str) -> str:
    """统一大小写、去掉端口与结尾的点，便于比较。"""
    host = (host or "").strip().lower().rstrip(".")
    # 若不小心把 "host:port" 传进来，去掉端口部分（IPv6 用 [] 包裹，这里不处理）
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
    role_scope: str | None = None          # None=对所有角色生效；否则仅对指定角色生效
    rule_id: str = ""                      # 命中时写入审计，便于定位是哪条规则
    _regex: re.Pattern | None = field(default=None, repr=False, compare=False)

    def compile(self) -> "Rule":
        """预编译正则（仅 REGEX 需要），避免每次匹配都重复编译。"""
        if self.kind is RuleKind.REGEX:
            self._regex = re.compile(self.pattern)
        return self

    def applies_to(self, role: str) -> bool:
        """本规则是否对给定角色生效。"""
        return self.role_scope is None or self.role_scope == role

    def matches(self, host: str) -> bool:
        """判断域名是否命中本规则（分类规则由引擎配合 classifier 处理，不在此）。"""
        if self.kind is RuleKind.REGEX:
            return bool(self._regex and self._regex.search(normalize_host(host)))
        return domain_matches(host, self.pattern)
