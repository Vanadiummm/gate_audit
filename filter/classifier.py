"""按后缀和关键词给域名贴一个类别标签。"""

from __future__ import annotations

# 后缀 -> 类别
_SUFFIX_RULES: list[tuple[str, str]] = [
    (".gov.cn", "gov"),
    (".edu.cn", "edu"),
    (".gov", "gov"),
    (".edu", "edu"),
    (".mil", "mil"),
]

# 关键词 -> 类别（域名里含该关键词即归类）
_KEYWORD_RULES: list[tuple[str, str]] = [
    ("gambling", "gambling"),
    ("casino", "gambling"),
    ("bet", "gambling"),
    ("porn", "adult"),
    ("xxx", "adult"),
]


def classify(host: str) -> str:
    """返回域名类别；未命中任何规则返回 "other"。"""
    host = (host or "").lower()
    for suffix, category in _SUFFIX_RULES:
        if host.endswith(suffix):
            return category
    for keyword, category in _KEYWORD_RULES:
        if keyword in host:
            return category
    return "other"
