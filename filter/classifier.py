"""网站粗分类：按域名后缀/关键词给出一个类别标签。

教学用途：演示"按网站类型过滤"。真实产品会用成熟的分类库或机器学习模型，
这里用最朴素的后缀 + 关键词规则，足够演示 category 规则怎么用。
"""

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
