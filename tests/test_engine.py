"""过滤引擎与域名匹配。"""

from filter.classifier import classify
from filter.engine import FilterEngine, RequestMeta
from filter.rules import Action, RuleKind, domain_matches, normalize_host


def test_normalize_host():
    assert normalize_host("WWW.Example.COM.") == "www.example.com"
    assert normalize_host("example.com:8080") == "example.com"
    assert normalize_host("  Example.com  ") == "example.com"


def test_domain_matches_exact_and_subdomain():
    assert domain_matches("evil.com", "evil.com")
    assert domain_matches("a.evil.com", "evil.com")
    assert not domain_matches("notevil.com", "evil.com")
    assert not domain_matches("evil.com.evil.org", "evil.com")


def test_domain_matches_wildcard():
    # "*.gov.cn" 命中 gov.cn 本身及其任意子域
    assert domain_matches("www.gov.cn", "*.gov.cn")
    assert domain_matches("gov.cn", "*.gov.cn")
    assert domain_matches("a.b.gov.cn", "*.gov.cn")
    assert not domain_matches("gov.cn.evil.com", "*.gov.cn")


def test_classify():
    assert classify("www.gov.cn") == "gov"
    assert classify("tsinghua.edu.cn") == "edu"
    assert classify("casino-bet.com") == "gambling"
    assert classify("example.com") == "other"


def test_default_policy_allow():
    engine = FilterEngine(rules={}, default_policy="allow")
    decision = engine.evaluate(RequestMeta(host="example.com"))
    assert decision.action is Action.ALLOW
    assert decision.rule is None


def test_default_policy_block():
    engine = FilterEngine(rules={}, default_policy="block")
    decision = engine.evaluate(RequestMeta(host="example.com"))
    assert decision.action is Action.BLOCK


def test_blacklist_blocks():
    engine = FilterEngine({"blacklist": ["evil.com"]})
    assert engine.evaluate(RequestMeta(host="evil.com")).action is Action.BLOCK
    # 子域同样被拦
    assert engine.evaluate(RequestMeta(host="a.evil.com")).action is Action.BLOCK
    # 无关域名走默认放行
    assert engine.evaluate(RequestMeta(host="good.com")).action is Action.ALLOW


def test_whitelist_has_top_priority():
    """白名单优先级最高：同一域名既在白名单又在黑名单时，应放行。"""
    engine = FilterEngine({"whitelist": ["example.com"], "blacklist": ["example.com"]})
    assert engine.evaluate(RequestMeta(host="example.com")).action is Action.ALLOW


def test_category_blocks_by_classification():
    engine = FilterEngine({"category": ["gambling"]})
    # 域名含关键词 -> classifier 归为 gambling -> 命中 category 规则
    decision = engine.evaluate(RequestMeta(host="www.casino-bet.com"))
    assert decision.action is Action.BLOCK
    assert "gambling" in decision.reason
    # 普通站点不受影响
    assert engine.evaluate(RequestMeta(host="example.com")).action is Action.ALLOW


def test_regex_blocks():
    engine = FilterEngine({"regex": [r".*\.bet\d+\..*"]})
    assert engine.evaluate(RequestMeta(host="www.bet365.com")).action is Action.BLOCK
    assert engine.evaluate(RequestMeta(host="www.example.com")).action is Action.ALLOW


def test_role_scope_only_affects_scoped_role():
    """只对 user 生效的规则，不应影响 admin。"""
    rules = {"blacklist": [{"pattern": "secret.com", "role": "user"}]}
    engine = FilterEngine(rules)

    assert engine.evaluate(RequestMeta(host="secret.com", role="user")).action is Action.BLOCK
    assert engine.evaluate(RequestMeta(host="secret.com", role="admin")).action is Action.ALLOW


def test_reload_is_hot_effective():
    """reload 之后判定结果应立刻改变（模拟管理端热更新）。"""
    engine = FilterEngine({})
    assert engine.evaluate(RequestMeta(host="evil.com")).action is Action.ALLOW

    engine.reload({"blacklist": ["evil.com"]})
    assert engine.evaluate(RequestMeta(host="evil.com")).action is Action.BLOCK

    # snapshot 应能还原出当前规则，供管理端展示
    snapshot = engine.snapshot()
    assert snapshot[RuleKind.BLACKLIST.value] == ["evil.com"]


def test_snapshot_preserves_role_scoped_form():
    engine = FilterEngine({"blacklist": [{"pattern": "x.com", "role": "user"}]})
    assert engine.snapshot()["blacklist"] == [{"pattern": "x.com", "role": "user"}]
