"""限速与配额。0 表示不限制。"""

from __future__ import annotations

import pytest

from proxy.limits import LimitTracker


def test_zero_means_unlimited():
    t = LimitTracker({"user": {"rps": 0, "quota_requests": 0, "quota_bytes": 0}})
    for _ in range(20):
        ok, _ = t.check("alice", "user")
        assert ok


def test_rps_rejects_burst_beyond_rate():
    # rps=1：第一发过，紧接着第二发拒绝。
    t = LimitTracker({"user": {"rps": 1}})
    ok, _ = t.check("alice", "user")
    assert ok
    ok, reason = t.check("alice", "user")
    assert ok is False
    assert "rps" in reason


def test_quota_requests_then_429():
    t = LimitTracker({"user": {"quota_requests": 2, "quota_window": 3600}})
    assert t.check("alice", "user")[0] is True
    assert t.check("alice", "user")[0] is True
    ok, reason = t.check("alice", "user")
    assert ok is False
    assert "quota" in reason


def test_quota_is_per_user():
    t = LimitTracker({"user": {"quota_requests": 1}})
    assert t.check("alice", "user")[0] is True
    assert t.check("bob", "user")[0] is True
    assert t.check("alice", "user")[0] is False


def test_admin_and_user_use_different_spec():
    t = LimitTracker({
        "user": {"quota_requests": 1},
        "admin": {"quota_requests": 0},
    })
    assert t.check("alice", "user")[0] is True
    assert t.check("alice", "user")[0] is False
    assert t.check("root", "admin")[0] is True
    assert t.check("root", "admin")[0] is True


def test_quota_bytes_counted_after_transfer():
    t = LimitTracker({"user": {"quota_bytes": 10}})
    assert t.check("alice", "user")[0] is True
    t.add_bytes("alice", "user", 10)
    ok, reason = t.check("alice", "user")
    assert ok is False
    assert "bytes" in reason


@pytest.mark.asyncio
async def test_bps_sleeps_proportional_to_bytes():
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    t = LimitTracker({"user": {"bps": 100}}, sleep=fake_sleep)
    await t.throttle_bytes("alice", "user", 50)
    assert slept == [0.5]