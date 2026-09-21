"""按角色限制 rps / bps / 请求次数 / 流量。数值 0 表示不限制。"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class _Spec:
    rps: float = 0.0
    bps: float = 0.0
    quota_requests: int = 0
    quota_bytes: int = 0
    quota_window: float = 86400.0


class _Bucket:
    def __init__(self, rate: float, clock):
        self.rate = rate
        self.burst = max(rate, 1.0)
        self.tokens = self.burst
        self.updated = clock()
        self._clock = clock

    def try_take(self) -> bool:
        if self.rate <= 0:
            return True
        now = self._clock()
        self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class _Quota:
    def __init__(self, spec: _Spec, clock):
        self.spec = spec
        self._clock = clock
        self.reset_at = clock() + spec.quota_window
        self.requests = 0
        self.bytes = 0

    def _maybe_reset(self) -> None:
        now = self._clock()
        if now >= self.reset_at:
            self.requests = 0
            self.bytes = 0
            self.reset_at = now + self.spec.quota_window

    def can_request(self) -> tuple[bool, str]:
        self._maybe_reset()
        if self.spec.quota_requests and self.requests >= self.spec.quota_requests:
            return False, "quota_requests"
        if self.spec.quota_bytes and self.bytes >= self.spec.quota_bytes:
            return False, "quota_bytes"
        return True, ""

    def hit_request(self) -> None:
        self._maybe_reset()
        self.requests += 1

    def add_bytes(self, n: int) -> None:
        self._maybe_reset()
        self.bytes += n


class LimitTracker:
    def __init__(self, by_role: dict | None = None, *, clock=None, sleep=None):
        self._by_role = by_role or {}
        self._clock = clock or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._buckets: dict[str, _Bucket] = {}
        self._quotas: dict[str, _Quota] = {}

    def _spec(self, role: str) -> _Spec:
        raw = self._by_role.get(role) or {}
        return _Spec(
            rps=float(raw.get("rps", 0) or 0),
            bps=float(raw.get("bps", 0) or 0),
            quota_requests=int(raw.get("quota_requests", 0) or 0),
            quota_bytes=int(raw.get("quota_bytes", 0) or 0),
            quota_window=float(raw.get("quota_window", 86400) or 86400),
        )

    def _state(self, user: str, role: str) -> tuple[_Bucket, _Quota]:
        spec = self._spec(role)
        if user not in self._buckets:
            self._buckets[user] = _Bucket(spec.rps, self._clock)
            self._quotas[user] = _Quota(spec, self._clock)
        return self._buckets[user], self._quotas[user]

    def check(self, user: str, role: str) -> tuple[bool, str]:
        bucket, quota = self._state(user, role)
        ok, reason = quota.can_request()
        if not ok:
            return False, reason
        if not bucket.try_take():
            return False, "rps"
        quota.hit_request()
        return True, ""

    def add_bytes(self, user: str, role: str, n: int) -> None:
        _, quota = self._state(user, role)
        quota.add_bytes(n)

    async def throttle_bytes(self, user: str, role: str, n: int) -> None:
        spec = self._spec(role)
        if spec.bps <= 0 or n <= 0:
            return
        await self._sleep(n / spec.bps)
        self.add_bytes(user, role, n)
