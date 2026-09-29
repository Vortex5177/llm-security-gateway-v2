"""内存令牌桶限流（per API key；单进程单用户场景，无需 Redis）。

语义：容量 = burst（缺省 = rpm），匀速回填 rpm/60 个令牌每秒；
取不到令牌即超限。时钟可注入便于测试。
"""

from __future__ import annotations

import threading
import time
from typing import Callable


class TokenBucket:
    __slots__ = ("capacity", "rate_per_sec", "tokens", "updated_at")

    def __init__(self, capacity: float, rate_per_sec: float, now: float) -> None:
        self.capacity = capacity
        self.rate_per_sec = rate_per_sec
        self.tokens = capacity
        self.updated_at = now

    def allow(self, now: float) -> bool:
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)
        self.updated_at = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    """按 key_hash 分桶；未配置 rpm_limit 的 key 直接放行（不占桶）。"""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def check(self, key_hash: str, rpm_limit: int | None, burst: int | None) -> bool:
        """True = 放行；False = 超限。"""
        if rpm_limit is None or rpm_limit <= 0:
            return True
        capacity = float(burst if (burst is not None and burst > 0) else rpm_limit)
        rate = rpm_limit / 60.0
        with self._lock:
            bucket = self._buckets.get(key_hash)
            now = self._clock()
            if bucket is None or bucket.rate_per_sec != rate or bucket.capacity != capacity:
                # 配置变更或首次见到：重建满桶
                bucket = TokenBucket(capacity, rate, now)
                self._buckets[key_hash] = bucket
            return bucket.allow(now)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
