"""令牌桶限流：边界、回填、配置变更、桶隔离（注入假时钟，不等真实时间）。"""

from __future__ import annotations

from app.ratelimit import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_unlimited_when_rpm_not_set():
    limiter = RateLimiter()
    for _ in range(1000):
        assert limiter.check("key-a", None, None) is True
        assert limiter.check("key-a", 0, None) is True


def test_burst_boundary_exact():
    clock = FakeClock()
    limiter = RateLimiter(clock)
    # rpm=60（每秒回填 1 个），burst=3：前 3 个放行，第 4 个拒
    assert [limiter.check("k", 60, 3) for _ in range(3)] == [True, True, True]
    assert limiter.check("k", 60, 3) is False


def test_refill_after_interval():
    clock = FakeClock()
    limiter = RateLimiter(clock)
    assert limiter.check("k", 60, 1) is True
    assert limiter.check("k", 60, 1) is False
    clock.now += 0.5  # 回填 0.5 个，仍不足 1
    assert limiter.check("k", 60, 1) is False
    clock.now += 0.5  # 累计回填 1 个
    assert limiter.check("k", 60, 1) is True


def test_default_burst_equals_rpm():
    clock = FakeClock()
    limiter = RateLimiter(clock)
    # burst 缺省 = rpm：rpm=2 → 桶容 2
    assert limiter.check("k", 2, None) is True
    assert limiter.check("k", 2, None) is True
    assert limiter.check("k", 2, None) is False


def test_bucket_rebuilt_on_config_change():
    clock = FakeClock()
    limiter = RateLimiter(clock)
    assert limiter.check("k", 60, 1) is True
    assert limiter.check("k", 60, 1) is False
    # 限额放宽后应重建满桶（立即放行 burst 个）
    assert [limiter.check("k", 120, 3) for _ in range(3)] == [True, True, True]
    assert limiter.check("k", 120, 3) is False


def test_buckets_isolated_per_key():
    clock = FakeClock()
    limiter = RateLimiter(clock)
    assert limiter.check("key-a", 60, 1) is True
    assert limiter.check("key-a", 60, 1) is False
    # 另一个 key 有独立的满桶
    assert limiter.check("key-b", 60, 1) is True


def test_reset_clears_buckets():
    limiter = RateLimiter()
    assert limiter.check("k", 60, 1) is True
    assert limiter.check("k", 60, 1) is False
    limiter.reset()
    assert limiter.check("k", 60, 1) is True
