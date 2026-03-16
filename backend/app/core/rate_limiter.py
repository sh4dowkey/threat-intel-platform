"""
Sliding-window rate limiter backed by Redis.

Usage:
    limiter = RateLimiter(key="virustotal", max_calls=4, period_seconds=60)
    await limiter.acquire()   # waits until a slot is free, then returns
"""

import asyncio
import time
from app.core.redis import get_redis


class RateLimiter:
    """
    Guarantees at most `max_calls` per `period_seconds` across all
    async workers, using a Redis sorted set of call timestamps.

    Algorithm:
      1. Remove timestamps older than the window
      2. Count how many calls remain in the window
      3. If under the limit — record this call and return immediately
      4. If at the limit — sleep until the oldest call expires, then retry
    """

    def __init__(self, key: str, max_calls: int, period_seconds: float):
        self.key = f"ratelimit:{key}"
        self.max_calls = max_calls
        self.period = period_seconds

    async def acquire(self) -> None:
        redis = await get_redis()

        while True:
            now = time.time()
            window_start = now - self.period

            pipe = redis.pipeline()
            pipe.zremrangebyscore(self.key, "-inf", window_start)
            pipe.zcard(self.key)
            _, count = await pipe.execute()

            if count < self.max_calls:
                # Slot is free — record this call
                await redis.zadd(self.key, {str(now): now})
                await redis.expire(self.key, int(self.period * 2))
                return

            # No slot — calculate exact wait time from the oldest entry
            oldest = await redis.zrange(self.key, 0, 0, withscores=True)
            if oldest:
                oldest_ts = oldest[0][1]
                wait = (oldest_ts + self.period) - time.time() + 0.1
                if wait > 0:
                    await asyncio.sleep(wait)
            else:
                await asyncio.sleep(0.5)


# ---------------------------------------------------------------------------
# Pre-configured limiters — one per external API, matching free tier limits
# ---------------------------------------------------------------------------

# VirusTotal free tier: 4 requests/minute, 500/day
# We enforce the per-minute limit; daily limit is tracked separately
virustotal_limiter = RateLimiter(
    key="virustotal",
    max_calls=4,
    period_seconds=60,
)

# AbuseIPDB free tier: 1 000 requests/day
# We allow up to 10/min so bursts feel responsive without burning the daily quota
abuseipdb_limiter = RateLimiter(
    key="abuseipdb",
    max_calls=10,
    period_seconds=60,
)

# OTX AlienVault: no hard rate limit published, keep it polite
otx_limiter = RateLimiter(
    key="otx",
    max_calls=10,
    period_seconds=60,
)

# Groq LLM: free tier is generous per-minute but has a daily token cap
# One explanation per alert is fine; 5/min leaves room for concurrent alerts
groq_limiter = RateLimiter(
    key="groq",
    max_calls=5,
    period_seconds=60,
)
