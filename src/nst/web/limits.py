"""
In-memory sliding-window rate limiting for the public demo.

One process serves the demo, so a per-process limiter is exact; no shared
store is needed.  Keys are client IP addresses (as reported by the
reverse proxy) or a fixed key for global quotas such as the upstream
GeoIP provider's request budget.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, Optional


class SlidingWindowLimiter:
    """Allow at most *limit* hits per *window* seconds for each key."""

    def __init__(
        self,
        limit: int,
        window: float,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._max_keys = max_keys
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, cost: int = 1) -> Optional[float]:
        """
        Record *cost* hits for *key*.

        Returns None when allowed, otherwise the number of seconds until
        enough of the window has passed (nothing is recorded then).
        """
        if cost > self.limit:
            return self.window
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self._max_keys:
                    self._evict(now)
                hits = deque()
                self._hits[key] = hits
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) + cost > self.limit:
                index = len(hits) + cost - self.limit - 1
                return max(0.0, self.window - (now - hits[index]))
            hits.extend([now] * cost)
            return None

    def _evict(self, now: float) -> None:
        """Drop keys whose whole window has expired (bounded memory)."""
        stale = [k for k, h in self._hits.items() if not h or now - h[-1] >= self.window]
        for key in stale:
            del self._hits[key]
