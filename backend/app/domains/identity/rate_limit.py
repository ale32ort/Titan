from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class LoginRateLimiter:
    """
    In-memory failed-login rate limiter.

    This is appropriate for local development and a
    single-process deployment.

    A production multi-instance deployment should use
    shared storage such as Redis.
    """

    def __init__(
        self,
        *,
        max_failures: int,
        window_seconds: int,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds

        self._failures: dict[
            str,
            deque[float],
        ] = defaultdict(deque)

        self._lock = Lock()

    def _remove_expired(
        self,
        failures: deque[float],
        now: float,
    ) -> None:
        cutoff = now - self.window_seconds

        while (
            failures
            and failures[0] <= cutoff
        ):
            failures.popleft()

    def is_limited(
        self,
        key: str,
    ) -> tuple[bool, int]:
        """
        Return whether the key is currently limited
        and the approximate retry delay in seconds.
        """

        now = monotonic()

        with self._lock:
            failures = self._failures[key]

            self._remove_expired(
                failures,
                now,
            )

            if (
                len(failures)
                < self.max_failures
            ):
                return False, 0

            oldest_failure = failures[0]

            retry_after = max(
                1,
                int(
                    self.window_seconds
                    - (
                        now
                        - oldest_failure
                    )
                )
                + 1,
            )

            return True, retry_after

    def record_failure(
        self,
        key: str,
    ) -> None:
        """Record one failed authentication attempt."""

        now = monotonic()

        with self._lock:
            failures = self._failures[key]

            self._remove_expired(
                failures,
                now,
            )

            failures.append(now)

    def reset(self) -> None:
        """Clear limiter state. Primarily useful for tests."""

        with self._lock:
            self._failures.clear()


login_rate_limiter = LoginRateLimiter(
    max_failures=5,
    window_seconds=60,
)