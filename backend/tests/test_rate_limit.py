from app.domains.identity.rate_limit import (
    LoginRateLimiter,
    login_rate_limiter,
)


def test_rate_limiter_allows_requests_below_threshold():
    limiter = LoginRateLimiter(
        max_failures=5,
        window_seconds=60,
    )

    ip_address = "192.0.2.10"

    for _ in range(4):
        limiter.record_failure(
            ip_address
        )

    is_limited, retry_after = (
        limiter.is_limited(
            ip_address
        )
    )

    assert is_limited is False
    assert retry_after == 0


def test_rate_limiter_blocks_at_threshold():
    limiter = LoginRateLimiter(
        max_failures=5,
        window_seconds=60,
    )

    ip_address = "192.0.2.20"

    for _ in range(5):
        limiter.record_failure(
            ip_address
        )

    is_limited, retry_after = (
        limiter.is_limited(
            ip_address
        )
    )

    assert is_limited is True
    assert retry_after > 0


def test_rate_limiter_tracks_ips_independently():
    limiter = LoginRateLimiter(
        max_failures=5,
        window_seconds=60,
    )

    attacker_ip = "192.0.2.30"
    normal_ip = "192.0.2.31"

    for _ in range(5):
        limiter.record_failure(
            attacker_ip
        )

    attacker_limited, _ = (
        limiter.is_limited(
            attacker_ip
        )
    )

    normal_limited, _ = (
        limiter.is_limited(
            normal_ip
        )
    )

    assert attacker_limited is True
    assert normal_limited is False


def test_rate_limiter_reset_clears_failures():
    limiter = LoginRateLimiter(
        max_failures=2,
        window_seconds=60,
    )

    ip_address = "192.0.2.40"

    limiter.record_failure(
        ip_address
    )
    limiter.record_failure(
        ip_address
    )

    is_limited, _ = limiter.is_limited(
        ip_address
    )

    assert is_limited is True

    limiter.reset()

    is_limited, retry_after = (
        limiter.is_limited(
            ip_address
        )
    )

    assert is_limited is False
    assert retry_after == 0

def test_login_endpoint_returns_429_after_failure_threshold(
    client,
    monkeypatch,
):
    """
    Verify the real login endpoint enforces
    the failed-login rate limit.
    """

    login_rate_limiter.reset()

    monkeypatch.setattr(
        "app.domains.identity.router.authenticate_user",
        lambda db, payload: None,
    )

    payload = {
        "email": "attacker@example.com",
        "password": "wrong-password",
    }

    try:
        for _ in range(5):
            response = client.post(
                "/api/v1/auth/login",
                json=payload,
            )

            assert response.status_code == 401

        blocked_response = client.post(
            "/api/v1/auth/login",
            json=payload,
        )

        assert blocked_response.status_code == 429

        assert blocked_response.json() == {
            "detail": (
                "Too many login attempts. "
                "Please try again later."
            )
        }

        assert (
            "Retry-After"
            in blocked_response.headers
        )

        assert int(
            blocked_response.headers[
                "Retry-After"
            ]
        ) > 0

    finally:
        login_rate_limiter.reset()