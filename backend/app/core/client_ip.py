from ipaddress import ip_address

from fastapi import Request

from app.core.config import settings


def _get_trusted_proxy_ips() -> set[str]:
    """
    Return normalized trusted proxy addresses
    from application configuration.
    """

    trusted_ips: set[str] = set()

    for value in settings.TRUSTED_PROXY_IPS.split(","):
        candidate = value.strip()

        if not candidate:
            continue

        try:
            normalized = str(
                ip_address(candidate)
            )
        except ValueError:
            normalized = candidate

        trusted_ips.add(normalized)

    return trusted_ips


def get_client_ip(
    request: Request,
) -> str | None:
    """
    Resolve the client IP safely.

    Forwarded headers are trusted only when the
    immediate network peer is a configured proxy.
    """

    if request.client is None:
        return None

    direct_ip = request.client.host

    try:
        normalized_direct_ip = str(
            ip_address(direct_ip)
        )
    except ValueError:
        normalized_direct_ip = direct_ip

    trusted_proxy_ips = (
        _get_trusted_proxy_ips()
    )

    if (
        normalized_direct_ip
        not in trusted_proxy_ips
    ):
        return normalized_direct_ip

    forwarded_for = request.headers.get(
        "x-forwarded-for"
    )

    if not forwarded_for:
        return normalized_direct_ip

    first_forwarded_ip = (
        forwarded_for
        .split(",", maxsplit=1)[0]
        .strip()
    )

    try:
        return str(
            ip_address(first_forwarded_ip)
        )
    except ValueError:
        return normalized_direct_ip