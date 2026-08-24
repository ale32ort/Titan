from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.core import client_ip


def create_test_app() -> FastAPI:
    app = FastAPI()

    @app.get("/client-ip")
    def client_ip_endpoint(
        request: Request,
    ):
        return {
            "ip": client_ip.get_client_ip(
                request
            )
        }

    return app


def test_direct_client_ip_is_used(
    monkeypatch,
):
    monkeypatch.setattr(
        client_ip.settings,
        "TRUSTED_PROXY_IPS",
        "",
    )

    app = create_test_app()

    with TestClient(app) as client:
        response = client.get(
            "/client-ip"
        )

    assert response.status_code == 200

    assert response.json()["ip"] == (
        "testclient"
    )


def test_untrusted_client_cannot_spoof_forwarded_ip(
    monkeypatch,
):
    monkeypatch.setattr(
        client_ip.settings,
        "TRUSTED_PROXY_IPS",
        "",
    )

    app = create_test_app()

    with TestClient(app) as client:
        response = client.get(
            "/client-ip",
            headers={
                "X-Forwarded-For":
                    "203.0.113.50"
            },
        )

    assert response.status_code == 200

    assert response.json()["ip"] == (
        "testclient"
    )


def test_trusted_proxy_uses_forwarded_client_ip(
    monkeypatch,
):
    monkeypatch.setattr(
        client_ip.settings,
        "TRUSTED_PROXY_IPS",
        "testclient",
    )

    app = create_test_app()

    with TestClient(app) as client:
        response = client.get(
            "/client-ip",
            headers={
                "X-Forwarded-For":
                    "203.0.113.50"
            },
        )

    assert response.status_code == 200

    assert response.json()["ip"] == (
        "203.0.113.50"
    )


def test_invalid_forwarded_ip_falls_back_to_proxy(
    monkeypatch,
):
    monkeypatch.setattr(
        client_ip.settings,
        "TRUSTED_PROXY_IPS",
        "testclient",
    )

    app = create_test_app()

    with TestClient(app) as client:
        response = client.get(
            "/client-ip",
            headers={
                "X-Forwarded-For":
                    "definitely-not-an-ip"
            },
        )

    assert response.status_code == 200

    assert response.json()["ip"] == (
        "testclient"
    )