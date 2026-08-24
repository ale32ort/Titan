from app.core.config import settings


def test_sensor_ingestion_rejects_missing_api_key(
    client,
):
    response = client.post(
        "/api/v1/security/ingest/events",
        json={
            "source": "suricata",
            "event_type": "alert",
            "host": "titan-pi",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid sensor credentials."
    }


def test_sensor_ingestion_rejects_wrong_api_key(
    client,
):
    response = client.post(
        "/api/v1/security/ingest/events",
        headers={
            settings.SENSOR_INGEST_HEADER_NAME:
                "definitely-wrong"
        },
        json={
            "source": "suricata",
            "event_type": "alert",
            "host": "titan-pi",
        },
    )

    assert response.status_code == 401


def test_sensor_ingestion_accepts_authenticated_event(
    client,
):
    response = client.post(
        "/api/v1/security/ingest/events",
        headers={
            settings.SENSOR_INGEST_HEADER_NAME:
                settings.SENSOR_INGEST_API_KEY
        },
        json={
            "source": "suricata",
            "event_type": "alert",
            "host": "titan-pi",
            "source_ip": "192.0.2.50",
            "destination_ip": "192.0.2.60",
            "severity": "high",
            "message": "Possible reconnaissance",
            "metadata": {
                "signature_id": 2001219,
                "protocol": "TCP",
            },
        },
    )

    assert response.status_code == 202

    body = response.json()

    assert body["status"] == "accepted"
    assert body["source"] == "suricata"
    assert (
        body["event_type"]
        == "SENSOR_SURICATA_ALERT"
    )
    assert body["event_id"]