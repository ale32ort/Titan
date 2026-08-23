from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domains.security.detections.authentication import (
    detect_password_spray,
    detect_repeated_login_failures,
    detect_success_after_failures,
)
from app.domains.security.evidence import FindingEvidence
from app.domains.security.findings import SecurityFinding
from app.domains.security.rules import (
    AUTH_001,
    AUTH_002,
    AUTH_003,
)

from conftest import create_audit_event


def test_auth_001_does_not_fire_below_threshold(
    db: Session,
):
    email = "auth001-negative@example.com"

    for _ in range(AUTH_001.threshold - 1):
        create_audit_event(
            db,
            event_type="LOGIN_FAILED",
            email=email,
            ip_address="10.0.0.10",
            result="failure",
        )

    detected = detect_repeated_login_failures(
        db,
        email=email,
    )

    finding = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.rule_id
            == AUTH_001.rule_id,
            SecurityFinding.subject
            == email,
        )
    )

    assert detected is False
    assert finding is None


def test_auth_001_creates_brute_force_finding(
    db: Session,
):
    email = "auth001-positive@example.com"

    created_events = []

    for _ in range(AUTH_001.threshold):
        created_events.append(
            create_audit_event(
                db,
                event_type="LOGIN_FAILED",
                email=email,
                ip_address="10.0.0.11",
                result="failure",
            )
        )

    detected = detect_repeated_login_failures(
        db,
        email=email,
    )

    finding = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.rule_id
            == AUTH_001.rule_id,
            SecurityFinding.subject
            == email,
        )
    )

    assert detected is True
    assert finding is not None

    assert (
        finding.finding_type
        == "AUTH_BRUTE_FORCE_SUSPECTED"
    )

    assert finding.severity == "high"
    assert finding.status == "open"
    assert finding.trigger_count == 1

    evidence = db.scalars(
        select(FindingEvidence).where(
            FindingEvidence.finding_id
            == finding.id
        )
    ).all()

    linked_event_ids = {
        item.audit_event_id
        for item in evidence
    }

    expected_event_ids = {
        event.id
        for event in created_events
    }

    assert linked_event_ids == expected_event_ids


def test_auth_002_uses_distinct_accounts_not_raw_failures(
    db: Session,
):
    source_ip = "10.0.0.20"

    # Generate many failures, but target only four
    # distinct accounts.
    #
    # AUTH-002 threshold is five distinct accounts,
    # so Titan must NOT fire.
    accounts = [
        "spray-a@example.com",
        "spray-b@example.com",
        "spray-c@example.com",
        "spray-d@example.com",
    ]

    for attempt_number in range(20):
        email = accounts[
            attempt_number % len(accounts)
        ]

        create_audit_event(
            db,
            event_type="LOGIN_FAILED",
            email=email,
            ip_address=source_ip,
            result="failure",
        )

    detected = detect_password_spray(
        db,
        ip_address=source_ip,
    )

    finding = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.rule_id
            == AUTH_002.rule_id,
            SecurityFinding.subject
            == source_ip,
        )
    )

    assert detected is False
    assert finding is None


def test_auth_002_fires_at_distinct_account_threshold(
    db: Session,
):
    source_ip = "10.0.0.21"

    created_events = []

    for account_number in range(
        AUTH_002.threshold
    ):
        created_events.append(
            create_audit_event(
                db,
                event_type="LOGIN_FAILED",
                email=(
                    f"spray-{account_number}"
                    "@example.com"
                ),
                ip_address=source_ip,
                result="failure",
            )
        )

    detected = detect_password_spray(
        db,
        ip_address=source_ip,
    )

    finding = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.rule_id
            == AUTH_002.rule_id,
            SecurityFinding.subject
            == source_ip,
        )
    )

    assert detected is True
    assert finding is not None

    assert (
        finding.finding_type
        == "PASSWORD_SPRAY_SUSPECTED"
    )

    assert finding.severity == "high"

    evidence = db.scalars(
        select(FindingEvidence).where(
            FindingEvidence.finding_id
            == finding.id
        )
    ).all()

    assert len(evidence) == len(
        created_events
    )


def test_auth_003_creates_finding_for_success_after_failures(
    db: Session,
):
    email = "auth003@example.com"

    start_time = datetime.now(
        timezone.utc
    ) - timedelta(seconds=30)

    failed_events = []

    for attempt_number in range(
        AUTH_003.threshold
    ):
        failed_events.append(
            create_audit_event(
                db,
                event_type="LOGIN_FAILED",
                email=email,
                ip_address="10.0.0.30",
                result="failure",
                created_at=(
                    start_time
                    + timedelta(
                        seconds=attempt_number
                    )
                ),
            )
        )

    success_event = create_audit_event(
        db,
        event_type="LOGIN_SUCCESS",
        email=email,
        ip_address="10.0.0.30",
        result="success",
        created_at=(
            start_time
            + timedelta(seconds=20)
        ),
    )

    detected = (
        detect_success_after_failures(
            db,
            email=email,
            success_event_id=(
                success_event.id
            ),
        )
    )

    finding = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.rule_id
            == AUTH_003.rule_id,
            SecurityFinding.subject
            == email,
        )
    )

    assert detected is True
    assert finding is not None

    assert (
        finding.finding_type
        == "SUCCESS_AFTER_REPEATED_FAILURES"
    )

    evidence = db.scalars(
        select(FindingEvidence).where(
            FindingEvidence.finding_id
            == finding.id
        )
    ).all()

    linked_event_ids = {
        item.audit_event_id
        for item in evidence
    }

    expected_event_ids = {
        event.id
        for event in failed_events
    }

    expected_event_ids.add(
        success_event.id
    )

    assert linked_event_ids == expected_event_ids

def test_auth_003_does_not_fire_for_non_success_event(
    db: Session,
):
    email = "auth003-wrong-event@example.com"

    start_time = datetime.now(
        timezone.utc
    ) - timedelta(seconds=30)

    for attempt_number in range(
        AUTH_003.threshold
    ):
        create_audit_event(
            db,
            event_type="LOGIN_FAILED",
            email=email,
            ip_address="10.0.0.31",
            result="failure",
            created_at=(
                start_time
                + timedelta(
                    seconds=attempt_number
                )
            ),
        )

    not_a_success_event = create_audit_event(
        db,
        event_type="LOGIN_FAILED",
        email=email,
        ip_address="10.0.0.31",
        result="failure",
        created_at=(
            start_time
            + timedelta(seconds=20)
        ),
    )

    detected = detect_success_after_failures(
        db,
        email=email,
        success_event_id=(
            not_a_success_event.id
        ),
    )

    assert detected is False


def test_auth_003_does_not_fire_when_success_precedes_failures(
    db: Session,
):
    email = "auth003-out-of-order@example.com"

    start_time = datetime.now(
        timezone.utc
    )

    success_event = create_audit_event(
        db,
        event_type="LOGIN_SUCCESS",
        email=email,
        ip_address="10.0.0.32",
        result="success",
        created_at=start_time,
    )

    for attempt_number in range(
        AUTH_003.threshold
    ):
        create_audit_event(
            db,
            event_type="LOGIN_FAILED",
            email=email,
            ip_address="10.0.0.32",
            result="failure",
            created_at=(
                start_time
                + timedelta(
                    seconds=attempt_number + 5
                )
            ),
        )

    detected = detect_success_after_failures(
        db,
        email=email,
        success_event_id=(
            success_event.id
        ),
    )

    assert detected is False