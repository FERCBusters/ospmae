"""Housekeeping: expired/done rows must not accumulate without bound.

Expired login states, sessions, second-factor challenges, reset and
email-verification tokens, recognised browsers, forgotten sign-in throttles,
stale rate-limit ledger rows and audit rows past their retention are swept on
a beat schedule so an attacker's floods or normal traffic cannot grow those
tables forever.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from celery.utils.log import get_task_logger

from app.celery_app import celery_app
from app.core.config import settings
from app.db.models import (
    AuditLog,
    EmailVerificationToken,
    LoginDevice,
    LoginThrottle,
    MfaChallenge,
    OidcLoginState,
    PasswordResetToken,
    RateLimitEntry,
)
from app.db.models import Session as SessionRow
from app.db.session import SessionLocal
from app.security.sign_in_throttle import FORGET_FAILURES_AFTER

log = get_task_logger(__name__)


@celery_app.task(name="app.tasks.maintenance.sweep_expired_rows")
def sweep_expired_rows() -> dict:
    now = datetime.utcnow()
    db = SessionLocal()
    try:
        states = (
            db.query(OidcLoginState)
            .filter(OidcLoginState.expires_at <= now)
            .delete(synchronize_session=False)
        )
        resets_watched = (
            db.query(PasswordResetToken)
            .filter(PasswordResetToken.expires_at <= now)
            .delete(synchronize_session=False)
        )
        verifications = (
            db.query(EmailVerificationToken)
            .filter(EmailVerificationToken.expires_at <= now)
            .delete(synchronize_session=False)
        )
        ledger = (
            db.query(RateLimitEntry)
            .filter(RateLimitEntry.timestamp <= now - timedelta(hours=2))
            .delete(synchronize_session=False)
        )
        sessions = (
            db.query(SessionRow)
            .filter(SessionRow.expires_at <= now)
            .delete(synchronize_session=False)
        )
        challenges = (
            db.query(MfaChallenge)
            .filter(MfaChallenge.expires_at <= now)
            .delete(synchronize_session=False)
        )
        devices = (
            db.query(LoginDevice)
            .filter(LoginDevice.expires_at <= now)
            .delete(synchronize_session=False)
        )
        throttles = (
            db.query(LoginThrottle)
            .filter(LoginThrottle.last_failure_at <= now - FORGET_FAILURES_AFTER)
            .delete(synchronize_session=False)
        )

        # Zero keeps audit rows indefinitely.
        retention_days = int(settings.audit_log_retention_days)
        audits = 0
        if retention_days > 0:
            audits = (
                db.query(AuditLog)
                .filter(AuditLog.ts <= now - timedelta(days=retention_days))
                .delete(synchronize_session=False)
            )
        db.commit()
        return {
            "ok": True,
            "login_states": states,
            "password_resets": resets_watched,
            "email_verifications": verifications,
            "rate_limit_entries": ledger,
            "sessions": sessions,
            "mfa_challenges": challenges,
            "login_devices": devices,
            "login_throttles": throttles,
            "audit_logs": audits,
        }
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
