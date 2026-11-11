"""Audit rows for sign-in attempts, alongside the request audit trail.

Ported from KEEN's ``record_sign_in``: the request trail records each
``/v1/auth/*`` request, and this adds one ``/action/sign-in`` row per attempt
that names the account the attempt reached, so an administrator can see which
account is under attack. A name that matches no account is never stored: it is
often a password typed into the wrong field. Refusals by the sign-in limits
add no row; their requests are already recorded within the audit allowance.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlencode

from fastapi import Request
from sqlalchemy.orm import Session

from app.db.models import AuditLog, User
from app.security.client_addr import request_client_address


def record_sign_in(
    db: Session,
    request: Request,
    *,
    method: str,
    outcome: str,
    account: User | None = None,
) -> None:
    """Add the audit row for one sign-in attempt; the caller commits."""

    user_agent = (request.headers.get("user-agent") or "").strip()[:256] or None
    db.add(
        AuditLog(
            ts=datetime.utcnow(),
            username=account.username if account is not None else None,
            method="ACTION",
            path="/action/sign-in",
            query_string=urlencode({"method": method, "outcome": outcome}),
            status_code=200,
            duration_ms=0,
            client_ip=request_client_address(request),
            user_agent=user_agent,
            referer=None,
        )
    )
