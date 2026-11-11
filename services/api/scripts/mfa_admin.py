#!/usr/bin/env python3
"""Operator recovery for a local account's second factor (run inside component-api).

    docker compose exec component-api python scripts/mfa_admin.py USERNAME \
        --reset --confirm-username USERNAME

Removes the account's authenticators and recovery codes and ends its local
sessions; the account owner is mailed a security notice. Where the policy
requires a second factor, enrolment is demanded again at the next sign-in.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.models import User  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.security.mfa import operator_reset  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("username")
    parser.add_argument("--reset", action="store_true", required=True)
    parser.add_argument("--confirm-username", required=True)
    args = parser.parse_args(argv)
    if args.username != args.confirm_username:
        parser.error("Confirmation must exactly match the username")
    with SessionLocal() as db:
        user = (
            db.query(User)
            .filter(User.username == args.username)
            .with_for_update()
            .one_or_none()
        )
        if user is None:
            parser.error("User not found")
        operator_reset(db, user)
        db.commit()
    print(
        "Local authenticators and recovery codes reset; local sessions revoked. "
        "Required MFA enrolment applies at next sign-in."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
