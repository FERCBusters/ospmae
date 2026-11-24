#!/usr/bin/env python3
"""Operator recovery for a local account's second factor (run inside component-api).

    docker compose exec component-api python scripts/mfa_admin.py USERNAME \
        --reset --confirm-username USERNAME

Removes the account's authenticators and recovery codes and ends every
session; the account owner is mailed a security notice. Where the account can
sign in without SSO, its SSO identities and SSO email addresses go too. For an
account that signs in only through SSO, --list-identities shows its SSO
identities, and --keep-identity ID keeps the owner's while --link-address gives
an address confirmed with the owner when none of them is theirs. Where the
policy requires a second factor, enrolment is demanded again at the next
sign-in.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.models import User  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from mosp.security.mfa import operator_reset  # noqa: E402
from mosp.services.sso_emails import linked_identities  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("username")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--reset", action="store_true")
    action.add_argument(
        "--list-identities",
        action="store_true",
        help="list the account's SSO identities and change nothing",
    )
    parser.add_argument("--confirm-username")
    parser.add_argument(
        "--keep-identity",
        type=int,
        metavar="ID",
        help="with --reset, keep this SSO identity and remove every other SSO "
        "identity and SSO email address, for an account that signs in only "
        "through SSO",
    )
    parser.add_argument(
        "--link-address",
        metavar="EMAIL",
        help="with --reset, remove every SSO identity and SSO email address and "
        "make this address, confirmed with the owner, the account's only one, so "
        "the owner's next verified SSO sign-in links again",
    )
    args = parser.parse_args(argv)
    if args.reset and args.username != args.confirm_username:
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
        if args.list_identities:
            # Oldest first; a link someone planted is usually the newest. Its
            # address is the one it was linked through, for links made since
            # that was kept; older links show the provider's latest address.
            for i in sorted(
                linked_identities(db, user), key=lambda i: (i.created_at, i.id)
            ):
                print(
                    f"{i.id}\t{i.provider}\t{i.issuer} {i.subject}\t"
                    f"{i.display_name or i.preferred_username or '-'}\t"
                    f"{i.email or '-'}\tlinked {i.created_at:%Y-%m-%d %H:%M}\t"
                    f"last used {i.updated_at:%Y-%m-%d %H:%M}"
                )
            return 0
        try:
            operator_reset(
                db,
                user,
                keep_identity=args.keep_identity,
                link_address=args.link_address,
            )
        except ValueError as exc:
            parser.error(str(exc))
        db.commit()
    print(
        "Authenticators and recovery codes reset and every session ended; an "
        "account that can sign in without SSO also lost its SSO identities and "
        "SSO email addresses. Required MFA enrolment applies at next sign-in."
        + (
            " Every SSO identity but the one kept, and every SSO email address, "
            "was removed."
            if args.keep_identity is not None
            else ""
        )
        + (
            " Every SSO identity was removed, and the address given is the "
            "account's only SSO email address."
            if args.link_address
            else ""
        )
        + (
            ""
            if args.keep_identity is not None or args.link_address
            else " Where SSO identities were removed, an owner who has only ever "
            "signed in through SSO also needs a password reset."
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
