"""The operator's account recovery script."""

import pytest
from app.db.models import UserIdentity, UserSsoEmail
from app.db.session import SessionLocal
from mosp.host.config import settings
from scripts import mfa_admin

from tests.conftest import generated_password, make_user


@pytest.fixture
def planted(monkeypatch):
    # An account that signs in only through SSO, holding only an identity
    # someone else linked after removing the owner's.
    monkeypatch.setattr(settings, "local_auth_enabled", False)
    user = make_user("ada", generated_password())
    with SessionLocal() as db:
        db.add(
            UserIdentity(
                user_id=user.id,
                provider="oidc",
                issuer="https://idp.example",
                subject="planted-subject",
                email="planted@attacker.example",
                display_name="Someone",
                claims={},
            )
        )
        db.add(UserSsoEmail(email="planted@attacker.example", user_id=user.id))
        db.commit()
    return user


def test_the_listing_tells_identities_apart(planted, capsys):
    assert mfa_admin.main(["ada", "--list-identities"]) == 0
    line = capsys.readouterr().out.strip()
    assert "\toidc\thttps://idp.example planted-subject\tSomeone\t" in line
    assert "planted@attacker.example" in line


def test_an_operator_gives_the_owner_a_new_linking_address(planted, capsys):
    argv = ["ada", "--reset", "--confirm-username", "ada"]
    assert mfa_admin.main([*argv, "--link-address", "Ada@Example.org"]) == 0
    assert "the address given is the account's only" in capsys.readouterr().out
    with SessionLocal() as db:
        assert db.query(UserIdentity).count() == 0
        assert [(a.email, a.user_id) for a in db.query(UserSsoEmail)] == [
            ("ada@example.org", planted.id)
        ]


def test_an_identity_the_account_lacks_is_refused(planted, capsys):
    argv = ["ada", "--reset", "--confirm-username", "ada", "--keep-identity", "999"]
    with pytest.raises(SystemExit):
        mfa_admin.main(argv)
    assert "no such SSO identity" in capsys.readouterr().err
