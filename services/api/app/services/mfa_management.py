"""Local second-factor management: enrol, verify, remove, recover.

Ceremony state lives in the pending challenge row the caller holds; every
step re-checks which stage the row is in, and the account's user row is
locked so concurrent guesses are counted in turn. Failures answer with the
 ceremonies' own codes: HTTP 400/401/403 with the browser-facing message.
"""

from __future__ import annotations

import base64
import io
import json

import pyotp
import qrcode
import qrcode.image.svg
from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from app.core.config import settings
from app.db.models import MfaCredential, MfaRecoveryCode
from app.security import mfa


class Password(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class Code(BaseModel):
    code: str = Field(min_length=1, max_length=128)
    kind: str = "totp"  # "totp" or "recovery"


class Credential(BaseModel):
    credential: dict
    name: str = Field(default="Security key / passkey", min_length=1, max_length=100)


class Remove(BaseModel):
    id: str = Field(min_length=1, max_length=100)


def _recovery_state(db: Session, user) -> int:
    return db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id).count()


def _factors(db: Session, user):
    return [
        {"id": str(c.id), "name": c.name, "last_used_at": c.last_used_at}
        for c in mfa.registered(db, user)
    ]


def status(db: Session, user):
    return {
        "enabled": user.mfa_enabled,
        "totp": bool(user.mfa_totp_secret),
        "credentials": _factors(db, user),
        "recovery_codes_remaining": _recovery_state(db, user),
        "policy": settings.mfa_policy,
        "required": mfa.required(db, user),
        "local_enabled": bool(getattr(settings, "local_auth_enabled", True)),
    }


def state(db: Session, row, user):
    return {
        "stage": row.stage,
        "purpose": row.purpose,
        "username": user.username,
        "totp": bool(user.mfa_totp_secret),
        "required": mfa.required(db, user),
        "credentials": _factors(db, user),
        "recovery_codes_remaining": _recovery_state(db, user),
    }


CODES_REFUSED = (
    "Too many incorrect codes; sign in again in an hour, or use a security key"
)


def verify_code(db: Session, row, user, payload: Code):
    if row.stage != "verify":
        raise HTTPException(400, "Start a second-factor verification first")
    # The account's row is locked, so concurrent guesses are counted in turn,
    # and the count survives a new sign-in.
    if mfa.codes_refused(user):
        db.delete(row)
        db.commit()
        raise HTTPException(401, CODES_REFUSED)
    if not mfa.verify_code(db, user, payload.code.strip(), payload.kind):
        if mfa.record_wrong_code(user):
            db.delete(row)
            db.commit()
            raise HTTPException(401, CODES_REFUSED)
        db.commit()
        raise HTTPException(400, "Invalid or already-used code")
    mfa.clear_wrong_codes(user)
    mfa.verified(row)
    db.commit()
    return {"ok": True}


def start_totp(db: Session, row, user):
    mfa.management(row)
    if user.mfa_totp_secret:
        raise HTTPException(
            409, "Remove the existing authenticator before adding another"
        )
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="OSPMAE")
    row.data = {
        **row.data,
        "totp_secret": mfa.cipher().encrypt(secret.encode()).decode(),
    }
    db.commit()
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    return {
        "secret": secret,
        "qr": "data:image/svg+xml;base64,"
        + base64.b64encode(output.getvalue()).decode(),
    }


def confirm_totp(db: Session, row, user, payload: Code):
    mfa.management(row)
    secret = row.data.get("totp_secret")
    if not secret or user.mfa_totp_secret:
        raise HTTPException(400, "Start authenticator setup first")
    # Assignment is rolled back on invalid proof; enabling happens only after proof.
    user.mfa_totp_secret = secret
    user.mfa_totp_last_step = -1
    if not mfa.verify_code(db, user, payload.code.strip(), "totp"):
        db.commit()
        raise HTTPException(400, "Invalid authenticator code")
    return mfa.activate(db, row, user)


def authentication_options(db: Session, row, user):
    if row.stage != "verify":
        raise HTTPException(400, "Start verification first")
    credentials = mfa.registered(db, user)
    if not credentials:
        raise HTTPException(400, "No security key or passkey is registered")
    _, rp = mfa.origin_config()
    options = generate_authentication_options(
        rp_id=rp,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=mfa.unb64(c.credential_id))
            for c in credentials
        ],
    )
    row.data = {"authenticate": mfa.b64(options.challenge)}
    db.commit()
    return json.loads(options_to_json(options))


def authentication_verify(db: Session, row, user, payload: Credential):
    if row.stage != "verify":
        raise HTTPException(400, "Start verification first")
    challenge = row.data.get("authenticate")
    row.data = {}
    try:
        if not challenge:
            raise ValueError()
        mfa.check_client_data(payload.credential, user)
        credential = (
            db.query(MfaCredential)
            .filter(
                MfaCredential.user_id == user.id,
                MfaCredential.credential_id == payload.credential.get("id"),
            )
            .one_or_none()
        )
        if not credential:
            raise ValueError()
        origin, rp = mfa.origin_config()
        result = verify_authentication_response(
            credential=payload.credential,
            expected_challenge=mfa.unb64(challenge),
            expected_rp_id=rp,
            expected_origin=origin,
            credential_public_key=mfa.unb64(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=False,
        )
    except HTTPException:
        row.data = {}
        db.commit()  # consume ceremony even when the assertion is invalid
        raise
    except Exception:
        db.commit()  # consume ceremony even when the assertion is invalid
        raise HTTPException(
            400, "Security key verification failed; request another challenge"
        )
    credential.sign_count = result.new_sign_count
    credential.last_used_at = mfa._now()
    mfa.verified(row)
    db.commit()
    return {"ok": True}


def registration_options(db: Session, row, user):
    mfa.management(row)
    credentials = mfa.registered(db, user)
    if len(credentials) >= 10:
        raise HTTPException(
            400, "A maximum of ten security keys/passkeys can be registered"
        )
    _, rp = mfa.origin_config()
    options = generate_registration_options(
        rp_id=rp,
        rp_name="OSPMAE",
        user_id=mfa.user_handle(user),
        user_name=user.username,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=mfa.unb64(c.credential_id))
            for c in credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED
        ),
    )
    row.data = {**row.data, "register": mfa.b64(options.challenge)}
    db.commit()
    return json.loads(options_to_json(options))


def registration_verify(db: Session, row, user, payload: Credential):
    mfa.management(row)
    challenge = row.data.get("register")
    row.data = {k: v for k, v in row.data.items() if k != "register"}
    try:
        if not challenge:
            raise ValueError()
        mfa.check_client_data(payload.credential)
        origin, rp = mfa.origin_config()
        result = verify_registration_response(
            credential=payload.credential,
            expected_challenge=mfa.unb64(challenge),
            expected_rp_id=rp,
            expected_origin=origin,
            require_user_presence=True,
            require_user_verification=False,
        )
    except HTTPException:
        db.commit()
        raise
    except Exception:
        db.commit()
        raise HTTPException(400, "Registration failed; request another challenge")
    if (
        db.query(MfaCredential)
        .filter(MfaCredential.credential_id == mfa.b64(result.credential_id))
        .first()
    ):
        db.commit()
        raise HTTPException(409, "This credential is already registered")
    db.add(
        MfaCredential(
            user_id=user.id,
            credential_id=mfa.b64(result.credential_id),
            public_key=mfa.b64(result.credential_public_key),
            sign_count=result.sign_count,
            name=payload.name.strip() or "Security key / passkey",
        )
    )
    return mfa.activate(db, row, user)


def remove(db: Session, row, user, payload: Remove):
    mfa.management(row)
    credentials = mfa.registered(db, user)
    total = len(credentials) + int(bool(user.mfa_totp_secret))
    if total <= 1 and mfa.required(db, user):
        raise HTTPException(
            400, "Register a replacement before removing your last required factor"
        )
    if payload.id == "totp" and user.mfa_totp_secret:
        user.mfa_totp_secret = None
        user.mfa_totp_last_step = -1
    else:
        credential = next((c for c in credentials if str(c.id) == payload.id), None)
        if not credential:
            raise HTTPException(404, "Authenticator not found")
        db.delete(credential)
    user.mfa_enabled = total > 1
    if not user.mfa_enabled:
        db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id).delete(
            synchronize_session=False
        )
    mfa.bump(db, user, row)
    row.data = {}
    db.commit()
    return {"ok": True}


def regenerate(db: Session, row, user):
    mfa.management(row)
    if not user.mfa_enabled:
        raise HTTPException(400, "Enrol an authenticator first")
    codes = mfa.recovery_codes(db, user)
    mfa.bump(db, user, row)
    db.commit()
    return {"recovery_codes": codes}


def consume_challenge(db: Session, row, user):
    if row.stage not in {"ready", "manage"} or (
        mfa.required(db, user) and not user.mfa_enabled
    ):
        raise HTTPException(
            403, "Complete second-factor verification or enrolment first"
        )
    verified_version, enabled = row.version, user.mfa_enabled
    db.delete(row)
    db.commit()
    return verified_version, enabled
