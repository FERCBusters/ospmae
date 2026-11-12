"""Local second-factor routes. The ceremony runs outside the session cookie."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.security import mfa
from app.security.auth import get_current_user, get_current_user_from_request
from app.security.client_addr import request_client_address
from app.services import mfa_management as service
from app.services.mfa_management import Code, Credential, Password, Remove

router = APIRouter()


def no_cache(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/v1/me/mfa")
def status(
    request: Request, db: Session = Depends(get_db), user=Depends(get_current_user)
):
    return service.status(db, user)


@router.post("/v1/auth/mfa/manage/start")
def start_management(
    payload: Password, request: Request, db: Session = Depends(get_db)
):
    mfa.check_origin(request)
    user = get_current_user_from_request(request, db)
    if not user:
        raise HTTPException(401, "Sign in before managing local account security")
    mfa.limit(request, user.id)
    from app.security.passwords import verify_password

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid password")
    return mfa.start(db, user, request, "manage")


@router.post("/v1/auth/mfa/state")
def state(request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    return service.state(db, row, user)


@router.post("/v1/auth/mfa/verify-code")
def verify_code(payload: Code, request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    mfa.limit(request, user.id)
    return service.verify_code(
        db, row, user, payload, ip=request_client_address(request)
    )


@router.post("/v1/auth/mfa/totp/start")
def start_totp(request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    mfa.limit(request, user.id)
    return service.start_totp(db, row, user)


@router.post("/v1/auth/mfa/totp/confirm")
def confirm_totp(payload: Code, request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    mfa.limit(request, user.id)
    return service.confirm_totp(
        db, row, user, payload, ip=request_client_address(request)
    )


@router.post("/v1/auth/mfa/webauthn/options")
def authentication_options(request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    mfa.limit(request, user.id)
    return service.authentication_options(db, row, user)


@router.post("/v1/auth/mfa/webauthn/verify")
def authentication_verify(
    payload: Credential, request: Request, db: Session = Depends(get_db)
):
    row, user = mfa.pending(db, request)
    mfa.limit(request, user.id)
    return service.authentication_verify(
        db, row, user, payload, ip=request_client_address(request)
    )


@router.post("/v1/auth/mfa/webauthn/register-options")
def registration_options(request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    mfa.limit(request, user.id)
    return service.registration_options(db, row, user)


@router.post("/v1/auth/mfa/webauthn/register")
def registration_verify(
    payload: Credential, request: Request, db: Session = Depends(get_db)
):
    row, user = mfa.pending(db, request)
    mfa.limit(request, user.id)
    return service.registration_verify(
        db, row, user, payload, ip=request_client_address(request)
    )


@router.post("/v1/auth/mfa/remove")
def remove(payload: Remove, request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    return service.remove(db, row, user, payload, ip=request_client_address(request))


@router.post("/v1/auth/mfa/recovery/regenerate")
def regenerate(request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    return service.regenerate(db, row, user, ip=request_client_address(request))


@router.post("/v1/auth/mfa/finish")
def finish(request: Request, db: Session = Depends(get_db)):
    row, user = mfa.pending(db, request)
    verified_version, enabled = service.consume_challenge(db, row, user)
    from app.api.routes.auth import complete_local_login

    response = complete_local_login(
        db, user, request, mfa_verified=enabled, verified_version=verified_version
    )
    mfa.clear_cookie(response)
    return no_cache(response)


@router.post("/v1/auth/mfa/cancel")
def cancel(request: Request, db: Session = Depends(get_db)):
    mfa.check_origin(request)
    return mfa.cancel(db, request, JSONResponse({"ok": True}))
