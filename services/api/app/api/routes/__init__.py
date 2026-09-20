from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import admin, auth, projects, frameworks, me, system, dependencies
from app.api.routes import project_questions as questions

router = APIRouter()

router.include_router(system.router, tags=["system"])
router.include_router(auth.router, tags=["auth"])
router.include_router(me.router, tags=["me"])
router.include_router(frameworks.router, tags=["frameworks"])
router.include_router(projects.router, tags=["projects"])
router.include_router(dependencies.router, tags=["dependencies"])
router.include_router(questions.router, tags=["questions"])
router.include_router(admin.router, tags=["admin"])
