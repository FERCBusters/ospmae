from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.routes import admin, auth, dependencies, frameworks, me, projects, system
from app.api.routes import project_questions as questions
from app.core.features import require_feature

router = APIRouter()

router.include_router(system.router, tags=["system"])
router.include_router(auth.router, tags=["auth"])
router.include_router(me.router, tags=["me"])
router.include_router(
    frameworks.router,
    dependencies=[Depends(require_feature("frameworks"))],
    tags=["frameworks"],
)
router.include_router(projects.router, tags=["projects"])
router.include_router(
    dependencies.router,
    dependencies=[Depends(require_feature("dependency_scans"))],
    tags=["dependencies"],
)
router.include_router(
    questions.router,
    dependencies=[Depends(require_feature("questions"))],
    tags=["questions"],
)
router.include_router(admin.router, tags=["admin"])
