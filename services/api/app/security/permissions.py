"""OSPMAE's permission catalogue.

Accounts hold mosp's roles (admin, normal, inherit) and these permissions,
directly or through their groups; mosp.security.permissions answers whether an
account holds one. An administrator holds every permission.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import Permission

PERM_PROJECT_WRITE = "project.write"
PERM_FRAMEWORK_WRITE = "framework.write"
PERM_MANIFEST_EXPORT = "manifest.export"
PERM_PROJECT_QUESTION = "project.question"
PERM_PROJECT_ANSWER = "project.answer"
PERM_PROJECT_DIFF = "project.diff"
PERM_AUDITTRAIL_READ = "audittrail.read"


DEFAULT_PERMISSION_SEED = [
    {
        "code": PERM_PROJECT_WRITE,
        "description": "Create projects, and edit the projects one's account or groups own",
    },
    {
        "code": PERM_FRAMEWORK_WRITE,
        "description": "Create and edit frameworks and framework node taxonomies",
    },
    {
        "code": PERM_MANIFEST_EXPORT,
        "description": "Export and save project manifests (JSON/XLSX/Markdown)",
    },
    {"code": PERM_PROJECT_QUESTION, "description": "Ask questions about a project"},
    {
        "code": PERM_PROJECT_ANSWER,
        "description": "Answer questions about the projects one's account or groups own",
    },
    {
        "code": PERM_PROJECT_DIFF,
        "description": "Generate comparison diffs between projects",
    },
    {
        "code": PERM_AUDITTRAIL_READ,
        "description": "View request audit logs and semantic entity changelogs",
    },
]


def seed_default_permissions(db: Session) -> None:
    """Idempotently seed baseline permission rows used by this application."""
    existing_codes = {
        code
        for (code,) in db.query(Permission.code)
        .filter(Permission.code.in_([p["code"] for p in DEFAULT_PERMISSION_SEED]))
        .all()
    }
    changed = False
    for item in DEFAULT_PERMISSION_SEED:
        if item["code"] in existing_codes:
            continue
        db.add(Permission(code=item["code"], description=item.get("description")))
        changed = True
    if changed:
        db.commit()
