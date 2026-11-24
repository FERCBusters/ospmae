"""OSPMAE's routes in mosp's route policy (mosp.security.route_policy).

mosp declares its own routes (signing in and out, second factors, single
sign-on, the account's own password and SSO addresses); this module declares
OSPMAE's, and mosp applies the two together. OSPMAE closes every write it does
not declare (``refuse_undeclared_writes``): a route added without a decision
about who may call it is refused for everyone, administrators included.

- public: reached without an account.
- self-service: the signed-in account acting on its own records.
- object-checked: any signed-in account; the route authorises the named
  object (a question's author or the project's answerers, a project the
  reader can see).
- gated: the account must hold the permission; the route still checks the
  object (project ownership, manifest ownership, administrator-only
  deletions).
- the /v1/admin/ namespace: the administrator role, apart from the audit
  readers, which the audittrail.read permission also opens and whose routes
  check it.

Routes keep their own checks in every case: this table is the second lock.
tests/test_route_policy.py fails when a write is undeclared or a declaration
names a route that does not exist.
"""

from __future__ import annotations

from mosp.security.route_policy import RouteCodes, RoutePolicy, RouteSet

from app.security.permissions import (
    PERM_FRAMEWORK_WRITE,
    PERM_MANIFEST_EXPORT,
    PERM_PROJECT_QUESTION,
    PERM_PROJECT_WRITE,
)

PUBLIC_ROUTES = RouteSet({"GET": ("/", "/v1/system/health")})

GATED_WRITES = {
    # Projects and their versions.
    ("POST", "/v1/projects"): PERM_PROJECT_WRITE,
    ("PUT", "/v1/projects/{project_id}"): PERM_PROJECT_WRITE,
    ("DELETE", "/v1/projects/{project_id}"): PERM_PROJECT_WRITE,
    ("POST", "/v1/projects/{project_id}/versions"): PERM_PROJECT_WRITE,
    ("PUT", "/v1/project-versions/{version_id}"): PERM_PROJECT_WRITE,
    ("DELETE", "/v1/project-versions/{version_id}"): PERM_PROJECT_WRITE,
    ("PUT", "/v1/project-versions/{version_id}/framework-nodes"): PERM_PROJECT_WRITE,
    ("PUT", "/v1/project-versions/{version_id}/capabilities"): PERM_PROJECT_WRITE,
    (
        "POST",
        "/v1/project-versions/{project_version_id}/dependency-discovery",
    ): PERM_PROJECT_WRITE,
    # Manifests.
    ("POST", "/v1/projects/{project_id}/manifest/save"): PERM_MANIFEST_EXPORT,
    ("POST", "/v1/manifests"): PERM_MANIFEST_EXPORT,
    ("DELETE", "/v1/manifests/{manifest_id}"): PERM_MANIFEST_EXPORT,
    ("PATCH", "/v1/manifests/{manifest_id}/sharing"): PERM_MANIFEST_EXPORT,
    ("POST", "/v1/manifests/{manifest_id}/clone"): PERM_MANIFEST_EXPORT,
    # Frameworks.
    ("POST", "/v1/frameworks"): PERM_FRAMEWORK_WRITE,
    ("PUT", "/v1/frameworks/{framework_id}"): PERM_FRAMEWORK_WRITE,
    ("DELETE", "/v1/frameworks/{framework_id}"): PERM_FRAMEWORK_WRITE,
    ("POST", "/v1/frameworks/{framework_id}/nodes"): PERM_FRAMEWORK_WRITE,
    ("PUT", "/v1/framework-nodes/{node_id}"): PERM_FRAMEWORK_WRITE,
    ("DELETE", "/v1/framework-nodes/{node_id}"): PERM_FRAMEWORK_WRITE,
    # Questions.
    ("POST", "/v1/projects/{project_id}/questions"): PERM_PROJECT_QUESTION,
}

OBJECT_CHECKED = RouteSet(
    {
        "POST": (
            "/v1/questions/{thread_id}/reply",
            "/v1/projects/{project_id}/subscription",
        ),
        "DELETE": ("/v1/projects/{project_id}/subscription",),
    }
)

SELF_SERVICE = RouteSet(
    {
        "PUT": ("/v1/me/preferences",),
        "POST": ("/v1/me/shortcuts",),
        "DELETE": ("/v1/me/shortcuts/{shortcut_id}",),
    }
)

OSPMAE_POLICY = RoutePolicy(
    public=PUBLIC_ROUTES,
    self_service=SELF_SERVICE,
    object_checked=OBJECT_CHECKED,
    gated=RouteCodes(GATED_WRITES),
    admin_prefixes=("/v1/admin/",),
    admin_exempt=RouteSet({"GET": ("/v1/admin/audit", "/v1/admin/entity-changelog")}),
    refuse_undeclared_writes=True,
    # The navigation bar's unanswered-questions badge polls this on every page.
    unaudited_paths=frozenset({"/v1/questions/unanswered/summary"}),
    unaudited_public_reads=frozenset({"/v1/system/health"}),
)
