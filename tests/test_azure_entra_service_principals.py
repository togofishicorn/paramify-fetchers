"""azure_entra_service_principals: owners and granted API permissions.

Synthetic Graph models only: no SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_service_principals" / "fetcher.py"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_service_principals_under_test", FETCHER)
sps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sps)
import entra_graph  # noqa: E402  (on sys.path once the fetcher is loaded)

TENANT = "00000000-0000-0000-0000-0000000000aa"
VENDOR_TENANT = "00000000-0000-0000-0000-0000000000bb"
MICROSOFT_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
GRAPH_APP_ID = entra_graph.MICROSOFT_GRAPH_APP_ID
ROLE_RW_DIRECTORY = "10000000-0000-0000-0000-000000000001"
ROLE_DIR_RW = "10000000-0000-0000-0000-000000000002"
ROLE_USER_READ = "10000000-0000-0000-0000-000000000003"
ROLE_MAIL_READ = "10000000-0000-0000-0000-000000000004"
ROLE_UNKNOWN = "10000000-0000-0000-0000-0000000000ff"
ROLE_FULL_ACCESS = "10000000-0000-0000-0000-000000000005"
EXCHANGE_APP_ID = "00000002-0000-0ff1-ce00-000000000000"
# The form kiota's APIError takes: "<message> (status <code>)".
DENIED = Exception("Insufficient privileges to complete the operation. (status 403)")
SERVER_ERROR = Exception("Service unavailable (status 500)")


def _api_error(status, message):
    """kiota's APIError carries the HTTP status as `response_status_code`."""
    exc = Exception(message)
    exc.response_status_code = status
    return exc

# The summary keys of 0.1.0, which this change must keep.
V010_SUMMARY_KEYS = {
    "total_service_principals", "disabled_service_principals", "application_service_principals",
    "managed_identities", "system_assigned_managed_identities", "user_assigned_managed_identities",
    "legacy_service_principals", "social_idp_service_principals",
    "microsoft_first_party_service_principals", "tenant_owned_service_principals",
    "other_tenant_service_principals", "unknown_owner_service_principals",
    "federated_service_principals", "certificate_based_service_principals",
    "secret_based_service_principals", "tenant_owned_service_principals_without_credentials",
    "federated_identity_credentials", "total_credentials", "service_principal_held_credentials",
    "application_held_credentials", "password_credentials", "certificate_credentials",
    "expired_credentials", "credentials_expiring_soon", "credentials_without_expiry",
    "healthy_credentials", "rotation_threshold_days", "credential_rotation_compliance_percentage",
    "platform_managed_credentials", "tenant_applications_without_service_principal",
    "federated_identity_credentials_on_applications_without_service_principal",
}


# --- synthetic Graph models -------------------------------------------------

def _sp(oid, app_id, name, owner_org=TENANT, sp_type="Application", **extra):
    return ns(
        id=oid, app_id=app_id, display_name=name, service_principal_type=sp_type,
        account_enabled=True, app_owner_organization_id=owner_org, alternative_names=[],
        password_credentials=[], key_credentials=[], **extra,
    )


def _secret():
    return ns(display_name="s", key_id="k-1", start_date_time=None, end_date_time="2099-01-01T00:00:00Z",
              usage=None, type=None)


def _app(oid, app_id, name, secrets=0):
    return ns(id=oid, app_id=app_id, display_name=name, password_credentials=[_secret()] * secrets,
              key_credentials=[], federated_identity_credentials=[])


def _user(oid, enabled=True):
    return ns(id=oid, odata_type="#microsoft.graph.user", display_name=f"User {oid}",
              user_principal_name=f"{oid}@contoso.test", account_enabled=enabled)


def _assignment(role_id, resource_id="sp-graph", resource_name="Microsoft Graph"):
    return ns(id=f"a-{role_id}", app_role_id=role_id, resource_id=resource_id,
              resource_display_name=resource_name, created_date_time="2026-01-01T00:00:00Z")


def _grant(client_id, scope, consent="AllPrincipals", principal=None, resource_id="sp-graph"):
    return ns(id=f"g-{client_id}", client_id=client_id, consent_type=consent, principal_id=principal,
              resource_id=resource_id, scope=scope)


GRAPH_SP = _sp(
    "sp-graph", GRAPH_APP_ID, "Microsoft Graph", owner_org=MICROSOFT_TENANT,
    app_roles=[
        ns(id=ROLE_RW_DIRECTORY, value="RoleManagement.ReadWrite.Directory"),
        ns(id=ROLE_DIR_RW, value="Directory.ReadWrite.All"),
        ns(id=ROLE_USER_READ, value="User.Read.All"),
        ns(id=ROLE_MAIL_READ, value="Mail.Read"),
    ],
)


class Builder:
    """A Graph collection: `get()` returns one page or raises; counts its calls."""

    def __init__(self, items=None, error=None):
        self.items, self.error, self.calls = list(items or []), error, 0

    async def get(self, request_configuration=None):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return ns(value=self.items, odata_next_link=None)


class Collection:
    """Tenant-wide reads are forbidden, including expanded reads."""
    async def get(self, request_configuration=None):
        raise AssertionError("unexpected tenant-wide Graph collection read")


class FakeGraph:
    def __init__(self, service_principals, applications, sp_owners=None, app_owners=None,
                 assignments=None, grants=()):
        sp_owners, app_owners, assignments = sp_owners or {}, app_owners or {}, assignments or {}
        self.selected_principals = [s.id for s in service_principals]
        self.selected_applications = [a.id for a in applications]
        self.organization = Builder([ns(id=TENANT, display_name="Contoso", verified_domains=[])])
        self.sp_owner_items = {s.id: Builder(sp_owners.get(s.id, [])) for s in service_principals}
        self.app_owner_items = {a.id: Builder(app_owners.get(a.id, [])) for a in applications}
        self.assignment_items = {s.id: Builder(assignments.get(s.id, [])) for s in service_principals}
        self.fic_items = {a.id: Builder(a.federated_identity_credentials) for a in applications}
        self.sp_owners, self.app_owners, self.assignments = Builder(), Builder(), Builder()
        self.oauth2_permission_grants = Builder(grants)  # error controls scoped grants only
        self.grant_items = {s.id: Builder([g for g in grants if g.client_id == s.id]) for s in service_principals}
        self.resource_error = {}
        self.primary_error = {}
        self.service_principals, self.applications = Collection(), Collection()
        by_id = {s.id: s for s in service_principals}
        apps_by_id = {a.id: a for a in applications}
        self.resource_reads, self.primary_reads = [], []

        async def resource_get(oid, request_configuration=None):
            select = request_configuration.query_parameters.select
            if "appRoles" in select:
                self.resource_reads.append(oid)
                if oid in self.resource_error:
                    raise self.resource_error[oid]
            else:
                self.primary_reads.append(("service_principals", oid))
                if oid in self.primary_error:
                    raise self.primary_error[oid]
            return by_id.get(oid)

        async def app_get(oid, request_configuration=None):
            self.primary_reads.append(("applications", oid))
            if oid in self.primary_error:
                raise self.primary_error[oid]
            return apps_by_id.get(oid)

        def related(oid, items, shared):
            builder = items[oid]
            if shared.error is not None:
                builder.error = shared.error
            return builder

        self.service_principals.by_service_principal_id = lambda oid: ns(
            owners=related(oid, self.sp_owner_items, self.sp_owners),
            app_role_assignments=related(oid, self.assignment_items, self.assignments),
            oauth2_permission_grants=related(oid, self.grant_items, self.oauth2_permission_grants),
            get=lambda request_configuration=None: resource_get(oid, request_configuration),
        )
        self.applications.by_application_id = lambda oid: ns(
            owners=related(oid, self.app_owner_items, self.app_owners),
            federated_identity_credentials=self.fic_items[oid],
            get=lambda request_configuration=None: app_get(oid, request_configuration),
        )


class Query:
    def __init__(self, select=None, expand=None):
        self.select, self.expand = select, expand


def _stub_msgraph(monkeypatch):
    """Stand in for the msgraph request builders the fetcher imports lazily."""
    builders = {
        "msgraph.generated.applications.item.application_item_request_builder": "ApplicationItemRequestBuilder",
        "msgraph.generated.service_principals.service_principals_request_builder": "ServicePrincipalsRequestBuilder",
        "msgraph.generated.applications.item.owners.owners_request_builder": "OwnersRequestBuilder",
        "msgraph.generated.service_principals.item.owners.owners_request_builder": "OwnersRequestBuilder",
        "msgraph.generated.service_principals.item.service_principal_item_request_builder": (
            "ServicePrincipalItemRequestBuilder"
        ),
    }
    for module_name, cls in builders.items():
        module = ModuleType(module_name)
        setattr(module, cls, type(cls, (), {f"{cls}GetQueryParameters": Query}))
        monkeypatch.setitem(sys.modules, module_name, module)
    config = ModuleType("kiota_abstractions.base_request_configuration")
    config.RequestConfiguration = lambda query_parameters=None: ns(query_parameters=query_parameters)
    monkeypatch.setitem(sys.modules, "kiota_abstractions.base_request_configuration", config)


def _run(monkeypatch, tmp_path, graph):
    async def fake_with_graph_client(collector, cred, work, default=None):
        return await work(graph)

    _stub_msgraph(monkeypatch)
    # Historical native regression models use readable symbolic IDs. Selection validation
    # itself is exercised with actual synthetic UUIDs in the boundary tests.
    monkeypatch.setattr(sps, "selected_object_ids", lambda collector, env, **kw:
                        graph.selected_applications if env == sps.APPLICATION_OBJECT_IDS_ENV else graph.selected_principals)
    monkeypatch.setattr(sps, "with_graph_client", fake_with_graph_client)
    monkeypatch.setattr(sps, "credential", lambda: object())
    monkeypatch.setattr(sps, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    status = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))
    code = sps.main()
    evidence = json.loads((tmp_path / f"azure_entra_service_principals_{TENANT}.json").read_text())
    return code, evidence, (json.loads(status.read_text()) if status.exists() else None)


def _tenant():
    """An owned app, an ownerless app with a secret and a privileged role, a managed
    identity with a privileged role, a vendor app with admin-consented delegated Mail.Read
    and Directory.ReadWrite.All, and an ownerless app registration with no service principal."""
    service_principals = [
        GRAPH_SP,
        _sp("sp-owned", "app-id-owned", "Owned app"),
        _sp("sp-orphan", "app-id-orphan", "Orphan app"),
        _sp("sp-mi", "app-id-mi", "Function identity", owner_org=None, sp_type="ManagedIdentity"),
        _sp("sp-vendor", "app-id-vendor", "Vendor app", owner_org=VENDOR_TENANT),
    ]
    applications = [
        _app("app-owned", "app-id-owned", "Owned app", secrets=1),
        _app("app-orphan", "app-id-orphan", "Orphan app", secrets=1),
        _app("app-unused", "app-id-unused", "Unused registration"),
    ]
    return dict(
        service_principals=service_principals,
        applications=applications,
        app_owners={"app-owned": [_user("u-1")]},
        assignments={
            "sp-owned": [_assignment(ROLE_USER_READ), _assignment(sps.DEFAULT_ACCESS_ROLE_ID, "sp-owned", "Owned app")],
            "sp-orphan": [_assignment(ROLE_RW_DIRECTORY)],
            "sp-mi": [_assignment(ROLE_DIR_RW)],
        },
        grants=[
            _grant("sp-vendor", "openid Mail.Read Directory.ReadWrite.All"),
            _grant("sp-owned", "User.Read", consent="Principal", principal="u-1"),
        ],
    )


def test_owners_and_privileged_permissions(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    summary = evidence["summary"]
    assert V010_SUMMARY_KEYS <= set(summary)
    assert summary["owners_readable"] is True
    assert summary["owner_details_readable"] is True
    assert summary["owner_eligible_service_principals"] == 3
    # The orphan app registered here and the vendor app, whose owners live in its own tenant.
    assert summary["service_principals_without_owner"] == 2
    assert summary["tenant_owned_service_principals_without_owner"] == 1
    assert summary["ownerless_service_principals_with_credentials"] == 1
    assert summary["service_principals_with_only_disabled_owners"] == 0
    assert summary["ownerless_applications_without_service_principal"] == 1
    assert summary["application_permissions_readable"] is True
    assert summary["service_principals_with_application_permissions"] == 3
    assert summary["application_permission_assignments"] == 4
    assert summary["unnamed_graph_application_permissions"] == summary["unnamed_other_application_permissions"] == 0
    assert summary["service_principals_with_privileged_application_permissions"] == 2
    assert summary["managed_identities_with_privileged_application_permissions"] == 1
    # The managed identity holds a privileged role too, but cannot have an owner.
    assert summary["ownerless_service_principals_with_privileged_application_permissions"] == 1
    assert summary["privileged_application_permissions_held"] == [
        "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    ]
    assert summary["delegated_grants_readable"] is True
    assert summary["delegated_grants_status"] == "ok"
    assert summary["service_principals_with_delegated_grants"] == 2
    assert summary["admin_consented_delegated_grants"] == 1
    assert summary["service_principals_with_privileged_delegated_grants"] == 1
    # Delegated Mail.Read reaches only the signed-in user's own mailbox.
    assert summary["privileged_delegated_permissions_granted"] == ["Directory.ReadWrite.All"]

    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    owned = by_id["sp-owned"]
    assert owned["owners"] == [] and owned["has_owner"] is True and owned["has_enabled_owner"] is True
    assert owned["application_owners"][0]["principal_type"] == "User"
    perms = {p["permission"]: p for p in owned["application_permissions"]}
    assert perms[None]["default_access"] is True and perms[None]["privileged"] is False
    assert perms["User.Read.All"]["resource_app_id"] == GRAPH_APP_ID
    assert by_id["sp-orphan"]["has_owner"] is False
    assert by_id["sp-orphan"]["privileged_application_permissions"] == ["RoleManagement.ReadWrite.Directory"]
    assert by_id["sp-mi"]["owner_eligible"] is False
    assert by_id["sp-graph"]["owner_eligible"] is False
    (vendor_grant,) = by_id["sp-vendor"]["delegated_permission_grants"]
    assert vendor_grant["scopes"] == ["Directory.ReadWrite.All", "Mail.Read", "openid"]
    assert vendor_grant["privileged_scopes"] == ["Directory.ReadWrite.All"]
    assert by_id["sp-vendor"]["has_privileged_permission"] is True
    assert by_id["sp-vendor"]["application_owners"] == []  # no app registration in this tenant
    (unused,) = evidence["results"]["applications_without_service_principal"]
    assert unused["has_owner"] is False
    checked = evidence["results"]
    assert "RoleManagement.ReadWrite.Directory" in checked["privileged_application_graph_permissions_checked"]
    assert "Mail.Read" in checked["privileged_application_graph_permissions_checked"]
    assert "RoleManagement.ReadWrite.Directory" in checked["privileged_delegated_graph_permissions_checked"]
    assert "Mail.Read" not in checked["privileged_delegated_graph_permissions_checked"]
    # Role names are read once per resource that an assignment points at.
    assert sorted(graph.resource_reads) == ["sp-graph", "sp-owned"]


def test_a_privileged_name_on_another_resource_is_not_judged():
    resources = {"sp-other": {"app_id": "not-graph", "display_name": "Other API", "app_roles": {"r": "Mail.Read"}}}
    record = sps.application_permission_record(
        {"resource_id": "sp-other", "app_role_id": "r", "resource_display_name": "Other API"}, resources
    )
    assert record["permission"] == "Mail.Read"
    assert (record["privileged"], record["judged"]) == (None, False)


def test_permissions_on_other_apis_leave_the_flag_unknown(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["service_principals"] += [
        _sp("sp-exchange", EXCHANGE_APP_ID, "Office 365 Exchange Online", owner_org=MICROSOFT_TENANT,
            app_roles=[ns(id=ROLE_FULL_ACCESS, value="full_access_as_app")]),
        _sp("sp-daemon", "app-id-daemon", "Mail daemon", owner_org=VENDOR_TENANT),
        _sp("sp-ews", "app-id-ews", "EWS client", owner_org=VENDOR_TENANT),
    ]
    tenant["assignments"]["sp-daemon"] = [_assignment(ROLE_FULL_ACCESS, "sp-exchange", "Office 365 Exchange Online")]
    tenant["grants"].append(_grant("sp-daemon", "EWS.AccessAsUser.All", resource_id="sp-exchange"))
    # Its only permission on another API is a delegated grant.
    tenant["grants"].append(_grant("sp-ews", "EWS.AccessAsUser.All", resource_id="sp-exchange"))
    code, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))

    assert code == 0
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    daemon = by_id["sp-daemon"]
    (perm,) = daemon["application_permissions"]
    assert perm["permission"] == "full_access_as_app"
    assert (perm["privileged"], perm["judged"]) == (None, False)
    (grant,) = daemon["delegated_permission_grants"]
    assert (grant["privileged_scopes"], grant["judged"]) == (None, False)
    # Not "checked, not privileged": Exchange and SharePoint permissions are never judged.
    assert daemon["has_privileged_permission"] is None
    assert daemon["privileged_application_permissions"] == daemon["privileged_delegated_permissions"] == []
    ews = by_id["sp-ews"]
    assert ews["application_permissions"] == []
    assert ews["has_privileged_permission"] is None
    graph_perm = {p["permission"]: p for p in by_id["sp-owned"]["application_permissions"]}["User.Read.All"]
    assert (graph_perm["privileged"], graph_perm["judged"]) == (False, True)
    assert evidence["summary"]["unnamed_other_application_permissions"] == 0


def test_tenant_data_permissions_are_privileged_only_as_application_permissions():
    resources = {"sp-graph": {"app_id": GRAPH_APP_ID, "display_name": "Microsoft Graph",
                              "app_roles": {ROLE_MAIL_READ: "Mail.Read"}}}
    application = sps.application_permission_record(
        {"resource_id": "sp-graph", "app_role_id": ROLE_MAIL_READ}, resources
    )
    delegated = sps.delegated_grant_record(
        {"resource_id": "sp-graph", "scope": "Mail.Read Files.Read.All Application.ReadWrite.OwnedBy"}, resources
    )
    assert application["privileged"] is True
    assert delegated["privileged_scopes"] == ["Application.ReadWrite.OwnedBy"]


@pytest.mark.parametrize(
    "permission",
    [
        # Any application write on Graph, as azure_managed_identity_configuration has always judged it.
        "Calendars.ReadWrite",
        "Policy.ReadWrite.CrossTenantAccess",
        "Synchronization.ReadWrite.All",
        "AdministrativeUnit.ReadWrite.All",
        "RoleManagement.ReadWrite.Exchange",
        "User.ManageIdentities.All",
        "Mail.ReadBasic.All",
        "Calendars.Read",
    ],
)
def test_the_shared_judgment_flags_these_application_permissions(permission):
    resources = {"sp-graph": {"app_id": GRAPH_APP_ID, "display_name": "Microsoft Graph", "app_roles": {"r": permission}}}
    record = sps.application_permission_record({"resource_id": "sp-graph", "app_role_id": "r"}, resources)
    assert record["privileged"] is True


def test_directory_access_as_user_is_a_privileged_delegated_scope():
    resources = {"sp-graph": {"app_id": GRAPH_APP_ID, "display_name": "Microsoft Graph", "app_roles": {}}}
    delegated = sps.delegated_grant_record(
        {"resource_id": "sp-graph", "scope": "Directory.AccessAsUser.All Calendars.ReadWrite"}, resources
    )
    # A delegated write to the signed-in user's own data is still not privileged.
    assert delegated["privileged_scopes"] == ["Directory.AccessAsUser.All"]


def test_privileged_names_match_in_any_case():
    resources = {"sp-graph": {"app_id": GRAPH_APP_ID, "display_name": "Microsoft Graph", "app_roles": {}}}
    delegated = sps.delegated_grant_record(
        {"resource_id": "sp-graph", "scope": "directory.readwrite.all mail.read User.Read"}, resources
    )
    assert delegated["privileged_scopes"] == ["directory.readwrite.all"]


def test_an_unnamed_permission_is_unknown_on_graph_and_not_judged_elsewhere():
    resources = {
        "sp-graph": {"app_id": GRAPH_APP_ID, "display_name": "Microsoft Graph", "app_roles": {}},
        "sp-other": {"app_id": "not-graph", "display_name": "Other API", "app_roles": {}},
    }
    on_graph = sps.application_permission_record({"resource_id": "sp-graph", "app_role_id": ROLE_UNKNOWN}, resources)
    elsewhere = sps.application_permission_record({"resource_id": "sp-other", "app_role_id": ROLE_UNKNOWN}, resources)
    missing = sps.application_permission_record({"resource_id": None, "app_role_id": ROLE_UNKNOWN}, resources)
    assert (on_graph["permission"], on_graph["privileged"], on_graph["judged"]) == (None, None, True)
    assert (elsewhere["privileged"], elsewhere["judged"]) == (None, False)
    assert (missing["privileged"], missing["judged"]) == (None, None)


def test_unnamed_graph_permission_is_counted_and_leaves_the_flag_unknown(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["assignments"]["sp-owned"].append(_assignment(ROLE_UNKNOWN))
    # An unnamed role on an API other than Graph is not privileged either way.
    tenant["assignments"]["sp-orphan"].append(_assignment(ROLE_UNKNOWN, "sp-owned", "Owned app"))
    code, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))

    assert code == 0
    assert evidence["summary"]["unnamed_graph_application_permissions"] == 1
    assert evidence["summary"]["unnamed_other_application_permissions"] == 1
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert by_id["sp-owned"]["has_privileged_permission"] is None


def test_only_disabled_owners_and_unread_owner_state(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["app_owners"]["app-orphan"] = [_user("u-gone", enabled=False)]
    code, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))
    assert code == 0
    summary = evidence["summary"]
    assert summary["service_principals_with_only_disabled_owners"] == 1
    assert summary["service_principals_without_owner"] == 1
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert by_id["sp-orphan"]["has_owner"] is True and by_id["sp-orphan"]["has_enabled_owner"] is False

    # An owner returned without its account state (id only) leaves the figure unknown.
    tenant["app_owners"]["app-orphan"] = [_user("u-gone", enabled=None)]
    _, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))
    assert evidence["summary"]["owner_details_readable"] is False
    assert evidence["summary"]["service_principals_with_only_disabled_owners"] is None


def test_a_selected_principal_deleted_before_related_reads_fails_closed(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    gone = _api_error(404, "Selected object was deleted")
    graph.sp_owner_items["sp-orphan"].error = gone
    graph.assignment_items["sp-mi"].error = gone
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)
    assert code == 1
    assert evidence["metadata"]["api_failures"]
    assert evidence["summary"]["owners_readable"] is False
    assert evidence["summary"]["application_permissions_readable"] is False
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert by_id["sp-orphan"]["owners"] is None
    assert by_id["sp-owned"]["has_owner"] is True
    assert evidence["metadata"]["collection_completeness"]["selected_related_reads_complete"] is False


def test_owners_past_the_expand_limit_are_read_per_object(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["app_owners"] = {"app-owned": [_user(f"u-{i}") for i in range(25)]}
    graph = FakeGraph(**tenant)
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    assert graph.app_owner_items["app-owned"].calls == 1
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert len(by_id["sp-owned"]["application_owners"]) == 25


def test_service_principal_owners_past_the_expand_limit_are_read_per_object(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["sp_owners"] = {"sp-orphan": [_user(f"u-{i}") for i in range(21)]}
    graph = FakeGraph(**tenant)
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    assert graph.sp_owner_items["sp-orphan"].calls == 1
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert len(by_id["sp-orphan"]["owners"]) == 21


def test_assignments_past_the_expand_limit_are_read_per_object(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["assignments"]["sp-mi"] = [_assignment(ROLE_USER_READ) for _ in range(24)] + [_assignment(ROLE_DIR_RW)]
    graph = FakeGraph(**tenant)
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    assert graph.assignment_items["sp-mi"].calls == 1
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert len(by_id["sp-mi"]["application_permissions"]) == 25
    assert by_id["sp-mi"]["privileged_application_permissions"] == ["Directory.ReadWrite.All"]


def test_assignments_are_always_read_from_the_selected_object(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)
    assert code == 0
    assert graph.assignment_items["sp-orphan"].calls == 1
    record = next(r for r in evidence["results"]["service_principals"] if r["id"] == "sp-orphan")
    assert record["application_permissions"][0]["permission"] == "RoleManagement.ReadWrite.Directory"


def test_denied_owner_read_fails_the_run_with_null_owner_figures(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.app_owners.error = DENIED
    code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert code == 1
    assert status["code"] == "not_authorized"
    summary = evidence["summary"]
    assert summary["owners_readable"] is False
    assert summary["service_principals_without_owner"] is None
    assert summary["ownerless_service_principals_with_credentials"] is None
    assert summary["ownerless_service_principals_with_privileged_application_permissions"] is None
    # The credential evidence and the permission figures are unaffected.
    assert summary["secret_based_service_principals"] == 2
    assert summary["service_principals_with_privileged_application_permissions"] == 2
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert by_id["sp-orphan"]["has_owner"] is None


def test_denied_service_principal_owner_read_fails_the_run(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.sp_owners.error = DENIED
    code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert code == 1
    assert status["code"] == "not_authorized"
    summary = evidence["summary"]
    assert summary["owners_readable"] is False
    assert summary["owner_details_readable"] is False
    assert summary["service_principals_without_owner"] is None
    assert summary["service_principals_with_only_disabled_owners"] is None
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert by_id["sp-owned"]["owners"] is None and by_id["sp-owned"]["has_owner"] is None


def test_a_failed_app_role_name_read_leaves_permissions_unreadable(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.resource_error["sp-graph"] = DENIED
    code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert code == 1
    assert status["code"] == "not_authorized"
    summary = evidence["summary"]
    assert summary["application_permissions_readable"] is False
    assert summary["application_permission_assignments"] is None
    assert summary["unnamed_graph_application_permissions"] is None
    assert summary["service_principals_with_privileged_application_permissions"] is None


def test_denied_app_role_assignments_fail_the_run_with_null_permission_figures(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.assignments.error = DENIED
    code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert code == 1
    assert status["code"] == "not_authorized"
    summary = evidence["summary"]
    assert summary["application_permissions_readable"] is False
    assert summary["service_principals_with_privileged_application_permissions"] is None
    assert summary["privileged_application_permissions_held"] is None
    by_id = {r["id"]: r for r in evidence["results"]["service_principals"]}
    assert by_id["sp-orphan"]["application_permissions"] is None
    assert by_id["sp-orphan"]["has_privileged_permission"] is None
    # A delegated privileged grant is still a definite yes.
    assert by_id["sp-vendor"]["has_privileged_permission"] is True


def test_denied_grants_leave_delegated_figures_null_without_failing(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.oauth2_permission_grants.error = _api_error(403, "Insufficient privileges to complete the operation.")
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    assert evidence["metadata"]["api_failures"] == []
    summary = evidence["summary"]
    assert summary["delegated_grants_readable"] is False
    assert summary["delegated_grants_status"] == "not_authorized"
    assert summary["delegated_permission_grants"] is None
    assert summary["service_principals_with_privileged_delegated_grants"] is None
    assert summary["service_principals_with_privileged_application_permissions"] == 2


def test_grants_status_follows_the_status_code_not_the_message(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.oauth2_permission_grants.error = _api_error(403, "Access to this resource is restricted.")
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)
    assert code == 0
    assert evidence["summary"]["delegated_grants_status"] == "not_authorized"

    # A gateway error that happens to say "Forbidden" is a failure, not a missing permission.
    graph = FakeGraph(**_tenant())
    graph.oauth2_permission_grants.error = _api_error(502, "Forbidden by upstream proxy")
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)
    assert code == 1
    assert evidence["summary"]["delegated_grants_status"] == "failed"
    assert evidence["metadata"]["api_failures"]

    # Graph's own error code counts, read from the error object rather than the text.
    graph = FakeGraph(**_tenant())
    denied = Exception("Access denied")
    denied.error = ns(code="Authorization_RequestDenied", message="Access denied")
    graph.oauth2_permission_grants.error = denied
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)
    assert code == 0
    assert evidence["summary"]["delegated_grants_status"] == "not_authorized"


def test_a_server_error_that_mentions_privileges_is_not_a_denial(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.oauth2_permission_grants.error = _api_error(500, "Insufficient privileges to complete the operation.")
    code, evidence, status = _run(monkeypatch, tmp_path, graph)
    assert code == 1
    assert evidence["summary"]["delegated_grants_status"] == "failed"
    assert evidence["metadata"]["api_failures"]


def test_other_grant_failures_still_fail_the_run(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.oauth2_permission_grants.error = SERVER_ERROR
    exit_code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert exit_code == 1
    assert status["code"] == "partial_failure"
    assert evidence["summary"]["delegated_grants_readable"] is False
    assert evidence["summary"]["delegated_grants_status"] == "failed"
