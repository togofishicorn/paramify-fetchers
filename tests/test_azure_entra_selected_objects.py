"""Selection boundaries use real generated Graph builders and synthetic HTTP only."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'fetchers' / '_lib'))


def load(method):
    path = ROOT / 'fetchers' / 'azure' / method / 'fetcher.py'
    spec = importlib.util.spec_from_file_location('selected_' + method, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


APP = '10000000-0000-4000-8000-000000000001'
UNMATCHED_APP = '10000000-0000-4000-8000-000000000002'
SP = '20000000-0000-4000-8000-000000000001'
MI = '20000000-0000-4000-8000-000000000002'
GRAPH = '30000000-0000-4000-8000-000000000001'
CUSTOM = '30000000-0000-4000-8000-000000000002'
CLIENT = '40000000-0000-4000-8000-000000000001'
TENANT = '50000000-0000-4000-8000-000000000001'
ROLE = '60000000-0000-4000-8000-000000000001'
USER = '70000000-0000-4000-8000-000000000001'


@pytest.mark.parametrize('method,applications,principals', [
    ('entra_app_registrations', None, None),
    ('entra_app_registrations', '[]', None),
    ('entra_app_registrations', '{}', None),
    ('entra_app_registrations', 'not-json', None),
    ('entra_app_registrations', '[null]', None),
    ('entra_app_registrations', '["not-uuid"]', None),
    ('entra_app_registrations', '["00000000-0000-0000-0000-000000000000"]', None),
    ('entra_app_registrations', json.dumps([APP, APP.upper()]), None),
    ('entra_service_principals', None, json.dumps([SP])),
    ('entra_service_principals', '[]', None),
    ('entra_service_principals', '[]', '[]'),
    ('entra_service_principals', '[]', json.dumps([SP, SP])),
    ('entra_service_principals', '[]', '[12]'),
])
def test_bad_selection_fails_before_credentials_or_graph(monkeypatch, tmp_path, method, applications, principals):
    module = load(method)
    def forbidden(*args, **kwargs):
        pytest.fail('invalid selection reached credentials or Graph')
    monkeypatch.setattr(module, 'credential', forbidden)
    monkeypatch.setattr(module, 'with_graph_client', forbidden)
    monkeypatch.setattr(module, 'load_dotenv', lambda: None)
    monkeypatch.setenv('EVIDENCE_DIR', str(tmp_path))
    monkeypatch.setenv('FETCHER_STATUS_FILE', str(tmp_path / 'status.json'))
    for key, value in [('AZURE_ENTRA_APPLICATION_OBJECT_IDS', applications),
                       ('AZURE_ENTRA_SERVICE_PRINCIPAL_OBJECT_IDS', principals)]:
        monkeypatch.delenv(key, raising=False)
        if value is not None:
            monkeypatch.setenv(key, value)
    assert module.main() == 1
    assert json.loads((tmp_path / 'status.json').read_text())['code'] == 'bad_config'


def run_sdk(monkeypatch, tmp_path, *, applications=(APP, UNMATCHED_APP), principals=(SP, MI),
            method='entra_service_principals', grants_denied=False, wrong_primary=False,
            missing_primary=False, wrong_grant=False, fic_denied=False, continuation=None):
    pytest.importorskip('msgraph')
    import httpx
    from azure.core.credentials import AccessToken
    from msgraph_core import GraphClientFactory
    module = load(method)
    calls, unexpected, tokens = [], [], []
    monkeypatch.setattr(module, 'load_dotenv', lambda: None)
    monkeypatch.setenv('AZURE_TENANT_ID', TENANT)
    monkeypatch.setenv('AZURE_SUBSCRIPTION_ID', '80000000-0000-4000-8000-000000000001')
    monkeypatch.setenv('AZURE_AUTHORITY_HOST', 'https://login.microsoftonline.us')
    monkeypatch.setenv('AZURE_ENTRA_APPLICATION_OBJECT_IDS', json.dumps(list(applications)))
    monkeypatch.setenv('AZURE_ENTRA_SERVICE_PRINCIPAL_OBJECT_IDS', json.dumps(list(principals)))
    monkeypatch.setenv('EVIDENCE_DIR', str(tmp_path))
    monkeypatch.setenv('FETCHER_STATUS_FILE', str(tmp_path / 'status.json'))

    class Credential:
        def get_token(self, *scopes, **kwargs):
            tokens.append(scopes)
            return AccessToken('synthetic-token', 9999999999)
    monkeypatch.setattr(module, 'credential', Credential)
    expected = {'/v1.0/organization'}
    expected.update(f'/v1.0/applications/{oid}' for oid in applications)
    if method == 'entra_service_principals':
        expected.update(f'/v1.0/servicePrincipals/{oid}' for oid in principals)
        for oid in applications:
            expected.update({f'/v1.0/applications/{oid}/owners', f'/v1.0/applications/{oid}/federatedIdentityCredentials'})
        for oid in principals:
            expected.update({f'/v1.0/servicePrincipals/{oid}/owners', f'/v1.0/servicePrincipals/{oid}/appRoleAssignments',
                             f'/v1.0/servicePrincipals/{oid}/oauth2PermissionGrants'})
        if SP in principals and not wrong_primary and not missing_primary:
            expected.update({f'/v1.0/servicePrincipals/{CUSTOM}', f'/v1.0/servicePrincipals/{GRAPH}'})

    async def handler(request):
        path = request.url.path.replace("/v1.0//", "/v1.0/")
        calls.append((path, dict(request.url.params)))
        assert request.method == 'GET'
        if path not in expected or request.url.host != 'graph.microsoft.us':
            unexpected.append(str(request.url))
            return httpx.Response(400, json={'error': {'code': 'UnexpectedRead', 'message': 'Unexpected read'}}, request=request)
        if path.endswith('/organization'):
            data = {'value': [{'id': TENANT, 'displayName': 'Synthetic tenant'}]}
        elif path in (f'/v1.0/applications/{APP}', f'/v1.0/applications/{UNMATCHED_APP}'):
            oid = path.rsplit('/', 1)[-1]
            if missing_primary:
                return httpx.Response(404, json={'error': {'code': 'Request_ResourceNotFound', 'message': 'Missing selected object'}}, request=request)
            data = {'id': UNMATCHED_APP if wrong_primary else oid, 'appId': CLIENT if oid == APP else ROLE,
                    'displayName': 'Selected application', 'signInAudience': 'AzureADMyOrg',
                    'passwordCredentials': [{'keyId': ROLE, 'startDateTime': '2020-01-01T00:00:00Z',
                                             'endDateTime': '2021-01-01T00:00:00Z'}]}
        elif path in (f'/v1.0/servicePrincipals/{SP}', f'/v1.0/servicePrincipals/{MI}'):
            oid = path.rsplit('/', 1)[-1]
            if missing_primary:
                return httpx.Response(404, json={'error': {'code': 'Request_ResourceNotFound', 'message': 'Missing selected object'}}, request=request)
            data = {'id': MI if wrong_primary else oid, 'appId': CLIENT if oid == SP else MI, 'displayName': 'Selected identity',
                    'servicePrincipalType': 'Application' if oid == SP else 'ManagedIdentity',
                    'appOwnerOrganizationId': TENANT if oid == SP else None, 'accountEnabled': True,
                    'keyCredentials': ([{'keyId': ROLE, 'endDateTime': '2020-01-01T00:00:00Z'}] if oid == MI else [])}
        elif path == f'/v1.0/servicePrincipals/{CUSTOM}':
            assert set(request.url.params.get('$select', '').split(',')) == {'id', 'appId', 'displayName', 'appRoles'}
            data = {'id': CUSTOM, 'appId': CUSTOM, 'displayName': 'Custom API', 'appRoles': [{'id': ROLE, 'value': 'Custom.Read'}]}
        elif path == f'/v1.0/servicePrincipals/{GRAPH}':
            assert set(request.url.params.get('$select', '').split(',')) == {'id', 'appId', 'displayName'}
            data = {'id': GRAPH, 'appId': '00000003-0000-0000-c000-000000000000', 'displayName': 'Microsoft Graph'}
        elif path.endswith('/federatedIdentityCredentials'):
            if fic_denied:
                return httpx.Response(403, json={'error': {'code': 'Authorization_RequestDenied', 'message': 'Denied'}}, request=request)
            data = {'value': [{'id': ROLE, 'name': 'Selected trust', 'issuer': 'https://issuer.example.test',
                               'subject': 'repo:synthetic/project:ref:refs/heads/main', 'audiences': ['api://AzureADTokenExchange']}]}
        elif path.endswith('/owners'):
            if path == f'/v1.0/applications/{APP}/owners':
                if '$skiptoken' not in request.url.params:
                    data = {'value': [], '@odata.nextLink': continuation or f'https://graph.microsoft.us{path}?$skiptoken=next'}
                else:
                    data = {'value': [{'@odata.type': '#microsoft.graph.user', 'id': USER,
                                       'displayName': 'Synthetic owner', 'accountEnabled': False}]}
            else:
                data = {'value': []}
        elif path.endswith('/appRoleAssignments'):
            data = {'value': ([{'id': ROLE, 'appRoleId': ROLE, 'resourceId': CUSTOM,
                                'resourceDisplayName': 'Custom API'}] if f'/{SP}/' in path else [])}
        elif path.endswith('/oauth2PermissionGrants'):
            if grants_denied:
                return httpx.Response(403, json={'error': {'code': 'Authorization_RequestDenied', 'message': 'Denied'}}, request=request)
            data = {'value': ([{'id': ROLE, 'clientId': MI if wrong_grant else SP, 'resourceId': GRAPH,
                                'consentType': 'AllPrincipals', 'scope': 'Directory.ReadWrite.All Mail.Read'}]
                              if f'/{SP}/' in path else [])}
        else:
            raise AssertionError(path)
        return httpx.Response(200, json=data, request=request)

    original_factory = GraphClientFactory.create_with_default_middleware
    def factory(**kwargs):
        client = httpx.AsyncClient(base_url='https://graph.microsoft.us/v1.0',
                                  transport=httpx.MockTransport(handler), follow_redirects=False)
        return original_factory(client=client, **kwargs)
    monkeypatch.setattr(GraphClientFactory, 'create_with_default_middleware', factory)
    code = module.main()
    evidence = json.loads((tmp_path / f'azure_{method}_{TENANT}.json').read_text())
    assert unexpected == []
    assert all(scope == ('https://graph.microsoft.us/.default',) for scope in tokens)
    assert all('$expand' not in query for _, query in calls)
    return code, evidence, calls


def test_generated_sdk_reads_only_selected_objects_and_selected_joins(monkeypatch, tmp_path):
    code, evidence, calls = run_sdk(monkeypatch, tmp_path)
    assert code == 0
    assert evidence['metadata']['collection_scope'] == {'mode': 'selected_objects',
        'application_object_ids': [APP, UNMATCHED_APP], 'service_principal_object_ids': [SP, MI]}
    assert evidence['metadata']['subscription_source'] == 'target_correlation_only'
    assert all(evidence['metadata']['collection_completeness'].values())
    by_id = {r['id']: r for r in evidence['results']['service_principals']}
    assert by_id[SP]['application_object_id'] == APP
    assert by_id[SP]['application_context'] == 'selected'
    assert by_id[SP]['application_owners'][0]['account_enabled'] is False
    assert by_id[SP]['credentials'][0]['expired'] is True
    assert by_id[SP]['federated_identity_credential_count'] == 1
    assert by_id[SP]['privileged_delegated_permissions'] == ['Directory.ReadWrite.All']
    assert by_id[SP]['application_permissions'][0]['permission'] == 'Custom.Read'
    assert by_id[MI]['application_context'] == 'not_applicable'
    assert by_id[MI]['credential_count'] == 0  # platform-managed cert is excluded
    assert evidence['summary']['total_service_principals'] == 2
    assert evidence['summary']['total_credentials'] == 1
    assert evidence['summary']['credential_rotation_compliance_percentage'] == 0
    assert evidence['summary']['tenant_applications_without_service_principal'] == 1
    assert evidence['results']['applications_without_service_principal'][0]['service_principal_match_scope'] == 'selected_objects'
    assert sum(path.endswith(f'/{APP}/owners') for path, _ in calls) == 2


def test_generated_sdk_managed_identity_only_selection(monkeypatch, tmp_path):
    code, evidence, _ = run_sdk(monkeypatch, tmp_path, applications=(), principals=(MI,))
    assert code == 0
    assert all(evidence['metadata']['collection_completeness'].values())
    assert evidence['summary']['total_service_principals'] == 1
    assert evidence['summary']['total_credentials'] == 0
    assert evidence['summary']['platform_managed_credentials'] == 1


def test_unselected_local_application_context_stays_unknown(monkeypatch, tmp_path):
    code, evidence, _ = run_sdk(monkeypatch, tmp_path, applications=(), principals=(SP,))
    assert code == 0
    assert evidence['metadata']['collection_completeness']['application_context_complete'] is False
    record = evidence['results']['service_principals'][0]
    assert record['application_context'] == 'not_selected'
    assert record['credential_count'] is record['federated_identity_credential_count'] is None
    assert record['uses_secret'] is record['uses_federated_credential'] is None
    for key in ('total_credentials', 'credential_rotation_compliance_percentage',
                'tenant_owned_service_principals_without_credentials', 'service_principals_without_owner'):
        assert evidence['summary'][key] is None


def test_optional_grants_denied_are_null_and_do_not_hide_other_findings(monkeypatch, tmp_path):
    code, evidence, _ = run_sdk(monkeypatch, tmp_path, grants_denied=True)
    assert code == 0
    assert evidence['metadata']['collection_completeness']['selected_related_reads_complete'] is False
    assert evidence['summary']['delegated_grants_status'] == 'not_authorized'
    assert evidence['summary']['delegated_permission_grants'] is None
    assert evidence['summary']['privileged_delegated_permissions_granted'] is None
    assert evidence['summary']['expired_credentials'] == 1


def test_grants_for_a_different_client_fail(monkeypatch, tmp_path):
    code, evidence, _ = run_sdk(monkeypatch, tmp_path, wrong_grant=True)
    assert code == 1
    assert evidence['summary']['delegated_grants_status'] == 'failed'
    assert evidence['summary']['delegated_permission_grants'] is None


@pytest.mark.parametrize('wrong,missing', [(True, False), (False, True)])
def test_selected_primary_must_be_returned_with_requested_id(monkeypatch, tmp_path, wrong, missing):
    code, evidence, _ = run_sdk(monkeypatch, tmp_path, method='entra_app_registrations',
                                applications=(APP,), wrong_primary=wrong, missing_primary=missing)
    assert code == 1
    assert evidence['metadata']['collection_completeness']['selected_primary_reads_complete'] is False
    assert evidence['summary']['credentials_issued_beyond_approved_lifetime'] is None
    assert evidence['summary']['credential_rotation_compliance_percentage'] is None


def test_selected_federation_failure_stays_unknown(monkeypatch, tmp_path):
    code, evidence, _ = run_sdk(monkeypatch, tmp_path, fic_denied=True)
    assert code == 1
    assert evidence['metadata']['collection_completeness']['application_context_complete'] is False
    assert evidence['summary']['federated_identity_credentials'] is None
    assert evidence['results']['service_principals'][0]['application_context'] in ('incomplete', 'not_applicable')
    assert evidence['results']['applications_without_service_principal'][0]['federated_identity_credential_count'] is None


@pytest.mark.parametrize('wrong,missing', [(True, False), (False, True)])
def test_selected_principal_must_be_returned_with_requested_id(monkeypatch, tmp_path, wrong, missing):
    code, evidence, _ = run_sdk(monkeypatch, tmp_path, applications=(), principals=(SP,),
                                wrong_primary=wrong, missing_primary=missing)
    assert code == 1
    assert evidence['metadata']['collection_completeness']['selected_primary_reads_complete'] is False
    assert evidence['summary']['total_service_principals'] == 0


def test_generated_sdk_selected_application_denominator(monkeypatch, tmp_path):
    code, evidence, calls = run_sdk(monkeypatch, tmp_path, method='entra_app_registrations', applications=(APP,))
    assert code == 0
    assert evidence['metadata']['collection_scope']['service_principal_object_ids'] == []
    assert evidence['metadata']['collection_completeness']['selected_primary_reads_complete'] is True
    assert evidence['summary']['total_app_registrations'] == 1
    assert evidence['summary']['total_credentials'] == 1
    assert evidence['summary']['expired_credentials'] == 1
    assert evidence['summary']['credential_rotation_compliance_percentage'] == 0
    assert set(path for path, _ in calls) == {'/v1.0/organization', f'/v1.0/applications/{APP}'}


@pytest.mark.parametrize('continuation', [
    'https://graph.microsoft.us/v1.0/servicePrincipals',
    f'https://graph.microsoft.us/v1.0/applications/{UNMATCHED_APP}/owners',
    'https://foreign.invalid/v1.0/applications/anything/owners',
])
def test_related_pagination_cannot_expand_selected_population(monkeypatch, tmp_path, continuation):
    code, evidence, calls = run_sdk(monkeypatch, tmp_path, continuation=continuation)
    assert code == 1
    assert evidence['metadata']['collection_completeness']['selected_related_reads_complete'] is False
    assert sum(path.endswith(f'/{APP}/owners') for path, _ in calls) == 1
    assert all('$skiptoken' not in query for _, query in calls)
    assert evidence['summary']['service_principals_without_owner'] is None
