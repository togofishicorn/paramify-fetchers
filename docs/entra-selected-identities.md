# Selected Entra application and service-principal evidence

The two identity methods are 0.3.0 because explicit selection is a required scope
change. Existing tenant-wide manifests must be updated before they run. The separate sign-in and access-review methods are unchanged. This update
grants no credentials, consent, live collection, upload or schedule.

## Configuration and reads

Use generic config strings containing JSON arrays of directory object UUIDs:

```yaml
config:
  application_object_ids: '["10000000-0000-4000-8000-000000000001"]'
  service_principal_object_ids: '["20000000-0000-4000-8000-000000000001"]'
```

The app-registration method requires only application_object_ids and a nonempty
array. The service-principal method requires both fields and a nonempty principal
array. Explicit application_object_ids: '[]' supports managed identities, which
have no local app registration. App/client IDs are not directory object IDs.
Missing, malformed, nil, non-UUID or duplicate selections fail before credential
construction and Graph reads. No default tenant-wide selection is available.

Each selected primary object is read by its object endpoint and its returned ID
must match. Missing selected objects fail. Owners, federated credentials,
assignments and delegated grants are paged only beneath those selected objects.
Resource definitions are read only for resource IDs referenced by selected
assignments (id/appId/displayName/appRoles) or grants (id/appId/displayName).
They provide permission names and Graph resource attribution, not extra inventory.
The existing Graph SDK allowed-host, no-redirect and continuation-origin guards
remain in use. Selected related reads additionally pin the continuation path to
the same selected object collection; only paging query tokens may change. Other
fetchers retain their existing pagination behavior. No separate HTTP/authentication
framework is introduced.

## Meaning and completeness

metadata.collection_scope records mode: selected_objects and the exact normalized
application_object_ids and service_principal_object_ids. The app method records
an empty service-principal list. Subscription metadata remains correlation only.
This selection does not establish an offering boundary or tenant completeness.

metadata.collection_completeness.selected_primary_reads_complete means every
selected primary object was returned with the requested ID. The service-principal
method also records selected_related_reads_complete and application_context_complete.
The first includes optional grant reads: a denied optional read leaves the native
successful run with null grant figures and related completeness false. Other failed
required reads fail collection. Null is unknown, never a healthy zero.

A principal's application_context is selected, not_applicable, not_selected or
incomplete. Managed identities and Microsoft/other-tenant applications have no
required local application context. A local application not selected, or an
unread selected federation list, cannot prove absent application credentials or
owners. Affected per-principal flags/counts and summary authentication/credential
counts, owner negative counts and rotation compliance remain null. Observed
credentials and service-principal-held credential counts remain available.

Native summary names and projections are retained. All denominators apply only
to selected identities and selected joined credentials. The existing
applications_without_service_principal records and
tenant_applications_without_service_principal summary now mean no selected join,
not absence of a principal elsewhere in the tenant. Their records explicitly
carry service_principal_match_scope: selected_objects. Credential rotation retains
the native platform-managed exclusion and expiry/lifetime classifications.

## Source uptake

The method implementations, descriptors and native regression tests are taken
from official Paramify commit 09eb429935b9482355a85c6be02ae93fc99f7fc4 and adjusted for explicit selection and honest scope.
The reviewed public c4601fb Graph SDK host/redirect/continuation guards are preserved.
Targeted shared dependencies are the native Graph permission judgments in
entra_graph.py and bounded_int_config in azure_rest.py, plus the invalid-setting
failure classifier marker. Unrelated catalogs and shared ARM boundary behavior
are not replaced. Synthetic tests exercise identity/owner joins, lifetime rules,
privileged permissions, missing/denied reads and unexpected-request boundaries.
