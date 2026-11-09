"""Native activity descriptors expose the shared opt-in before source authentication."""
from importlib import import_module
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from framework.config_loader import discover_fetchers

ROOT = Path(__file__).parents[1]
NAMES = ('network_traffic_activity', 'waf_ddos_activity')
SUB = '00000000-0000-0000-0000-000000000001'
OTHER = '00000000-0000-0000-0000-000000000002'


@pytest.mark.parametrize('name', NAMES)
def test_activity_descriptor_exposes_native_scope_and_keeps_query_cost_opt_in(name):
    descriptor = discover_fetchers(ROOT)['azure_' + name]
    setting = descriptor.config_schema['target_subscription_only']
    assert setting.type == 'boolean'
    assert setting.default is False
    assert setting.env == 'AZURE_TARGET_SUBSCRIPTION_ONLY'
    assert descriptor.config_schema['query_basic_tables'].default is False


@pytest.mark.parametrize('name', NAMES)
def test_activity_requires_explicit_subscription_before_credential_creation(monkeypatch, name):
    native = import_module('fetchers.azure.' + name + '.fetcher')
    helper = import_module('azure_rest')
    monkeypatch.setenv('AZURE_TARGET_SUBSCRIPTION_ONLY', 'true')
    monkeypatch.delenv('AZURE_SUBSCRIPTION_ID', raising=False)
    credential = Mock(side_effect=AssertionError('credential created'))
    monkeypatch.setattr(helper, 'pinned_credential', credential)
    with pytest.raises(ValueError, match='AZURE_SUBSCRIPTION_ID'):
        native.main()
    credential.assert_not_called()


@pytest.mark.parametrize('name', NAMES)
def test_activity_foreign_workspace_stops_before_authentication_or_query(monkeypatch, name):
    native = import_module('fetchers.azure.' + name + '.fetcher')
    helper = import_module('azure_rest')
    from azure_common import Collector
    monkeypatch.setenv('AZURE_TARGET_SUBSCRIPTION_ONLY', 'true')
    monkeypatch.setenv('AZURE_SUBSCRIPTION_ID', SUB)
    credential, session = Mock(), Mock()
    client = helper.AzureRestClient(credential, session)
    collector = Collector(logging.getLogger('activity-boundary'))
    workspace = f'/subscriptions/{OTHER}/resourceGroups/synthetic/providers/Microsoft.OperationalInsights/workspaces/foreign'
    args = (client, workspace, [], False)
    if name == 'waf_ddos_activity':
        args += (7,)
    result = native.read_workspace(*args, collector)
    assert result['status'] == 'error'
    assert not collector.ok
    credential.get_token.assert_not_called()
    session.get.assert_not_called()
    session.post.assert_not_called()


@pytest.mark.parametrize('name', NAMES)
def test_activity_queries_are_bounded_to_selected_subscription(name):
    native = import_module('fetchers.azure.' + name + '.fetcher')
    fmt = dict(days=7, span=14, subscription_id=SUB, sample=10)
    queries = native.filled_queries(fmt)
    for key, query in queries.items():
        # Origin queries use the explicit app IDs selected by the subscription's ARM list.
        assert SUB in query or (name == 'network_traffic_activity' and '{app_ids}' in query)
        assert 'ago(7d)' in query or 'ago(14d)' in query
        assert not any(term in query.lower() for term in ('workspace(', 'cluster(', 'externaldata'))
