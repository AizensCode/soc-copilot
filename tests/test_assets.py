"""Unit tests for the asset-inventory matcher (no API, no network).

The matcher is the deterministic half of the environment-context feature:
these tests pin that it matches by IP, hostname (both raw_log shapes),
and service account, dedupes to one entry per canonical asset, and stays
inert for un-inventoried alerts.
"""
import json

from soc_copilot.assets import match_assets
from soc_copilot.models import Alert

INVENTORY = {
    "hosts": {
        "scanner-01.corp.internal": {
            "role": "vulnerability scanner",
            "owner": "secops",
            "notes": "authorized appliance",
            "expected_activity": ["scan window: Tue 03:00-04:00 UTC"],
        },
    },
    "ips": {"10.9.9.9": {"host": "scanner-01.corp.internal"}},
    "service_accounts": {
        "svc-scan": {
            "role": "authenticated scanning",
            "owner": "secops",
            "expected_activity": ["logins from 10.9.9.9 only"],
        },
    },
}


def _inventory_file(tmp_path):
    p = tmp_path / "inventory.json"
    p.write_text(json.dumps(INVENTORY))
    return p


def _alert(raw_log=None, indicators=None) -> Alert:
    return Alert(
        alert_id="ALRT-TEST-001",
        timestamp="2026-04-01T03:10:00Z",
        source="siem",
        severity="medium",
        title="test alert",
        raw_log=raw_log or {},
        indicators=indicators or {},
    )


def test_matches_ip_and_resolves_host_entry(tmp_path):
    alert = _alert(indicators={"ips": ["10.9.9.9"]})
    matches = match_assets(alert, _inventory_file(tmp_path))
    assert len(matches) == 1
    m = matches[0]
    assert m.entity == "10.9.9.9"
    assert m.entity_type == "ip"
    assert m.name == "scanner-01.corp.internal"
    assert m.role == "vulnerability scanner"
    assert m.expected_activity == ["scan window: Tue 03:00-04:00 UTC"]


def test_matches_hostname_in_native_string_shape(tmp_path):
    alert = _alert(raw_log={"source_host": "scanner-01.corp.internal"})
    matches = match_assets(alert, _inventory_file(tmp_path))
    assert [m.entity_type for m in matches] == ["host"]


def test_matches_hostname_in_ecs_dict_shape(tmp_path):
    alert = _alert(raw_log={"host": {"name": "scanner-01.corp.internal"}})
    matches = match_assets(alert, _inventory_file(tmp_path))
    assert [m.name for m in matches] == ["scanner-01.corp.internal"]


def test_matches_service_account(tmp_path):
    alert = _alert(indicators={"users": ["svc-scan"]})
    matches = match_assets(alert, _inventory_file(tmp_path))
    assert len(matches) == 1
    assert matches[0].entity_type == "service_account"
    assert matches[0].role == "authenticated scanning"


def test_same_asset_referenced_twice_appears_once(tmp_path):
    # By IP in indicators AND by hostname in raw_log — one canonical asset.
    alert = _alert(
        raw_log={"source_host": "scanner-01.corp.internal"},
        indicators={"ips": ["10.9.9.9"]},
    )
    matches = match_assets(alert, _inventory_file(tmp_path))
    assert len(matches) == 1


def test_uninventoried_alert_matches_nothing(tmp_path):
    alert = _alert(
        raw_log={"host": "prod-web-02"},
        indicators={"ips": ["203.0.113.66"], "users": ["root"]},
    )
    assert match_assets(alert, _inventory_file(tmp_path)) == []


def test_missing_inventory_file_is_inert(tmp_path):
    alert = _alert(indicators={"ips": ["10.9.9.9"]})
    assert match_assets(alert, tmp_path / "nope.json") == []


def test_committed_inventory_covers_the_benign_fixtures():
    """The real inventory must recognize the assets the benign fixtures
    (and their ECS twins) rely on — this is the contract that lets the
    copilot call them false positives with confidence.
    """
    scanner = _alert(
        raw_log={"source_host": "qualys-scanner-02.corp.internal"},
        indicators={"ips": ["10.20.8.15"], "users": ["svc-qualys"]},
    )
    matched = {m.entity for m in match_assets(scanner)}
    assert "10.20.8.15" in matched
    assert "svc-qualys" in matched

    sccm = _alert(raw_log={"host": "sccm-mp-01.corp.internal"})
    assert [m.role for m in match_assets(sccm)] == ["SCCM management point"]
