"""Invariants over the labeled alert set itself (API-free).

The eval fixtures are data, but they are also load-bearing: a flaw in one
silently weakens every assertion built on it. These tests check properties
the harness assumes but cannot see.

    uv run pytest tests/test_fixtures.py -v
"""
import pytest

from src.history import alert_host, alert_iocs
from src.models import Alert
from tests.alert_loading import load_all_fixtures
from tests.expectations import EXPECTATIONS


def _alerts() -> dict[str, Alert]:
    return load_all_fixtures()


def test_every_sample_alert_is_labeled():
    """A fixture with no expectations entry is dead weight — it costs two
    API calls per harness run and asserts nothing."""
    unlabeled = set(_alerts()) - set(EXPECTATIONS)
    assert not unlabeled, f"sample alerts missing from EXPECTATIONS: {unlabeled}"


def test_every_expectation_has_a_fixture():
    missing = set(EXPECTATIONS) - set(_alerts())
    assert not missing, f"EXPECTATIONS reference missing alert files: {missing}"


def test_fixtures_are_memory_decoupled():
    """No two fixtures may share an IOC or a host.

    Cross-alert memory is global to a harness run: when two fixtures share
    an indicator, whichever runs second inherits the first's prior sighting
    and its verdict shifts. That is correct copilot behavior and a broken
    experiment — it makes assertions depend on dict ordering. This caught a
    real bug: a benign vuln-scan fixture originally targeted the same host
    the brute-force attack fixture hits, and the copilot rightly refused to
    call it benign.

    Deliberate coupling (a campaign scenario) belongs in a dedicated test
    with its own store, not in the shared labeled set.
    """
    alerts = _alerts()
    iocs = {name: set(alert_iocs(a)) for name, a in alerts.items()}
    # alert_host handles both fixture shapes (native string, ECS object),
    # so ECS fixtures participate in the host-decoupling invariant too.
    hosts = {
        name: alert_host(a)
        for name, a in alerts.items()
        if alert_host(a) is not None
    }

    names = sorted(alerts)
    for i, a_name in enumerate(names):
        for b_name in names[i + 1:]:
            shared = iocs[a_name] & iocs[b_name]
            assert not shared, (
                f"{a_name} and {b_name} share IOCs {sorted(shared)}: "
                f"cross-alert memory will make harness results order-dependent"
            )
            if a_name in hosts and b_name in hosts:
                assert hosts[a_name] != hosts[b_name], (
                    f"{a_name} and {b_name} both target host "
                    f"'{hosts[a_name]}': same coupling problem"
                )


def test_alert_ids_are_unique():
    """The history store keys on alert_id; duplicates would make one
    fixture's investigation invisible to the other's prior-sighting scan."""
    seen: dict[str, str] = {}
    for name, alert in _alerts().items():
        assert alert.alert_id not in seen, (
            f"{name} reuses alert_id {alert.alert_id} from {seen[alert.alert_id]}"
        )
        seen[alert.alert_id] = name


@pytest.mark.parametrize("name", sorted(EXPECTATIONS))
def test_expectation_keys_are_known(name):
    """Typo guard: a misspelled expectation key is silently ignored by the
    harness (every test skips on absence), so it would pass while asserting
    nothing."""
    known = {
        "expected_verdict", "allowed_verdicts", "min_confidence",
        "required_techniques", "any_of_techniques", "forbidden_techniques",
        "must_escalate", "pivots_must_include", "min_evidence_count",
        "min_associated_groups", "min_injection_flags", "min_sigma_matches",
    }
    unknown = set(EXPECTATIONS[name]) - known
    assert not unknown, f"{name} has unrecognized expectation keys: {unknown}"
