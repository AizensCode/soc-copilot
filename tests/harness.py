"""One construction point for a cassette-backed eval copilot.

Every live-eval site builds the same shape: a copilot whose external
reputation is replayed from the recorded cassette (so a moved verdict is
a MODEL change, not reputation drift — see tests/cassette.py) and whose
internal-log backend is under the harness's control rather than pointed
at whatever SIEM the developer's .env happens to hold. Duplicating that
wiring at four sites is how one of them silently drifts back to live
reputation, so it lives here.

`search_internal_logs` is dropped by default — the labeled expectations
were calibrated on external evidence and memory alone (see conftest). The
one site that DOES want it (the differential SIEM eval) passes its own
fake-backed SearchLogsTool in `extra_replacing`; the factory then keeps
it, replaced in place, instead of removing it.
"""
from soc_copilot.copilot import SOCCopilot
from soc_copilot.history import AlertHistoryStore
from soc_copilot.tools.base import Tool
from soc_copilot.tools.registry import default_registry

from .cassette import ReputationCassette


def make_copilot(
    *,
    store: AlertHistoryStore,
    cassette: ReputationCassette,
    extra_replacing: tuple[Tool, ...] = (),
) -> SOCCopilot:
    """A copilot with reputation replayed from `cassette`.

    The cassette's three tools replace the live reputation tools in place
    (position preserved, so the schema list the model reads is unchanged),
    plus any `extra_replacing` a site needs (e.g. a fake-SIEM
    SearchLogsTool). `search_internal_logs` is removed unless the caller
    replaced it, matching the base harness's "no internal telemetry"
    deployment.
    """
    registry = default_registry().replacing(*cassette.tools(), *extra_replacing)
    if "search_internal_logs" not in {t.name for t in extra_replacing}:
        registry = registry.without("search_internal_logs")
    return SOCCopilot(history_store=store, tools=registry)
