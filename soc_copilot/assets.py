"""Environment context — matching alerts against the asset inventory.

A SOC analyst separates "unknown activity" from "known-benign activity"
with environment knowledge: which hosts are scanners, which service
accounts exist for what, what runs on a schedule. This module is that
knowledge as data — a committed, operator-owned inventory
(data/asset_context.json) plus a pure matcher that surfaces the entries
relevant to an alert.

Trust model: alert content is attacker-influenced, so a prose claim like
"authorized vuln scanner" inside a log message proves nothing. The same
claim in the inventory is trusted BY PROVENANCE — the operator wrote it.
The matcher is deterministic and the model can only cite matches, never
invent them: the same grounding-by-construction contract as the Sigma
matcher and the case history.

A match states an entity's sanctioned role. Whether the observed
activity fits that role remains the analyst's judgment.
"""
import json
from pathlib import Path

from .models import Alert, AssetMatch

ASSET_CONTEXT_PATH = Path("data/asset_context.json")

# raw_log keys that may carry a hostname, in either fixture shape
# (plain string) or ECS shape ({"name": ...}).
_HOST_KEYS = ["host", "source_host", "destination_host"]


def load_inventory(path: str | Path = ASSET_CONTEXT_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def _hostnames(alert: Alert) -> list[str]:
    """Hostname candidates from the alert's raw log, deduped."""
    if not isinstance(alert.raw_log, dict):
        return []
    names: list[str] = []
    for key in _HOST_KEYS:
        value = alert.raw_log.get(key)
        if isinstance(value, dict):
            value = value.get("name")
        if isinstance(value, str) and value and value not in names:
            names.append(value)
    return names


def match_assets(
    alert: Alert, path: str | Path = ASSET_CONTEXT_PATH
) -> list[AssetMatch]:
    """Surface the inventory entries an alert's identifiers point at.

    Matches IPs (via the inventory's ip -> host mapping), hostnames, and
    service accounts. Each canonical asset appears once even when the
    alert references it several ways (e.g. by IP and by hostname).
    """
    inventory = load_inventory(path)
    if not inventory:
        return []
    hosts = inventory.get("hosts", {})
    ips = inventory.get("ips", {})
    accounts = inventory.get("service_accounts", {})

    matches: list[AssetMatch] = []
    seen_assets: set[str] = set()

    def add(match: AssetMatch) -> None:
        canonical = match.name or match.entity
        if canonical not in seen_assets:
            seen_assets.add(canonical)
            matches.append(match)

    for ip in alert.indicators.get("ips", []):
        entry = ips.get(ip)
        if not entry:
            continue
        host_name = entry.get("host")
        host_entry = hosts.get(host_name, {})
        add(
            AssetMatch(
                entity=ip,
                entity_type="ip",
                name=host_name,
                role=host_entry.get("role", "inventoried asset"),
                owner=host_entry.get("owner"),
                notes=host_entry.get("notes"),
                expected_activity=host_entry.get("expected_activity", []),
            )
        )

    for name in _hostnames(alert):
        entry = hosts.get(name)
        if not entry:
            continue
        add(
            AssetMatch(
                entity=name,
                entity_type="host",
                name=name,
                role=entry.get("role", "inventoried asset"),
                owner=entry.get("owner"),
                notes=entry.get("notes"),
                expected_activity=entry.get("expected_activity", []),
            )
        )

    for user in alert.indicators.get("users", []):
        entry = accounts.get(user)
        if not entry:
            continue
        add(
            AssetMatch(
                entity=user,
                entity_type="service_account",
                name=user,
                role=entry.get("role", "inventoried service account"),
                owner=entry.get("owner"),
                notes=entry.get("notes"),
                expected_activity=entry.get("expected_activity", []),
            )
        )

    # Sanctioned SaaS / OAuth applications. An app is identified two ways
    # in consent alerts — by application (client) id GUID and by display
    # name — and display names are attacker-choosable (a rogue app can
    # call itself anything), so the inventory is keyed by the GUID and a
    # display-name match is honored only when the entry itself lists that
    # name. Candidates come from indicators.apps plus the audit-log keys
    # Entra events actually carry.
    apps = inventory.get("saas_apps", {})
    if apps:
        by_name = {
            entry["name"]: (app_id, entry)
            for app_id, entry in apps.items()
            if entry.get("name")
        }
        # indicators.apps is attacker-influenced free-form data; an
        # unhashable element (a nested list/dict) would raise TypeError on
        # the `in` membership test below, so filter to strings first — the
        # same guard the raw_log keys already get.
        candidates = [
            a for a in alert.indicators.get("apps", []) if isinstance(a, str)
        ]
        if isinstance(alert.raw_log, dict):
            for key in ("app_id", "application_id", "app_display_name"):
                value = alert.raw_log.get(key)
                if isinstance(value, str) and value:
                    candidates.append(value)
        for candidate in candidates:
            if candidate in apps:
                app_id, entry = candidate, apps[candidate]
            elif candidate in by_name:
                app_id, entry = by_name[candidate]
            else:
                continue
            add(
                AssetMatch(
                    entity=app_id,
                    entity_type="saas_app",
                    name=entry.get("name", app_id),
                    role=entry.get("role", "sanctioned SaaS application"),
                    owner=entry.get("owner"),
                    notes=entry.get("notes"),
                    expected_activity=entry.get("expected_activity", []),
                )
            )

    return matches
