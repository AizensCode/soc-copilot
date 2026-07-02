"""Build a compact technique -> threat-group lookup from MITRE ATT&CK.

The full MITRE ATT&CK enterprise STIX bundle is ~53 MB — too large to commit
or fetch at runtime. This one-time build script downloads it, extracts only
the intrusion-set ("uses") -> attack-pattern relationships, and writes a small
JSON (a few hundred KB) that the runtime ThreatActorTool reads offline.

Every group name in the output traces back to the official MITRE bundle — this
is deliberate: the project forbids inventing threat-actor names, so the mapping
must be sourced, never hand-written.

Usage:
    uv run python scripts/build_group_map.py            # download + build
    uv run python scripts/build_group_map.py --bundle /path/to/enterprise-attack.json

Output: data/mitre/technique_groups.json
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "data" / "mitre" / "technique_groups.json"


def _load_bundle(bundle_path: str | None) -> dict:
    if bundle_path:
        print(f"Reading STIX bundle from {bundle_path}")
        with open(bundle_path) as f:
            return json.load(f)
    print(f"Downloading STIX bundle from {BUNDLE_URL} (~53 MB)...")
    with urlopen(BUNDLE_URL) as resp:  # noqa: S310 (trusted MITRE URL)
        return json.loads(resp.read())


def _is_live(obj: dict) -> bool:
    """Skip revoked or deprecated objects."""
    return not obj.get("revoked", False) and not obj.get(
        "x_mitre_deprecated", False
    )


def _mitre_id(obj: dict) -> str | None:
    """Pull the T-code from an attack-pattern's external references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build(bundle: dict) -> dict:
    objects = bundle.get("objects", [])

    # STIX id -> T-code, for live attack-patterns only
    technique_by_ref: dict[str, str] = {}
    # STIX id -> {"name", "aliases"}, for live intrusion-sets only
    group_by_ref: dict[str, dict] = {}
    attack_version = "unknown"

    for obj in objects:
        otype = obj.get("type")
        if otype == "x-mitre-collection":
            attack_version = obj.get("x_mitre_version", attack_version)
        elif otype == "attack-pattern" and _is_live(obj):
            tid = _mitre_id(obj)
            if tid:
                technique_by_ref[obj["id"]] = tid
        elif otype == "intrusion-set" and _is_live(obj):
            name = obj.get("name")
            if name:
                # aliases usually includes the primary name; drop the dup
                aliases = [a for a in obj.get("aliases", []) if a != name]
                group_by_ref[obj["id"]] = {"name": name, "aliases": aliases}

    # technique T-code -> set of group names
    techniques: dict[str, set[str]] = {}
    groups: dict[str, dict] = {}

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if not _is_live(obj):
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if not src.startswith("intrusion-set--"):
            continue
        if not tgt.startswith("attack-pattern--"):
            continue
        group = group_by_ref.get(src)
        tid = technique_by_ref.get(tgt)
        if group is None or tid is None:
            continue
        techniques.setdefault(tid, set()).add(group["name"])
        groups[group["name"]] = {"aliases": group["aliases"]}

    return {
        "_meta": {
            "source": BUNDLE_URL,
            "attack_version": attack_version,
            "generated": datetime.now(timezone.utc).isoformat(),
            "technique_count": len(techniques),
            "group_count": len(groups),
        },
        # sort for stable, reviewable diffs
        "techniques": {
            tid: sorted(names) for tid, names in sorted(techniques.items())
        },
        "groups": dict(sorted(groups.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        help="Path to a local enterprise-attack.json (skips download)",
    )
    args = parser.parse_args()

    bundle = _load_bundle(args.bundle)
    result = build(bundle)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w") as f:
        json.dump(result, f, indent=2, sort_keys=False)
        f.write("\n")

    meta = result["_meta"]
    size_kb = OUT_PATH.stat().st_size / 1024
    print(
        f"Wrote {OUT_PATH.relative_to(REPO_ROOT)} "
        f"({size_kb:.0f} KB): {meta['technique_count']} techniques, "
        f"{meta['group_count']} groups, ATT&CK v{meta['attack_version']}"
    )
    if meta["technique_count"] == 0:
        print("ERROR: no techniques extracted — bundle format may have changed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
