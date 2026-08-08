"""Deterministic Sigma rule matching over alert raw logs.

Answers "which community detection logic recognizes this behavior?" by
evaluating curated SigmaHQ rules (committed under data/sigma/, Detection
Rule License) directly against an alert's raw_log dict. Matches are
computed in Python and injected into the prompt as grounded context — the
model can corroborate with them but cannot invent them, the same
grounding-by-construction pattern as the MITRE group map.

Scope, honestly stated: this is an event matcher for the common Sigma
subset our curated rules use, not a full Sigma engine —

- selections as maps (fields AND-ed), lists of maps (OR-ed), and value
  lists (any-of); bare string list entries act as keyword searches over
  the serialized raw log
- field modifiers: contains, startswith, endswith; unmodified values
  compare equal, with ``*`` wildcards honored; everything matches
  case-insensitively per the Sigma spec
- conditions: identifiers combined with and/or/not, parentheses, and
  ``1 of pattern`` / ``all of pattern`` / ``... of them``
- aggregation rules (near/count) are out of scope — SigmaHQ itself parks
  those in unsupported/, which is why e.g. DNS-tunneling thresholds
  cannot be expressed as an event rule

Field names are translated through FIELD_MAP (the moral equivalent of a
pySigma pipeline): each Sigma field lists the raw_log paths — flat keys
or dotted ECS paths — that may carry the value. Path-shaped patterns like
``\\powershell.exe`` additionally match a bare basename, since normalized
alerts often carry ``process: powershell.exe`` without a full path.
"""
import fnmatch
import json
import re
from functools import lru_cache
from pathlib import Path

import yaml

from .models import Alert, SigmaMatch

RULES_DIR = Path("data/sigma")

# Sigma field -> candidate raw_log locations (flat keys and dotted ECS
# paths), tried in order. Extend as curated rules require new fields.
FIELD_MAP: dict[str, list[str]] = {
    "Image": ["process_path", "process.executable", "process", "process.name"],
    "CommandLine": ["command_line", "process.command_line"],
    "ParentImage": [
        "parent_process",
        "parent_process_path",
        "process.parent.executable",
        "process.parent.name",
    ],
    "ParentCommandLine": [
        "parent_command_line",
        "process.parent.command_line",
    ],
    "OriginalFileName": ["process", "process.name", "process_path"],
    "TargetFilename": ["file_path", "file.path", "file.name"],
    # Needed by false-positive filters that exclude SYSTEM-context activity
    # (e.g. the schtasks rule's 'AUTHORI'/'AUTORI' filter). Without the
    # mapping the filter can never fire and benign SYSTEM tasks would match.
    "User": ["user", "user.name"],
}


def _lookup(raw_log: dict, path: str) -> list[str]:
    """Resolve a flat or dotted path to its string value(s), if any."""
    cur: object = raw_log
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            cur = raw_log.get(path) if isinstance(raw_log, dict) else None
            break
    if isinstance(cur, str):
        return [cur]
    if isinstance(cur, list):
        return [v for v in cur if isinstance(v, str)]
    return []


# Modifiers this matcher implements. A curated rule using anything else is
# REJECTED at load time rather than silently mis-evaluated — a Sigma match is
# a grounding claim, so "quietly wrong" is the one outcome we cannot allow.
_MATCH_MODIFIERS = {"contains", "startswith", "endswith"}
_VALUE_MODIFIERS = {"windash"}
SUPPORTED_MODIFIERS = _MATCH_MODIFIERS | _VALUE_MODIFIERS

# Sigma's `windash` modifier: the pattern's leading dash/slash may appear as
# any of these in real command lines (including unicode dashes attackers use).
_WINDASH_PREFIXES = ("-", "/", "–", "—", "―")


def _expand_windash(pattern: str) -> list[str]:
    """Expand a pattern's leading dash/slash into every accepted variant."""
    if not pattern or pattern[0] not in _WINDASH_PREFIXES:
        return [pattern]
    rest = pattern[1:]
    return [prefix + rest for prefix in _WINDASH_PREFIXES]


def _match_value(value: str, pattern: str, modifier: str | None) -> bool:
    v, p = value.lower(), str(pattern).lower()
    if modifier == "contains":
        return p in v
    if modifier == "startswith":
        return v.startswith(p)
    if modifier == "endswith":
        # A rule pattern like '\powershell.exe' should also match an alert
        # that carries the bare basename 'powershell.exe'.
        return v.endswith(p) or v == p.lstrip("\\/")
    if "*" in p or "?" in p:
        return fnmatch.fnmatch(v, p)
    return v == p


def _field_matches(raw_log: dict, sigma_field: str, patterns: object) -> bool:
    name, *modifiers = sigma_field.split("|")
    unknown = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
    if unknown:
        raise ValueError(
            f"Unsupported Sigma modifier(s) {unknown} on field '{sigma_field}'"
        )
    candidates = FIELD_MAP.get(name, [name])
    values = [v for path in candidates for v in _lookup(raw_log, path)]
    if not values:
        return False

    pats = patterns if isinstance(patterns, list) else [patterns]
    pats = [str(p) for p in pats]
    if "windash" in modifiers:
        pats = [variant for p in pats for variant in _expand_windash(p)]

    match_mod = next((m for m in modifiers if m in _MATCH_MODIFIERS), None)
    return any(_match_value(v, p, match_mod) for v in values for p in pats)


def _eval_selection(selection: object, raw_log: dict, blob: str) -> bool:
    """Evaluate one named selection against the raw log.

    Map: all fields must match. List: any entry may match — dict entries
    are nested maps, bare strings are keyword searches over the blob.
    """
    if isinstance(selection, dict):
        return all(
            _field_matches(raw_log, field, pats)
            for field, pats in selection.items()
        )
    if isinstance(selection, list):
        return any(
            _eval_selection(entry, raw_log, blob)
            if isinstance(entry, dict)
            else str(entry).lower() in blob
            for entry in selection
        )
    return False


class _ConditionParser:
    """Recursive-descent parser for the Sigma condition subset."""

    def __init__(self, condition: str, results: dict[str, bool]) -> None:
        spaced = condition.replace("(", " ( ").replace(")", " ) ")
        self.tokens = spaced.split()
        self.pos = 0
        self.results = results

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> bool:
        value = self._parse_or()
        if self._peek() is not None:
            raise ValueError(f"Trailing tokens in condition: {self.tokens}")
        return value

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while self._peek() == "or":
            self._next()
            value = self._parse_and() or value
        return value

    def _parse_and(self) -> bool:
        value = self._parse_unary()
        while self._peek() == "and":
            self._next()
            value = self._parse_unary() and value
        return value

    def _parse_unary(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._parse_unary()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._next()
        if tok == "(":
            value = self._parse_or()
            if self._next() != ")":
                raise ValueError("Unbalanced parentheses in condition")
            return value
        if self._peek() == "of":
            self._next()
            pattern = self._next()
            names = (
                list(self.results)
                if pattern == "them"
                else [n for n in self.results if fnmatch.fnmatch(n, pattern)]
            )
            matched = [n for n in names if self.results[n]]
            if tok == "all":
                return bool(names) and len(matched) == len(names)
            return len(matched) >= int(tok)  # 'N of pattern'
        if tok not in self.results:
            raise ValueError(f"Unknown selection '{tok}' in condition")
        return self.results[tok]


def _validate_modifiers(selection: object, where: str) -> None:
    """Reject a rule that uses field modifiers this matcher can't evaluate.

    Checked eagerly at load time: condition evaluation short-circuits, so a
    lazy check could leave an unevaluable field silently unexercised until
    some future alert happens to reach it.
    """
    if isinstance(selection, dict):
        for field in selection:
            unknown = [
                m for m in field.split("|")[1:] if m not in SUPPORTED_MODIFIERS
            ]
            if unknown:
                raise ValueError(
                    f"{where}: Unsupported Sigma modifier(s) {unknown} on "
                    f"field '{field}'. Implement them in soc_copilot/sigma.py or drop "
                    f"the rule — a rule that cannot be evaluated correctly "
                    f"must not be curated."
                )
    elif isinstance(selection, list):
        for entry in selection:
            _validate_modifiers(entry, where)


@lru_cache(maxsize=1)
def load_rules(rules_dir: str = str(RULES_DIR)) -> list[dict]:
    """Load and validate the curated rule files."""
    rules = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        rule = yaml.safe_load(path.read_text())
        detection = rule.get("detection", {})
        if "condition" not in detection:
            raise ValueError(f"{path.name}: rule has no condition")
        for name, selection in detection.items():
            if name != "condition":
                _validate_modifiers(selection, path.name)
        rules.append(
            {
                "id": str(rule.get("id", path.stem)),
                "title": rule.get("title", path.stem),
                "level": rule.get("level", "medium"),
                "tags": [str(t) for t in rule.get("tags", [])],
                "detection": detection,
                "file": path.name,
            }
        )
    return rules


def match_sigma_rules(alert: Alert) -> list[SigmaMatch]:
    """Evaluate every curated rule against the alert's raw log."""
    raw_log = alert.raw_log or {}
    blob = json.dumps(raw_log).lower()
    matches: list[SigmaMatch] = []
    for rule in load_rules():
        detection = rule["detection"]
        results = {
            name: _eval_selection(sel, raw_log, blob)
            for name, sel in detection.items()
            if name != "condition"
        }
        condition = detection["condition"]
        # Sigma allows a list of conditions (OR semantics)
        conditions = condition if isinstance(condition, list) else [condition]
        if any(_ConditionParser(c, results).parse() for c in conditions):
            matches.append(
                SigmaMatch(
                    rule_id=rule["id"],
                    title=rule["title"],
                    level=rule["level"],
                    tags=rule["tags"],
                )
            )
    return matches


_TCODE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


def tags_to_techniques(tags: list[str]) -> list[str]:
    """Extract T-codes from Sigma attack.* tags (e.g. attack.t1059.001)."""
    out = []
    for tag in tags:
        m = _TCODE_RE.match(tag.lower())
        if m:
            out.append(m.group(1).upper())
    return out
