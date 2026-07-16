"""
SOAR MCP Server — Policy Layer (gated-autonomous run_playbook, issue #135/#136)

A narrow policy guard that decides how a playbook run may proceed:
  ALLOW           — autonomous (audit only)
  APPROVE_1CLICK  — reversible, one approver
  APPROVE_2PERSON — irreversible / high-impact, two approvers
  DENY            — fail-safe (unknown category, policy error)

Pure decision logic — no SOAR access. The category → base gate mapping lives in
policy_config.json (data-driven; extend without code changes). The risk score can
only *escalate* a gate, never relax it, so the default is always safe.

Design decisions (per epic #135): JSON config (no new dependency), fail-safe to
the configured default (never ALLOW) for anything unknown.

Copyright 2026 Andreas Buis
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional, Union

log = logging.getLogger("soar_mcp.policy")

_DEFAULT_CONFIG = Path(__file__).parent / "policy_config.json"


class Gate(IntEnum):
    """Order = strictness. max() returns the strictest gate."""
    ALLOW = 0
    APPROVE_1CLICK = 1
    APPROVE_2PERSON = 2
    DENY = 3

    @classmethod
    def from_name(cls, name: object) -> "Gate":
        try:
            return cls[str(name)]
        except KeyError:
            log.warning("unknown gate name %r -> DENY (fail-safe)", name)
            return cls.DENY


@dataclass
class ActionContext:
    """What the guard knows about the planned run_playbook action."""
    playbook_id: int
    playbook_name: str
    category: str
    reversible: bool = True
    agent_confidence: float = 0.5          # 0..1 (missing -> 0.5)
    asset_criticality: float = 0.0         # 0..1
    target_asset_tags: list[str] = field(default_factory=list)
    target_identity_tags: list[str] = field(default_factory=list)


@dataclass
class PolicyDecision:
    gate: Gate
    reason: str
    risk_score: float
    context: ActionContext

    @property
    def needed_approvers(self) -> int:
        return {Gate.APPROVE_1CLICK: 1, Gate.APPROVE_2PERSON: 2}.get(self.gate, 0)

    def to_dict(self) -> dict:
        return {
            "gate": self.gate.name,
            "reason": self.reason,
            "risk_score": round(self.risk_score, 3),
            "needed_approvers": self.needed_approvers,
            "playbook_id": self.context.playbook_id,
            "playbook_name": self.context.playbook_name,
            "category": self.context.category,
        }


class PolicyLayer:
    def __init__(self, config_path: Union[str, Path, None] = None):
        self._cfg = self._load(config_path or _DEFAULT_CONFIG)
        self._default = Gate.from_name(self._cfg.get("default_gate", "DENY"))
        self._categories = self._cfg.get("categories", {}) or {}
        self._irreversible = {
            str(c).lower() for c in (self._cfg.get("irreversible_categories") or [])
        }
        self._risk = self._cfg.get("risk", {}) or {}
        self._targets = self._cfg.get("always_2person_targets", {}) or {}
        self._asset_ctx = self._cfg.get("asset_context", {}) or {}

    @staticmethod
    def _load(path: Union[str, Path]) -> dict:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            # Fail-safe: no config -> empty dict -> default_gate falls back to DENY.
            log.error("[policy] could not load config %s: %s -> DENY defaults", path, exc)
            return {}

    def category_is_reversible(self, category: str) -> bool:
        """Ground truth for reversibility from config (irreversible list)."""
        return str(category).lower() not in self._irreversible

    @property
    def asset_context_enabled(self) -> bool:
        """True if the config defines an asset_context tag map (Phase 4, #139)."""
        return bool(self._asset_ctx.get("asset_tags") or self._asset_ctx.get("identity_tags"))

    @staticmethod
    def _match_tags(values: list, tag_map: dict, exact: bool) -> set:
        """Return the set of tags whose patterns match any of the given values."""
        vals = [str(v).strip().lower() for v in values if str(v).strip()]
        tags = set()
        for tag, patterns in (tag_map or {}).items():
            for pat in (patterns or []):
                p = str(pat).strip().lower()
                if not p:
                    continue
                if any(p == v for v in vals) if exact else any(p in v for v in vals):
                    tags.add(tag)
                    break
        return tags

    def enrich(self, values: list) -> dict:
        """Derive target tags + asset_criticality from observed artifact values.

        Only ESCALATES: matched crown-jewel asset tags set asset_criticality=1.0 and,
        together with matched identity tags, feed the target override in evaluate().
        No match -> empty tags / 0.0 (never relaxes the base gate). Fail-safe.
        """
        exact = str(self._asset_ctx.get("match", "substring")).lower() == "exact"
        asset_tags = self._match_tags(values, self._asset_ctx.get("asset_tags", {}), exact)
        identity_tags = self._match_tags(values, self._asset_ctx.get("identity_tags", {}), exact)
        crown = set(self._targets.get("asset_tags", []))
        criticality = 1.0 if (asset_tags & crown) else 0.0
        return {
            "target_asset_tags": sorted(asset_tags),
            "target_identity_tags": sorted(identity_tags),
            "asset_criticality": criticality,
        }

    def evaluate(self, ctx: ActionContext) -> PolicyDecision:
        # 1) Base gate from category (unknown -> fail-safe default, never ALLOW).
        base_name = self._categories.get(ctx.category)
        if base_name is None:
            log.warning("[policy] category %r not in policy -> default %s",
                        ctx.category, self._default.name)
            base = self._default
        else:
            base = Gate.from_name(base_name)

        # 2) Risk score -> possible escalation (never relaxation).
        w = self._risk.get("weights", {})
        score = (
            float(w.get("asset_criticality", 0.0)) * _clamp01(ctx.asset_criticality)
            + float(w.get("reversibility", 0.0)) * (0.0 if ctx.reversible else 1.0)
            + float(w.get("low_confidence", 0.0)) * (1.0 - _clamp01(ctx.agent_confidence))
        )
        th = self._risk.get("escalate_thresholds", {})
        risk_gate = Gate.ALLOW
        if score >= float(th.get("to_2person", 1.1)):
            risk_gate = Gate.APPROVE_2PERSON
        elif score >= float(th.get("to_1click", 1.1)):
            risk_gate = Gate.APPROVE_1CLICK

        # 3) Target override: critical assets/identities -> always 2-person.
        override = Gate.ALLOW
        if _overlap(ctx.target_asset_tags, self._targets.get("asset_tags", [])) or \
                _overlap(ctx.target_identity_tags, self._targets.get("identity_tags", [])):
            override = Gate.APPROVE_2PERSON

        gate = max(base, risk_gate, override)
        reason = (f"base={base.name} risk={score:.2f}->{risk_gate.name} "
                  f"override={override.name} => {gate.name}")
        return PolicyDecision(gate=gate, reason=reason, risk_score=score, context=ctx)


def _clamp01(x: object) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return 0.0


def _overlap(a: list, b: list) -> bool:
    return bool({str(x).lower() for x in (a or [])} & {str(x).lower() for x in (b or [])})
