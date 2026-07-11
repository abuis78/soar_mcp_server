"""
SOAR MCP Server — Configuration Manager

Loads and parses mcp.conf from the app's local/ (user overrides) or
default/ (bundled defaults) directory, following Splunk/SOAR config
precedence rules (local beats default).

Copyright 2026 Andreas Buis
"""

from __future__ import annotations

import configparser
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set, Union

logger = logging.getLogger(__name__)

_CONFIG_FILENAME = "mcp.conf"
_MANIFEST_FILENAME = "soar_mcp_server.json"


def _manifest_app_version() -> str:
    """Return app_version from the manifest so the MCP server reports the real
    version to clients instead of a hardcoded, drift-prone literal (issue #48)."""
    try:
        import json as _json
        manifest = Path(__file__).parent / _MANIFEST_FILENAME
        with open(manifest, encoding="utf-8") as fh:
            return str(_json.load(fh).get("app_version") or "").strip() or "0.0.0"
    except Exception:
        return "0.0.0"


# ── Valid values ───────────────────────────────────────────────────────────────
_VALID_SEVERITIES = {"high", "medium", "low", "informational", ""}

# ── All known tool names ───────────────────────────────────────────────────────
ALL_TOOLS: list[str] = [
    # Read-only
    "list_cases",
    "get_case",
    "search_cases",
    "list_artifacts",
    "get_artifact",
    "list_case_notes",
    "list_playbooks",
    "get_playbook_run",
    "list_action_runs",
    "list_users",
    "get_soar_info",
    # Write (controlled)
    "add_case_note",
    "run_playbook",
    "update_case_status",
    "update_case_severity",
    "update_case_owner",
    "create_artifact",
    # Playbook-Discovery & Build (v1.6.0+)
    "list_apps",
    "list_assets",
    "get_action_schema",
    "export_playbook",
    "import_playbook",
    "create_container",
    "delete_container",
    # COA Visual Editor tools (v1.6.3+)
    "resolve_playbook_current_id",
    "get_playbook_identity_map",
    "get_playbook_coa_summary",
    "list_playbook_nodes",
    "list_playbook_edges",
    "check_saved_generated_python_drift",
    "check_datapath_selectability",
    "diff_playbook_versions",
    "verify_layout_only_change",
    "validate_playbook_bundle",
    "check_visual_editor_compat",
    # Write tools (v1.6.3+)
    "save_playbook_layout_only",
    # Client config helper (v1.8.0+)
    "generate_mcp_client_config",
    # Diagnostics (v1.9.0+)
    "diagnose_soar_mcp_environment",
    # Capability detection (v1.10.0+)
    "detect_soar_capabilities",
    # Visual playbook pre-edit audit (v1.11.0+)
    "audit_visual_playbook",
]

READ_ONLY_TOOLS: frozenset[str] = frozenset(
    [
        "list_cases",
        "get_case",
        "search_cases",
        "list_artifacts",
        "get_artifact",
        "list_case_notes",
        "list_playbooks",
        "get_playbook_run",
        "list_action_runs",
        "list_users",
        "get_soar_info",
        # Playbook-Discovery & Build read tools (v1.6.0+)
        "list_apps",
        "list_assets",
        "get_action_schema",
        "export_playbook",
        # COA Visual Editor read tools (v1.6.3+)
        "resolve_playbook_current_id",
        "get_playbook_identity_map",
        "get_playbook_coa_summary",
        "list_playbook_nodes",
        "list_playbook_edges",
        "check_saved_generated_python_drift",
        "check_datapath_selectability",
        "diff_playbook_versions",
        "verify_layout_only_change",
        "validate_playbook_bundle",
        "check_visual_editor_compat",
        # Client config helper (v1.8.0+)
        "generate_mcp_client_config",
        # Diagnostics (v1.9.0+)
        "diagnose_soar_mcp_environment",
        # Capability detection (v1.10.0+)
        "detect_soar_capabilities",
        # Visual playbook pre-edit audit (v1.11.0+)
        "audit_visual_playbook",
    ]
)


@dataclass
class McpServerConfig:
    """
    Resolved configuration for the SOAR MCP Server.

    Populated by McpConfigLoader.load() from the mcp.conf file.
    All fields have safe defaults that match the bundled default/mcp.conf.
    """

    # [server] section
    timeout: float = 60.0
    max_results: int = 50
    ssl_verify: Union[bool, str] = True
    log_tool_calls: bool = True
    protocol_version: str = "2024-11-05"
    server_name: str = "splunk-soar-mcp-server"
    server_version: str = field(default_factory=_manifest_app_version)

    # [tools] section — set of enabled tool names
    enabled_tools: Set[str] = field(default_factory=lambda: set(READ_ONLY_TOOLS))

    # [safety] section
    advisory_disclaimer: bool = True
    allowed_labels: list[str] = field(default_factory=list)
    max_items_per_case: int = 20
    min_severity: str = ""
    # Extra gate for create_container — prevents accidental case creation in production
    enable_test_harness: bool = False
    # Two-step commit for write tools (issue #50). When true, write tools must be
    # called twice: the first call returns a confirm_token, the second (with the
    # same args + token) executes. Default off = backwards-compatible.
    require_confirmation: bool = False

    # AI instructions — sent to the LLM in every MCP initialize response
    ai_instructions: str = ""

    # MCP endpoint URL (persisted from asset_overrides.json after first connect)
    mcp_endpoint: str = ""

    # ── Scoped MCP token settings (v1.5.0+) ───────────────────────────────
    # When enabled, incoming auth headers are first checked against the
    # app's local token store; matching scoped tokens get tool restrictions
    # and per-token audit. Legacy full-access SOAR ph-auth-token continues
    # to work as a fallback unless scoped_tokens_required is also True.
    scoped_tokens_enabled: bool = False  # opt-in; see default/mcp.conf [tokens]
    scoped_tokens_required: bool = False
    legacy_full_token_warn: bool = True
    # Default lifetime for newly minted tokens (days)
    token_default_lifetime_days: int = 90
    # Per-token rate limit (requests per minute). 0 disables.
    token_rate_limit_per_minute: int = 120

    @property
    def disabled_tools(self) -> list[str]:
        return [t for t in ALL_TOOLS if t not in self.enabled_tools]

    @property
    def write_tools_enabled(self) -> bool:
        return bool(self.enabled_tools - READ_ONLY_TOOLS)

    def to_summary_dict(self) -> dict:
        """Return a safe, serialisable summary (no secrets)."""
        return {
            "enabled_tools": sorted(self.enabled_tools),
            "disabled_tools": sorted(self.disabled_tools),
            "max_results": self.max_results,
            "max_items_per_case": self.max_items_per_case,
            "write_tools_enabled": self.write_tools_enabled,
            "advisory_disclaimer": self.advisory_disclaimer,
            "log_tool_calls": self.log_tool_calls,
            "protocol_version": self.protocol_version,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "ssl_verify": self.ssl_verify if isinstance(self.ssl_verify, bool) else "custom_path",
            "allowed_labels": self.allowed_labels,
            "min_severity": self.min_severity,
            "ai_instructions": self.ai_instructions,
        }


def build_posture_report(config: "McpServerConfig") -> dict:
    """Return the effective security posture of this asset (issue #51).

    Shared by Test Connectivity (#51) and the diagnostics tool (#67) so both
    surfaces report identical, non-secret state. Contains no tokens or secrets.
    """
    try:
        from soar_mcp_tokens import _have_fernet
        fernet_available = bool(_have_fernet())
    except Exception:
        fernet_available = False

    enabled_write = sorted(config.enabled_tools - READ_ONLY_TOOLS)
    ssl = config.ssl_verify if isinstance(config.ssl_verify, bool) else "custom_path"

    # Coarse risk flags for a quick red/yellow/green read — advisory only.
    risk_flags: list[str] = []
    if enabled_write and ssl is False:
        risk_flags.append("write_tools_enabled_with_ssl_verify_off")
    if config.enable_test_harness:
        risk_flags.append("test_harness_enabled")
    if enabled_write and not config.require_confirmation:
        risk_flags.append("write_tools_without_confirmation")
    if config.scoped_tokens_enabled and not fernet_available:
        risk_flags.append("scoped_tokens_without_fernet_encryption")
    if config.scoped_tokens_enabled and not config.scoped_tokens_required and enabled_write:
        risk_flags.append("legacy_full_tokens_still_accepted")

    return {
        "write_tools_enabled": config.write_tools_enabled,
        "enabled_write_tools": enabled_write,
        "ssl_verify": ssl,
        "enable_test_harness": config.enable_test_harness,
        "require_confirmation": config.require_confirmation,
        "scoped_tokens_enabled": config.scoped_tokens_enabled,
        "scoped_tokens_required": config.scoped_tokens_required,
        "fernet_available": fernet_available,
        "legacy_path_rate_limited": config.token_rate_limit_per_minute > 0,
        "advisory_disclaimer": config.advisory_disclaimer,
        "risk_flags": risk_flags,
    }


class McpConfigLoader:
    """
    Loads and parses mcp.conf following Splunk/SOAR config precedence.

    Search order:
      1. <app_root>/local/mcp.conf   (user overrides — highest precedence)
      2. <app_root>/default/mcp.conf (bundled defaults — fallback)

    The app root is determined relative to this module's location.
    """

    def __init__(self, app_root: Optional[Path] = None) -> None:
        if app_root is None:
            # This file lives at <app_root>/soar_mcp_config.py
            app_root = Path(__file__).parent
        self._app_root = app_root

    def _find_config_file(self) -> Optional[Path]:
        """Return the highest-precedence mcp.conf path, or None if not found."""
        for subdir in ("local", "default"):
            candidate = self._app_root / subdir / _CONFIG_FILENAME
            if candidate.exists():
                logger.info("[MCP Config] Found config at: %s", candidate)
                return candidate
        logger.warning("[MCP Config] No mcp.conf found in local/ or default/")
        return None

    def load(self) -> McpServerConfig:
        """
        Load and parse mcp.conf, returning a McpServerConfig with resolved values.

        Falls back to safe defaults for any missing or invalid values.
        Never raises; always returns a valid config object.
        """
        config = McpServerConfig()
        conf_path = self._find_config_file()

        if conf_path is None:
            logger.warning("[MCP Config] Using all defaults (no config file found).")
            return config

        parser = configparser.ConfigParser()
        try:
            parser.read(conf_path, encoding="utf-8")
        except Exception as exc:
            logger.error("[MCP Config] Failed to read %s: %s — using defaults.", conf_path, exc)
            return config

        # ── [server] ──────────────────────────────────────────────────────────
        config.timeout = self._get_float(parser, "server", "timeout", 60.0, min_val=1.0, max_val=300.0)
        config.max_results = self._get_int(parser, "server", "max_results", 50, min_val=1, max_val=500)
        config.ssl_verify = self._parse_ssl_verify(parser.get("server", "ssl_verify", fallback="true"))
        config.log_tool_calls = self._get_bool(parser, "server", "log_tool_calls", True)
        config.protocol_version = parser.get("server", "protocol_version", fallback="2024-11-05").strip()
        config.server_name = parser.get("server", "server_name", fallback="splunk-soar-mcp-server").strip()
        config.server_version = parser.get(
            "server", "server_version", fallback=_manifest_app_version()
        ).strip() or _manifest_app_version()

        # ── [tools] ───────────────────────────────────────────────────────────
        enabled: set[str] = set()
        for tool in ALL_TOOLS:
            if self._get_bool(parser, "tools", tool, tool in READ_ONLY_TOOLS):
                enabled.add(tool)
        config.enabled_tools = enabled

        # ── [safety] ──────────────────────────────────────────────────────────
        config.advisory_disclaimer = self._get_bool(parser, "safety", "advisory_disclaimer", True)
        config.max_items_per_case = self._get_int(parser, "safety", "max_items_per_case", 20, min_val=1, max_val=200)

        raw_labels = parser.get("safety", "allowed_labels", fallback="").strip()
        config.allowed_labels = [lbl.strip() for lbl in raw_labels.split(",") if lbl.strip()] if raw_labels else []

        raw_sev = parser.get("safety", "min_severity", fallback="").strip().lower()
        config.min_severity = raw_sev if raw_sev in _VALID_SEVERITIES else ""
        config.enable_test_harness = self._get_bool(parser, "safety", "enable_test_harness", False)
        config.require_confirmation = self._get_bool(parser, "safety", "require_confirmation", False)

        # ── [server] ai_instructions ───────────────────────────────────────────
        config.ai_instructions = parser.get("server", "ai_instructions", fallback="").strip()

        # ── [tokens] scoped MCP tokens (v1.5.0+) ──────────────────────────────
        config.scoped_tokens_enabled = self._get_bool(
            parser, "tokens", "scoped_tokens_enabled", False)
        config.scoped_tokens_required = self._get_bool(
            parser, "tokens", "scoped_tokens_required", False)
        config.legacy_full_token_warn = self._get_bool(
            parser, "tokens", "legacy_full_token_warn", True)
        config.token_default_lifetime_days = self._get_int(
            parser, "tokens", "default_lifetime_days", 90,
            min_val=1, max_val=3650)
        config.token_rate_limit_per_minute = self._get_int(
            parser, "tokens", "rate_limit_per_minute", 120,
            min_val=0, max_val=10000)

        logger.info(
            "[MCP Config] Loaded: %d tools enabled, write=%s, max_results=%d",
            len(config.enabled_tools),
            config.write_tools_enabled,
            config.max_results,
        )

        # Apply asset-level overrides (written by the connector from asset config)
        config = self._apply_asset_overrides(config)

        return config

    def _apply_asset_overrides(self, config: "McpServerConfig") -> "McpServerConfig":
        """
        Apply asset-level overrides from local/asset_overrides.json.

        This file is written by the connector when it reads the asset
        configuration checkboxes (tool_* fields and ai_instructions).
        It takes precedence over everything in mcp.conf.
        """
        import json as _json

        overrides_path = self._app_root / "local" / "asset_overrides.json"
        if not overrides_path.exists():
            return config

        try:
            with open(overrides_path, encoding="utf-8") as fh:
                overrides = _json.load(fh)
        except Exception as exc:
            logger.warning("[MCP Config] Could not read asset_overrides.json: %s", exc)
            return config

        # Apply tool overrides
        tool_overrides = overrides.get("tools")
        if isinstance(tool_overrides, dict):
            new_enabled: set[str] = set()
            for tool in ALL_TOOLS:
                if tool in tool_overrides:
                    if tool_overrides[tool]:
                        new_enabled.add(tool)
                else:
                    # Not in overrides — keep current state from mcp.conf
                    if tool in config.enabled_tools:
                        new_enabled.add(tool)
            config.enabled_tools = new_enabled
            logger.info(
                "[MCP Config] Asset overrides applied: %d tools enabled",
                len(config.enabled_tools),
            )

        # Apply AI instructions override
        ai_instr = overrides.get("ai_instructions")
        if ai_instr and isinstance(ai_instr, str):
            config.ai_instructions = ai_instr.strip()

        # Apply enable_test_harness override (None = not set in asset config → keep mcp.conf value)
        eth = overrides.get("enable_test_harness")
        if eth is not None:
            config.enable_test_harness = bool(eth)

        ssl_override = overrides.get("ssl_verify")
        if ssl_override is not None:
            if isinstance(ssl_override, bool):
                config.ssl_verify = ssl_override
            else:
                config.ssl_verify = self._parse_ssl_verify(str(ssl_override))

        # Persist MCP endpoint URL so tools can display it
        mcp_ep = overrides.get("mcp_endpoint")
        if mcp_ep and isinstance(mcp_ep, str):
            config.mcp_endpoint = mcp_ep.strip()

        return config

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _get_bool(parser: configparser.ConfigParser, section: str, key: str, default: bool) -> bool:
        try:
            raw = parser.get(section, key, fallback=None)
            if raw is None:
                return default
            return raw.strip().lower() in ("true", "yes", "1", "on", "enabled")
        except Exception:
            return default

    @staticmethod
    def _get_float(
        parser: configparser.ConfigParser,
        section: str,
        key: str,
        default: float,
        *,
        min_val: float = 0.0,
        max_val: float = float("inf"),
    ) -> float:
        try:
            raw = parser.get(section, key, fallback=None)
            if raw is None:
                return default
            val = float(raw)
            return max(min_val, min(val, max_val))
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _get_int(
        parser: configparser.ConfigParser,
        section: str,
        key: str,
        default: int,
        *,
        min_val: int = 0,
        max_val: int = 10_000,
    ) -> int:
        try:
            raw = parser.get(section, key, fallback=None)
            if raw is None:
                return default
            val = int(float(raw))
            return max(min_val, min(val, max_val))
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _parse_ssl_verify(raw: str) -> Union[bool, str]:
        val = raw.strip()
        if val.lower() in ("true", "yes", "1", "on"):
            return True
        if val.lower() in ("false", "no", "0", "off"):
            return False
        # Treat as path
        expanded = os.path.expandvars(os.path.expanduser(val))
        if os.path.isfile(expanded):
            return expanded
        logger.warning("[MCP Config] ssl_verify value '%s' not recognised — defaulting to True.", val)
        return True


# Module-level singleton (lazy-loaded)
_cached_config: Optional[McpServerConfig] = None


def get_config(reload: bool = False) -> McpServerConfig:
    """
    Return the cached McpServerConfig, loading it on first call.

    Args:
        reload: If True, discard the cache and reload from disk.

    Returns:
        McpServerConfig with resolved values.
    """
    global _cached_config
    if _cached_config is None or reload:
        _cached_config = McpConfigLoader().load()
    return _cached_config
