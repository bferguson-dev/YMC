"""
registry.py
-----------
Self-registering check registry using a decorator pattern.

Instead of manually maintaining a CHECK_REGISTRY dictionary in runner.py,
check functions declare their own check IDs at definition time using the
@register_check decorator. The runner discovers them automatically.

Usage in a check module:
    from engine.registry import register_check

    @register_check("AC-001", "AC-002", dedup_primary=True)
    def check_inactive_accounts(connector, settings, tool_name, tool_version, executed_by):
        ...

Adding a new check:
    1. Write the function in the appropriate checks/windows/ module
    2. Decorate it with @register_check("YOUR-ID")
    3. That's it — no changes needed anywhere else

The runner calls ensure_checks_loaded() at startup to trigger imports
of all check modules, which fires all the decorators and populates
the registry automatically.
"""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ── Internal registry storage ──────────────────────────────────────────────
# Maps check_id -> registered check function
_REGISTRY: dict[str, Callable] = {}

# Maps function name -> list of check_ids it handles (for deduplication)
# When a function handles multiple IDs, only the first (primary) executes;
# subsequent IDs reuse the result.
_DEDUP_GROUPS: dict[str, list[str]] = {}


# ── Decorator ──────────────────────────────────────────────────────────────


def register_check(*check_ids: str, dedup_primary: bool = False):
    """
    Decorator that registers a check function for one or more check IDs.

    Args:
        *check_ids: One or more check IDs this function handles.
                    e.g. @register_check("AC-001") or
                         @register_check("AC-001", "AC-002", dedup_primary=True)

        dedup_primary: Set True when one function covers multiple check IDs
                       that represent the same underlying check (e.g. password
                       length, complexity, and max age are all checked by one
                       PowerShell call). The function runs once; subsequent
                       check IDs in the list reuse the result without re-running.

    Example:
        @register_check("IA-001", "IA-002", "IA-003", dedup_primary=True)
        def check_password_policy(connector, settings, tool_name, tool_version, executed_by):
            ...
    """

    def decorator(fn: Callable) -> Callable:
        if not check_ids:
            raise ValueError(
                f"@register_check requires at least one check_id (on {fn.__name__})"
            )

        for check_id in check_ids:
            if check_id in _REGISTRY:
                existing = _REGISTRY[check_id].__name__
                raise ValueError(
                    f"Duplicate check_id '{check_id}': already registered to "
                    f"'{existing}', cannot also register to '{fn.__name__}'"
                )
            _REGISTRY[check_id] = fn
            logger.debug(
                f"Registered check {check_id} -> {fn.__module__}.{fn.__name__}"
            )

        # Track dedup groups so the runner knows which IDs share a single execution
        if dedup_primary and len(check_ids) > 1:
            _DEDUP_GROUPS[fn.__name__] = list(check_ids)

        return fn

    return decorator


# ── Public API ─────────────────────────────────────────────────────────────


def get_check(check_id: str) -> Optional[Callable]:
    """Returns the registered function for a check_id, or None if not found."""
    return _REGISTRY.get(check_id)


def get_all_check_ids() -> list[str]:
    """Returns all registered check IDs, sorted."""
    return sorted(_REGISTRY.keys())


def is_dedup_secondary(check_id: str, fn_name: str) -> bool:
    """
    Returns True if this check_id is a secondary entry in a dedup group.
    Secondary checks reuse the primary's result without re-running.
    """
    group = _DEDUP_GROUPS.get(fn_name, [])
    if len(group) <= 1:
        return False
    return check_id != group[0]


def ensure_checks_loaded():
    """
    Imports all modules under checks/ so their @register_check decorators fire.

    This is called once at runner startup. Because Python only executes module
    code on first import, subsequent calls are free (modules are cached).
    """
    checks_root = Path(__file__).parent.parent / "checks"

    for platform_dir in checks_root.iterdir():
        if not platform_dir.is_dir() or platform_dir.name.startswith("_"):
            continue
        package = f"checks.{platform_dir.name}"
        for module_info in pkgutil.iter_modules([str(platform_dir)]):
            module_name = f"{package}.{module_info.name}"
            try:
                importlib.import_module(module_name)
                logger.debug(f"Loaded check module: {module_name}")
            except ImportError as e:
                logger.error(f"Failed to import check module {module_name}: {e}")


def registry_summary() -> str:
    """Returns a human-readable summary of all registered checks. Useful for debugging."""
    if not _REGISTRY:
        return "Registry is empty — ensure_checks_loaded() has not been called."
    lines = [f"Registered checks ({len(_REGISTRY)} total):"]
    for check_id in sorted(_REGISTRY.keys()):
        fn = _REGISTRY[check_id]
        lines.append(f"  {check_id:<10} -> {fn.__module__}.{fn.__name__}")
    return "\n".join(lines)
