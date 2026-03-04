"""
registry.py
-----------
Self-registering check registry using a decorator pattern.

Instead of manually maintaining a dictionary in runner.py, each check
function declares its own check_id(s) via the @register_check decorator.
The runner discovers all registered checks automatically by importing
the check modules.

Usage
-----
In a check module:

    from checks.registry import register_check

    @register_check("AC-001", dedup_group="inactive_accounts")
    def check_inactive_accounts(connector, settings, tool_name, tool_version, executed_by):
        ...

    # A check that shares the same underlying function for multiple IDs:
    @register_check("AC-001", "AC-002", dedup_group="inactive_accounts")
    def check_inactive_accounts(...):
        ...

In runner.py, instead of CHECK_REGISTRY dict lookups, call:

    from checks.registry import CheckRegistry
    fn, is_primary = CheckRegistry.get("AC-001")
"""

from __future__ import annotations
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class _CheckRegistry:
    """
    Singleton registry that maps check_id strings to their handler functions.

    Attributes
    ----------
    _registry : dict[str, Callable]
        Maps check_id -> check function.
    _dedup_groups : dict[str, list[str]]
        Maps dedup_group_name -> ordered list of check_ids.
        The first check_id in each group is the primary (executes the function).
        Subsequent IDs are secondaries (reuse the primary's result).
    _check_ids_by_fn : dict[str, list[str]]
        Maps function name -> list of check_ids it handles.
        Used for introspection and debugging.
    """

    def __init__(self):
        self._registry: dict[str, Callable] = {}
        self._dedup_groups: dict[str, list[str]] = {}
        self._check_ids_by_fn: dict[str, list[str]] = {}

    def register(
        self,
        *check_ids: str,
        dedup_group: Optional[str] = None,
    ) -> Callable:
        """
        Decorator factory. Registers a check function for one or more check IDs.

        Parameters
        ----------
        *check_ids : str
            One or more check IDs this function handles (e.g. "AC-001", "AC-002").
        dedup_group : str, optional
            If multiple check IDs share this group name, the runner will only
            execute the function once (for the first/primary ID) and reuse
            the result for subsequent IDs in the group. This avoids running
            the same PowerShell command multiple times per scan.

        Returns
        -------
        Callable
            The original function, unmodified (decorator is transparent).
        """

        def decorator(fn: Callable) -> Callable:
            for check_id in check_ids:
                if check_id in self._registry:
                    logger.warning(
                        f"Check ID '{check_id}' is already registered to "
                        f"'{self._registry[check_id].__name__}'. "
                        f"Overwriting with '{fn.__name__}'."
                    )
                self._registry[check_id] = fn
                logger.debug(f"Registered check: {check_id} -> {fn.__name__}")

            # Track function -> check_ids mapping for introspection
            fn_ids = self._check_ids_by_fn.setdefault(fn.__name__, [])
            for check_id in check_ids:
                if check_id not in fn_ids:
                    fn_ids.append(check_id)

            # Register dedup group
            if dedup_group:
                group = self._dedup_groups.setdefault(dedup_group, [])
                for check_id in check_ids:
                    if check_id not in group:
                        group.append(check_id)

            # Attach metadata to the function for introspection
            fn._check_ids = list(check_ids)
            fn._dedup_group = dedup_group

            return fn

        return decorator

    def get(self, check_id: str) -> Optional[Callable]:
        """
        Returns the check function registered for a given check_id,
        or None if not registered.
        """
        return self._registry.get(check_id)

    def is_dedup_secondary(self, check_id: str) -> bool:
        """
        Returns True if this check_id is a secondary entry in a dedup group,
        meaning the runner should reuse a previously computed result rather
        than calling the function again.

        The first check_id registered in a dedup group is the primary.
        All others are secondaries.
        """
        for group in self._dedup_groups.values():
            if check_id in group:
                return check_id != group[0]
        return False

    def all_check_ids(self) -> list[str]:
        """Returns a sorted list of all registered check IDs."""
        return sorted(self._registry.keys())

    def summary(self) -> dict:
        """
        Returns a summary dict for debugging/logging.
        Shows each registered function and which check IDs it handles.
        """
        return {fn_name: ids for fn_name, ids in sorted(self._check_ids_by_fn.items())}

    def __len__(self) -> int:
        return len(self._registry)

    def __contains__(self, check_id: str) -> bool:
        return check_id in self._registry


# ── Singleton instance ─────────────────────────────────────────────────────
# All check modules import this single instance and call .register() on it.
CheckRegistry = _CheckRegistry()

# Convenience alias so check modules can write:
#   from checks.registry import register_check
register_check = CheckRegistry.register
