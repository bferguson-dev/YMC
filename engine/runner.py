"""
runner.py
---------
The orchestration engine. Loads a compliance profile, discovers all
registered check functions via the CheckRegistry, runs them against
a connected host, and returns a HostScanResult with all evidence collected.

Adding a new check
------------------
1. Write your check function in the appropriate module under checks/windows/
2. Decorate it with @register_check("XX-000") from checks.registry
3. Add the check_id to the relevant profile YAML(s)
4. That's it — no changes needed here.

The runner discovers checks automatically by importing the check modules.
"""

import yaml
import logging
import importlib.util
import re
import sys
from pathlib import Path

from engine.evidence import (
    CheckResult,
    HostScanResult,
    STATUS_ERROR,
    STATUS_PASS,
    STATUS_FAIL,
    STATUS_WARNING,
    make_timestamp,
)
from connector.winrm_connector import WinRMConnector

logger = logging.getLogger(__name__)


# ── Check module auto-discovery ───────────────────────────────────────────
# Check modules are discovered automatically by walking the checks/ directory
# tree and importing every .py file that is not __init__.py or common.py.
#
# To add a new check:
#   1. Create a new .py file anywhere under checks/windows/ (or checks/linux/ etc.)
#   2. Add @register_check("XX-000") to your check function
#   3. Add the check_id to the relevant profile YAML(s)
#   4. That is it — no changes needed here or anywhere else.
#
# The import itself triggers the @register_check decorators to fire,
# self-registering every function with the CheckRegistry singleton.

# Root directory of the checks package — resolved relative to this file
# so the tool works regardless of the current working directory.
_CHECKS_ROOT = Path(__file__).parent.parent / "checks"


def _discover_check_modules() -> list[Path]:
    """
    Walks the checks/ directory tree and returns .py file paths for every
    check module, excluding __init__.py/common.py/registry.py.

    The loader imports these files directly by path. This avoids Python module
    name constraints for check filenames that include hyphens (e.g. AC-001_*.py).
    """
    module_files: list[Path] = []
    for py_file in sorted(_CHECKS_ROOT.rglob("*.py")):
        # Skip package init files and the shared helper
        if py_file.name in ("__init__.py", "common.py", "registry.py"):
            continue
        module_files.append(py_file)
    return module_files


def _module_name_for_file(py_file: Path) -> str:
    """
    Builds a stable synthetic module name for a check file path.
    """
    relative = py_file.relative_to(_CHECKS_ROOT)
    stem_parts = list(relative.with_suffix("").parts)
    raw = "_".join(stem_parts)
    safe = re.sub(r"[^0-9a-zA-Z_]", "_", raw)
    return f"checks.dynamic.{safe}"


def _load_check_modules() -> None:
    """
    Imports all discovered check modules so their @register_check decorators
    fire and populate the CheckRegistry singleton.
    Called once at module load time (bottom of this file).
    """
    from checks.registry import CheckRegistry

    modules = _discover_check_modules()
    import_failures: list[tuple[Path, Exception]] = []
    for module_file in modules:
        module_name = _module_name_for_file(module_file)
        try:
            if module_name in sys.modules:
                continue

            spec = importlib.util.spec_from_file_location(module_name, module_file)
            if spec is None or spec.loader is None:
                raise ImportError(f"Could not build import spec for {module_file}")

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            logger.debug(f"Loaded check module: {module_file}")
        except Exception as e:
            logger.error(f"Failed to import check module '{module_file}': {e}")
            import_failures.append((module_file, e))

    if import_failures:
        failed_modules = ", ".join(str(p) for p, _ in import_failures[:5])
        if len(import_failures) > 5:
            failed_modules += f", ... (+{len(import_failures) - 5} more)"
        raise ImportError(
            "Check module discovery failed; aborting to avoid partial scan coverage. "
            f"Failed modules: {failed_modules}"
        )

    logger.info(
        f"Check registry loaded: {len(CheckRegistry)} checks registered "
        f"across {len(modules)} modules."
    )


# Load all modules when runner is first imported
_load_check_modules()


class ComplianceRunner:
    """
    Loads a compliance profile and runs all mapped checks against a host.

    The runner no longer maintains a hardcoded check registry. Instead,
    it delegates all check_id -> function lookups to the CheckRegistry
    singleton, which is populated automatically by @register_check
    decorators when check modules are imported above.

    Usage
    -----
        runner = ComplianceRunner(
            profile_path="profiles/nist_800_53.yaml",
            settings=settings_dict
        )
        result = runner.scan(connector, executed_by="domain\\\\svcaccount")
    """

    def __init__(self, profile_path: str, settings: dict):
        self.profile_path = Path(profile_path)
        self.settings = settings
        self.profile = self._load_profile()

    def _load_profile(self) -> dict:
        """Loads and validates the compliance profile YAML."""
        if not self.profile_path.exists():
            raise FileNotFoundError(f"Profile not found: {self.profile_path}")
        with open(self.profile_path, "r") as f:
            profile = yaml.safe_load(f)
        logger.info(
            f"Loaded profile: {profile['profile_name']} "
            f"({len(profile['checks'])} checks)"
        )
        return profile

    def scan(
        self,
        connector: WinRMConnector,
        executed_by: str,
        tool_name: str = "YMC",
        tool_version: str = "1.0.0",
        progress_callback=None,
        host_label: str = "",
    ) -> HostScanResult:
        """
        Runs all checks defined in the loaded profile against the connected host.
        Returns a HostScanResult containing all CheckResult objects.
        """
        from checks.registry import CheckRegistry

        scan_start = make_timestamp()
        profile_name = self.profile["profile_name"]
        check_defs = self.profile["checks"]

        # Use provided label or fall back to hostname for display purposes
        label = host_label or connector.host

        logger.info(
            f"Starting {profile_name} scan on {connector.host} "
            f"({len(check_defs)} checks) as {executed_by}"
        )

        results: list[CheckResult] = []
        seen_fn_results: dict[str, CheckResult] = {}  # fn_name -> result, for dedup
        current = 0  # count of checks actually executed (not dedup skips)
        total = len(check_defs)

        for check_def in check_defs:
            check_id = check_def["check_id"]
            check_name = check_def.get("control_name", check_id)

            # Registry lookup — no manual mapping needed
            fn = CheckRegistry.get(check_id)
            if fn is None:
                logger.warning(
                    f"No handler registered for check_id '{check_id}' — "
                    f'skipping. Did you forget to add @register_check("{check_id}") '
                    f"to a check function?"
                )
                continue

            fn_name = fn.__name__

            # Deduplication: if this function was already called for another
            # check_id in this scan, reuse the result rather than running
            # the same PowerShell command again.
            if fn_name in seen_fn_results and CheckRegistry.is_dedup_secondary(
                check_id
            ):
                logger.debug(f"Deduplicating {check_id} -> reusing {fn_name} result")
                primary = seen_fn_results[fn_name]
                framework_key = self.profile["profile_id"]

                # Emit a concrete result row for the secondary control so
                # reporting/compliance math includes every check in the profile.
                secondary = CheckResult(
                    hostname=primary.hostname,
                    ip_address=primary.ip_address,
                    timestamp_utc=primary.timestamp_utc,
                    tool_name=primary.tool_name,
                    tool_version=primary.tool_version,
                    executed_by=primary.executed_by,
                    check_id=check_id,
                    check_name=check_name or primary.check_name,
                    check_category=primary.check_category,
                    description=primary.description,
                    framework_mappings={framework_key: check_def["control_id"]},
                    status=primary.status,
                    raw_evidence=primary.raw_evidence,
                    finding=primary.finding,
                    remediation=primary.remediation,
                    details=primary.details,
                )
                results.append(secondary)
                continue

            current += 1

            # Notify caller that a check is about to run (spinner / "running..." line)
            if progress_callback:
                progress_callback(
                    "check_start",
                    {
                        "check_id": check_id,
                        "check_name": check_name,
                        "host_label": label,
                        "current": current,
                        "total": total,
                    },
                )

            # Execute the check
            result = self._run_check(
                check_id=check_id,
                fn=fn,
                connector=connector,
                executed_by=executed_by,
                tool_name=tool_name,
                tool_version=tool_version,
            )

            # Attach framework mapping from the profile
            framework_key = self.profile["profile_id"]
            result.framework_mappings[framework_key] = check_def["control_id"]

            # Use profile's control_name if the check didn't set one
            if not result.check_name:
                result.check_name = check_name

            results.append(result)
            seen_fn_results[fn_name] = result

            status_symbol = {
                STATUS_PASS: "✓",
                STATUS_FAIL: "✗",
                STATUS_WARNING: "⚠",
                STATUS_ERROR: "!",
            }.get(result.status, "?")
            logger.info(
                f"  [{status_symbol}] {check_id}: {result.check_name} -> {result.status}"
            )

            # Notify caller that the check completed with its result
            if progress_callback:
                progress_callback(
                    "check_complete",
                    {
                        "check_id": check_id,
                        "check_name": result.check_name,
                        "host_label": label,
                        "status": result.status,
                        "finding": result.finding,
                        "current": current,
                        "total": total,
                    },
                )

        scan_end = make_timestamp()

        host_result = HostScanResult(
            hostname=connector.host,
            ip_address=connector.ip_address,
            scan_start_utc=scan_start,
            scan_end_utc=scan_end,
            profile_name=profile_name,
            executed_by=executed_by,
            checks=results,
        )

        logger.info(
            f"Scan complete: {host_result.passed} passed, {host_result.failed} failed, "
            f"{host_result.warnings} warnings, {host_result.errors} errors. "
            f"Compliance: {host_result.compliance_percentage}%"
        )

        # Notify caller that the full scan is done
        if progress_callback:
            progress_callback(
                "scan_complete",
                {
                    "passed": host_result.passed,
                    "failed": host_result.failed,
                    "warnings": host_result.warnings,
                    "errors": host_result.errors,
                    "compliance_pct": host_result.compliance_percentage,
                    "host_label": label,
                },
            )

        return host_result

    def _run_check(
        self,
        check_id: str,
        fn,
        connector: WinRMConnector,
        executed_by: str,
        tool_name: str,
        tool_version: str,
    ) -> CheckResult:
        """
        Calls a check function and wraps all exceptions so a single
        failing check never stops the scan.
        """
        try:
            return fn(
                connector=connector,
                settings=self.settings,
                tool_name=tool_name,
                tool_version=tool_version,
                executed_by=executed_by,
            )
        except Exception as e:
            logger.error(
                f"Unhandled exception in check {check_id} ({fn.__name__}): {e}",
                exc_info=True,
            )
            return self._error_result(
                check_id,
                connector,
                executed_by,
                tool_name,
                tool_version,
                f"Unexpected error: {e}",
            )

    def _error_result(
        self,
        check_id: str,
        connector: WinRMConnector,
        executed_by: str,
        tool_name: str,
        tool_version: str,
        message: str,
    ) -> CheckResult:
        return CheckResult(
            hostname=connector.host,
            ip_address=connector.ip_address,
            timestamp_utc=make_timestamp(),
            tool_name=tool_name,
            tool_version=tool_version,
            executed_by=executed_by,
            check_id=check_id,
            check_name=f"Check {check_id}",
            check_category="Unknown",
            description="",
            status=STATUS_ERROR,
            finding=message,
            remediation="Review tool logs for details.",
        )


def load_settings(settings_path: str = "config/settings.yaml") -> dict:
    """Loads the global settings file."""
    path = Path(settings_path)
    if not path.exists():
        logger.warning(f"Settings file not found at {path}. Using defaults.")
        return {}
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    return config.get("evidence", {})


def list_profiles(profiles_dir: str = "profiles") -> list:
    """Returns a list of available profile files."""
    profiles_path = Path(profiles_dir)
    return sorted([p.stem for p in profiles_path.glob("*.yaml")])
