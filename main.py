#!/usr/bin/env python3
"""
main.py
-------
YMC Ã¢â‚¬â€ CLI entry point and scan orchestrator.

Responsibilities
----------------
- Parse CLI arguments and resolve final settings from the full priority chain
  (CLI flags > env vars > named config profile > personal settings > program defaults)
- Load scan targets from --host (single or comma-separated) or --csv
- Resolve hostnames: apply domain suffix to bare hostnames, leave FQDNs/IPs alone
- Collect credentials securely: prompt once per unique username, never store
- Create a timestamped scan output folder
- For each target: run prechecks, execute the compliance scan, generate reports
- Display a rich live progress view showing each check as it runs
- Generate per-host reports and a combined summary report

Usage
-----
    # Single host
    python main.py --host web01.corp.local --username compliance-svc --profile nist_800_53

    # Multiple hosts (comma-separated)
    python main.py --host web01,db01,dc01 --domain corp.local --username compliance-svc

    # CSV file
    python main.py --csv docs/hosts.csv --profile pci_dss_4

    # List available profiles
    python main.py --list-profiles

    # List available config profiles
    python main.py --list-configs

Credentials
-----------
Passwords are NEVER passed on the command line, stored in files, or logged.
Supply them via:
  1. COLLECTOR_PASSWORD env var (or COLLECTOR_PASSWORD_<USERNAME> for multi-account)
  2. Interactive prompt (hidden input via getpass)

See docs/environment_variables.md for the full list of environment variables.
"""

import argparse
import csv
import getpass
import html
import logging
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Ensure the project root is in sys.path when run directly (python main.py)
# rather than as an installed package. Harmless when installed properly.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

import yaml
from colorama import init as colorama_init, Fore, Style

from connector.winrm_connector import (
    WinRMConnector,
    WinRMConnectionError,
    resolve_hostname,
)
from engine.runner import ComplianceRunner, list_profiles
from reporters.html_reporter import HtmlReporter
from reporters.json_reporter import JsonReporter

# ---------------------------------------------------------------------------
# Colorama init Ã¢â‚¬â€ handles Windows ANSI terminal codes transparently.
# On Linux/macOS it's a passthrough no-op.
# ---------------------------------------------------------------------------
colorama_init(autoreset=True)

TOOL_NAME = "YMC"
TOOL_VERSION = "1.0.0"

# Resolve paths relative to this file so the tool works regardless of the
# current working directory when invoked.
INSTALL_DIR = Path(__file__).parent
PROFILES_DIR = INSTALL_DIR / "profiles"  # compliance framework YAMLs
CONFIG_DIR = INSTALL_DIR / "config"  # program config directory
DEFAULT_CFG = CONFIG_DIR / "settings.yaml"  # shipped program defaults
NAMED_CFG_DIR = CONFIG_DIR / "profiles"  # named config profiles

# User-level settings Ã¢â‚¬â€ personal overrides that live outside the install dir
USER_CFG_DIR = Path.home() / ".ymc"
USER_CFG_FILE = USER_CFG_DIR / "settings.yaml"
USER_PROFILES_DIR = USER_CFG_DIR / "profiles"


# =============================================================================
# LOGGING
# =============================================================================


def setup_logging(verbose: bool, no_color: bool) -> None:
    """
    Configures the root logger.

    In verbose mode all DEBUG messages are shown.
    In normal mode only WARNING and above from third-party libraries are shown
    (the rich progress display handles user-facing scan output).
    """
    level = logging.DEBUG if verbose else logging.WARNING
    fmt = "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%Y-%m-%dT%H:%M:%S")

    # Always show our own module logs at INFO+ so scan milestones appear in
    # verbose mode without drowning in pywinrm/requests noise.
    if verbose:
        logging.getLogger("ymc").setLevel(logging.DEBUG)


logger = logging.getLogger("ymc.main")


def configure_console_output() -> None:
    """
    Avoid hard failures on terminals with legacy encodings (e.g., cp1252).
    Unsupported Unicode symbols are replaced rather than raising.
    """
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass


# =============================================================================
# SETTINGS RESOLUTION
# Priority (highest to lowest):
#   CLI flag > env var > named config profile > personal settings > program defaults
# =============================================================================


def _load_yaml(path: Path) -> dict:
    """Loads a YAML file and returns its contents as a dict. Returns {} on error."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data or {}
    except FileNotFoundError:
        return {}
    except UnicodeDecodeError as e:
        print(
            f"{Fore.YELLOW}Warning: Could not decode {path} as UTF-8: {e}{Style.RESET_ALL}"
        )
        return {}
    except yaml.YAMLError as e:
        print(f"{Fore.YELLOW}Warning: Could not parse {path}: {e}{Style.RESET_ALL}")
        return {}


def load_program_defaults() -> dict:
    """Loads the program default settings shipped with the tool."""
    return _load_yaml(DEFAULT_CFG)


def load_user_settings() -> dict:
    """Loads personal user settings from ~/.ymc/settings.yaml."""
    return _load_yaml(USER_CFG_FILE)


def load_named_profile(name: str) -> dict:
    """
    Loads a named config profile.
    Searches user profiles first, then program profiles.

    Parameters
    ----------
    name : str
        Profile name without .yaml extension, e.g. "corporate".
    """
    # User profiles take precedence over program-shipped profiles
    for search_dir in [USER_PROFILES_DIR, NAMED_CFG_DIR]:
        candidate = search_dir / f"{name}.yaml"
        if candidate.exists():
            logger.debug(f"Loading named config profile: {candidate}")
            return _load_yaml(candidate)

    print(f"{Fore.RED}Error: Config profile '{name}' not found.{Style.RESET_ALL}")
    print(f"  Searched: {USER_PROFILES_DIR}")
    print(f"            {NAMED_CFG_DIR}")
    print("  Use --list-configs to see available profiles.")
    sys.exit(1)


def _get(key: str, section: str, *dicts: dict, default=None):
    """
    Retrieves a value from the first dict that contains it under section.key.
    Used to layer config sources Ã¢â‚¬â€ pass in highest-priority dict first.
    """
    for d in dicts:
        section_data = d.get(section, {}) or {}
        if key in section_data and section_data[key] not in (None, ""):
            return section_data[key]
    return default


def _coerce_bool(value, setting_name: str) -> bool:
    """Coerces bool-like env/config values into a real bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False

    print(
        f"{Fore.RED}Error: Invalid boolean value for {setting_name}: {value!r}{Style.RESET_ALL}"
    )
    print("  Expected one of: true/false, 1/0, yes/no, on/off")
    sys.exit(1)


def _coerce_int(value, setting_name: str) -> int:
    """Coerces an int-like env/config value into a real int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        print(
            f"{Fore.RED}Error: Invalid integer value for {setting_name}: {value!r}{Style.RESET_ALL}"
        )
        print("  Expected a whole number, e.g. 5985")
        sys.exit(1)


def resolve_settings(args: argparse.Namespace) -> dict:
    """
    Builds the final resolved settings dict by layering all config sources.

    Returns a flat dict with every setting the program needs, fully resolved.
    The caller never needs to know where a value came from.
    """
    # Load all config layers (lowest priority first)
    prog_defaults = load_program_defaults()
    user_settings = load_user_settings()

    # Named config profile Ã¢â‚¬â€ from --config flag, env var, or settings cascade
    config_name = (
        args.config
        or os.environ.get("COLLECTOR_CONFIG")
        or _get("config", "cli_defaults", user_settings, prog_defaults)
    )
    named_profile = load_named_profile(config_name) if config_name else {}

    # Helper that checks CLI > env var > named profile > user settings > program defaults
    def resolve(
        cli_val, env_var: str, key: str, section: str = "cli_defaults", default=None
    ):
        """Resolves a single setting through the full priority chain."""
        if cli_val not in (None, False, ""):
            return cli_val
        env_val = os.environ.get(env_var)
        if env_val not in (None, ""):
            return env_val
        return _get(
            key, section, named_profile, user_settings, prog_defaults, default=default
        )

    # ---------------------------------------------------------------------------
    # Resolve every setting
    # ---------------------------------------------------------------------------
    settings = {}

    # Scan targets Ã¢â‚¬â€ handled by the caller, not resolved here
    settings["domain"] = resolve(
        getattr(args, "domain", None), "COLLECTOR_DOMAIN", "domain", default=""
    )
    settings["username"] = resolve(
        getattr(args, "username", None), "COLLECTOR_USERNAME", "username", default=""
    )
    settings["winrm_port"] = _coerce_int(
        resolve(
            getattr(args, "winrm_port", None),
            "COLLECTOR_WINRM_PORT",
            "winrm_port",
            default=5985,
        ),
        "COLLECTOR_WINRM_PORT",
    )
    settings["profile"] = resolve(
        getattr(args, "profile", None),
        "COLLECTOR_PROFILE",
        "profile",
        default="nist_800_53",
    )
    settings["format"] = resolve(
        getattr(args, "format", None), "COLLECTOR_FORMAT", "format", default="html"
    )
    settings["output_dir"] = resolve(
        getattr(args, "output_dir", None),
        "COLLECTOR_OUTPUT_DIR",
        "output_dir",
        default="",
    )
    settings["verbose"] = resolve(
        getattr(args, "verbose", False), "COLLECTOR_VERBOSE", "verbose", default=False
    )
    settings["verbose"] = _coerce_bool(settings["verbose"], "COLLECTOR_VERBOSE")
    settings["no_color"] = resolve(
        getattr(args, "no_color", False),
        "COLLECTOR_NO_COLOR",
        "no_color",
        default=False,
    )
    settings["no_color"] = _coerce_bool(settings["no_color"], "COLLECTOR_NO_COLOR")
    settings["no_banner"] = resolve(
        getattr(args, "no_banner", False),
        "COLLECTOR_NO_BANNER",
        "no_banner",
        default=False,
    )
    settings["no_banner"] = _coerce_bool(settings["no_banner"], "COLLECTOR_NO_BANNER")

    # Connection settings Ã¢â‚¬â€ from connection section
    settings["winrm_transport"] = resolve(
        None,
        "COLLECTOR_WINRM_TRANSPORT",
        "winrm_transport",
        section="connection",
        default="ntlm",
    )
    settings["connection_timeout"] = _coerce_int(
        resolve(
            None,
            "COLLECTOR_CONN_TIMEOUT",
            "connection_timeout",
            section="connection",
            default=30,
        ),
        "COLLECTOR_CONN_TIMEOUT",
    )
    settings["read_timeout"] = _coerce_int(
        resolve(
            None,
            "COLLECTOR_READ_TIMEOUT",
            "read_timeout",
            section="connection",
            default=120,
        ),
        "COLLECTOR_READ_TIMEOUT",
    )

    # Evidence thresholds Ã¢â‚¬â€ from evidence section
    settings["inactive_account_threshold_days"] = _coerce_int(
        resolve(
            None,
            "COLLECTOR_INACTIVE_DAYS",
            "inactive_account_threshold_days",
            section="evidence",
            default=90,
        ),
        "COLLECTOR_INACTIVE_DAYS",
    )
    settings["max_lockout_attempts"] = _coerce_int(
        resolve(
            None,
            "COLLECTOR_MAX_LOCKOUT",
            "max_lockout_attempts",
            section="evidence",
            default=5,
        ),
        "COLLECTOR_MAX_LOCKOUT",
    )

    log_size_mb = os.environ.get("COLLECTOR_LOG_SIZE_MB")
    if log_size_mb:
        settings["min_security_log_size_kb"] = (
            _coerce_int(log_size_mb, "COLLECTOR_LOG_SIZE_MB") * 1024
        )
    else:
        settings["min_security_log_size_kb"] = _coerce_int(
            _get(
                "min_security_log_size_kb",
                "evidence",
                named_profile,
                user_settings,
                prog_defaults,
                default=196608,
            ),
            "min_security_log_size_kb",
        )

    settings["min_password_length"] = _coerce_int(
        _get(
            "min_password_length",
            "evidence",
            named_profile,
            user_settings,
            prog_defaults,
            default=14,
        ),
        "min_password_length",
    )
    settings["max_password_age_days"] = _coerce_int(
        _get(
            "max_password_age_days",
            "evidence",
            named_profile,
            user_settings,
            prog_defaults,
            default=90,
        ),
        "max_password_age_days",
    )

    # Output settings
    settings["include_raw_evidence"] = _coerce_bool(
        _get(
            "include_raw_evidence",
            "output",
            named_profile,
            user_settings,
            prog_defaults,
            default=True,
        ),
        "include_raw_evidence",
    )
    settings["filename_timestamp_format"] = _get(
        "filename_timestamp_format",
        "output",
        named_profile,
        user_settings,
        prog_defaults,
        default="%Y%m%d_%H%M%S",
    )

    return settings


# =============================================================================
# OUTPUT DIRECTORY
# =============================================================================


def resolve_output_dir(output_dir_setting: str) -> Path:
    """
    Determines the root output directory for all scan reports.

    If the user specified an explicit path, use it.
    Otherwise use the platform-appropriate default Documents folder.

    The returned path is the ROOT Ã¢â‚¬â€ the scan subfolder (scan_YYYYMMDD_HHMMSS)
    is created inside it by create_scan_folder().
    """
    if output_dir_setting:
        return Path(output_dir_setting).expanduser()

    # Platform-appropriate default
    home = Path.home()
    documents = home / "Documents"

    if platform.system() == "Windows":
        # On Windows, Documents always exists under the user profile
        base = documents
    else:
        # Linux / macOS Ã¢â‚¬â€ use Documents if it exists, otherwise home directly
        base = documents if documents.exists() else home

    return base / "Compliance Scans"


def create_scan_folder(output_root: Path, timestamp_fmt: str) -> Path:
    """
    Creates a uniquely timestamped folder for this scan run.

    Every scan Ã¢â‚¬â€ whether against one host or fifty Ã¢â‚¬â€ gets its own folder so
    results are never overwritten and are easy to locate later.

    Parameters
    ----------
    output_root : Path
        The root Compliance Scans directory.
    timestamp_fmt : str
        strftime format string for the folder name suffix.

    Returns
    -------
    Path
        The created scan folder, e.g. .../Compliance Scans/scan_20260218_143022/
    """
    base_name = f"scan_{datetime.now().strftime(timestamp_fmt)}"

    try:
        output_root.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(
            f"{Fore.RED}Error: Cannot create output root {output_root}: {e}{Style.RESET_ALL}"
        )
        sys.exit(1)

    # Ensure uniqueness even when multiple scans start in the same timestamp second.
    for suffix in [""] + [f"_{i:02d}" for i in range(1, 100)]:
        candidate = output_root / f"{base_name}{suffix}"
        try:
            candidate.mkdir(parents=False, exist_ok=False)
            return candidate
        except FileExistsError:
            continue
        except OSError as e:
            print(
                f"{Fore.RED}Error: Cannot create output directory {candidate}: {e}{Style.RESET_ALL}"
            )
            sys.exit(1)

    print(
        f"{Fore.RED}Error: Could not allocate a unique scan folder under {output_root}.{Style.RESET_ALL}"
    )
    sys.exit(1)


# =============================================================================
# SLUG / FILENAME HELPERS
# =============================================================================


def slugify(text: str) -> str:
    """
    Converts a human-readable label into a safe filename component.

    Example: "Production Web Server" -> "production_web_server"

    Replaces spaces and non-alphanumeric characters with underscores,
    collapses consecutive underscores, strips leading/trailing underscores.
    """
    slug = text.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    slug = slug.strip("_")
    return slug or "host"


def report_filename(label: str, host: str, profile: str) -> str:
    """
    Builds a report filename from host identity and profile name.

    Example:
      label="Production Web Server", host="web01.corp.local", profile="nist_800_53"
      -> "production_web_server_web01_corp_local_nist_800_53"
    """
    return f"{slugify(label)}_{slugify(host)}_{slugify(profile)}"


# =============================================================================
# TARGET LOADING
# =============================================================================


def load_targets_from_csv(csv_path: Path, cli_settings: dict) -> list[dict]:
    """
    Loads scan targets from a CSV file.

    CSV format (see docs/hosts_template.csv for full documentation):
      - First non-comment line may be a metadata row: "domain,<suffix>"
      - Header row: host,username,label,port,notes
      - Data rows: one per target host

    Priority rules applied here:
      - cli_settings["username"] overrides CSV username column for all rows
      - cli_settings["domain"]   overrides CSV domain metadata row
      - CSV username column used when no CLI username provided
      - CSV domain metadata used when no CLI domain provided

    Parameters
    ----------
    csv_path : Path
        Path to the hosts CSV file.
    cli_settings : dict
        Resolved settings from the CLI/env/config chain. Used to apply
        CLI overrides to CSV values.

    Returns
    -------
    list[dict]
        List of target dicts, each with keys:
        host, username, label, port, domain, notes
    """
    if not csv_path.exists():
        print(f"{Fore.RED}Error: CSV file not found: {csv_path}{Style.RESET_ALL}")
        sys.exit(1)

    targets = []
    csv_domain = ""  # domain suffix from CSV metadata row

    with open(csv_path, newline="", encoding="utf-8") as f:
        raw_lines = f.readlines()

    # Strip comment lines (starting with #) and blank lines for processing
    lines = [
        line for line in raw_lines if line.strip() and not line.strip().startswith("#")
    ]

    if not lines:
        print(
            f"{Fore.RED}Error: CSV file is empty or contains only comments: {csv_path}{Style.RESET_ALL}"
        )
        sys.exit(1)

    # Check for optional metadata row: "domain,corp.local"
    # This lets the CSV file carry its own domain default without CLI flags
    first_line = lines[0].strip().lower()
    if first_line.startswith("domain,"):
        csv_domain = lines[0].split(",", 1)[1].strip()
        lines = lines[1:]  # consume the metadata row

    # Effective domain: CLI wins over CSV metadata
    effective_domain = cli_settings.get("domain") or csv_domain

    # Parse remaining lines as CSV
    reader = csv.DictReader(lines)

    # Validate required column exists
    if "host" not in (reader.fieldnames or []):
        print(f"{Fore.RED}Error: CSV missing required 'host' column.{Style.RESET_ALL}")
        print("  Expected header: host,username,label,port,notes")
        sys.exit(1)

    for row_num, row in enumerate(reader, start=2):
        host_raw = (row.get("host") or "").strip()
        if not host_raw or host_raw.startswith("#"):
            continue  # Skip blank host entries and inline-commented rows

        # Username: CLI flag > CSV column
        username = cli_settings.get("username") or (row.get("username") or "").strip()

        # Label: CSV column > hostname (friendly display name)
        label = (row.get("label") or "").strip() or host_raw

        # Port: CSV column > CLI/settings default
        try:
            port = int(
                (row.get("port") or "").strip() or cli_settings.get("winrm_port", 5985)
            )
        except ValueError:
            default_port = int(cli_settings.get("winrm_port", 5985))
            print(
                f"{Fore.YELLOW}Warning: Invalid port on row {row_num}, using default {default_port}{Style.RESET_ALL}"
            )
            port = default_port

        notes = (row.get("notes") or "").strip()

        targets.append(
            {
                "host_raw": host_raw,
                "host": resolve_hostname(host_raw, effective_domain),
                "username": username,
                "label": label,
                "port": port,
                "notes": notes,
            }
        )

    if not targets:
        print(f"{Fore.RED}Error: No valid targets found in {csv_path}{Style.RESET_ALL}")
        sys.exit(1)

    return targets


def load_targets_from_args(args: argparse.Namespace, settings: dict) -> list[dict]:
    """
    Builds the target list from the --host CLI argument.

    --host accepts a single value or a comma-separated list.
    Each value can be a bare hostname, FQDN, or IP address.
    The domain suffix is applied to bare hostnames automatically.
    """
    raw_hosts = [h.strip() for h in args.host.split(",") if h.strip()]

    if not raw_hosts:
        print(
            f"{Fore.RED}Error: --host was provided but contained no valid hostnames.{Style.RESET_ALL}"
        )
        sys.exit(1)

    targets = []
    for host_raw in raw_hosts:
        resolved = resolve_hostname(host_raw, settings.get("domain", ""))

        # Label: --label only applies when there's a single host.
        # For multiple hosts, the label falls back to the hostname.
        if len(raw_hosts) == 1 and getattr(args, "label", None):
            label = args.label
        else:
            label = host_raw  # use the original unresolved name as display label

        targets.append(
            {
                "host_raw": host_raw,
                "host": resolved,
                "username": settings.get("username", ""),
                "label": label,
                "port": settings.get("winrm_port", 5985),
                "notes": "",
            }
        )

    return targets


# =============================================================================
# CREDENTIAL MANAGEMENT
# =============================================================================


def collect_passwords(targets: list[dict]) -> dict[str, str]:
    """
    Collects passwords for all unique usernames found across all targets.

    Priority for each username:
      1. COLLECTOR_PASSWORD_<USERNAME>  env var (uppercased, hyphens->underscores)
      2. COLLECTOR_PASSWORD             env var (single shared password)
      3. Interactive getpass prompt     (hidden, never echoed)

    Passwords are collected BEFORE the scan starts so the user isn't
    interrupted mid-scan waiting for input.

    Parameters
    ----------
    targets : list[dict]
        Resolved target list. Each dict must have a "username" key.

    Returns
    -------
    dict[str, str]
        Maps username -> password. Never written to disk or logged.
    """
    # First pass: ensure all targets have a username
    for t in targets:
        if not t.get("username"):
            print(
                f"{Fore.YELLOW}Username required for {t['label']} ({t['host']}){Style.RESET_ALL}"
            )
            t["username"] = input("  Username: ").strip()

    # Collect unique usernames
    unique_usernames = sorted(set(t["username"] for t in targets))

    passwords = {}
    default_password = os.environ.get("COLLECTOR_PASSWORD", "")

    for username in unique_usernames:
        # Build the per-username env var name:
        # e.g. "CORP\compliance-svc" -> "COLLECTOR_PASSWORD_CORP_COMPLIANCE_SVC"
        env_key = "COLLECTOR_PASSWORD_" + re.sub(r"[^A-Z0-9]", "_", username.upper())
        per_user_pw = os.environ.get(env_key, "")

        if per_user_pw:
            logger.debug(f"Using {env_key} env var for {username}")
            passwords[username] = per_user_pw
        elif default_password:
            logger.debug(f"Using COLLECTOR_PASSWORD env var for {username}")
            passwords[username] = default_password
        else:
            print(
                f"\n{Fore.YELLOW}Password required for: {Fore.CYAN}{username}{Style.RESET_ALL}"
            )
            print("  (Input hidden Ã¢â‚¬â€ will not be echoed)")
            passwords[username] = getpass.getpass("  Password: ")

    return passwords


# =============================================================================
# RICH PROGRESS DISPLAY
# =============================================================================


def build_progress_callback(settings: dict):
    """
    Returns a progress_callback function that drives an animated terminal
    display during the scan.

    Each completed check prints a permanent result line. While a check is
    running, a spinner + progress bar animates on a single line below the
    results using carriage return (\r) overwrite Ã¢â‚¬â€ compatible with all
    terminal types including Windows Terminal, VS Code, and CI pipelines.

    The spinner runs on a background thread at 80ms so it keeps animating
    even while PowerShell is executing on the remote host.

    Events from runner.scan():
      check_start    Ã¢â‚¬â€ a new check is about to run
      check_complete Ã¢â‚¬â€ a check finished, result is available
      scan_complete  Ã¢â‚¬â€ all checks done, clean up display
    """
    import threading
    import time

    # Enable Windows VT100 processing so ANSI codes work in all Windows terminals
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            # Get current console mode and enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004)
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass  # Non-fatal Ã¢â‚¬â€ fall back to plain output

    no_color = settings.get("no_color", False)
    interactive = sys.stdout.isatty()

    STATUS_COLORS = {
        "PASS": Fore.GREEN if not no_color else "",
        "FAIL": Fore.RED if not no_color else "",
        "WARNING": Fore.YELLOW if not no_color else "",
        "ERROR": Fore.RED if not no_color else "",
    }
    STATUS_SYMBOLS = {
        "PASS": "Ã¢Å“â€œ",
        "FAIL": "Ã¢Å“â€”",
        "WARNING": "Ã¢Å¡Â ",
        "ERROR": "!",
    }

    # Braille spinner Ã¢â‚¬â€ smooth 10-frame animation
    SPINNER_FRAMES = [
        "Ã¢Â â€¹",
        "Ã¢Â â„¢",
        "Ã¢Â Â¹",
        "Ã¢Â Â¸",
        "Ã¢Â Â¼",
        "Ã¢Â Â´",
        "Ã¢Â Â¦",
        "Ã¢Â Â§",
        "Ã¢Â â€¡",
        "Ã¢Â Â",
    ]

    # Shared state between callback (main thread) and spinner (background thread)
    state = {
        "active": False,  # True while spinner should be running
        "frame": 0,  # Current spinner frame index
        "check_id": "",  # ID of currently running check
        "check_name": "",  # Name of currently running check
        "host_label": "",  # Display label for the target host
        "current": 0,  # Checks completed so far
        "total": 0,  # Total checks in this scan
        "lock": threading.Lock(),
    }
    _thread = [None]  # Spinner thread reference for clean shutdown

    def _cyan(text):
        return (Fore.CYAN + str(text) + Style.RESET_ALL) if not no_color else str(text)

    def _progress_bar(current: int, total: int, width: int = 24) -> str:
        """Unicode block progress bar."""
        if total == 0:
            return "Ã¢â€“â€˜" * width
        filled = int(width * current / total)
        return "Ã¢â€“Ë†" * filled + "Ã¢â€“â€˜" * (width - filled)

    def _render_spinner_line(frame: str) -> None:
        """
        Writes the animated spinner+progress line using \r to overwrite.
        This approach works on all terminal types Ã¢â‚¬â€ no cursor-up codes needed.
        Called with state["lock"] held.
        """
        current = state["current"]
        total = state["total"]
        pct = int(100 * current / total) if total else 0
        bar = _progress_bar(current, total)
        label = state["host_label"]
        check_id = state["check_id"]
        name = state["check_name"][:35]  # truncate long names to keep line short

        cyan = Fore.CYAN if not no_color else ""
        reset = Style.RESET_ALL if not no_color else ""

        line = (
            f"  {cyan}{frame}{reset} "
            f"{cyan}{label[:20]}{reset} "
            f"{check_id:<8} {name:<35} "
            f"{cyan}{bar}{reset} {current}/{total} {pct}%"
        )

        # Pad to terminal width to overwrite any previous longer line
        padded = line + " " * max(0, 120 - len(line))
        sys.stdout.write("\r" + padded)
        sys.stdout.flush()

    def _run_spinner() -> None:
        """Background thread: animates spinner at 80ms until stopped."""
        while True:
            with state["lock"]:
                if not state["active"]:
                    break
                frame = SPINNER_FRAMES[state["frame"] % len(SPINNER_FRAMES)]
                state["frame"] += 1
                _render_spinner_line(frame)
            time.sleep(0.08)

    def _start_spinner() -> None:
        """Starts the background spinner thread."""
        if not interactive:
            return
        state["active"] = True
        state["frame"] = 0
        t = threading.Thread(target=_run_spinner, daemon=True)
        t.start()
        _thread[0] = t

    def _stop_spinner() -> None:
        """
        Stops the spinner thread and clears the spinner line.
        Must be called before printing any permanent output.
        """
        if not interactive:
            return
        with state["lock"]:
            state["active"] = False
        if _thread[0]:
            _thread[0].join(timeout=0.3)
            _thread[0] = None
        # Clear the spinner line completely
        sys.stdout.write("\r" + " " * 130 + "\r")
        sys.stdout.flush()

    def callback(event: str, payload: dict) -> None:
        """
        Receives events from runner.scan() and updates the terminal display.

        check_start:    Update state, start spinner on first check.
        check_complete: Stop spinner, print permanent result, restart spinner.
        scan_complete:  Stop spinner, print final progress bar.
        """
        label = payload.get("host_label", "")
        check_id = payload.get("check_id", "")
        name = payload.get("check_name", check_id)
        current = payload.get("current", 0)
        total = payload.get("total", 0)

        if event == "check_start":
            with state["lock"]:
                state["check_id"] = check_id
                state["check_name"] = name
                state["host_label"] = label
                state["current"] = current - 1  # not yet complete
                state["total"] = total
            if interactive and not state["active"]:
                _start_spinner()

        elif event == "check_complete":
            status = payload.get("status", "")
            color = STATUS_COLORS.get(status, "")
            symbol = STATUS_SYMBOLS.get(status, "?")
            reset = Style.RESET_ALL if not no_color else ""
            cyan = Fore.CYAN if not no_color else ""

            if interactive:
                _stop_spinner()

            # Print the permanent completed-check line
            print(
                f"  {color}{symbol}{reset} "
                f"{cyan}{label:<28}{reset} "
                f"{check_id:<8} "
                f"{name:<42} "
                f"{color}{status}{reset}"
            )

            # Update state and restart spinner for next check
            with state["lock"]:
                state["current"] = current
                state["total"] = total
            if interactive:
                _start_spinner()

        elif event == "scan_complete":
            _stop_spinner()
            total = state["total"]
            cyan = Fore.CYAN if not no_color else ""
            reset = Style.RESET_ALL if not no_color else ""
            print(f"  {cyan}{_progress_bar(total, total)}{reset} {total}/{total}  100%")

    return callback


def print_banner(settings: dict) -> None:
    """Prints the startup banner unless --no-banner is set."""
    if settings.get("no_banner"):
        return
    width = 66
    line1 = f"{TOOL_NAME} v{TOOL_VERSION}".center(width)
    line2 = "NIST 800-53 | PCI DSS 4.0 | SOC 2 | HIPAA | CMMC | ISO 27001".center(width)
    banner = f"\n+{'-' * width}+\n|{line1}|\n|{line2}|\n+{'-' * width}+"
    print(Fore.CYAN + banner + Style.RESET_ALL)


def print_scan_header(targets: list[dict], settings: dict, scan_folder: Path) -> None:
    """Prints a pre-scan summary: targets, profile, output location."""
    print(f"  {'Profile':<18} {settings['profile']}")
    print(f"  {'Output':<18} {scan_folder}")
    print(f"  {'Targets':<18} {len(targets)}")
    if settings.get("domain"):
        print(f"  {'Domain suffix':<18} {settings['domain']}")
    print()

    for t in targets:
        port_str = f":{t['port']}" if t["port"] != 5985 else ""
        print(f"    Ã¢â‚¬Â¢ {t['label']:<30} {t['host']}{port_str}  ({t['username']})")
    print()


# =============================================================================
# PER-HOST SCAN
# =============================================================================


def scan_host(
    target: dict,
    password: str,
    settings: dict,
    scan_folder: Path,
    profile_path: Path,
) -> Optional[object]:
    """
    Runs the full compliance scan against a single host.

    Sequence:
      1. WinRM precheck (TCP + authentication)
      2. Load compliance profile
      3. Run all checks with live progress display
      4. Generate per-host report(s)

    Parameters
    ----------
    target : dict
        Resolved target dict with keys: host, username, label, port.
    password : str
        Password for this target's username. Never stored beyond this call.
    settings : dict
        Fully resolved settings from the settings chain.
    scan_folder : Path
        Timestamped folder where reports for this scan run are saved.
    profile_path : Path
        Path to the compliance framework YAML to run.

    Returns
    -------
    HostScanResult or None
        The scan result object, or None if the host could not be reached.
    """
    host = target["host"]
    username = target["username"]
    label = target["label"]
    port = target["port"]

    print(f"\n{Fore.CYAN}{'Ã¢â€â‚¬' * 66}{Style.RESET_ALL}")
    print(f"  Target : {Fore.CYAN}{label}{Style.RESET_ALL}  ({host}:{port})")
    print(f"  User   : {username}")

    # ------------------------------------------------------------------
    # Precheck 1: TCP port reachability + WinRM authentication
    # ------------------------------------------------------------------
    print(f"\n  {Fore.CYAN}[1/3] WinRM precheck...{Style.RESET_ALL}")

    connector = WinRMConnector(
        host=host,
        username=username,
        port=port,
        transport=settings["winrm_transport"],
        connection_timeout=settings["connection_timeout"],
        read_timeout=settings["read_timeout"],
    )

    available, reason = connector.check_winrm_available(password)
    if not available:
        connector.disconnect()
        print(f"  {Fore.RED}! WinRM not available: {reason}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Troubleshooting:{Style.RESET_ALL}")
        print("    - Enable WinRM on target:  winrm quickconfig -y")
        print("    - Open firewall:           netsh advfirewall firewall add rule")
        print("                               name='WinRM' dir=in action=allow")
        print("                               protocol=tcp localport=5985")
        print("    - Verify credentials and remote management rights")
        return None

    print(f"  {Fore.GREEN}OK WinRM available and authenticated{Style.RESET_ALL}")

    # ------------------------------------------------------------------
    # [2/3]: Load compliance profile
    # ------------------------------------------------------------------
    print(
        f"\n  {Fore.CYAN}[2/3] Loading profile: {settings['profile']}...{Style.RESET_ALL}"
    )
    runner = ComplianceRunner(str(profile_path), settings)
    check_count = len(runner.profile["checks"])
    print(
        f"  {Fore.GREEN}Ã¢Å“â€œ {runner.profile['profile_name']} Ã¢â‚¬â€ {check_count} checks{Style.RESET_ALL}"
    )

    # ------------------------------------------------------------------
    # [3/3]: Run checks
    # ------------------------------------------------------------------
    print(f"\n  {Fore.CYAN}[3/3] Running {check_count} checks...{Style.RESET_ALL}\n")

    # Column headers
    print(f"  {'':3}  {'Target':<28}  {'Check':<8}  {'Name':<45}  {'Result'}")
    print(f"  {'Ã¢â€â‚¬' * 100}")

    progress_callback = build_progress_callback(settings)

    try:
        scan_result = runner.scan(
            connector=connector,
            executed_by=username,
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            progress_callback=progress_callback,
            host_label=label,
        )
    except WinRMConnectionError as e:
        print(
            f"\n  {Fore.RED}Ã¢Å“â€” Connection lost during scan: {e}{Style.RESET_ALL}"
        )
        return None
    finally:
        connector.disconnect()

    # ------------------------------------------------------------------
    # Per-host results summary
    # ------------------------------------------------------------------
    print(f"\n  {'Ã¢â€â‚¬' * 66}")
    print(
        f"  {Fore.GREEN}PASS {scan_result.passed:>3}{Style.RESET_ALL}   "
        f"{Fore.RED}FAIL {scan_result.failed:>3}{Style.RESET_ALL}   "
        f"{Fore.YELLOW}WARN {scan_result.warnings:>3}{Style.RESET_ALL}   "
        f"ERR {scan_result.errors:>3}   "
        f"Compliance: {Fore.CYAN}{scan_result.compliance_percentage}%{Style.RESET_ALL}"
    )

    if scan_result.failed > 0:
        print(f"\n  {Fore.RED}Findings requiring remediation:{Style.RESET_ALL}")
        for check in scan_result.checks:
            if check.status == "FAIL":
                print(f"    Ã¢Å“â€” [{check.check_id}] {check.check_name}")
                print(f"        {check.finding}")

    # ------------------------------------------------------------------
    # Generate per-host report(s)
    # ------------------------------------------------------------------
    fname = report_filename(label, host, settings["profile"])

    if settings["format"] in ("html", "both"):
        path = HtmlReporter(str(scan_folder), filename=fname).generate(scan_result)
        print(f"\n  {Fore.GREEN}Ã¢Å“â€œ HTML report: {path}{Style.RESET_ALL}")

    if settings["format"] in ("json", "both"):
        path = JsonReporter(str(scan_folder), filename=fname).generate(scan_result)
        print(f"  {Fore.GREEN}Ã¢Å“â€œ JSON report: {path}{Style.RESET_ALL}")

    return scan_result


# =============================================================================
# COMBINED SUMMARY REPORT
# =============================================================================


def generate_summary_report(
    results: list,
    targets: list[dict],
    scan_folder: Path,
    settings: dict,
) -> None:
    """
    Generates a combined summary HTML report covering all hosts in this scan run.

    The summary shows a comparison table: one row per host with compliance
    percentage, pass/fail/warn/error counts, and a link to the per-host report.
    This is the first thing an auditor or manager sees Ã¢â‚¬â€ the per-host reports
    contain the full evidence detail.

    Parameters
    ----------
    results : list
        HostScanResult objects, in the same order as targets.
        May contain None for hosts that failed the precheck.
    targets : list[dict]
        Original target list (used for labels and hostnames).
    scan_folder : Path
        Where to write the summary file.
    settings : dict
        Resolved settings (used for profile name, format, etc.)
    """
    # Only write the summary if we have at least one successful result
    successful = [(t, r) for t, r in zip(targets, results) if r is not None]
    failed_hosts = [(t, r) for t, r in zip(targets, results) if r is None]

    if not successful:
        print(
            f"\n{Fore.YELLOW}No successful scans Ã¢â‚¬â€ summary report not generated.{Style.RESET_ALL}"
        )
        return

    # Build HTML summary table
    rows = ""
    esc = html.escape
    for target, result in successful:
        pct = result.compliance_percentage
        color = "green" if pct >= 80 else "orange" if pct >= 60 else "red"
        report_ext = ".html" if settings.get("format") in ("html", "both") else ".json"
        fname = (
            report_filename(target["label"], target["host"], settings["profile"])
            + report_ext
        )
        rows += f"""
        <tr>
            <td><a href="{esc(fname, quote=True)}">{esc(target["label"])}</a></td>
            <td>{esc(target["host"])}</td>
            <td style="color:{color};font-weight:bold">{pct}%</td>
            <td style="color:green">{result.passed}</td>
            <td style="color:red">{result.failed}</td>
            <td style="color:orange">{result.warnings}</td>
            <td>{result.errors}</td>
        </tr>"""

    for target in [t for t, _ in failed_hosts]:
        rows += f"""
        <tr>
            <td>{esc(target["label"])}</td>
            <td>{esc(target["host"])}</td>
            <td colspan="5" style="color:gray">Connection failed Ã¢â‚¬â€ no data</td>
        </tr>"""

    scan_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    profile_name = successful[0][1].profile_name if successful else settings["profile"]

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Compliance Scan Summary Ã¢â‚¬â€ {esc(profile_name)}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
  h1   {{ color: #2c3e50; }}
  table {{ border-collapse: collapse; width: 100%; background: white; }}
  th,td {{ border: 1px solid #ddd; padding: 10px 14px; text-align: left; }}
  th   {{ background: #2c3e50; color: white; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  .meta {{ color: #666; margin-bottom: 20px; }}
</style>
</head>
<body>
<h1>Compliance Scan Summary</h1>
<div class="meta">
  <strong>Profile:</strong> {esc(profile_name)}<br>
  <strong>Scan time:</strong> {scan_time}<br>
  <strong>Hosts scanned:</strong> {len(targets)}
  ({len(successful)} successful, {len(failed_hosts)} failed)
</div>
<table>
  <thead>
    <tr>
      <th>Host Label</th><th>Hostname / IP</th><th>Compliance</th>
      <th>Pass</th><th>Fail</th><th>Warn</th><th>Error</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</body>
</html>"""

    summary_path = scan_folder / f"summary_{slugify(settings['profile'])}.html"
    summary_path.write_text(html_doc, encoding="utf-8")
    print(f"\n  {Fore.GREEN}Ã¢Å“â€œ Summary report: {summary_path}{Style.RESET_ALL}")


# =============================================================================
# ARGUMENT PARSING
# =============================================================================


def parse_args() -> argparse.Namespace:
    """
    Defines and parses all CLI arguments.

    Every argument here has a corresponding:
      - settings.yaml key (in cli_defaults section)
      - Environment variable (COLLECTOR_*)
    See docs/settings_reference.md for the full mapping table.
    """
    parser = argparse.ArgumentParser(
        prog="ymc",
        description="Run YMC compliance scans on remote Windows hosts via WinRM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --host web01.corp.local --username compliance-svc --profile nist_800_53
  python main.py --host web01,db01,dc01 --domain corp.local --profile pci_dss_4
  python main.py --csv docs/hosts.csv --profile hipaa --format both
  python main.py --host 192.168.1.50 --label "Production Web Server" --username admin
  python main.py --list-profiles
  python main.py --list-configs

Environment variables:
  Every CLI flag has a COLLECTOR_* env var equivalent.
  See docs/environment_variables.md for the full list.
        """,
    )

    # ------------------------------------------------------------------
    # Scan targets (mutually exclusive)
    # ------------------------------------------------------------------
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "--host",
        help=(
            "Target hostname, FQDN, IP, or comma-separated list. "
            "Bare hostnames get the --domain suffix appended automatically."
        ),
    )
    target_group.add_argument(
        "--csv",
        metavar="FILE",
        help="Path to a CSV file containing multiple scan targets. See docs/hosts_template.csv.",
    )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    parser.add_argument(
        "--username",
        "-u",
        help=(
            "Username for WinRM authentication. Overrides CSV and settings.yaml. "
            "Formats: administrator  |  DOMAIN\\\\user  |  user@domain.com"
        ),
    )
    parser.add_argument(
        "--label",
        help=(
            "Friendly name for the target host (single --host only). "
            "Used in report filenames and progress display. "
            "Example: 'Production Web Server'"
        ),
    )
    parser.add_argument(
        "--domain",
        help=(
            "DNS domain suffix appended to bare hostnames. "
            "Example: --domain corp.local makes 'web01' resolve as 'web01.corp.local'. "
            "FQDNs and IP addresses are never modified."
        ),
    )

    # ------------------------------------------------------------------
    # Scan options
    # ------------------------------------------------------------------
    parser.add_argument(
        "--profile",
        "-p",
        help="Compliance framework profile to run. Use --list-profiles to see options.",
    )
    parser.add_argument(
        "--config",
        metavar="NAME",
        help=(
            "Named config profile from ~/.ymc/profiles/<name>.yaml. "
            "Use --list-configs to see available profiles."
        ),
    )
    parser.add_argument(
        "--winrm-port",
        type=int,
        dest="winrm_port",
        help="WinRM port (default: 5985 for HTTP, 5986 for HTTPS).",
    )

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    parser.add_argument(
        "--format",
        "-f",
        choices=["html", "json", "both"],
        help="Report output format (default: html).",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        dest="output_dir",
        help=(
            "Root directory for scan report folders. "
            "Default: ~/Documents/Compliance Scans/ (platform-appropriate)."
        ),
    )

    # ------------------------------------------------------------------
    # Runtime flags
    # ------------------------------------------------------------------
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable verbose/debug logging.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        default=False,
        help="Disable colour output. Useful in CI/CD pipelines.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        dest="no_banner",
        default=False,
        help="Suppress the startup banner.",
    )

    # ------------------------------------------------------------------
    # Informational actions
    # ------------------------------------------------------------------
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available compliance framework profiles and exit.",
    )
    parser.add_argument(
        "--list-configs",
        action="store_true",
        help="List available named config profiles and exit.",
    )

    return parser.parse_args()


# =============================================================================
# INFORMATIONAL ACTIONS
# =============================================================================


def cmd_list_profiles() -> None:
    """Prints available compliance framework profiles and exits."""
    profiles = list_profiles(str(PROFILES_DIR))
    print(f"{Fore.CYAN}Available compliance profiles:{Style.RESET_ALL}\n")
    for p in profiles:
        try:
            with open(PROFILES_DIR / f"{p}.yaml", encoding="utf-8") as f:
                meta = yaml.safe_load(f)
            name = meta.get("profile_name", p)
            checks = len(meta.get("checks", []))
            print(f"  {Fore.GREEN}{p:<25}{Style.RESET_ALL}  {name}  ({checks} checks)")
        except Exception:
            print(f"  {p}")
    print()


def cmd_list_configs() -> None:
    """Prints available named config profiles from both user and program dirs."""
    print(f"{Fore.CYAN}Available config profiles:{Style.RESET_ALL}\n")
    found = False
    for search_dir, label in [
        (USER_PROFILES_DIR, "user"),
        (NAMED_CFG_DIR, "program"),
    ]:
        if search_dir.exists():
            for p in sorted(search_dir.glob("*.yaml")):
                print(f"  {Fore.GREEN}{p.stem:<25}{Style.RESET_ALL}  [{label}]  {p}")
                found = True
    if not found:
        print("  No named config profiles found.")
        print(f"  Create one at: {USER_PROFILES_DIR / 'myprofile.yaml'}")
    print()


# =============================================================================
# MAIN
# =============================================================================


def main() -> None:
    configure_console_output()
    args = parse_args()

    # ------------------------------------------------------------------
    # Informational commands Ã¢â‚¬â€ print and exit
    # ------------------------------------------------------------------
    if args.list_profiles:
        cmd_list_profiles()
        sys.exit(0)

    if args.list_configs:
        cmd_list_configs()
        sys.exit(0)

    settings = resolve_settings(args)

    setup_logging(
        verbose=settings.get("verbose", False),
        no_color=settings.get("no_color", False),
    )

    print_banner(settings)

    # ------------------------------------------------------------------
    # Validate we have a scan target
    # ------------------------------------------------------------------
    if not args.host and not args.csv:
        print(
            f"{Fore.RED}Error: Specify a scan target with --host or --csv.{Style.RESET_ALL}"
        )
        print("  Run with --help for usage, --list-profiles for available profiles.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Validate the compliance profile exists
    # ------------------------------------------------------------------
    profile_path = PROFILES_DIR / f"{settings['profile']}.yaml"
    if not profile_path.exists():
        print(
            f"{Fore.RED}Error: Profile '{settings['profile']}' not found at {profile_path}{Style.RESET_ALL}"
        )
        print("  Use --list-profiles to see available options.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Load targets
    # ------------------------------------------------------------------
    if args.csv:
        targets = load_targets_from_csv(Path(args.csv), settings)
    else:
        targets = load_targets_from_args(args, settings)

    # ------------------------------------------------------------------
    # Resolve output directory and create scan folder
    # ------------------------------------------------------------------
    output_root = resolve_output_dir(settings.get("output_dir", ""))
    scan_folder = create_scan_folder(output_root, settings["filename_timestamp_format"])

    # ------------------------------------------------------------------
    # Pre-scan summary
    # ------------------------------------------------------------------
    print_scan_header(targets, settings, scan_folder)

    # ------------------------------------------------------------------
    # Collect passwords for all unique usernames before scanning starts
    # ------------------------------------------------------------------
    passwords = collect_passwords(targets)

    # ------------------------------------------------------------------
    # Run scans
    # ------------------------------------------------------------------
    results = []
    for i, target in enumerate(targets, start=1):
        if len(targets) > 1:
            print(f"\n{Fore.CYAN}Host {i} of {len(targets)}{Style.RESET_ALL}")

        result = scan_host(
            target=target,
            password=passwords[target["username"]],
            settings=settings,
            scan_folder=scan_folder,
            profile_path=profile_path,
        )
        results.append(result)

    # ------------------------------------------------------------------
    # Combined summary report
    # ------------------------------------------------------------------
    generate_summary_report(results, targets, scan_folder, settings)

    # ------------------------------------------------------------------
    # Final exit code
    # 0 = all hosts passed
    # 1 = one or more hosts had connection errors
    # 2 = one or more checks failed (findings found)
    # ------------------------------------------------------------------
    any_failed_connection = any(r is None for r in results)
    any_failed_checks = any(r is not None and r.failed > 0 for r in results)

    if any_failed_connection and any_failed_checks:
        sys.exit(2)
    elif any_failed_connection:
        sys.exit(1)
    elif any_failed_checks:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
