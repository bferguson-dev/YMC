"""
winrm_connector.py
------------------
Manages WinRM connections to remote Windows hosts.
All remote PowerShell execution flows through this module.

Design principles:
- Credentials are never stored, logged, or written to disk
- One session per host, reused across all checks for that host
- Clear separation between connection errors and check errors
- WinRM availability is verified before any checks run
"""

import winrm
import socket
import re
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def resolve_hostname(host: str, domain_suffix: str = "") -> str:
    """
    Applies a DNS domain suffix to a bare hostname if appropriate.

    Rules (applied in order):
      1. If host is an IP address (v4 or v6)  -> return unchanged
      2. If host already contains a dot        -> treat as FQDN, return unchanged
      3. If domain_suffix is set               -> append it: host.domain_suffix
      4. Otherwise                             -> return unchanged

    Parameters
    ----------
    host : str
        Hostname, FQDN, or IP address as provided by the user.
    domain_suffix : str
        DNS suffix to append to bare hostnames, e.g. "corp.local".
        Leading/trailing dots are stripped automatically.

    Returns
    -------
    str
        The resolved hostname, ready to pass to WinRM and socket calls.

    Examples
    --------
        resolve_hostname("webserver", "corp.local")  -> "webserver.corp.local"
        resolve_hostname("web01.corp.local", "corp.local")  -> "web01.corp.local"
        resolve_hostname("192.168.1.10", "corp.local")  -> "192.168.1.10"
        resolve_hostname("webserver", "")  -> "webserver"
    """
    host = host.strip()

    # IPv4 pattern — four octets of 0-255 separated by dots
    ipv4_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

    # IPv6 — contains colons
    is_ipv6 = ":" in host

    if ipv4_pattern.match(host) or is_ipv6:
        # It's an IP address — never append a suffix
        return host

    if "." in host:
        # Already a FQDN — leave it alone
        return host

    if domain_suffix:
        # Bare hostname + suffix provided — append it
        suffix = domain_suffix.strip().strip(".")
        return f"{host}.{suffix}"

    # Bare hostname, no suffix — return as-is
    return host


class WinRMConnectionError(Exception):
    """Raised when a connection to a remote host cannot be established."""

    pass


class WinRMExecutionError(Exception):
    """Raised when a command executes but returns an unexpected error."""

    pass


class WinRMConnector:
    """
    Manages a WinRM session to a single remote Windows host.

    Usage:
        connector = WinRMConnector(host="192.168.1.10", username="domain\\svcaccount")
        connector.connect(password)          # prompts or accepts password in memory
        result = connector.run_ps("Get-Date")
        connector.disconnect()

    Or use as a context manager:
        with WinRMConnector(host, username) as conn:
            conn.connect(password)
            result = conn.run_ps("Get-Date")
    """

    def __init__(
        self,
        host: str,
        username: str,
        port: int = 5985,
        transport: str = "ntlm",
        connection_timeout: int = 30,
        read_timeout: int = 60,
    ):
        self.host = host
        self.username = username
        self.port = port
        self.transport = transport
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self._session: Optional[winrm.Session] = None
        self._ip_address: Optional[str] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self, password: str) -> None:
        """
        Establishes a WinRM session to the target host.
        Password is accepted as a parameter so callers control
        how it was obtained (getpass, env var, etc.) — never stored here
        beyond the session lifetime.
        """
        logger.info(f"Connecting to {self.host} via WinRM ({self.transport})")

        # Resolve hostname to IP for audit evidence
        try:
            self._ip_address = socket.gethostbyname(self.host)
        except socket.gaierror:
            self._ip_address = self.host  # Fall back to whatever was provided

        try:
            scheme = self._winrm_scheme()
            self._session = winrm.Session(
                target=f"{scheme}://{self.host}:{self.port}/wsman",
                auth=(self.username, password),
                transport=self.transport,
                read_timeout_sec=self.read_timeout,
                operation_timeout_sec=self.connection_timeout,
            )
            # Verify the session actually works before proceeding
            self._verify_connection()
            logger.info(f"Connected to {self.host} ({self._ip_address})")

        except Exception as e:
            self._session = None
            raise WinRMConnectionError(
                f"Failed to connect to {self.host}:{self.port} — {e}"
            ) from e

    def disconnect(self) -> None:
        """Clears the session. Credentials are gone when this is called."""
        self._session = None
        logger.info(f"Disconnected from {self.host}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False  # Don't suppress exceptions

    # ------------------------------------------------------------------
    # WinRM availability check
    # ------------------------------------------------------------------

    def check_winrm_available(self, password: str) -> Tuple[bool, str]:
        """
        Verifies WinRM is reachable and responsive on the target host
        before running any compliance checks.

        Returns:
            (True, "") on success
            (False, "reason string") on failure

        This is always the first check run against any host.
        """
        # Step 1: TCP port reachability
        try:
            sock = socket.create_connection(
                (self.host, self.port), timeout=self.connection_timeout
            )
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return False, f"TCP port {self.port} unreachable on {self.host}: {e}"

        # Step 2: WinRM authentication and basic execution
        try:
            self.connect(password)
            result = self.run_ps("Write-Output 'WinRM-OK'")
            if "WinRM-OK" in result.stdout:
                return True, ""
            else:
                return (
                    False,
                    f"WinRM responded but returned unexpected output: {result.stdout}",
                )
        except WinRMConnectionError as e:
            return False, str(e)
        except Exception as e:
            return False, f"WinRM check failed unexpectedly: {e}"

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def run_ps(self, script: str) -> "CommandResult":
        """
        Executes a PowerShell script on the remote host and returns
        a CommandResult with stdout, stderr, and exit code.

        Raises WinRMConnectionError if not connected.
        Raises WinRMExecutionError on transport-level failures.
        """
        if not self._session:
            raise WinRMConnectionError(
                f"Not connected to {self.host}. Call connect() first."
            )

        try:
            response = self._session.run_ps(script)
            return CommandResult(
                stdout=response.std_out.decode("utf-8", errors="replace").strip(),
                stderr=response.std_err.decode("utf-8", errors="replace").strip(),
                exit_code=response.status_code,
            )
        except Exception as e:
            raise WinRMExecutionError(
                f"PowerShell execution failed on {self.host}: {e}"
            ) from e

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def ip_address(self) -> str:
        return self._ip_address or self.host

    @property
    def is_connected(self) -> bool:
        return self._session is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_connection(self) -> None:
        """
        Runs a trivial command to confirm the session is live.
        Called immediately after session creation in connect().
        """
        try:
            response = self._session.run_ps("$true")
            if response.status_code != 0:
                raise WinRMConnectionError(
                    f"Session verification failed (exit code {response.status_code})"
                )
        except winrm.exceptions.WinRMError as e:
            raise WinRMConnectionError(f"Session verification failed: {e}") from e

    def _winrm_scheme(self) -> str:
        """
        Selects the endpoint scheme based on transport/port settings.
        """
        secure_transports = {"ssl", "certificate"}
        if self.transport.lower() in secure_transports or self.port == 5986:
            return "https"
        return "http"


class CommandResult:
    """
    Holds the output of a remote PowerShell command.
    Provides clean access to stdout, stderr, and success/failure.
    """

    def __init__(self, stdout: str, stderr: str, exit_code: int):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0

    @property
    def failed(self) -> bool:
        return self.exit_code != 0

    def __repr__(self):
        return f"CommandResult(exit_code={self.exit_code}, stdout={self.stdout[:80]!r})"
