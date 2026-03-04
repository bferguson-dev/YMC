"""
base_reporter.py
----------------
Abstract base class for all reporters.

Any new output format (fancy HTML, PDF, CSV, SIEM JSON, etc.) inherits
from this class and implements generate(). The rest of the codebase only
ever calls generate() — adding a new reporter never requires changes
anywhere else.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from engine.evidence import HostScanResult


class BaseReporter(ABC):
    """
    Abstract base class for compliance report generators.

    Subclass this and implement generate() to add a new output format.
    """

    def __init__(self, output_dir: str = "./reports", filename: str = ""):
        """
        Parameters
        ----------
        output_dir : str
            Directory where the report file will be written.
        filename : str, optional
            Base filename without extension. If provided, used as the report
            filename. If blank, _make_filename() generates one automatically
            from hostname, profile name, and timestamp.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._filename = filename

    @abstractmethod
    def generate(self, scan_result: HostScanResult) -> str:
        """
        Generates a report from the scan result.

        Args:
            scan_result: A HostScanResult containing all check evidence.

        Returns:
            The absolute path to the generated report file.
        """
        pass

    def _make_filename(self, scan_result: HostScanResult, extension: str) -> Path:
        """
        Constructs the report file path.

        If a filename was provided to __init__, uses that (plus the extension).
        Otherwise generates one automatically from hostname, profile, and timestamp.

        Format (auto): <hostname>_<profile>_<timestamp>.<ext>
        Example (auto): WEBSERVER01_NIST_800_53_20260218_143201.html
        Example (label): production_web_server_nist_800_53.html
        """
        if self._filename:
            return self.output_dir / f"{self._filename}.{extension}"

        timestamp = (
            scan_result.scan_start_utc.replace(":", "")
            .replace("-", "")
            .replace("T", "_")
            .replace("Z", "")
        )
        hostname = scan_result.hostname.replace(".", "_").upper()
        profile = scan_result.profile_name.replace(" ", "_").replace("/", "_")
        filename = f"{hostname}_{profile}_{timestamp}.{extension}"
        return self.output_dir / filename
