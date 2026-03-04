import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_main(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "main.py", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_help_runs() -> None:
    result = run_main("--help")
    assert result.returncode == 0
    assert "usage: ymc" in result.stdout.lower()


def test_list_profiles_runs() -> None:
    result = run_main("--list-profiles")
    assert result.returncode == 0
    assert "available compliance profiles" in result.stdout.lower()


def test_list_configs_runs() -> None:
    result = run_main("--list-configs")
    assert result.returncode == 0
    assert "available config profiles" in result.stdout.lower()
