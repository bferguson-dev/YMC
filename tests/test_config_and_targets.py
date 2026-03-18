import argparse
from pathlib import Path

import pytest
import yaml

import main


def make_args(**overrides):
    defaults = {
        "config": None,
        "domain": None,
        "username": None,
        "winrm_port": None,
        "profile": None,
        "format": None,
        "output_dir": None,
        "verbose": False,
        "no_color": False,
        "no_banner": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def write_yaml(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")


def test_resolve_settings_uses_named_profile_from_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    defaults_path = tmp_path / "config" / "settings.yaml"
    user_settings_path = tmp_path / "user" / "settings.yaml"
    program_profile_dir = tmp_path / "config" / "profiles"
    user_profile_dir = tmp_path / "user" / "profiles"

    write_yaml(
        defaults_path,
        {
            "cli_defaults": {
                "config": "corp",
                "profile": "default_profile",
                "format": "html",
            },
            "connection": {"connection_timeout": 30, "read_timeout": 120},
            "evidence": {
                "inactive_account_threshold_days": 90,
                "max_lockout_attempts": 5,
                "min_security_log_size_kb": 196608,
                "min_password_length": 14,
                "max_password_age_days": 90,
            },
            "output": {
                "include_raw_evidence": True,
                "filename_timestamp_format": "%Y%m%d_%H%M%S",
            },
        },
    )
    write_yaml(user_settings_path, {})
    write_yaml(
        user_profile_dir / "corp.yaml",
        {
            "cli_defaults": {
                "domain": "corp.local",
                "username": "CORP\\svc-audit",
            }
        },
    )

    monkeypatch.setattr(main, "DEFAULT_CFG", defaults_path)
    monkeypatch.setattr(main, "USER_CFG_FILE", user_settings_path)
    monkeypatch.setattr(main, "NAMED_CFG_DIR", program_profile_dir)
    monkeypatch.setattr(main, "USER_PROFILES_DIR", user_profile_dir)

    settings = main.resolve_settings(make_args())

    assert settings["domain"] == "corp.local"
    assert settings["username"] == "CORP\\svc-audit"
    assert settings["profile"] == "default_profile"
    assert settings["winrm_port"] == 5985


def test_resolve_settings_prefers_cli_over_env_and_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    defaults_path = tmp_path / "config" / "settings.yaml"
    user_settings_path = tmp_path / "user" / "settings.yaml"
    profile_dir = tmp_path / "config" / "profiles"

    write_yaml(
        defaults_path,
        {
            "cli_defaults": {"config": "corp", "domain": "defaults.local"},
            "connection": {"connection_timeout": 30, "read_timeout": 120},
            "evidence": {
                "inactive_account_threshold_days": 90,
                "max_lockout_attempts": 5,
                "min_security_log_size_kb": 196608,
                "min_password_length": 14,
                "max_password_age_days": 90,
            },
            "output": {
                "include_raw_evidence": True,
                "filename_timestamp_format": "%Y%m%d_%H%M%S",
            },
        },
    )
    write_yaml(user_settings_path, {})
    write_yaml(profile_dir / "corp.yaml", {"cli_defaults": {"domain": "profile.local"}})

    monkeypatch.setattr(main, "DEFAULT_CFG", defaults_path)
    monkeypatch.setattr(main, "USER_CFG_FILE", user_settings_path)
    monkeypatch.setattr(main, "NAMED_CFG_DIR", profile_dir)
    monkeypatch.setattr(main, "USER_PROFILES_DIR", tmp_path / "user" / "profiles")
    monkeypatch.setenv("COLLECTOR_DOMAIN", "env.local")

    settings = main.resolve_settings(make_args(domain="cli.local"))

    assert settings["domain"] == "cli.local"


def test_load_targets_from_csv_applies_csv_domain_and_cli_username(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "hosts.csv"
    csv_path.write_text(
        "\n".join(
            [
                "# comment",
                "domain,corp.local",
                "host,username,label,port,notes",
                "web01,,Production Web,5986,primary host",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    targets = main.load_targets_from_csv(
        csv_path,
        {
            "domain": "",
            "username": "CORP\\auditor",
            "winrm_port": 5985,
        },
    )

    assert targets == [
        {
            "host_raw": "web01",
            "host": "web01.corp.local",
            "username": "CORP\\auditor",
            "label": "Production Web",
            "port": 5986,
            "notes": "primary host",
        }
    ]


def test_load_targets_from_csv_requires_host_column(tmp_path: Path) -> None:
    csv_path = tmp_path / "bad_hosts.csv"
    csv_path.write_text("name,username\nweb01,CORP\\auditor\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main.load_targets_from_csv(csv_path, {"domain": "", "username": ""})

    assert exc_info.value.code == 1
