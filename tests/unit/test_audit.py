from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pytest_httpx import HTTPXMock

from pwned.audit import (
    AuditEntry,
    AuditFinding,
    AuditSummary,
    audit_entries,
    load_export,
    parse_bitwarden_csv,
    parse_bitwarden_json,
    parse_generic_csv,
    parse_keepass,
)
from pwned.passwords import PwnedPasswordsClient


class TestAuditModels:
    def test_audit_entry_hides_password_in_repr(self) -> None:
        expected = "super-secret-value"
        entry = AuditEntry(name="GitHub", username="alice", password=expected)
        assert entry.name == "GitHub"
        assert entry.username == "alice"
        assert entry.password == expected
        assert expected not in repr(entry)

    def test_audit_finding_has_no_password_field(self) -> None:
        finding = AuditFinding(name="GitHub", username="alice", pwn_count=42)
        assert finding.name == "GitHub"
        assert finding.username == "alice"
        assert finding.pwn_count == 42
        assert "password" not in AuditFinding.model_fields
        assert finding.model_dump() == {"name": "GitHub", "username": "alice", "pwn_count": 42}

    def test_audit_summary_fields(self) -> None:
        finding = AuditFinding(name="GitHub", username="alice", pwn_count=10)
        summary = AuditSummary(
            total_entries=3,
            unique_passwords=2,
            compromised_entries=1,
            findings=[finding],
        )
        assert summary.total_entries == 3
        assert summary.unique_passwords == 2
        assert summary.compromised_entries == 1
        assert summary.findings == [finding]


class TestParseBitwardenJson:
    def test_valid_export(self, tmp_path: Path) -> None:
        export_file = tmp_path / "bitwarden.json"
        payload = {
            "encrypted": False,
            "items": [
                {
                    "name": "GitHub",
                    "login": {"username": "alice@example.com", "password": "pw1"},
                },
                {
                    "name": None,
                    "login": {"username": None, "password": "pw2"},
                },
                {
                    "name": "Secure Note",
                    "login": None,
                },
                {
                    "name": "Empty Password",
                    "login": {"username": "bob", "password": ""},
                },
                {
                    "name": "Null Password",
                    "login": {"username": "carol", "password": None},
                },
                "not-a-dict-item",
                {
                    "name": "Bad Login Shape",
                    "login": "not-a-dict",
                },
            ],
        }
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        entries = parse_bitwarden_json(export_file)
        assert entries == [
            AuditEntry(name="GitHub", username="alice@example.com", password="pw1"),
            AuditEntry(name="", username="", password="pw2"),
        ]

    def test_invalid_json_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "bad.json"
        export_file.write_text("{not valid json", encoding="utf-8")

        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_bitwarden_json(export_file)

    def test_non_dict_root_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "list.json"
        export_file.write_text("[]", encoding="utf-8")

        with pytest.raises(ValueError, match="items"):
            parse_bitwarden_json(export_file)

    def test_missing_items_list_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "no_items.json"
        export_file.write_text('{"items": "not-a-list"}', encoding="utf-8")

        with pytest.raises(ValueError, match="items"):
            parse_bitwarden_json(export_file)


class TestParseBitwardenCsv:
    def test_valid_csv(self, tmp_path: Path) -> None:
        export_file = tmp_path / "bitwarden.csv"
        export_file.write_text(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password\n"
            ",,login,GitHub,,,,https://github.com,alice,pw1\n"
            ",,note,Note,,,,,,\n"
            ",,login,,, ,,,bob,pw2\n",
            encoding="utf-8",
        )

        entries = parse_bitwarden_csv(export_file)
        assert entries == [
            AuditEntry(name="GitHub", username="alice", password="pw1"),
            AuditEntry(name="", username="bob", password="pw2"),
        ]

    def test_missing_login_password_column_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "missing.csv"
        export_file.write_text("name,login_username\nGitHub,alice\n", encoding="utf-8")

        with pytest.raises(ValueError, match="login_password"):
            parse_bitwarden_csv(export_file)

    def test_empty_file_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "empty.csv"
        export_file.write_text("", encoding="utf-8")

        with pytest.raises(ValueError, match="login_password"):
            parse_bitwarden_csv(export_file)


class TestParseGenericCsv:
    def test_case_insensitive_headers_and_aliases(self, tmp_path: Path) -> None:
        export_file = tmp_path / "generic.csv"
        export_file.write_text(
            "Title,Email,Password\nGitHub,alice@example.com,pw1\nEmpty,,\n,bob@example.com,pw2\n",
            encoding="utf-8",
        )

        entries = parse_generic_csv(export_file)
        assert entries == [
            AuditEntry(name="GitHub", username="alice@example.com", password="pw1"),
            AuditEntry(name="", username="bob@example.com", password="pw2"),
        ]

    def test_standard_headers_and_minimal_columns(self, tmp_path: Path) -> None:
        export_file = tmp_path / "minimal.csv"
        export_file.write_text("PASSWORD\nsecret1\nsecret2\n", encoding="utf-8")

        entries = parse_generic_csv(export_file)
        assert entries == [
            AuditEntry(name="", username="", password="secret1"),
            AuditEntry(name="", username="", password="secret2"),
        ]

    def test_missing_password_column_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "no_pw.csv"
        export_file.write_text("name,username\nGitHub,alice\n", encoding="utf-8")

        with pytest.raises(ValueError, match="password"):
            parse_generic_csv(export_file)

    def test_empty_file_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "empty.csv"
        export_file.write_text("", encoding="utf-8")

        with pytest.raises(ValueError, match="password"):
            parse_generic_csv(export_file)


class TestParseKeepass:
    def test_missing_dependency_raises_runtime_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "pykeepass", None)
        kdbx = tmp_path / "vault.kdbx"
        kdbx.write_bytes(b"fake")

        with pytest.raises(
            RuntimeError,
            match=(
                r"KeePass support requires the optional 'keepass' dependency: "
                r"uv pip install 'pwned\[keepass\]'"
            ),
        ):
            parse_keepass(kdbx, master_password="master")

    def test_mocked_pykeepass(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        kdbx = tmp_path / "vault.kdbx"
        kdbx.write_bytes(b"fake")

        fake_entries = [
            SimpleNamespace(title="GitHub", username="alice", password="pw1"),
            SimpleNamespace(title=None, username=None, password="pw2"),
            SimpleNamespace(title="Empty", username="bob", password=""),
            SimpleNamespace(title="NonePw", username="carol", password=None),
        ]
        fake_kp_instance = SimpleNamespace(entries=fake_entries)
        mock_cls = MagicMock(return_value=fake_kp_instance)

        fake_module = ModuleType("pykeepass")
        fake_module.PyKeePass = mock_cls  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "pykeepass", fake_module)

        entries = parse_keepass(kdbx, master_password="master-secret")

        mock_cls.assert_called_once_with(str(kdbx), password="master-secret")
        assert entries == [
            AuditEntry(name="GitHub", username="alice", password="pw1"),
            AuditEntry(name="", username="", password="pw2"),
        ]


class TestLoadExport:
    def test_dispatches_bitwarden_json(self, tmp_path: Path) -> None:
        export_file = tmp_path / "bw.json"
        export_file.write_text(
            json.dumps({"items": [{"name": "Site", "login": {"username": "u", "password": "p"}}]}),
            encoding="utf-8",
        )
        entries = load_export(export_file, source="bitwarden-json")
        assert entries == [AuditEntry(name="Site", username="u", password="p")]

    def test_dispatches_bitwarden_csv(self, tmp_path: Path) -> None:
        export_file = tmp_path / "bw.csv"
        export_file.write_text("name,login_username,login_password\nSite,u,p\n", encoding="utf-8")
        entries = load_export(export_file, source="bitwarden-csv")
        assert entries == [AuditEntry(name="Site", username="u", password="p")]

    def test_dispatches_generic_csv(self, tmp_path: Path) -> None:
        export_file = tmp_path / "gen.csv"
        export_file.write_text("name,username,password\nSite,u,p\n", encoding="utf-8")
        entries = load_export(export_file, source="csv")
        assert entries == [AuditEntry(name="Site", username="u", password="p")]

    def test_dispatches_keepass(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        kdbx = tmp_path / "vault.kdbx"
        kdbx.write_bytes(b"fake")
        fake_module = ModuleType("pykeepass")
        fake_module.PyKeePass = MagicMock(  # type: ignore[attr-defined]
            return_value=SimpleNamespace(
                entries=[SimpleNamespace(title="KP", username="u", password="p")]
            )
        )
        monkeypatch.setitem(sys.modules, "pykeepass", fake_module)

        entries = load_export(kdbx, source="keepass", master_password="pw")
        assert entries == [AuditEntry(name="KP", username="u", password="p")]

    def test_keepass_without_master_password_raises_value_error(self, tmp_path: Path) -> None:
        kdbx = tmp_path / "vault.kdbx"
        kdbx.write_bytes(b"fake")

        with pytest.raises(ValueError, match="master_password"):
            load_export(kdbx, source="keepass", master_password=None)

    def test_unsupported_source_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "x.txt"
        export_file.write_text("", encoding="utf-8")

        with pytest.raises(ValueError, match="Unsupported export source"):
            load_export(export_file, source="unknown")  # type: ignore[arg-type]


class TestAuditEntries:
    def test_invalid_threshold_raises_value_error(self) -> None:
        client = MagicMock(spec=PwnedPasswordsClient)
        with pytest.raises(ValueError, match="threshold"):
            audit_entries([], client, threshold=0)

    def test_empty_entries(self) -> None:
        client = MagicMock(spec=PwnedPasswordsClient)
        summary = audit_entries([], client)

        assert summary == AuditSummary(
            total_entries=0,
            unique_passwords=0,
            compromised_entries=0,
            findings=[],
        )
        client.check_password.assert_not_called()

    def test_deduplication_threshold_sorting_and_no_password_leak(self) -> None:
        entries = [
            AuditEntry(name="Zeta", username="u1", password="reused-weak-password"),
            AuditEntry(name="Alpha", username="u2", password="reused-weak-password"),
            AuditEntry(name="Beta", username="u3", password="very-weak-password"),
            AuditEntry(name="Safe", username="u4", password="unique-strong-password"),
            AuditEntry(name="BelowThreshold", username="u5", password="rare-password"),
        ]
        counts = {
            "reused-weak-password": 100,
            "very-weak-password": 500,
            "unique-strong-password": 0,
            "rare-password": 4,
        }
        client = MagicMock(spec=PwnedPasswordsClient)
        client.check_password.side_effect = lambda pw, **_: counts[pw]

        summary = audit_entries(entries, client, threshold=5, ntlm=True, pad=False)

        assert client.check_password.call_count == 4
        for pw in counts:
            client.check_password.assert_any_call(pw, ntlm=True, pad=False)

        assert summary.total_entries == 5
        assert summary.unique_passwords == 4
        assert summary.compromised_entries == 3
        assert summary.findings == [
            AuditFinding(name="Beta", username="u3", pwn_count=500),
            AuditFinding(name="Alpha", username="u2", pwn_count=100),
            AuditFinding(name="Zeta", username="u1", pwn_count=100),
        ]

        serialized = summary.model_dump_json()
        for pw in counts:
            assert pw not in serialized

    def test_defaults_with_real_pwned_passwords_client(self, httpx_mock: HTTPXMock) -> None:
        import hashlib

        pw_hash = hashlib.sha1(b"password").hexdigest().upper()
        prefix, suffix = pw_hash[:5], pw_hash[5:]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:12345\n",
        )

        entries = [
            AuditEntry(name="Site1", username="a", password="password"),
            AuditEntry(name="Site2", username="b", password="password"),
        ]
        with PwnedPasswordsClient(user_agent="test-agent") as client:
            summary = audit_entries(entries, client)

        assert summary.total_entries == 2
        assert summary.unique_passwords == 1
        assert summary.compromised_entries == 2
        assert len(httpx_mock.get_requests()) == 1
        req = httpx_mock.get_requests()[0]
        assert req.headers["Add-Padding"] == "true"
