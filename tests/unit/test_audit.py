from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac as std_hmac
import json
import sys
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import get_args
from unittest.mock import MagicMock

import pytest
from pytest_httpx import HTTPXMock

from pwned.audit import (
    AuditEntry,
    AuditFinding,
    AuditSummary,
    ExportSource,
    ReuseGroup,
    async_audit_entries,
    audit_entries,
    load_export,
    parse_1password_1pux,
    parse_1password_csv,
    parse_apple_csv,
    parse_bitwarden_csv,
    parse_bitwarden_encrypted_json,
    parse_bitwarden_json,
    parse_chrome_csv,
    parse_firefox_csv,
    parse_generic_csv,
    parse_keepass,
)
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient


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
        assert summary.reused_groups == []

    def test_reuse_group_fields_and_no_password_field(self) -> None:
        group = ReuseGroup(entries=["GitHub (alice)", "GitLab (alice)"], count=2, pwn_count=42)
        assert group.entries == ["GitHub (alice)", "GitLab (alice)"]
        assert group.count == 2
        assert group.pwn_count == 42
        assert "password" not in ReuseGroup.model_fields
        assert ReuseGroup(entries=["A", "B"], count=2).pwn_count == 0

    def test_export_source_literal_values(self) -> None:
        assert set(get_args(ExportSource)) == {
            "bitwarden-json",
            "bitwarden-encrypted-json",
            "bitwarden-csv",
            "1password-csv",
            "1password-1pux",
            "chrome-csv",
            "firefox-csv",
            "apple-csv",
            "csv",
            "keepass",
        }


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


def _xor_keystream(key: bytes, iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    for block_idx, offset in enumerate(range(0, len(data), 16)):
        block = data[offset : offset + 16]
        pad_stream = hashlib.sha256(key + iv + block_idx.to_bytes(4, "big")).digest()[:16]
        out.extend(a ^ b for a, b in zip(block, pad_stream, strict=False))
    return bytes(out)


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes.")
    return data[:-pad_len]


def _install_fake_cryptography(
    monkeypatch: pytest.MonkeyPatch,
    *,
    force_bad_padding: bool = False,
) -> None:
    class _FakeSHA256:
        pass

    class _FakePBKDF2HMAC:
        def __init__(
            self,
            *,
            algorithm: object,
            length: int,
            salt: bytes,
            iterations: int,
        ) -> None:
            self._length = length
            self._salt = salt
            self._iterations = iterations

        def derive(self, key_material: bytes) -> bytes:
            return hashlib.pbkdf2_hmac(
                "sha256",
                key_material,
                self._salt,
                self._iterations,
                dklen=self._length,
            )

    class _FakeHKDFExpand:
        def __init__(self, *, algorithm: object, length: int, info: bytes) -> None:
            self._length = length
            self._info = info

        def derive(self, key_material: bytes) -> bytes:
            okm = b""
            prev = b""
            counter = 1
            while len(okm) < self._length:
                prev = std_hmac.new(
                    key_material,
                    prev + self._info + bytes([counter]),
                    hashlib.sha256,
                ).digest()
                okm += prev
                counter += 1
            return okm[: self._length]

    class _FakeHMAC:
        def __init__(self, key: bytes, algorithm: object) -> None:
            self._hmac = std_hmac.new(key, digestmod=hashlib.sha256)

        def update(self, data: bytes) -> None:
            self._hmac.update(data)

        def verify(self, signature: bytes) -> None:
            if not std_hmac.compare_digest(self._hmac.digest(), signature):
                raise ValueError("Signature did not match digest.")

    class _FakeAES:
        def __init__(self, key: bytes) -> None:
            self.key = key

    class _FakeCBC:
        def __init__(self, iv: bytes) -> None:
            self.iv = iv

    class _FakeDecryptor:
        def __init__(self, key: bytes, iv: bytes) -> None:
            self._key = key
            self._iv = iv
            self._buf = bytearray()

        def update(self, data: bytes) -> bytes:
            self._buf.extend(data)
            return b""

        def finalize(self) -> bytes:
            return _xor_keystream(self._key, self._iv, bytes(self._buf))

    class _FakeCipher:
        def __init__(self, algorithm: _FakeAES, mode: _FakeCBC) -> None:
            self._algorithm = algorithm
            self._mode = mode

        def decryptor(self) -> _FakeDecryptor:
            return _FakeDecryptor(self._algorithm.key, self._mode.iv)

    class _FakeUnpadder:
        def __init__(self, block_size: int) -> None:
            self._block_size = block_size
            self._buf = bytearray()

        def update(self, data: bytes) -> bytes:
            self._buf.extend(data)
            return b""

        def finalize(self) -> bytes:
            if force_bad_padding:
                raise ValueError("Invalid padding bytes.")
            return _pkcs7_unpad(bytes(self._buf), self._block_size)

    class _FakePKCS7:
        def __init__(self, size: int) -> None:
            self._block_size = size // 8

        def unpadder(self) -> _FakeUnpadder:
            return _FakeUnpadder(self._block_size)

    def _mod(name: str, **attrs: object) -> ModuleType:
        mod = ModuleType(name)
        for key, value in attrs.items():
            setattr(mod, key, value)
        return mod

    hashes_mod = _mod("cryptography.hazmat.primitives.hashes", SHA256=_FakeSHA256)
    hmac_mod = _mod("cryptography.hazmat.primitives.hmac", HMAC=_FakeHMAC)
    pbkdf2_mod = _mod(
        "cryptography.hazmat.primitives.kdf.pbkdf2",
        PBKDF2HMAC=_FakePBKDF2HMAC,
    )
    hkdf_mod = _mod(
        "cryptography.hazmat.primitives.kdf.hkdf",
        HKDFExpand=_FakeHKDFExpand,
    )
    kdf_mod = _mod(
        "cryptography.hazmat.primitives.kdf",
        pbkdf2=pbkdf2_mod,
        hkdf=hkdf_mod,
    )
    alg_mod = _mod("cryptography.hazmat.primitives.ciphers.algorithms", AES=_FakeAES)
    modes_mod = _mod("cryptography.hazmat.primitives.ciphers.modes", CBC=_FakeCBC)
    ciphers_mod = _mod(
        "cryptography.hazmat.primitives.ciphers",
        Cipher=_FakeCipher,
        algorithms=alg_mod,
        modes=modes_mod,
    )
    padding_mod = _mod("cryptography.hazmat.primitives.padding", PKCS7=_FakePKCS7)
    primitives_mod = _mod(
        "cryptography.hazmat.primitives",
        hashes=hashes_mod,
        hmac=hmac_mod,
        kdf=kdf_mod,
        ciphers=ciphers_mod,
        padding=padding_mod,
    )
    hazmat_mod = _mod("cryptography.hazmat", primitives=primitives_mod)
    root_mod = _mod("cryptography", hazmat=hazmat_mod)

    modules = {
        "cryptography": root_mod,
        "cryptography.hazmat": hazmat_mod,
        "cryptography.hazmat.primitives": primitives_mod,
        "cryptography.hazmat.primitives.hashes": hashes_mod,
        "cryptography.hazmat.primitives.hmac": hmac_mod,
        "cryptography.hazmat.primitives.kdf": kdf_mod,
        "cryptography.hazmat.primitives.kdf.pbkdf2": pbkdf2_mod,
        "cryptography.hazmat.primitives.kdf.hkdf": hkdf_mod,
        "cryptography.hazmat.primitives.ciphers": ciphers_mod,
        "cryptography.hazmat.primitives.ciphers.algorithms": alg_mod,
        "cryptography.hazmat.primitives.ciphers.modes": modes_mod,
        "cryptography.hazmat.primitives.padding": padding_mod,
    }
    for name, mod in modules.items():
        monkeypatch.setitem(sys.modules, name, mod)


def _derive_bw_keys(master_password: str, salt: str, iterations: int) -> tuple[bytes, bytes]:
    master_key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=32,
    )
    enc_key = std_hmac.new(master_key, b"enc\x01", hashlib.sha256).digest()
    mac_key = std_hmac.new(master_key, b"mac\x01", hashlib.sha256).digest()
    return enc_key, mac_key


def _make_bw_cipher_string(
    plaintext: bytes,
    *,
    enc_key: bytes,
    mac_key: bytes,
    iv: bytes = b"0123456789abcdef",
) -> str:
    ct = _xor_keystream(enc_key, iv, _pkcs7_pad(plaintext))
    mac = std_hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    iv_b64 = base64.b64encode(iv).decode("ascii")
    ct_b64 = base64.b64encode(ct).decode("ascii")
    mac_b64 = base64.b64encode(mac).decode("ascii")
    return f"2.{iv_b64}|{ct_b64}|{mac_b64}"


def _make_bw_encrypted_payload(
    vault_obj: object,
    *,
    master_password: str | None = None,
    salt: str = "alice@example.com",
    iterations: int = 100,
) -> dict[str, object]:
    resolved = "correct-horse" if master_password is None else master_password
    enc_key, mac_key = _derive_bw_keys(resolved, salt, iterations)
    validation = _make_bw_cipher_string(b"validation-uuid", enc_key=enc_key, mac_key=mac_key)
    data = _make_bw_cipher_string(
        json.dumps(vault_obj).encode("utf-8"),
        enc_key=enc_key,
        mac_key=mac_key,
        iv=b"fedcba9876543210",
    )
    return {
        "encrypted": True,
        "passwordProtected": True,
        "kdfType": 0,
        "salt": salt,
        "kdfIterations": iterations,
        "encKeyValidation_DO_NOT_EDIT": validation,
        "data": data,
    }


class TestParse1PasswordCsv:
    def test_valid_csv_case_insensitive_and_url_fallback(self, tmp_path: Path) -> None:
        export_file = tmp_path / "1p.csv"
        export_file.write_text(
            "title,url,username,password\n"
            "GitHub,https://github.com,alice,pw1\n"
            ",https://gitlab.com,bob,pw2\n"
            ",,,pw3\n"
            "Empty,https://example.com,carol,\n",
            encoding="utf-8",
        )

        entries = parse_1password_csv(export_file)
        assert entries == [
            AuditEntry(name="GitHub", username="alice", password="pw1"),
            AuditEntry(name="https://gitlab.com", username="bob", password="pw2"),
            AuditEntry(name="", username="", password="pw3"),
        ]

    def test_missing_password_column_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "1p_missing.csv"
        export_file.write_text("Title,Url,Username\nGitHub,https://github.com,alice\n")

        with pytest.raises(ValueError, match="Password"):
            parse_1password_csv(export_file)

    def test_empty_file_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "empty.csv"
        export_file.write_text("", encoding="utf-8")

        with pytest.raises(ValueError, match="Password"):
            parse_1password_csv(export_file)


class TestParse1Password1Pux:
    def test_valid_1pux(self, tmp_path: Path) -> None:
        pux_file = tmp_path / "export.1pux"
        payload = {
            "accounts": [
                {
                    "vaults": [
                        {
                            "items": [
                                {
                                    "overview": {"title": "GitHub"},
                                    "details": {
                                        "loginFields": [
                                            {"designation": "username", "value": "alice"},
                                            {"designation": "password", "value": "pw1"},
                                        ]
                                    },
                                },
                                {
                                    "overview": {},
                                    "details": {
                                        "loginFields": [
                                            "not-a-dict",
                                            {"designation": "username", "value": None},
                                            {"designation": "other", "value": "ignored"},
                                            {"designation": "password", "value": "pw2"},
                                            {"designation": "password", "value": "ignored-dup"},
                                        ]
                                    },
                                },
                                {
                                    "overview": {"title": "Note"},
                                    "details": {"notesPlain": "hello"},
                                },
                                {
                                    "overview": {"title": "EmptyPw"},
                                    "details": {
                                        "loginFields": [
                                            {"designation": "username", "value": "bob"},
                                            {"designation": "password", "value": ""},
                                        ]
                                    },
                                },
                                {
                                    "overview": {"title": "NoDetails"},
                                    "details": "bad",
                                },
                                "not-a-dict",
                            ]
                        }
                    ]
                }
            ]
        }
        with zipfile.ZipFile(pux_file, "w") as zf:
            zf.writestr("export.data", json.dumps(payload))

        entries = parse_1password_1pux(pux_file)
        assert entries == [
            AuditEntry(name="GitHub", username="alice", password="pw1"),
            AuditEntry(name="", username="", password="pw2"),
        ]

    def test_bad_zip_raises_value_error(self, tmp_path: Path) -> None:
        bad_zip = tmp_path / "bad.1pux"
        bad_zip.write_bytes(b"not a zip")

        with pytest.raises(ValueError, match="ZIP"):
            parse_1password_1pux(bad_zip)

    def test_missing_export_data_raises_value_error(self, tmp_path: Path) -> None:
        pux_file = tmp_path / "no_data.1pux"
        with zipfile.ZipFile(pux_file, "w") as zf:
            zf.writestr("other.txt", "hi")

        with pytest.raises(ValueError, match="export.data"):
            parse_1password_1pux(pux_file)

    @pytest.mark.parametrize("raw_bytes", [b"\xff\xfe", b"{bad json"])
    def test_invalid_utf8_or_json_raises_value_error(
        self, tmp_path: Path, raw_bytes: bytes
    ) -> None:
        pux_file = tmp_path / "bad_json.1pux"
        with zipfile.ZipFile(pux_file, "w") as zf:
            zf.writestr("export.data", raw_bytes)

        with pytest.raises(ValueError, match="1PUX"):
            parse_1password_1pux(pux_file)

    @pytest.mark.parametrize(
        "payload",
        [
            [],
            {},
            {"accounts": "not-a-list"},
            {"accounts": ["not-a-dict"]},
            {"accounts": [{"vaults": "not-a-list"}]},
            {"accounts": [{"vaults": ["not-a-dict"]}]},
            {"accounts": [{"vaults": [{"items": "not-a-list"}]}]},
        ],
    )
    def test_malformed_structure_raises_value_error(self, tmp_path: Path, payload: object) -> None:
        pux_file = tmp_path / "malformed.1pux"
        with zipfile.ZipFile(pux_file, "w") as zf:
            zf.writestr("export.data", json.dumps(payload))

        with pytest.raises(ValueError, match="1PUX"):
            parse_1password_1pux(pux_file)


class TestParseBrowserAndAppleCsv:
    def test_chrome_csv_with_name_and_fallback(self, tmp_path: Path) -> None:
        export_file = tmp_path / "chrome.csv"
        export_file.write_text(
            "name,url,username,password\n"
            "GitHub,https://github.com,alice,pw1\n"
            ",https://gitlab.com,bob,pw2\n"
            "Empty,https://example.com,carol,\n",
            encoding="utf-8",
        )
        assert parse_chrome_csv(export_file) == [
            AuditEntry(name="GitHub", username="alice", password="pw1"),
            AuditEntry(name="https://gitlab.com", username="bob", password="pw2"),
        ]

    def test_chrome_csv_without_name_column(self, tmp_path: Path) -> None:
        export_file = tmp_path / "chrome_no_name.csv"
        export_file.write_text(
            "url,username,password\nhttps://github.com,alice,pw1\n",
            encoding="utf-8",
        )
        assert parse_chrome_csv(export_file) == [
            AuditEntry(name="https://github.com", username="alice", password="pw1"),
        ]

    def test_chrome_csv_missing_password_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "chrome_bad.csv"
        export_file.write_text("name,url,username\nGitHub,https://github.com,alice\n")
        with pytest.raises(ValueError, match="password"):
            parse_chrome_csv(export_file)

    def test_firefox_csv(self, tmp_path: Path) -> None:
        export_file = tmp_path / "firefox.csv"
        export_file.write_text(
            "url,username,password,httpRealm,formActionOrigin,guid\n"
            "https://github.com,alice,pw1,,,g1\n"
            "https://empty.com,bob,,,,g2\n",
            encoding="utf-8",
        )
        assert parse_firefox_csv(export_file) == [
            AuditEntry(name="https://github.com", username="alice", password="pw1"),
        ]

    def test_firefox_csv_missing_password_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "firefox_bad.csv"
        export_file.write_text("url,username\nhttps://github.com,alice\n")
        with pytest.raises(ValueError, match="password"):
            parse_firefox_csv(export_file)

    def test_apple_csv_with_title_and_url_fallback(self, tmp_path: Path) -> None:
        export_file = tmp_path / "apple.csv"
        export_file.write_text(
            "Title,URL,Username,Password,Notes,OTPAuth\n"
            "GitHub,https://github.com,alice,pw1,,\n"
            ",https://icloud.com,bob,pw2,,\n"
            "Blank,https://example.com,carol,,,\n",
            encoding="utf-8",
        )
        assert parse_apple_csv(export_file) == [
            AuditEntry(name="GitHub", username="alice", password="pw1"),
            AuditEntry(name="https://icloud.com", username="bob", password="pw2"),
        ]

    def test_apple_csv_missing_password_raises_value_error(self, tmp_path: Path) -> None:
        export_file = tmp_path / "apple_bad.csv"
        export_file.write_text("Title,URL,Username\nGitHub,https://github.com,alice\n")
        with pytest.raises(ValueError, match="Password"):
            parse_apple_csv(export_file)


class TestParseBitwardenEncryptedJson:
    def test_missing_cryptography_raises_runtime_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "cryptography", None)
        export_file = tmp_path / "bw_enc.json"
        export_file.write_text("{}", encoding="utf-8")

        with pytest.raises(RuntimeError, match=r"uv pip install 'pwned\[crypto\]'"):
            parse_bitwarden_encrypted_json(export_file, master_password="pw")

    def test_valid_encrypted_json_decrypts_and_parses_items(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        payload = _make_bw_encrypted_payload(
            {
                "items": [
                    {"name": "GitHub", "login": {"username": "alice", "password": "pw1"}},
                    {"name": "Note", "login": None},
                    {"name": "Empty", "login": {"username": "bob", "password": ""}},
                ]
            },
            master_password="secret-password",
        )
        export_file = tmp_path / "bw_enc.json"
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        entries = parse_bitwarden_encrypted_json(export_file, master_password="secret-password")
        assert entries == [AuditEntry(name="GitHub", username="alice", password="pw1")]

    def test_invalid_json_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        export_file = tmp_path / "bad.json"
        export_file.write_text("{invalid", encoding="utf-8")

        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_bitwarden_encrypted_json(export_file, master_password="pw")

    @pytest.mark.parametrize(
        "mutator",
        [
            lambda d: [],
            lambda d: {**d, "encrypted": False},
            lambda d: {**d, "passwordProtected": False},
            lambda d: {**d, "kdfType": 1},
            lambda d: {**d, "kdfType": False},
            lambda d: {**d, "salt": ""},
            lambda d: {**d, "kdfIterations": 0},
            lambda d: {**d, "kdfIterations": True},
            lambda d: {**d, "encKeyValidation_DO_NOT_EDIT": ""},
            lambda d: {**d, "data": ""},
        ],
    )
    def test_invalid_metadata_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutator: object
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        base = _make_bw_encrypted_payload({"items": []})
        mutated = mutator(base)  # type: ignore[operator]
        export_file = tmp_path / "invalid_meta.json"
        export_file.write_text(json.dumps(mutated), encoding="utf-8")

        with pytest.raises(ValueError):
            parse_bitwarden_encrypted_json(export_file, master_password="correct-horse")

    @pytest.mark.parametrize(
        "bad_cipher",
        [
            "no-dot",
            "0.AAAA|BBBB|CCCC",
            "2.only|two",
            "2.not!base64|BBBB|CCCC",
            "2.||",
        ],
    )
    def test_malformed_cipher_string_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_cipher: str
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        payload = _make_bw_encrypted_payload({"items": []})
        payload["encKeyValidation_DO_NOT_EDIT"] = bad_cipher
        export_file = tmp_path / "bad_cipher.json"
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError):
            parse_bitwarden_encrypted_json(export_file, master_password="correct-horse")

    def test_wrong_master_password_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        payload = _make_bw_encrypted_payload({"items": []}, master_password="right-password")
        export_file = tmp_path / "wrong_pw.json"
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError, match="password|MAC|corrupt"):
            parse_bitwarden_encrypted_json(export_file, master_password="wrong-password")

    def test_tampered_data_mac_mismatch_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        payload = _make_bw_encrypted_payload({"items": []})
        iv_b64, ct_b64, mac_b64 = str(payload["data"]).removeprefix("2.").split("|")
        tampered_mac = base64.b64encode(b"\x00" * 32).decode("ascii")
        assert tampered_mac != mac_b64
        payload["data"] = f"2.{iv_b64}|{ct_b64}|{tampered_mac}"
        export_file = tmp_path / "tampered.json"
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError):
            parse_bitwarden_encrypted_json(export_file, master_password="correct-horse")

    def test_bad_padding_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch, force_bad_padding=True)
        payload = _make_bw_encrypted_payload({"items": []})
        export_file = tmp_path / "bad_pad.json"
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError):
            parse_bitwarden_encrypted_json(export_file, master_password="correct-horse")

    def test_invalid_decrypted_json_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        enc_key, mac_key = _derive_bw_keys("correct-horse", "alice@example.com", 100)
        payload = {
            "encrypted": True,
            "passwordProtected": True,
            "kdfType": 0,
            "salt": "alice@example.com",
            "kdfIterations": 100,
            "encKeyValidation_DO_NOT_EDIT": _make_bw_cipher_string(
                b"ok", enc_key=enc_key, mac_key=mac_key
            ),
            "data": _make_bw_cipher_string(
                b"{not-json", enc_key=enc_key, mac_key=mac_key, iv=b"fedcba9876543210"
            ),
        }
        export_file = tmp_path / "bad_inner.json"
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_bitwarden_encrypted_json(export_file, master_password="correct-horse")


class TestLoadExportNewSources:
    def test_dispatches_1password_csv(self, tmp_path: Path) -> None:
        p = tmp_path / "1p.csv"
        p.write_text("Title,Url,Username,Password\nSite,https://s.test,u,p\n", encoding="utf-8")
        assert load_export(p, source="1password-csv") == [
            AuditEntry(name="Site", username="u", password="p")
        ]

    def test_dispatches_1password_1pux(self, tmp_path: Path) -> None:
        p = tmp_path / "1p.1pux"
        payload = {
            "accounts": [
                {
                    "vaults": [
                        {
                            "items": [
                                {
                                    "overview": {"title": "Site"},
                                    "details": {
                                        "loginFields": [
                                            {"designation": "username", "value": "u"},
                                            {"designation": "password", "value": "p"},
                                        ]
                                    },
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("export.data", json.dumps(payload))
        assert load_export(p, source="1password-1pux") == [
            AuditEntry(name="Site", username="u", password="p")
        ]

    def test_dispatches_chrome_csv(self, tmp_path: Path) -> None:
        p = tmp_path / "chrome.csv"
        p.write_text("name,url,username,password\nSite,https://s.test,u,p\n", encoding="utf-8")
        assert load_export(p, source="chrome-csv") == [
            AuditEntry(name="Site", username="u", password="p")
        ]

    def test_dispatches_firefox_csv(self, tmp_path: Path) -> None:
        p = tmp_path / "firefox.csv"
        p.write_text("url,username,password\nhttps://s.test,u,p\n", encoding="utf-8")
        assert load_export(p, source="firefox-csv") == [
            AuditEntry(name="https://s.test", username="u", password="p")
        ]

    def test_dispatches_apple_csv(self, tmp_path: Path) -> None:
        p = tmp_path / "apple.csv"
        p.write_text("Title,URL,Username,Password\nSite,https://s.test,u,p\n", encoding="utf-8")
        assert load_export(p, source="apple-csv") == [
            AuditEntry(name="Site", username="u", password="p")
        ]

    def test_dispatches_bitwarden_encrypted_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        p = tmp_path / "bw_enc.json"
        payload = _make_bw_encrypted_payload(
            {"items": [{"name": "Site", "login": {"username": "u", "password": "p"}}]},
            master_password="pw",
        )
        p.write_text(json.dumps(payload), encoding="utf-8")
        assert load_export(p, source="bitwarden-encrypted-json", master_password="pw") == [
            AuditEntry(name="Site", username="u", password="p")
        ]

    def test_bitwarden_encrypted_json_without_master_password_raises_value_error(
        self, tmp_path: Path
    ) -> None:
        p = tmp_path / "bw_enc.json"
        p.write_text("{}", encoding="utf-8")
        with pytest.raises(ValueError, match="master_password"):
            load_export(p, source="bitwarden-encrypted-json", master_password=None)


class TestPasswordReuseAndProtocol:
    def test_audit_entries_accepts_password_checker_protocol(self) -> None:
        class _OfflineChecker:
            def check_password(
                self, password: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                return {"leaked": 7}.get(password, 0)

            def check_hash(self, hash_hex: str, *, ntlm: bool = False, pad: bool = False) -> int:
                return 0

        entries = [
            AuditEntry(name="SiteA", username="u1", password="leaked"),
            AuditEntry(name="SiteB", username="u2", password="safe"),
        ]
        summary = audit_entries(entries, _OfflineChecker())
        assert summary.findings == [AuditFinding(name="SiteA", username="u1", pwn_count=7)]

    def test_check_reuse_groups_labels_and_sorting(self) -> None:
        entries = [
            AuditEntry(name="Beta", username="b", password="pw_count2_pwn0"),
            AuditEntry(name="Alpha", username="a", password="pw_count2_pwn0"),
            AuditEntry(name="Gamma", username="", password="pw_count2_pwn50"),
            AuditEntry(name="", username="delta", password="pw_count2_pwn50"),
            AuditEntry(name="", username="", password="pw_count3_pwn10"),
            AuditEntry(name="One", username="u1", password="pw_count3_pwn10"),
            AuditEntry(name="Two", username="u2", password="pw_count3_pwn10"),
            AuditEntry(name="Unique", username="u3", password="unique_pw"),
        ]
        counts = {
            "pw_count2_pwn0": 0,
            "pw_count2_pwn50": 50,
            "pw_count3_pwn10": 10,
            "unique_pw": 0,
        }
        client = MagicMock(spec=PwnedPasswordsClient)
        client.check_password.side_effect = lambda pw, **_: counts[pw]

        summary = audit_entries(entries, client, check_reuse=True)

        assert summary.reused_groups == [
            ReuseGroup(
                entries=["<unnamed>", "One (u1)", "Two (u2)"],
                count=3,
                pwn_count=10,
            ),
            ReuseGroup(
                entries=["Gamma", "delta"],
                count=2,
                pwn_count=50,
            ),
            ReuseGroup(
                entries=["Beta (b)", "Alpha (a)"],
                count=2,
                pwn_count=0,
            ),
        ]
        serialized = summary.model_dump_json()
        for pw in counts:
            assert pw not in serialized

    def test_check_reuse_tiebreaker_by_entries(self) -> None:
        entries = [
            AuditEntry(name="Zebra", username="", password="pw1"),
            AuditEntry(name="Yak", username="", password="pw1"),
            AuditEntry(name="Apple", username="", password="pw2"),
            AuditEntry(name="Banana", username="", password="pw2"),
        ]
        client = MagicMock(spec=PwnedPasswordsClient)
        client.check_password.return_value = 0

        summary = audit_entries(entries, client, check_reuse=True)
        assert [g.entries for g in summary.reused_groups] == [
            ["Apple", "Banana"],
            ["Zebra", "Yak"],
        ]


class TestAsyncAuditEntries:
    def test_invalid_threshold_raises_value_error(self) -> None:
        client = MagicMock(spec=AsyncPwnedPasswordsClient)

        async def _run() -> None:
            with pytest.raises(ValueError, match="threshold"):
                await async_audit_entries([], client, threshold=0)

        asyncio.run(_run())

    def test_invalid_concurrency_raises_value_error(self) -> None:
        client = MagicMock(spec=AsyncPwnedPasswordsClient)

        async def _run() -> None:
            with pytest.raises(ValueError, match="concurrency"):
                await async_audit_entries([], client, concurrency=0)

        asyncio.run(_run())

    def test_empty_entries(self) -> None:
        client = MagicMock(spec=AsyncPwnedPasswordsClient)

        async def _run() -> None:
            summary = await async_audit_entries([], client)
            assert summary == AuditSummary(
                total_entries=0,
                unique_passwords=0,
                compromised_entries=0,
                findings=[],
                reused_groups=[],
            )

        asyncio.run(_run())

    def test_dedup_threshold_reuse_matches_sync(self) -> None:
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

        class _FakeAsyncClient:
            def __init__(self) -> None:
                self.calls: list[tuple[str, bool, bool]] = []

            async def check_password(
                self, password: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                self.calls.append((password, ntlm, pad))
                return counts[password]

        async_client = _FakeAsyncClient()
        sync_client = MagicMock(spec=PwnedPasswordsClient)
        sync_client.check_password.side_effect = lambda pw, **_: counts[pw]

        async def _run() -> AuditSummary:
            return await async_audit_entries(
                entries,
                async_client,  # type: ignore[arg-type]
                threshold=5,
                ntlm=True,
                pad=False,
                check_reuse=True,
                concurrency=2,
            )

        async_summary = asyncio.run(_run())
        sync_summary = audit_entries(
            entries,
            sync_client,
            threshold=5,
            ntlm=True,
            pad=False,
            check_reuse=True,
        )
        assert async_summary == sync_summary
        assert len(async_client.calls) == 4

    def test_concurrency_bounded_by_semaphore(self) -> None:
        entries = [AuditEntry(name=f"S{i}", username="u", password=f"pw{i}") for i in range(6)]
        in_flight = 0
        max_in_flight = 0

        class _BoundedAsyncClient:
            async def check_password(
                self, password: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                nonlocal in_flight, max_in_flight
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
                await asyncio.sleep(0.01)
                in_flight -= 1
                return 0

        async def _run() -> AuditSummary:
            return await async_audit_entries(
                entries,
                _BoundedAsyncClient(),  # type: ignore[arg-type]
                concurrency=2,
            )

        summary = asyncio.run(_run())
        assert summary.unique_passwords == 6
        assert max_in_flight <= 2
        assert max_in_flight == 2

    def test_with_real_async_pwned_passwords_client(self, httpx_mock: HTTPXMock) -> None:
        pw_hash = hashlib.sha1(b"password").hexdigest().upper()
        prefix, suffix = pw_hash[:5], pw_hash[5:]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:321\n",
        )
        entries = [
            AuditEntry(name="Site1", username="a", password="password"),
            AuditEntry(name="Site2", username="b", password="password"),
        ]

        async def _run() -> AuditSummary:
            async with AsyncPwnedPasswordsClient(user_agent="test-agent") as client:
                return await async_audit_entries(entries, client, check_reuse=True)

        summary = asyncio.run(_run())
        assert summary.total_entries == 2
        assert summary.unique_passwords == 1
        assert summary.compromised_entries == 2
        assert summary.reused_groups == [
            ReuseGroup(entries=["Site1 (a)", "Site2 (b)"], count=2, pwn_count=321)
        ]
