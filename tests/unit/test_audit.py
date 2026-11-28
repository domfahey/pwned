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

from pwned._parsers import _md4
from pwned.audit import (
    EMPTY_LM_HASH,
    EMPTY_NTLM_HASH,
    ADHygieneFinding,
    AuditEntry,
    AuditFinding,
    AuditSummary,
    ExportSource,
    ReuseGroup,
    StrengthFinding,
    WordlistFinding,
    _parse_pass_entry_output,
    async_audit_entries,
    audit_entries,
    load_custom_wordlist,
    load_export,
    parse_1password_1pux,
    parse_1password_csv,
    parse_apple_csv,
    parse_bitwarden_csv,
    parse_bitwarden_encrypted_json,
    parse_bitwarden_json,
    parse_chrome_csv,
    parse_dashlane_csv,
    parse_firefox_csv,
    parse_generic_csv,
    parse_gopass_store,
    parse_keepass,
    parse_lastpass_csv,
    parse_pass_store,
    parse_protonpass_csv,
    parse_pwdump,
)
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient


class TestAuditModels:
    def test_audit_entry_hides_password_in_repr(self) -> None:
        expected = "super-secret-value"
        entry = AuditEntry(name="GitHub", username="alice", password=expected)
        assert entry.name == "GitHub"
        assert entry.username == "alice"
        assert entry.password == expected
        assert entry.is_hash is False
        assert entry.hash_type is None
        assert expected not in repr(entry)

    def test_audit_entry_pre_hashed_fields(self) -> None:
        ntlm_hash = "8846F7EAEE8FB117AD06BDD830B7586C"
        entry = AuditEntry(
            name="CORP",
            username="alice",
            password=ntlm_hash,
            is_hash=True,
            hash_type="ntlm",
        )
        assert entry.is_hash is True
        assert entry.hash_type == "ntlm"
        assert ntlm_hash not in repr(entry)

    def test_audit_finding_has_no_password_field(self) -> None:
        finding = AuditFinding(name="GitHub", username="alice", pwn_count=42)
        assert finding.name == "GitHub"
        assert finding.username == "alice"
        assert finding.pwn_count == 42
        assert "password" not in AuditFinding.model_fields
        assert finding.model_dump() == {"name": "GitHub", "username": "alice", "pwn_count": 42}

    def test_strength_finding_fields_and_no_password(self) -> None:
        finding = StrengthFinding(
            name="GitHub",
            username="alice",
            score=1,
            reasons=["Shorter than 12 characters"],
        )
        assert finding.name == "GitHub"
        assert finding.username == "alice"
        assert finding.score == 1
        assert finding.reasons == ["Shorter than 12 characters"]
        assert "password" not in StrengthFinding.model_fields
        assert StrengthFinding(name="A", username="u", score=0).reasons == []

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
        assert summary.weak_entries == 0
        assert summary.strength_findings == []
        assert summary.risk_score is None
        assert summary.model_dump(exclude_unset=True) == {
            "total_entries": 3,
            "unique_passwords": 2,
            "compromised_entries": 1,
            "findings": [{"name": "GitHub", "username": "alice", "pwn_count": 10}],
        }

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
            "pwdump",
            "lastpass-csv",
            "dashlane-csv",
            "protonpass-csv",
            "pass",
            "gopass",
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

    class _FakeArgon2id:
        def __init__(
            self,
            *,
            salt: bytes,
            length: int,
            iterations: int,
            lanes: int,
            memory_cost: int,
        ) -> None:
            self._salt = salt
            self._length = length
            self._iterations = iterations
            self._lanes = lanes
            self._memory_cost = memory_cost

        def derive(self, key_material: bytes) -> bytes:
            tag = f"{self._iterations}:{self._lanes}:{self._memory_cost}".encode("ascii")
            return hashlib.pbkdf2_hmac(
                "sha256",
                key_material,
                self._salt + tag,
                1,
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
    argon2_mod = _mod(
        "cryptography.hazmat.primitives.kdf.argon2",
        Argon2id=_FakeArgon2id,
    )
    hkdf_mod = _mod(
        "cryptography.hazmat.primitives.kdf.hkdf",
        HKDFExpand=_FakeHKDFExpand,
    )
    kdf_mod = _mod(
        "cryptography.hazmat.primitives.kdf",
        pbkdf2=pbkdf2_mod,
        argon2=argon2_mod,
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
        "cryptography.hazmat.primitives.kdf.argon2": argon2_mod,
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


def _derive_bw_argon2_keys(
    master_password: str,
    salt: str,
    iterations: int,
    memory_mib: int,
    parallelism: int,
) -> tuple[bytes, bytes]:
    salt_bytes = hashlib.sha256(salt.encode("utf-8")).digest()
    tag = f"{iterations}:{parallelism}:{memory_mib * 1024}".encode("ascii")
    master_key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt_bytes + tag,
        1,
        dklen=32,
    )
    enc_key = std_hmac.new(master_key, b"enc\x01", hashlib.sha256).digest()
    mac_key = std_hmac.new(master_key, b"mac\x01", hashlib.sha256).digest()
    return enc_key, mac_key


def _make_bw_argon2_encrypted_payload(
    vault_obj: object,
    *,
    master_password: str | None = None,
    salt: str = "alice@example.com",
    iterations: int = 3,
    memory_mib: int = 64,
    parallelism: int = 4,
) -> dict[str, object]:
    resolved = "correct-horse" if master_password is None else master_password
    enc_key, mac_key = _derive_bw_argon2_keys(resolved, salt, iterations, memory_mib, parallelism)
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
        "kdfType": 1,
        "salt": salt,
        "kdfIterations": iterations,
        "kdfMemory": memory_mib,
        "kdfParallelism": parallelism,
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
            lambda d: {**d, "kdfType": 2},
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

    def test_valid_argon2id_encrypted_json_decrypts_and_parses_items(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        payload = _make_bw_argon2_encrypted_payload(
            {
                "items": [
                    {"name": "GitHub", "login": {"username": "alice", "password": "pw1"}},
                ]
            },
            master_password="argon-password",
            iterations=3,
            memory_mib=64,
            parallelism=4,
        )
        export_file = tmp_path / "bw_argon2.json"
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        entries = parse_bitwarden_encrypted_json(export_file, master_password="argon-password")
        assert entries == [AuditEntry(name="GitHub", username="alice", password="pw1")]

    @pytest.mark.parametrize(
        "mutator",
        [
            lambda d: {**d, "kdfMemory": None},
            lambda d: {**d, "kdfMemory": 0},
            lambda d: {**d, "kdfMemory": -16},
            lambda d: {**d, "kdfMemory": True},
            lambda d: {**d, "kdfMemory": "64"},
            lambda d: {**d, "kdfParallelism": None},
            lambda d: {**d, "kdfParallelism": 0},
            lambda d: {**d, "kdfParallelism": -1},
            lambda d: {**d, "kdfParallelism": True},
            lambda d: {**d, "kdfParallelism": "4"},
        ],
    )
    def test_argon2id_invalid_parameters_raise_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutator: object
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        base = _make_bw_argon2_encrypted_payload({"items": []})
        mutated = mutator(base)  # type: ignore[operator]
        export_file = tmp_path / "invalid_argon2.json"
        export_file.write_text(json.dumps(mutated), encoding="utf-8")

        with pytest.raises(ValueError, match="kdfMemory|kdfParallelism"):
            parse_bitwarden_encrypted_json(export_file, master_password="correct-horse")

    def test_argon2id_wrong_master_password_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_cryptography(monkeypatch)
        payload = _make_bw_argon2_encrypted_payload({"items": []}, master_password="right-pw")
        export_file = tmp_path / "argon2_wrong_pw.json"
        export_file.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError, match="password|corrupt"):
            parse_bitwarden_encrypted_json(export_file, master_password="wrong-pw")

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


class TestParsePwdump:
    def test_valid_pwdump_file(self, tmp_path: Path) -> None:
        dump_file = tmp_path / "hashes.txt"
        dump_file.write_text(
            "# comment\n"
            "[*] Dumping Domain Credentials\n"
            "\n"
            "CORP\\alice:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "invalid:line\n",
            encoding="utf-8",
        )
        entries = parse_pwdump(dump_file)
        assert entries == [
            AuditEntry(
                name="CORP",
                username="alice",
                password="8846F7EAEE8FB117AD06BDD830B7586C",
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="",
                username="Administrator",
                password="31D6CFE0D16AE931B73C59D7E0C089C0",
                is_hash=True,
                hash_type="ntlm",
            ),
        ]

    def test_empty_pwdump_file(self, tmp_path: Path) -> None:
        dump_file = tmp_path / "empty.txt"
        dump_file.write_text("", encoding="utf-8")
        assert parse_pwdump(dump_file) == []


class TestParseLastPassDashlaneProtonPassCsv:
    def test_lastpass_csv_valid_and_missing_col(self, tmp_path: Path) -> None:
        lp_file = tmp_path / "lastpass.csv"
        lp_file.write_text(
            "url,username,password,extra,name,grouping,fav\n"
            "https://github.com,alice,pw1,,GitHub,Dev,0\n"
            "https://gitlab.com,bob,pw2,,,Dev,0\n"
            "https://empty.test,carol,, ,Empty,Dev,0\n",
            encoding="utf-8",
        )
        assert parse_lastpass_csv(lp_file) == [
            AuditEntry(name="GitHub", username="alice", password="pw1"),
            AuditEntry(name="https://gitlab.com", username="bob", password="pw2"),
        ]

        bad_file = tmp_path / "lp_bad.csv"
        bad_file.write_text("url,username,name\nhttps://a.test,alice,A\n", encoding="utf-8")
        with pytest.raises(ValueError, match="LastPass CSV"):
            parse_lastpass_csv(bad_file)

    def test_dashlane_csv_valid_and_missing_col(self, tmp_path: Path) -> None:
        dl_file = tmp_path / "dashlane.csv"
        dl_file.write_text(
            "username,username2,username3,title,password,note,url,domain\n"
            "alice,,,GitHub,pw1,,https://github.com,github.com\n"
            ",bob,, ,pw2,,https://gitlab.com,gitlab.com\n"
            ",,,GitLab,pw3,,https://b.test,b.test\n",
            encoding="utf-8",
        )
        # Ensure blank title falls back to domain, then url; username falls back to login/username2
        dl_fallback = tmp_path / "dashlane_fb.csv"
        dl_fallback.write_text(
            "title,domain,url,username,login,username2,password\n"
            ",example.com,https://example.com,,bob_login,,pw1\n"
            ",,https://onlyurl.test,,,carol2,pw2\n"
            "Site,site.com,https://site.com,alice,,,pw3\n"
            "Empty,e.com,https://e.com,dave,,,\n",
            encoding="utf-8",
        )
        assert parse_dashlane_csv(dl_fallback) == [
            AuditEntry(name="example.com", username="bob_login", password="pw1"),
            AuditEntry(name="https://onlyurl.test", username="carol2", password="pw2"),
            AuditEntry(name="Site", username="alice", password="pw3"),
        ]
        assert len(parse_dashlane_csv(dl_file)) == 3

        bad_file = tmp_path / "dl_bad.csv"
        bad_file.write_text("title,username\nSite,alice\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Dashlane CSV"):
            parse_dashlane_csv(bad_file)

    def test_protonpass_csv_valid_and_missing_col(self, tmp_path: Path) -> None:
        pp_file = tmp_path / "protonpass.csv"
        pp_file.write_text(
            "type,name,url,email,username,password,note\n"
            "login,GitHub,https://github.com,alice@example.com,alice,pw1,\n"
            "login,,https://proton.me,bob@proton.me,,pw2,\n"
            "login,Empty,https://e.test,c@e.test,carol,,\n",
            encoding="utf-8",
        )
        assert parse_protonpass_csv(pp_file) == [
            AuditEntry(name="GitHub", username="alice", password="pw1"),
            AuditEntry(name="https://proton.me", username="bob@proton.me", password="pw2"),
        ]

        bad_file = tmp_path / "pp_bad.csv"
        bad_file.write_text("name,url,username\nSite,https://a.test,alice\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Proton Pass CSV"):
            parse_protonpass_csv(bad_file)


class TestParsePassAndGopass:
    @pytest.mark.parametrize(
        ("output", "expected"),
        [
            ("", None),
            ("\r\nusername: alice\r\n", None),
            ("s3cr3t\n", AuditEntry(name="site", username="", password="s3cr3t")),
            (
                "s3cr3t\r\nurl: https://site.test\r\nUsername: alice\r\n",
                AuditEntry(name="site", username="alice", password="s3cr3t"),
            ),
            (
                "pw2\nlogin: bob\n",
                AuditEntry(name="site", username="bob", password="pw2"),
            ),
            (
                "pw3\nusername:\n  USER: carol \n",
                AuditEntry(name="site", username="carol", password="pw3"),
            ),
        ],
    )
    def test_parse_pass_entry_output(self, output: str, expected: AuditEntry | None) -> None:
        assert _parse_pass_entry_output("site", output) == expected

    def test_parse_pass_store_missing_cli_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("pwned.audit.shutil.which", lambda _: None)
        with pytest.raises(RuntimeError, match="pass"):
            parse_pass_store()

    def test_parse_pass_store_missing_dir_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("pwned.audit.shutil.which", lambda _: "/usr/bin/pass")
        missing = tmp_path / "does-not-exist"
        with pytest.raises(ValueError, match="does not exist|directory"):
            parse_pass_store(missing)

        not_a_dir = tmp_path / "file.txt"
        not_a_dir.write_text("x", encoding="utf-8")
        with pytest.raises(ValueError, match="does not exist|directory"):
            parse_pass_store(not_a_dir)

    def test_parse_pass_store_reads_sorted_entries_and_env_resolution(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = tmp_path / "store"
        (store / "work").mkdir(parents=True)
        (store / ".git").mkdir()
        (store / ".gpg-id").write_text("KEYID\n", encoding="utf-8")
        (store / ".hidden.gpg").write_bytes(b"skip")
        (store / ".git" / "ignored.gpg").write_bytes(b"skip")
        (store / "-flag.gpg").write_bytes(b"skip")
        (store / "work" / "github.gpg").write_bytes(b"gpg1")
        (store / "empty.gpg").write_bytes(b"gpg2")
        (store / "alpha.gpg").write_bytes(b"gpg3")

        calls: list[tuple[list[str], str]] = []

        def _fake_run(
            cmd: list[str],
            *,
            capture_output: bool,
            text: bool,
            check: bool,
            env: dict[str, str],
        ) -> SimpleNamespace:
            assert capture_output is True
            assert text is True
            assert check is False
            calls.append((cmd, env["PASSWORD_STORE_DIR"]))
            entry = cmd[2]
            outputs = {
                "alpha": "pw-alpha\nuser: a@example.com\n",
                "empty": "\nusername: ignored\n",
                "work/github": "pw-gh\nlogin: octocat\n",
            }
            return SimpleNamespace(returncode=0, stdout=outputs[entry], stderr="")

        monkeypatch.setattr("pwned.audit.shutil.which", lambda _: "/usr/bin/pass")
        monkeypatch.setattr("pwned.audit.subprocess.run", _fake_run)
        monkeypatch.setenv("PASSWORD_STORE_DIR", str(store))

        entries = parse_pass_store()
        assert entries == [
            AuditEntry(name="alpha", username="a@example.com", password="pw-alpha"),
            AuditEntry(name="work/github", username="octocat", password="pw-gh"),
        ]
        assert calls == [
            (["/usr/bin/pass", "show", "alpha"], str(store)),
            (["/usr/bin/pass", "show", "empty"], str(store)),
            (["/usr/bin/pass", "show", "work/github"], str(store)),
        ]

    def test_parse_pass_store_default_home_dir_and_nonzero_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        default_store = tmp_path / ".password-store"
        default_store.mkdir()
        (default_store / "a.gpg").write_bytes(b"x")
        (default_store / "b.gpg").write_bytes(b"y")

        monkeypatch.delenv("PASSWORD_STORE_DIR", raising=False)
        monkeypatch.setattr("pwned.audit.Path.home", lambda: tmp_path)
        monkeypatch.setattr("pwned.audit.shutil.which", lambda _: "/usr/bin/pass")

        monkeypatch.setattr(
            "pwned.audit.subprocess.run",
            lambda *a, **kw: SimpleNamespace(
                returncode=2,
                stdout="",
                stderr="gpg:\n decryption failed",
            ),
        )
        with pytest.raises(RuntimeError, match="gpg: decryption failed"):
            parse_pass_store()

        monkeypatch.setattr(
            "pwned.audit.subprocess.run",
            lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr=""),
        )
        with pytest.raises(RuntimeError, match="exit code 1"):
            parse_pass_store()

    def test_parse_gopass_store_missing_cli_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("pwned.audit.shutil.which", lambda _: None)
        with pytest.raises(RuntimeError, match="gopass"):
            parse_gopass_store()

    def test_parse_gopass_store_lists_and_shows_entries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[list[str], str | None]] = []

        def _fake_run(
            cmd: list[str],
            *,
            capture_output: bool,
            text: bool,
            check: bool,
            env: dict[str, str],
        ) -> SimpleNamespace:
            calls.append((cmd, env.get("PASSWORD_STORE_DIR")))
            if cmd[1] == "ls":
                return SimpleNamespace(
                    returncode=0,
                    stdout="\nwork/jira\n-bad\nempty\npersonal/mail\n",
                    stderr="",
                )
            entry = cmd[2]
            outputs = {
                "empty": "",
                "personal/mail": "mail-pw\nusername: alice@mail.test\n",
                "work/jira": "jira-pw\n",
            }
            return SimpleNamespace(returncode=0, stdout=outputs[entry], stderr="")

        monkeypatch.delenv("PASSWORD_STORE_DIR", raising=False)
        monkeypatch.setattr("pwned.audit.shutil.which", lambda _: "/usr/bin/gopass")
        monkeypatch.setattr("pwned.audit.subprocess.run", _fake_run)

        entries = parse_gopass_store(tmp_path)
        assert entries == [
            AuditEntry(name="personal/mail", username="alice@mail.test", password="mail-pw"),
            AuditEntry(name="work/jira", username="", password="jira-pw"),
        ]
        assert calls == [
            (["/usr/bin/gopass", "ls", "--flat"], str(tmp_path)),
            (["/usr/bin/gopass", "show", "empty"], str(tmp_path)),
            (["/usr/bin/gopass", "show", "personal/mail"], str(tmp_path)),
            (["/usr/bin/gopass", "show", "work/jira"], str(tmp_path)),
        ]

        calls.clear()
        assert len(parse_gopass_store(None)) == 2
        assert calls[0] == (["/usr/bin/gopass", "ls", "--flat"], None)

    def test_parse_gopass_store_nonzero_exit_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("pwned.audit.shutil.which", lambda _: "/usr/bin/gopass")

        monkeypatch.setattr(
            "pwned.audit.subprocess.run",
            lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr="store locked\n"),
        )
        with pytest.raises(RuntimeError, match="store locked"):
            parse_gopass_store()

        def _ls_ok_show_fail(cmd: list[str], **kw: object) -> SimpleNamespace:
            if cmd[1] == "ls":
                return SimpleNamespace(returncode=0, stdout="item1\n", stderr="")
            return SimpleNamespace(returncode=3, stdout="", stderr="")

        monkeypatch.setattr("pwned.audit.subprocess.run", _ls_ok_show_fail)
        with pytest.raises(RuntimeError, match="exit code 3"):
            parse_gopass_store()


class TestLoadExportWave2A:
    def test_dispatches_new_file_sources(self, tmp_path: Path) -> None:
        pwd = tmp_path / "pwdump.txt"
        pwd.write_text(
            "D\\u:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n",
            encoding="utf-8",
        )
        assert load_export(pwd, source="pwdump") == [
            AuditEntry(
                name="D",
                username="u",
                password="8846F7EAEE8FB117AD06BDD830B7586C",
                is_hash=True,
                hash_type="ntlm",
            )
        ]

        lp = tmp_path / "lp.csv"
        lp.write_text("name,username,password\nS,u,p\n", encoding="utf-8")
        assert load_export(lp, source="lastpass-csv") == [
            AuditEntry(name="S", username="u", password="p")
        ]

        dl = tmp_path / "dl.csv"
        dl.write_text("title,username,password\nS,u,p\n", encoding="utf-8")
        assert load_export(dl, source="dashlane-csv") == [
            AuditEntry(name="S", username="u", password="p")
        ]

        pp = tmp_path / "pp.csv"
        pp.write_text("name,username,password\nS,u,p\n", encoding="utf-8")
        assert load_export(pp, source="protonpass-csv") == [
            AuditEntry(name="S", username="u", password="p")
        ]

    def test_dispatches_pass_and_gopass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "pwned.audit.parse_pass_store",
            lambda p=None: [AuditEntry(name="p", username="u", password=str(p))],
        )
        monkeypatch.setattr(
            "pwned.audit.parse_gopass_store",
            lambda p=None: [AuditEntry(name="g", username="u", password=str(p))],
        )
        assert load_export(None, source="pass") == [
            AuditEntry(name="p", username="u", password="None")
        ]
        assert load_export(tmp_path, source="pass") == [
            AuditEntry(name="p", username="u", password=str(tmp_path))
        ]
        assert load_export(None, source="gopass") == [
            AuditEntry(name="g", username="u", password="None")
        ]

    @pytest.mark.parametrize(
        "source",
        ["csv", "keepass", "bitwarden-encrypted-json", "pwdump"],
    )
    def test_none_path_for_file_source_raises_value_error(self, source: ExportSource) -> None:
        with pytest.raises(ValueError, match="A file path is required"):
            load_export(None, source=source)

    def test_none_path_with_unknown_source_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unsupported export source"):
            load_export(None, source="unknown")  # type: ignore[arg-type]


class TestPreHashedAndStrengthAudit:
    @pytest.mark.parametrize("bad_score", [-1, 5, True])
    def test_invalid_min_strength_score_raises_value_error(self, bad_score: int) -> None:
        sync_client = MagicMock(spec=PwnedPasswordsClient)
        with pytest.raises(ValueError, match="min_strength_score"):
            audit_entries([], sync_client, min_strength_score=bad_score)

        async_client = MagicMock(spec=AsyncPwnedPasswordsClient)

        async def _run() -> None:
            with pytest.raises(ValueError, match="min_strength_score"):
                await async_audit_entries([], async_client, min_strength_score=bad_score)

        asyncio.run(_run())

    def test_pre_hashed_entries_sync_and_async(self) -> None:
        ntlm_shared = "8846F7EAEE8FB117AD06BDD830B7586C"
        sha1_unique = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        entries = [
            AuditEntry(
                name="CORP",
                username="alice",
                password=ntlm_shared,
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="CORP",
                username="bob",
                password=ntlm_shared,
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="Legacy",
                username="carol",
                password=sha1_unique,
                is_hash=True,
                hash_type="sha1",
            ),
            AuditEntry(name="Plain", username="dave", password="strong!UniquePassword99"),
        ]

        sync_client = MagicMock(spec=PwnedPasswordsClient)
        sync_client.check_hash.side_effect = lambda h, **kw: (
            42 if h == ntlm_shared and kw["ntlm"] else (7 if h == sha1_unique else 0)
        )
        sync_client.check_password.return_value = 0

        class _FakeAsyncClient:
            def __init__(self) -> None:
                self.hash_calls: list[tuple[str, bool, bool]] = []
                self.pw_calls: list[tuple[str, bool, bool]] = []

            async def check_hash(
                self, hash_hex: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                self.hash_calls.append((hash_hex, ntlm, pad))
                if hash_hex == ntlm_shared and ntlm:
                    return 42
                return 7 if hash_hex == sha1_unique else 0

            async def check_password(
                self, password: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                self.pw_calls.append((password, ntlm, pad))
                return 0

        async_client = _FakeAsyncClient()

        sync_summary = audit_entries(
            entries,
            sync_client,
            ntlm=False,
            pad=False,
            check_reuse=True,
            check_strength=True,
        )

        async def _run() -> AuditSummary:
            return await async_audit_entries(
                entries,
                async_client,  # type: ignore[arg-type]
                ntlm=False,
                pad=False,
                check_reuse=True,
                check_strength=True,
            )

        async_summary = asyncio.run(_run())

        assert sync_summary == async_summary
        assert sync_client.check_hash.call_count == 2
        sync_client.check_hash.assert_any_call(ntlm_shared, ntlm=True, pad=False)
        sync_client.check_hash.assert_any_call(sha1_unique, ntlm=False, pad=False)
        sync_client.check_password.assert_called_once_with(
            "strong!UniquePassword99", ntlm=False, pad=False
        )
        assert sync_summary.unique_passwords == 3
        assert sync_summary.compromised_entries == 3
        assert sync_summary.reused_groups == [
            ReuseGroup(
                entries=["CORP (alice)", "CORP (bob)"],
                count=2,
                pwn_count=42,
            )
        ]
        # Pre-hashed entries are skipped for strength evaluation; Plain is strong (score >= 3)
        assert sync_summary.weak_entries == 0
        assert sync_summary.strength_findings == []
        assert sync_summary.risk_score is not None

    def test_strength_and_risk_score_and_exclude_unset(self) -> None:
        entries = [
            AuditEntry(name="Zebra", username="alice", password="password"),
            AuditEntry(name="Alpha", username="bob", password="12345"),
            AuditEntry(name="Strong", username="carol", password="X9!kLm#7Qp$2Zv@8Rw"),
        ]
        sync_client = MagicMock(spec=PwnedPasswordsClient)
        sync_client.check_password.side_effect = lambda pw, **_: 10 if pw == "12345" else 0

        # Without check_strength / check_reuse: optional fields stay unset
        plain_summary = audit_entries(entries, sync_client)
        plain_dumped = plain_summary.model_dump(exclude_unset=True)
        assert "reused_groups" not in plain_dumped
        assert "weak_entries" not in plain_dumped
        assert "strength_findings" not in plain_dumped
        assert "risk_score" not in plain_dumped

        # With check_strength=True and check_reuse=False
        strength_summary = audit_entries(
            entries,
            sync_client,
            check_strength=True,
            min_strength_score=2,
        )
        strength_dumped = strength_summary.model_dump(exclude_unset=True)
        assert "reused_groups" not in strength_dumped
        assert "weak_entries" in strength_dumped
        assert "strength_findings" in strength_dumped
        assert "risk_score" in strength_dumped
        assert strength_summary.weak_entries == 2
        assert [(f.score, f.name) for f in strength_summary.strength_findings] == sorted(
            [(f.score, f.name) for f in strength_summary.strength_findings]
        )
        assert strength_summary.risk_score == 30  # round((1/3)*60 + 0 + (2/3)*15) = 30

        # With check_strength=True and check_reuse=True on reused weak passwords
        reused_entries = [
            AuditEntry(name="A", username="u1", password="123"),
            AuditEntry(name="B", username="u2", password="123"),
        ]
        reused_client = MagicMock(spec=PwnedPasswordsClient)
        reused_client.check_password.return_value = 500
        both_summary = audit_entries(
            reused_entries,
            reused_client,
            check_reuse=True,
            check_strength=True,
        )
        assert both_summary.risk_score == 100
        assert "reused_groups" in both_summary.model_dump(exclude_unset=True)
        assert "risk_score" in both_summary.model_dump(exclude_unset=True)


def _ntlm_upper(password: str) -> str:
    return _md4(password.encode("utf-16-le")).upper()


def _sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


class TestADHygieneAndCustomWordlist:
    def test_parse_pwdump_lm_hash_and_exclude_machines(self, tmp_path: Path) -> None:
        dump_file = tmp_path / "ad.pwdump"
        present_lm = "e52cac67419a9a224a3b108f3fa6cb6d"
        nt_hash = _ntlm_upper("Summer2026!")
        dump_file.write_text(
            f"CORP\\alice:1001:{present_lm}:{nt_hash}:::\n"
            f"CORP\\DC01$:1002:{EMPTY_LM_HASH.lower()}:{nt_hash}:::\n"
            f"WS02$:1003:NO PASSWORD*********************:{EMPTY_NTLM_HASH.lower()}:::\n",
            encoding="utf-8",
        )

        all_entries = parse_pwdump(dump_file)
        assert all_entries == [
            AuditEntry(
                name="CORP",
                username="alice",
                password=nt_hash,
                is_hash=True,
                hash_type="ntlm",
                has_lm_hash=True,
            ),
            AuditEntry(
                name="CORP",
                username="DC01$",
                password=nt_hash,
                is_hash=True,
                hash_type="ntlm",
                has_lm_hash=False,
            ),
            AuditEntry(
                name="",
                username="WS02$",
                password=EMPTY_NTLM_HASH,
                is_hash=True,
                hash_type="ntlm",
                has_lm_hash=False,
            ),
        ]

        filtered_entries = parse_pwdump(dump_file, exclude_machines=True)
        assert filtered_entries == [all_entries[0]]

        loaded_filtered = load_export(dump_file, source="pwdump", exclude_machines=True)
        assert loaded_filtered == [all_entries[0]]

        csv_file = tmp_path / "ad.csv"
        csv_file.write_text(
            "name,username,password\nCORP,alice,pw1\nCORP,DC01$,pw2\n",
            encoding="utf-8",
        )
        assert load_export(csv_file, source="csv", exclude_machines=True) == [
            AuditEntry(name="CORP", username="alice", password="pw1"),
        ]

    def test_load_custom_wordlist_bom_comments_dedup(self, tmp_path: Path) -> None:
        wl_file = tmp_path / "banned.txt"
        wl_file.write_bytes(
            b"\xef\xbb\xbf# Corporate banned list\r\n"
            b"\r\n"
            b"  AcmeCorp2026!  \r\n"
            b"Welcome123\n"
            b"AcmeCorp2026!\n"
            b"   # indented comment\n"
            b"Summer2026\n"
        )
        assert load_custom_wordlist(wl_file) == [
            "AcmeCorp2026!",
            "Welcome123",
            "Summer2026",
        ]
        assert load_custom_wordlist(wl_file, ignore_comments=False) == [
            "# Corporate banned list",
            "AcmeCorp2026!",
            "Welcome123",
            "# indented comment",
            "Summer2026",
        ]

    def test_ad_hygiene_checks_sync_and_async(self) -> None:
        entries = [
            AuditEntry(
                name="CORP",
                username="blank_user",
                password=EMPTY_NTLM_HASH,
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="CORP",
                username="LegacyUser",
                password=_ntlm_upper("Legacyuser"),
                is_hash=True,
                hash_type="ntlm",
                has_lm_hash=True,
            ),
            AuditEntry(
                name="CORP",
                username="john.doe",
                password=_ntlm_upper("John.Doe"),
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="CORP",
                username="DC01$",
                password=_ntlm_upper("dc01"),
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="CORP",
                username="upn.user@corp.local",
                password=_sha1_upper("UPN.USER"),
                is_hash=True,
                hash_type="sha1",
            ),
            AuditEntry(
                name="Portal",
                username="PlainUser",
                password="plainuser",
            ),
            AuditEntry(
                name="NoUser",
                username="",
                password="StrongPassword99!",
            ),
            AuditEntry(
                name="CleanAD",
                username="safe_user",
                password=_ntlm_upper("TotallyUnrelatedStrong!99"),
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="DollarOnly",
                username="$",
                password=_ntlm_upper("TotallyDifferent!"),
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="AtOnly",
                username="@corp.local",
                password=_ntlm_upper("AnotherDifferent!"),
                is_hash=True,
                hash_type="ntlm",
            ),
        ]

        sync_client = MagicMock(spec=PwnedPasswordsClient)
        sync_client.check_hash.return_value = 0
        sync_client.check_password.return_value = 0

        class _FakeAsyncClient:
            async def check_hash(
                self, hash_hex: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                return 0

            async def check_password(
                self, password: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                return 0

        # Off by default -> ad_findings omitted from exclude_unset dump
        plain_summary = audit_entries(entries, sync_client)
        assert "ad_findings" not in plain_summary.model_dump(exclude_unset=True)

        sync_summary = audit_entries(entries, sync_client, check_ad_hygiene=True)
        async_summary = asyncio.run(
            async_audit_entries(
                entries,
                _FakeAsyncClient(),  # type: ignore[arg-type]
                check_ad_hygiene=True,
            )
        )
        assert sync_summary == async_summary
        assert "ad_findings" in sync_summary.model_dump(exclude_unset=True)

        expected = [
            ADHygieneFinding(
                name="CORP",
                username="blank_user",
                issue="empty_ntlm",
                detail="Account has an empty NTLM password hash.",
            ),
            ADHygieneFinding(
                name="CORP",
                username="LegacyUser",
                issue="lm_hash_present",
                detail="Legacy LM hash is stored for this account.",
            ),
            ADHygieneFinding(
                name="CORP",
                username="DC01$",
                issue="username_as_password",
                detail="Password matches account username.",
            ),
            ADHygieneFinding(
                name="CORP",
                username="LegacyUser",
                issue="username_as_password",
                detail="Password matches account username.",
            ),
            ADHygieneFinding(
                name="CORP",
                username="john.doe",
                issue="username_as_password",
                detail="Password matches account username.",
            ),
            ADHygieneFinding(
                name="CORP",
                username="upn.user@corp.local",
                issue="username_as_password",
                detail="Password matches account username.",
            ),
            ADHygieneFinding(
                name="Portal",
                username="PlainUser",
                issue="username_as_password",
                detail="Password matches account username.",
            ),
        ]
        assert sync_summary.ad_findings == expected
        dumped_json = sync_summary.model_dump_json()
        assert "plainuser" not in dumped_json
        assert "StrongPassword99!" not in dumped_json

    def test_custom_wordlist_plaintext_ntlm_sha1_sync_and_async(self) -> None:
        wordlist = ["AcmeCorp2026!", "Welcome123", ""]
        entries = [
            AuditEntry(name="PlainExact", username="u1", password="AcmeCorp2026!"),
            AuditEntry(name="PlainCI", username="u2", password="acmecorp2026!"),
            AuditEntry(name="PlainSafe", username="u3", password="UniqueSafe!99"),
            AuditEntry(
                name="NtlmExact",
                username="u4",
                password=_ntlm_upper("AcmeCorp2026!"),
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="NtlmCI",
                username="u5",
                password=_ntlm_upper("WELCOME123"),
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="NtlmSafe",
                username="u6",
                password=_ntlm_upper("NotBanned!99"),
                is_hash=True,
                hash_type="ntlm",
            ),
            AuditEntry(
                name="Sha1Exact",
                username="u7",
                password=_sha1_upper("Welcome123"),
                is_hash=True,
                hash_type="sha1",
            ),
            AuditEntry(
                name="Sha1CI",
                username="u8",
                password=_sha1_upper("welcome123"),
                is_hash=True,
                hash_type="sha1",
            ),
            AuditEntry(
                name="Sha1Safe",
                username="u9",
                password=_sha1_upper("AlsoNotBanned!99"),
                is_hash=True,
                hash_type="sha1",
            ),
        ]

        sync_client = MagicMock(spec=PwnedPasswordsClient)
        sync_client.check_hash.return_value = 0
        sync_client.check_password.return_value = 0

        class _FakeAsyncClient:
            async def check_hash(
                self, hash_hex: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                return 0

            async def check_password(
                self, password: str, *, ntlm: bool = False, pad: bool = False
            ) -> int:
                return 0

        # Without custom_wordlist -> fields stay unset
        no_wl = audit_entries(entries, sync_client)
        no_wl_dump = no_wl.model_dump(exclude_unset=True)
        assert "wordlist_matches" not in no_wl_dump
        assert "wordlist_findings" not in no_wl_dump

        # Empty custom_wordlist -> fields present with 0 / []
        empty_wl = audit_entries(entries, sync_client, custom_wordlist=[])
        empty_wl_dump = empty_wl.model_dump(exclude_unset=True)
        assert empty_wl_dump["wordlist_matches"] == 0
        assert empty_wl_dump["wordlist_findings"] == []

        # Populated custom_wordlist on empty entries -> 0 / []
        empty_entries = audit_entries([], sync_client, custom_wordlist=wordlist)
        assert empty_entries.wordlist_matches == 0
        assert empty_entries.wordlist_findings == []

        # Full sync vs async parity
        sync_summary = audit_entries(entries, sync_client, custom_wordlist=wordlist)
        async_summary = asyncio.run(
            async_audit_entries(
                entries,
                _FakeAsyncClient(),  # type: ignore[arg-type]
                custom_wordlist=wordlist,
            )
        )
        assert sync_summary == async_summary
        assert sync_summary.wordlist_matches == 6
        assert sync_summary.wordlist_findings == [
            WordlistFinding(name="NtlmCI", username="u5", match_type="case_insensitive"),
            WordlistFinding(name="NtlmExact", username="u4", match_type="exact"),
            WordlistFinding(name="PlainCI", username="u2", match_type="case_insensitive"),
            WordlistFinding(name="PlainExact", username="u1", match_type="exact"),
            WordlistFinding(name="Sha1CI", username="u8", match_type="case_insensitive"),
            WordlistFinding(name="Sha1Exact", username="u7", match_type="exact"),
        ]

        # Never leak plaintext passwords or wordlist terms into JSON output
        dumped_json = sync_summary.model_dump_json()
        assert "AcmeCorp2026!" not in dumped_json
        assert "Welcome123" not in dumped_json
        assert "acmecorp2026!" not in dumped_json

    def test_untyped_hash_entries_respect_ntlm_flag(self) -> None:
        entries = [
            AuditEntry(
                name="CORP",
                username="blank",
                password=EMPTY_NTLM_HASH,
                is_hash=True,
                hash_type=None,
            ),
            AuditEntry(
                name="CORP",
                username="jdoe",
                password=_ntlm_upper("Acme2026!"),
                is_hash=True,
                hash_type=None,
            ),
        ]
        client = MagicMock(spec=PwnedPasswordsClient)
        client.check_hash.return_value = 0

        summary = audit_entries(
            entries,
            client,
            ntlm=True,
            check_ad_hygiene=True,
            custom_wordlist=["Acme2026!"],
        )
        assert [f.issue for f in summary.ad_findings] == ["empty_ntlm"]
        assert summary.wordlist_findings == [
            WordlistFinding(name="CORP", username="jdoe", match_type="exact")
        ]
