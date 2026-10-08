import datetime
import os
import stat

import pytest

from shareit.certs import (
    CertificateError,
    describe_certificate,
    generate_self_signed,
    remove_certificate_files,
    resolve_https_files,
)
from shareit.cli import build_parser


def _pair(tmp_path):
    return str(tmp_path / "shareit.crt"), str(tmp_path / "shareit.key")


class TestSelfSignedCertificate:
    def test_generate_includes_local_names_and_protects_the_key(self, tmp_path):
        cert_path, key_path = _pair(tmp_path)
        generate_self_signed(cert_path, key_path, names=["files.local", "192.168.1.20"])
        details = describe_certificate(cert_path)
        assert details["common_name"] == "shareit"
        assert details["self_signed"]
        assert not details["expired"]
        assert "localhost" in details["dns_names"]
        assert "files.local" in details["dns_names"]
        assert "127.0.0.1" in details["ip_addresses"]
        assert "192.168.1.20" in details["ip_addresses"]
        assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600

    def test_refuses_to_replace_without_force(self, tmp_path):
        cert_path, key_path = _pair(tmp_path)
        generate_self_signed(cert_path, key_path)
        with pytest.raises(CertificateError):
            generate_self_signed(cert_path, key_path)

    def test_reuses_a_current_certificate_and_replaces_an_expired_one(self, tmp_path):
        cert_path, key_path = _pair(tmp_path)
        first = resolve_https_files(True, None, None, ["files.local"], directory=str(tmp_path))
        assert first["generated"]
        second = resolve_https_files(True, None, None, ["files.local"], directory=str(tmp_path))
        assert not second["generated"]
        assert describe_certificate(first["cert"])["fingerprint_sha256"] == describe_certificate(second["cert"])["fingerprint_sha256"]

        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)
        generate_self_signed(
            cert_path,
            key_path,
            names=["files.local"],
            force=True,
            not_before=past - datetime.timedelta(days=1),
            not_after=past,
        )
        assert describe_certificate(cert_path)["expired"]
        renewed = resolve_https_files(True, None, None, ["files.local"], directory=str(tmp_path))
        assert renewed["generated"]
        assert not describe_certificate(renewed["cert"])["expired"]

    def test_rejects_a_mismatched_key(self, tmp_path):
        first_cert, first_key = _pair(tmp_path)
        other = tmp_path / "other"
        other.mkdir()
        second_cert, second_key = _pair(other)
        generate_self_signed(first_cert, first_key)
        generate_self_signed(second_cert, second_key)
        with pytest.raises(CertificateError):
            resolve_https_files(True, first_cert, second_key, [])

    def test_remove_deletes_only_certificate_files(self, tmp_path):
        cert_path, key_path = _pair(tmp_path)
        generate_self_signed(cert_path, key_path)
        notes = tmp_path / "notes.txt"
        notes.write_text("keep")
        with pytest.raises(CertificateError):
            remove_certificate_files(str(notes), key_path)
        assert notes.read_text() == "keep"
        removed = remove_certificate_files(cert_path, key_path)
        assert set(removed) == {cert_path, key_path}
        assert not os.path.exists(cert_path)
        assert not os.path.exists(key_path)
        with pytest.raises(CertificateError):
            remove_certificate_files(str(tmp_path / "missing.crt"), str(tmp_path / "missing.key"))

    def test_parser_accepts_https_and_cert_commands(self):
        https_args = build_parser().parse_args(["share", "--dir", "/tmp", "--https"])
        assert https_args.https
        generate_args = build_parser().parse_args(["cert", "generate", "--days", "10", "--force", "--skip-lan"])
        assert generate_args.cert_command == "generate"
        assert generate_args.days == 10
        assert generate_args.force
        assert generate_args.skip_lan
