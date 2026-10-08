import base64
import logging
import os
import socketserver
import ssl
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest
from shareit.certs import configure_https, generate_self_signed
from shareit.cli import (
    build_parser,
    build_request_handler,
    configure_logging,
    get_all_ip_addresses,
    is_sensitive_name,
    is_valid_ip,
    logger,
    resolve_protection,
    resolve_upload_directory,
    safe_upload_filename,
)

class TestIPValidation:
    def test_valid_ipv4(self):
        assert is_valid_ip('192.168.1.1')
        assert is_valid_ip('127.0.0.1')
        assert is_valid_ip('0.0.0.0')

    def test_invalid_ipv4(self):
        assert not is_valid_ip('999.999.999.999')
        assert not is_valid_ip('abc.def.ghi.jkl')
        assert not is_valid_ip('256.256.256.256')

    def test_valid_ipv6(self):
        assert is_valid_ip('::1')
        assert is_valid_ip('2001:0db8:85a3:0000:0000:8a2e:0370:7334')

    def test_invalid_ipv6(self):
        assert not is_valid_ip('2001:0db8:85a3:0000:0000:8a2e:0370:zzzz')
        assert not is_valid_ip(':::')

class TestGetAllIPAddresses:
    def test_get_all_ip_addresses(self):
        ips = get_all_ip_addresses()
        assert isinstance(ips, dict)
        assert any(isinstance(ip, str) for ips_list in ips.values() for ip in ips_list)


class TestUploadFilename:
    def test_strips_directory_parts(self):
        assert safe_upload_filename("../../outside.txt") == "outside.txt"
        assert safe_upload_filename(r"..\windows\system.ini") == "system.ini"

    def test_rejects_empty_and_reserved_names(self):
        assert safe_upload_filename("") is None
        assert safe_upload_filename("..") is None
        assert safe_upload_filename("CON.txt") is None

    def test_keeps_dotfiles(self):
        assert safe_upload_filename(".env") == ".env"


class TestUploadCommand:
    def test_parser_defaults(self):
        args = build_parser().parse_args(["upload", "--dir", "/tmp/inbox"])
        assert args.command == "upload"
        assert args.dir == "/tmp/inbox"
        assert args.port == 18338
        assert args.max_upload_mb == 512


def _multipart_body(files, boundary="----ShareItTestBoundary7f3a"):
    chunks = []
    for filename, content in files:
        header = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
        ).encode()
        chunks.append(header)
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), boundary


def _request(port, path, body, boundary, auth=None, scheme="http", context=None):
    req = urllib.request.Request(f"{scheme}://127.0.0.1:{port}{path}", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, context=context) as response:
        return response.status, response.read()


@contextmanager
def running_server(directory, allow_upload=True, username=None, password=None, max_upload_bytes=1024 * 1024, cert_path=None, key_path=None, allow_sensitive=False, page_title="ShareIt"):
    handler = build_request_handler(
        username=username,
        password=password,
        allow_upload=allow_upload,
        share_root=str(directory),
        max_upload_bytes=max_upload_bytes,
        allow_sensitive=allow_sensitive,
        page_title=page_title,
    )
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    if cert_path and key_path:
        configure_https(httpd, cert_path, key_path)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class TestUploadServer:
    def test_saves_file_and_binary_bytes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        payload = b"hello\r\nworld\x00\xff"
        body, boundary = _multipart_body([("note.txt", payload)])
        with running_server(tmp_path) as httpd:
            port = httpd.server_address[1]
            status, page = _request(port, "/", body, boundary)
        assert status == 200
        assert b"Uploaded 1 file(s)." in page
        assert b"Upload files into this directory" in page
        assert (tmp_path / "note.txt").read_bytes() == payload

    def test_upload_lands_in_subdirectory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()
        body, boundary = _multipart_body([("photo.bin", b"\x00\x01")])
        with running_server(tmp_path) as httpd:
            port = httpd.server_address[1]
            _request(port, "/inbox/", body, boundary)
            page = urllib.request.urlopen(f"http://127.0.0.1:{port}/inbox/").read()
        assert (inbox / "photo.bin").read_bytes() == b"\x00\x01"
        assert b"Parent directory" in page

    def test_path_traversal_stays_inside_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        outside = tmp_path.parent / "shareit-should-not-escape.txt"
        if outside.exists():
            outside.unlink()
        body, boundary = _multipart_body([("../../shareit-should-not-escape.txt", b"pwned")])
        with running_server(tmp_path) as httpd:
            port = httpd.server_address[1]
            _request(port, "/", body, boundary)
        assert (tmp_path / "shareit-should-not-escape.txt").read_bytes() == b"pwned"
        assert not outside.exists()

    def test_does_not_overwrite_existing_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "note.txt").write_text("original")
        body, boundary = _multipart_body([("note.txt", b"new")])
        with running_server(tmp_path) as httpd:
            port = httpd.server_address[1]
            _request(port, "/", body, boundary)
        assert (tmp_path / "note.txt").read_text() == "original"
        assert (tmp_path / "note (1).txt").read_bytes() == b"new"

    def test_share_mode_rejects_upload(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        body, boundary = _multipart_body([("note.txt", b"nope")])
        with running_server(tmp_path, allow_upload=False) as httpd:
            port = httpd.server_address[1]
            with pytest.raises(urllib.error.HTTPError) as exc:
                _request(port, "/", body, boundary)
            page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
        assert exc.value.code == 405
        assert b"Upload files into this directory" not in page
        assert not (tmp_path / "note.txt").exists()

    def test_requires_auth_when_configured(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        body, boundary = _multipart_body([("note.txt", b"secret")])
        with running_server(tmp_path, username="ada", password="secret") as httpd:
            port = httpd.server_address[1]
            with pytest.raises(urllib.error.HTTPError) as exc:
                _request(port, "/", body, boundary)
            status, _page = _request(port, "/", body, boundary, auth=("ada", "secret"))
        assert exc.value.code == 401
        assert status == 200
        assert (tmp_path / "note.txt").read_bytes() == b"secret"

    def test_rejects_oversize_upload(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        body, boundary = _multipart_body([("big.txt", b"0123456789")])
        with running_server(tmp_path, max_upload_bytes=8) as httpd:
            port = httpd.server_address[1]
            with pytest.raises(urllib.error.HTTPError) as exc:
                _request(port, "/", body, boundary)
        assert exc.value.code == 413
        assert not (tmp_path / "big.txt").exists()

    def test_rejects_escape_outside_share_root(self, tmp_path):
        assert resolve_upload_directory(str(tmp_path), "/../") is None
        assert resolve_upload_directory(str(tmp_path), "/") == os.path.realpath(tmp_path)

    def test_directory_is_served_over_tls(self, tmp_path, monkeypatch):
        share_dir = tmp_path / "share"
        share_dir.mkdir()
        monkeypatch.chdir(share_dir)
        (share_dir / "readme.txt").write_text("hello https")
        cert_path = str(tmp_path / "shareit.crt")
        key_path = str(tmp_path / "shareit.key")
        generate_self_signed(cert_path, key_path)
        trusted = ssl.create_default_context(cafile=cert_path)
        with running_server(share_dir, allow_upload=False, cert_path=cert_path, key_path=key_path) as httpd:
            port = httpd.server_address[1]
            page = urllib.request.urlopen(f"https://127.0.0.1:{port}/", context=trusted).read()
            file_body = urllib.request.urlopen(f"https://127.0.0.1:{port}/readme.txt", context=trusted).read()
            with pytest.raises(urllib.error.URLError):
                urllib.request.urlopen(f"https://127.0.0.1:{port}/readme.txt")
        assert b"readme.txt" in page
        assert file_body == b"hello https"


class TestSensitiveFiles:
    def test_name_rules(self):
        assert is_sensitive_name(".env")
        assert is_sensitive_name(".env.local")
        assert is_sensitive_name(".git")
        assert is_sensitive_name("id_rsa")
        assert not is_sensitive_name("readme.txt")
        assert not is_sensitive_name(".gitignore")

    def test_listing_hides_sensitive_files_and_blocks_download(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "readme.txt").write_text("ok")
        (tmp_path / ".env").write_text("SECRET=1")
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("secret")
        with running_server(tmp_path, allow_upload=False, page_title="Lan Drop") as httpd:
            port = httpd.server_address[1]
            page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
            with pytest.raises(urllib.error.HTTPError) as env_error:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/.env")
            with pytest.raises(urllib.error.HTTPError) as git_error:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/.git/config")
        assert b"Lan Drop" in page
        assert b"readme.txt" in page
        assert b"href='.env'" not in page
        assert b"href='.git/'" not in page
        assert b"Filter files" in page
        assert b"Home" in page
        assert env_error.value.code == 403
        assert git_error.value.code == 403

    def test_allow_sensitive_serves_env_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=1")
        with running_server(tmp_path, allow_upload=False, allow_sensitive=True) as httpd:
            port = httpd.server_address[1]
            page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
            body = urllib.request.urlopen(f"http://127.0.0.1:{port}/.env").read()
        assert b"href='.env'" in page
        assert body == b"SECRET=1"

    def test_upload_of_sensitive_name_is_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        body, boundary = _multipart_body([(".env", b"nope")])
        with running_server(tmp_path) as httpd:
            port = httpd.server_address[1]
            with pytest.raises(urllib.error.HTTPError) as exc:
                _request(port, "/", body, boundary)
        assert exc.value.code == 403
        assert not (tmp_path / ".env").exists()

    def test_requests_are_written_to_the_log_file(self, tmp_path, monkeypatch):
        share_dir = tmp_path / "share"
        share_dir.mkdir()
        monkeypatch.chdir(share_dir)
        (share_dir / "readme.txt").write_text("hi")
        log_path = tmp_path / "shareit.log"
        configure_logging(str(log_path))
        try:
            with running_server(share_dir, allow_upload=False) as httpd:
                port = httpd.server_address[1]
                urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
        finally:
            logger.handlers.clear()
            logger.addHandler(logging.NullHandler())
        assert "GET /" in log_path.read_text()

    def test_parser_accepts_customization_options(self):
        args = build_parser().parse_args([
            "upload",
            "--dir",
            "/tmp",
            "--title",
            "Drop box",
            "--allow-sensitive",
            "--log-file",
            "share.log",
        ])
        assert args.title == "Drop box"
        assert args.allow_sensitive
        assert args.log_file == "share.log"


class TestProtection:
    def test_keeps_username_and_password_when_both_are_set(self):
        assert resolve_protection(True, "ada", "your-password") == ("ada", "your-password")

    def test_generates_both_when_protected_and_omitted(self):
        username, password = resolve_protection(True, None, None)
        assert username
        assert password
        assert username != password
        assert resolve_protection(True, "ada", None)[0] == "ada"
        assert resolve_protection(True, None, "secret")[1] == "secret"

    def test_credentials_without_protected_are_rejected(self):
        with pytest.raises(ValueError):
            resolve_protection(False, "ada", None)
        assert resolve_protection(False, None, None) == (None, None)

    def test_parser_accepts_protected(self):
        args = build_parser().parse_args([
            "share",
            "--dir",
            "/tmp",
            "--protected",
            "--username",
            "ada",
            "--password",
            "your-password",
        ])
        assert args.protected
        assert args.username == "ada"
        assert args.password == "your-password"

