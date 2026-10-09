import argparse
import datetime
import errno
import logging
import psutil
import ipaddress
import os
import html
import re
import urllib.parse
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

import uuid
import shutil

import http.server as http_server
import socketserver
import base64
from http.server import SimpleHTTPRequestHandler

logger = logging.getLogger("shareit")
logger.addHandler(logging.NullHandler())

_SENSITIVE_NAMES = {
    ".git", ".svn", ".hg", ".ssh", ".aws", ".gnupg",
    ".htpasswd", ".netrc", ".npmrc", ".pypirc",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials.json", "secrets.json", '.env', '.env.local', 
    '.env.development', '.env.production', '.env.test', '.env.development.local', 
    '.env.production.local', '.env.test.local',
}

from shareit.certs import (
    CertificateError,
    certificate_matches_key,
    configure_https,
    describe_certificate,
    generate_self_signed,
    remove_certificate_files,
    resolve_certificate_pair,
    resolve_https_files,
)

# Function to read the version from pyproject.toml
def read_pyproject_toml():
    the_pyproject_toml_file = os.path.dirname(os.path.realpath(__file__)) \
                              + os.sep + "pyproject.toml"
    if not os.path.exists(the_pyproject_toml_file):
        the_pyproject_toml_file = the_pyproject_toml_file.replace("/shareit", "", 1)
    with open(file=the_pyproject_toml_file, mode='r', encoding='utf-8') as tomlfile:
        lines = tomlfile.readlines()
        for line in lines:
            if "version" in line:
                return line.split('"')[-2]
        return ""


def generate_temporary_dir(the_path):
    """Generate a unique identifier for the file sharing session."""
    dir_name = f".tmp_dir_{uuid.uuid4()}"
    temp_dir = os.path.join(the_path, dir_name)
    os.makedirs(temp_dir, exist_ok=True)
    return dir_name

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_all_ip_addresses():
    """Return a dict of interface: [ip addresses] using psutil for cross-platform support."""
    ip_dict = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # AF_INET
                ip_dict.setdefault(iface, []).append(addr.address)
    return ip_dict

def random_password(length=12):
    """Generate a random password of specified length."""
    import random
    import string
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def random_username(length=8):
    """Generate a short username that is easy to type."""
    import random
    import string
    first = random.choice(string.ascii_lowercase)
    rest = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length - 1))
    return first + rest


def resolve_protection(protected, username, password):
    """Return credentials when --protected is set, generating any that were omitted."""
    username = username.strip() if isinstance(username, str) else None
    username = username or None
    password = password if isinstance(password, str) and password != "" else None
    if not protected:
        if username or password:
            raise ValueError("Pass --protected to require a username and password.")
        return None, None
    if username is None:
        username = random_username()
    if password is None:
        password = random_password()
    return username, password


class UploadError(Exception):
    """A rejected upload, with the HTTP status to send back."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


_RESERVED_FILENAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

_LISTING_CSS = """<style>
body{font-family:sans-serif;margin:24px;background:#fff;color:#222;}
table{width:100%;border-collapse:collapse;}
th,td{padding:8px;border-bottom:1px solid #ddd;text-align:left;}
th{background:#f4f4f4;}
tr:hover{background:#f9f9f9;}
a{color:#0074d9;text-decoration:none;}
a:hover{text-decoration:underline;}
form.upload{background:#f4f8fb;border:1px solid #d7e6f5;border-radius:8px;padding:16px;margin:16px 0;}
form.upload label{display:block;font-weight:600;margin-bottom:8px;}
form.upload input{margin-right:8px;}
form.upload button{background:#0074d9;color:#fff;border:none;border-radius:4px;padding:8px 14px;cursor:pointer;}
.banner{background:#d4edda;color:#155724;padding:10px 12px;border-radius:6px;}
.crumbs{color:#555;margin:8px 0 16px;}
.crumbs a{margin:0 4px;}
.filter{margin:0 0 16px;padding:8px 10px;width:100%;max-width:320px;border:1px solid #ccc;border-radius:4px;}
.note{color:#666;font-size:14px;}
.empty{color:#666;padding:12px 0;}
</style>"""


def is_sensitive_name(name):
    """True for secret files and version-control metadata."""
    if not name:
        return False
    lowered = name.lower()
    if lowered in _SENSITIVE_NAMES or lowered.startswith(".env"):
        return True
    return False


def path_is_sensitive(root, path):
    """True when any path segment between root and path is sensitive."""
    root = os.path.realpath(root)
    real = os.path.realpath(path)
    if real != root and not _is_inside(root, real):
        return False
    relative = os.path.relpath(real, root)
    if relative == ".":
        return is_sensitive_name(os.path.basename(root))
    return any(is_sensitive_name(part) for part in relative.split(os.sep))


def format_size(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{int(size)} B"


def format_mtime(path):
    stamp = datetime.datetime.fromtimestamp(os.path.getmtime(path))
    return stamp.strftime("%Y-%m-%d %H:%M")


def breadcrumb_links(url_path):
    path = urllib.parse.urlsplit(url_path).path or "/"
    parts = [part for part in path.split("/") if part]
    links = [("/", "Home")]
    built = ""
    for part in parts:
        built += "/" + part
        links.append((built + "/", urllib.parse.unquote(part)))
    return links


def configure_logging(log_file=None):
    """Send server logs to stderr and, when requested, a file."""
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)
    if log_file:
        directory = os.path.dirname(os.path.abspath(log_file))
        if directory:
            os.makedirs(directory, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    logger.propagate = False


def safe_upload_filename(raw):
    """Return a single path segment that is safe to write, or None."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    name = raw.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable())
    name = name.replace("\x00", "").strip()
    if not name or name in {".", ".."}:
        return None
    if os.path.splitext(name)[0].split(".")[0].upper() in _RESERVED_FILENAMES:
        return None
    if len(name) > 200:
        base, ext = os.path.splitext(name)
        ext = ext[:20]
        name = base[: max(1, 200 - len(ext))] + ext
    return name


def _is_inside(root, path):
    root = os.path.realpath(root)
    path = os.path.realpath(path)
    try:
        return os.path.commonpath([root, path]) == root
    except ValueError:
        return False


def resolve_upload_directory(share_root, url_path):
    """Map a request path to a directory inside the shared root."""
    if not share_root:
        return None
    root = os.path.realpath(share_root)
    raw_path = urllib.parse.urlsplit(url_path).path
    raw_path = urllib.parse.unquote(raw_path)
    if not raw_path.startswith("/") or raw_path.startswith("//") or "\\" in raw_path or "\x00" in raw_path:
        return None
    relative = raw_path.lstrip("/")
    if relative.endswith("/"):
        relative = relative[:-1]
    candidate = root if relative == "" else os.path.realpath(os.path.join(root, relative))
    if not _is_inside(root, candidate) or not os.path.isdir(candidate):
        return None
    return candidate


def _boundary_from_content_type(content_type):
    match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type, re.IGNORECASE)
    if not match:
        raise UploadError(400, "Missing multipart boundary")
    boundary = (match.group(1) or match.group(2)).strip()
    if not boundary:
        raise UploadError(400, "Missing multipart boundary")
    return boundary


def _filename_from_disposition(value):
    extended = re.search(r"filename\*=([^;]+)", value, re.IGNORECASE)
    if extended:
        raw = extended.group(1).strip().strip('"')
        if "''" in raw:
            raw = raw.split("''", 1)[1]
        return urllib.parse.unquote(raw)
    quoted = re.search(r'filename="([^"]*)"', value, re.IGNORECASE)
    if quoted:
        return quoted.group(1)
    plain = re.search(r"filename=([^;]+)", value, re.IGNORECASE)
    if plain:
        return plain.group(1).strip().strip('"')
    return None


def _iter_uploaded_files(body, boundary):
    try:
        boundary_bytes = boundary.encode("ascii")
    except UnicodeEncodeError:
        raise UploadError(400, "Invalid multipart boundary")
    delimiter = b"\r\n--" + boundary_bytes
    for segment in (b"\r\n" + body).split(delimiter)[1:]:
        if segment.startswith(b"--"):
            break
        if segment.startswith(b"\r\n"):
            segment = segment[2:]
        header_blob, separator, content = segment.partition(b"\r\n\r\n")
        if not separator:
            continue
        filename = None
        for line in header_blob.decode("utf-8", "replace").split("\r\n"):
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            if key.strip().lower() == "content-disposition":
                filename = _filename_from_disposition(val.strip())
        if filename:
            yield filename, content


def _read_exact(stream, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_upload(dest_dir, filename, payload):
    dest_dir = os.path.realpath(dest_dir)
    base, ext = os.path.splitext(filename)
    for index in range(10001):
        candidate_name = filename if index == 0 else f"{base} ({index}){ext}"
        candidate = os.path.join(dest_dir, candidate_name)
        if os.path.realpath(os.path.dirname(candidate)) != dest_dir:
            raise UploadError(400, "Invalid filename")
        try:
            descriptor = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            continue
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        return candidate_name
    raise UploadError(400, "Could not choose a filename")


def save_uploaded_files(stream, headers, dest_dir, max_upload_bytes, allow_sensitive=False):
    """Read one multipart request and store its files in dest_dir."""
    content_type = headers.get("Content-Type", "")
    if "multipart/form-data" not in content_type.lower():
        raise UploadError(400, "Expected a multipart form upload")
    raw_length = headers.get("Content-Length")
    if raw_length is None:
        raise UploadError(411, "Content-Length required")
    try:
        length = int(raw_length)
    except ValueError:
        raise UploadError(400, "Invalid Content-Length")
    if length < 0 or length > max_upload_bytes:
        raise UploadError(413, "Upload exceeds the size limit")
    body = _read_exact(stream, length)
    if len(body) != length:
        raise UploadError(400, "Incomplete upload")
    saved = []
    for filename, payload in _iter_uploaded_files(body, _boundary_from_content_type(content_type)):
        safe_name = safe_upload_filename(filename)
        if not safe_name:
            raise UploadError(400, "Invalid filename")
        if not allow_sensitive and is_sensitive_name(safe_name):
            raise UploadError(403, "That filename is blocked")
        saved.append(_write_upload(dest_dir, safe_name, payload))
    if not saved:
        raise UploadError(400, "No file was uploaded")
    return saved


def _uploaded_count(url_path):
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url_path).query)
    raw = query.get("uploaded", [""])[0]
    if raw.isdigit():
        return int(raw)
    return None


def _redirect_path(url_path):
    path = urllib.parse.urlsplit(url_path).path or "/"
    if not path.startswith("/") or path.startswith("//"):
        return "/"
    return path

class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, username=None, password=None, **kwargs):
        self.username = username
        self.password = password
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        if not self.authenticate():
            return
        super().do_HEAD()

    def do_GET(self):
        if not self.authenticate():
            return
        super().do_GET()

    def authenticate(self):
        # Only require authentication if both username and password are set
        if self.username is None or self.password is None:
            return True
        auth_header = self.headers.get('Authorization')
        if auth_header is None or not auth_header.startswith('Basic '):
            self.send_auth_required()
            return False
        encoded = auth_header.split(' ', 1)[1].strip()
        decoded = base64.b64decode(encoded).decode('utf-8')
        user, pwd = decoded.split(':', 1)
        if user != self.username or pwd != self.password:
            self.send_auth_required()
            return False
        return True

    def send_auth_required(self):
        logger.warning("Authentication failed from %s", self.address_string())
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="FileShare"')
        self.end_headers()

    def log_message(self, fmt, *args):
        logger.info("%s - %s", self.address_string(), fmt % args)


class ShareRequestHandler(AuthHTTPRequestHandler):
    allow_upload = False
    allow_sensitive = False
    page_title = "ShareIt"
    share_root = None
    max_upload_bytes = 512 * 1024 * 1024

    def _request_is_sensitive(self):
        if self.allow_sensitive or not self.share_root:
            return False
        return path_is_sensitive(self.share_root, self.translate_path(self.path))

    def _guard_request(self):
        if not self.authenticate():
            return False
        if self._request_is_sensitive():
            logger.warning("Blocked sensitive path %s from %s", self.path, self.address_string())
            self.send_error(403, "Sensitive files are hidden")
            return False
        return True

    def do_GET(self):
        if not self._guard_request():
            return
        super(AuthHTTPRequestHandler, self).do_GET()

    def do_HEAD(self):
        if not self._guard_request():
            return
        super(AuthHTTPRequestHandler, self).do_HEAD()

    def list_directory(self, path):
        try:
            file_list = os.listdir(path)
        except OSError:
            logger.error("Cannot list directory %s", path)
            self.send_error(404, "No permission to list directory")
            return None
        file_list.sort(key=lambda a: a.lower())
        visible = []
        for name in file_list:
            if not self.allow_sensitive and is_sensitive_name(name):
                continue
            visible.append(name)
        display_path = os.path.basename(path.rstrip(os.sep)) or path
        title = html.escape(self.page_title or "ShareIt")
        uploaded_count = _uploaded_count(self.path) if self.allow_upload else None
        crumbs = []
        links = breadcrumb_links(self.path)
        for index, (href, label) in enumerate(links):
            escaped = html.escape(label)
            if index == len(links) - 1:
                crumbs.append(f"<span>{escaped}</span>")
            else:
                crumbs.append(f"<a href='{html.escape(href, quote=True)}'>{escaped}</a>")
        html_parts = [
            "<html><head><title>",
            title,
            "</title>",
            _LISTING_CSS,
            "</head><body>",
            f"<h1>{title}</h1>",
            f"<p class='crumbs'>{' / '.join(crumbs)}</p>",
            f"<h2>Directory listing for <span style='color:#0074d9'>{html.escape(display_path)}</span></h2>",
        ]
        if not self.allow_sensitive:
            html_parts.append("<p class='note'>Sensitive files such as .env and .git are hidden.</p>")
        if uploaded_count is not None:
            html_parts.append(f"<p class='banner'>Uploaded {uploaded_count} file(s).</p>")
        if self.allow_upload:
            html_parts.append(
                "<form class='upload' method='post' enctype='multipart/form-data'>"
                "<label for='file'>Upload files into this directory</label>"
                "<input id='file' type='file' name='file' multiple required>"
                "<button type='submit'>Upload</button>"
                "</form>"
            )
        if self.share_root and os.path.realpath(path) != os.path.realpath(self.share_root):
            html_parts.append("<p><a href='../'>Parent directory</a></p>")
        if visible:
            html_parts.append("<input id='filter' class='filter' type='search' placeholder='Filter files' aria-label='Filter files'>")
            html_parts.append("<table>")
            html_parts.append("<tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th></tr>")
            for name in visible:
                fullname = os.path.join(path, name)
                escaped = html.escape(name)
                link = urllib.parse.quote(name)
                modified = html.escape(format_mtime(fullname))
                if os.path.isdir(fullname):
                    filetype = "[DIR]"
                    filesize = "-"
                    link += "/"
                else:
                    filetype = "File"
                    filesize = html.escape(format_size(os.path.getsize(fullname)))
                html_parts.append(
                    "<tr>"
                    f"<td><a href='{link}'>{escaped}</a></td>"
                    f"<td>{filetype}</td><td>{filesize}</td><td>{modified}</td>"
                    "</tr>"
                )
            html_parts.append("</table>")
            html_parts.append(
                "<script>"
                "var filter=document.getElementById('filter');"
                "filter.addEventListener('input',function(){"
                "var query=filter.value.toLowerCase();"
                "document.querySelectorAll('table tr').forEach(function(row,index){"
                "if(index===0){return;}"
                "row.style.display=row.textContent.toLowerCase().indexOf(query)===-1?'none':'';"
                "});"
                "});"
                "</script>"
            )
        else:
            html_parts.append("<p class='empty'>No files to show.</p>")
        html_parts.append(
            "<div style='text-align:center; margin-top:30px; color:#888;'>"
            "<a href='https://github.com/fahadahammed/shareit' target=_blank>ShareIt File Server</a> "
            f"v{html.escape(read_pyproject_toml())} &copy; {datetime.datetime.now().year}</div>"
        )
        html_parts.append("</body></html>")
        encoded = "\n".join(html_parts).encode("utf-8", "surrogateescape")
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        return None

    def do_POST(self):
        if not self.authenticate():
            return
        if self._request_is_sensitive():
            logger.warning("Blocked sensitive upload path %s", self.path)
            self.send_error(403, "Sensitive files are hidden")
            return
        if not self.allow_upload:
            self.send_error(405, "Uploads are disabled")
            return
        destination = resolve_upload_directory(self.share_root, self.path)
        if destination is None:
            self.send_error(400, "Cannot upload to that path")
            return
        try:
            saved = save_uploaded_files(
                self.rfile,
                self.headers,
                destination,
                self.max_upload_bytes,
                allow_sensitive=self.allow_sensitive,
            )
        except UploadError as exc:
            logger.warning("Upload rejected: %s", exc.message)
            self.send_error(exc.status, exc.message)
            return
        logger.info("Saved %s file(s) in %s", len(saved), destination)
        location = _redirect_path(self.path)
        self.send_response(303)
        self.send_header("Location", f"{location}?uploaded={len(saved)}")
        self.send_header("Content-Length", "0")
        self.end_headers()


def build_request_handler(username, password, allow_upload, share_root, max_upload_bytes, allow_sensitive=False, page_title="ShareIt"):
    """Return a request handler bound to one shared directory."""

    class Handler(ShareRequestHandler):
        pass

    Handler.allow_upload = allow_upload
    Handler.allow_sensitive = allow_sensitive
    Handler.page_title = page_title or "ShareIt"
    Handler.share_root = os.path.realpath(share_root)
    Handler.max_upload_bytes = max_upload_bytes

    def handler(*args, **kwargs):
        kwargs["username"] = username
        kwargs["password"] = password
        return Handler(*args, **kwargs)

    return handler


def file_share(directory=None, file=None, host="0.0.0.0", port=18338, username=None, password=None, upload=False, max_upload_mb=512, cert_file=None, key_file=None, tls_generated=False, tls_self_signed=False, allow_sensitive=False, page_title="ShareIt"):
    """Function to share files over the network."""
    if not directory and not file:
        logger.error("No directory or file was provided")
        rprint("[bold red]Error:[/] You must specify either a directory or a file to share.")
        exit(1)

    if not os.path.isdir(directory):
        logger.error("Directory does not exist: %s", directory)
        rprint(f"[bold red]Error:[/] The directory [yellow]{directory}[/] does not exist or is not a directory.")
        exit(1)

    if upload and max_upload_mb <= 0:
        logger.error("Invalid maximum upload size: %s", max_upload_mb)
        rprint("[bold red]Error:[/] Maximum upload size must be greater than 0 MB.")
        exit(1)

    # If a file is specified, copy it to the directory to share
    if file:
        if not os.path.isfile(file):
            logger.error("File does not exist: %s", file)
            rprint(f"[bold red]Error:[/] The file [yellow]{file}[/] does not exist or is not a file.")
            exit(1)
        if not allow_sensitive and is_sensitive_name(os.path.basename(file)):
            logger.error("Refused to share sensitive file %s", file)
            rprint(f"[bold red]Error:[/] Refusing to share sensitive file [yellow]{file}[/]. Use --allow-sensitive to override.")
            exit(1)
        try:
            # Copy the file to the directory to share
            shutil.copy(file, directory)
            rprint(f"[bold green]File [yellow]{file}[/] copied to [yellow]{directory}[/] for sharing.[/]")
        except Exception as e:
            logger.exception("Failed to copy file %s", file)
            rprint(f"[bold red]Error:[/] Failed to copy file: {e}")
            exit(1)

    share_root = os.path.realpath(directory)
    if not allow_sensitive and is_sensitive_name(os.path.basename(share_root)):
        logger.error("Refused to share sensitive directory %s", share_root)
        rprint(f"[bold red]Error:[/] Refusing to share sensitive directory [yellow]{directory}[/]. Use --allow-sensitive to override.")
        exit(1)
    os.chdir(share_root)  # Change to the directory to share

    handler = build_request_handler(
        username=username,
        password=password,
        allow_upload=upload,
        share_root=share_root,
        max_upload_bytes=max_upload_mb * 1024 * 1024,
        allow_sensitive=allow_sensitive,
        page_title=page_title,
    )
    with socketserver.TCPServer((host, port), handler) as httpd:
        if cert_file and key_file:
            configure_https(httpd, cert_file, key_file)
        scheme = "https" if cert_file and key_file else "http"
        if upload:
            summary = (
                f"[bold green]Upload server started.[/]\n"
                f"[bold white]Others can upload files into {directory}.[/]\n"
                f"[bold white]Maximum upload size is {max_upload_mb} MB.[/]"
            )
        else:
            summary = (
                f"[bold green]File sharing service started successfully![/]\n"
                f"[bold white]Directory {directory} is shared.[/]"
            )
        if scheme == "https":
            created = "A new self-signed certificate was created.\n" if tls_generated else ""
            summary += (
                f"\n[bold white]HTTPS is enabled.[/]\n"
                f"[bold white]{created}Certificate: {cert_file}[/]"
            )
        rprint(Panel.fit(summary, title="[bold blue]Server Status"))
        if username and password:
            logger.info("Password protection enabled for user %s", username)
            table = Table(title="Basic Authentication", show_header=True, header_style="bold magenta")
            table.add_column("Username", style="dim")
            table.add_column("Password", style="dim")
            table.add_row(username, password)
            rprint(table)
        if host == "0.0.0.0":
            table = Table(title="Access URLs", show_header=True, header_style="bold magenta")
            table.add_column("Interface", style="dim")
            table.add_column("IP Address")
            table.add_column("URL")
            for iface, ips in get_all_ip_addresses().items():
                for ip in ips:
                    if ip != "0.0.0.0":
                        url = f"{scheme}://{ip}:{port}"
                        if file:
                            url += f"/{os.path.basename(file)}"
                        table.add_row(iface, ip, url)
            rprint(table)
        else:
            url = f"{scheme}://{host}:{port}"
            rprint(f"[bold green]Serving {scheme.upper()} on [yellow]{host}:{port}[/] ([cyan]{url}[/])")
            rprint(f"[bold blue]Access your files at [underline]{url}[/]")
        if scheme == "https" and tls_self_signed:
            rprint("[bold yellow]This certificate is self-signed. Browsers will warn until you trust it.[/]")
        logger.info(
            "Serving %s on %s:%s upload=%s https=%s sensitive=%s",
            directory,
            host,
            port,
            upload,
            scheme == "https",
            allow_sensitive,
        )
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.shutdown()

            # Change the working directory to parent
            parent_path = os.path.dirname(os.getcwd())  # Move to parent directory
            os.chdir(parent_path)

            # Remove the temporary directory if it was created and is inside the current working directory
            if os.path.exists(directory) and os.path.basename(directory).startswith(".tmp_dir_"):
                shutil.rmtree(directory, ignore_errors=True)

            logger.info("Server stopped")
            rprint("\n[bold red]Server stopped by user.[/]")


def certificate_names(bind_host=None, extra_names=None, include_lan=True):
    """Host names and IP addresses to put on a self-signed certificate."""
    names = list(extra_names or [])
    if bind_host:
        names.append(bind_host)
    if include_lan:
        for ips in get_all_ip_addresses().values():
            names.extend(ips)
    return names


def add_https_arguments(parser):
    parser.add_argument('--https', action='store_true', help='Serve over HTTPS. Creates a self-signed certificate when --cert and --key are omitted')
    parser.add_argument('--cert', type=str, default=None, help='PEM certificate for HTTPS')
    parser.add_argument('--key', type=str, default=None, help='PEM private key for HTTPS')


def add_server_arguments(parser):
    add_https_arguments(parser)
    parser.add_argument('--protected', action='store_true', help='Require a username and password. Missing values are generated for this run')
    parser.add_argument('--title', type=str, default='ShareIt', help='Title shown in the browser (default: ShareIt)')
    parser.add_argument('--allow-sensitive', action='store_true', help='Also share sensitive files such as .env and .git')
    parser.add_argument('--log-file', type=str, default=None, help='Write server logs to this file as well as the terminal')


def _format_certificate_time(value):
    return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def handle_cert_command(args):
    try:
        if args.cert_command == "generate":
            cert_path, key_path = resolve_certificate_pair(args.cert, args.key)
            names = certificate_names(extra_names=[*(args.dns or []), *(args.ip or [])], include_lan=not args.skip_lan)
            generate_self_signed(
                cert_path,
                key_path,
                days=args.days,
                common_name=args.name,
                names=names,
                force=args.force,
            )
            rprint("[bold green]Self-signed certificate written.[/]")
            rprint(f"[bold white]Certificate:[/] {cert_path}")
            rprint(f"[bold white]Private key:[/] {key_path}")
            rprint("[bold yellow]Browsers will warn about this certificate until you trust it.[/]")
        elif args.cert_command == "info":
            if args.key and not args.cert:
                raise CertificateError("Provide --cert with --key.")
            if args.cert and not args.key:
                cert_path = args.cert
                key_path = None
            else:
                cert_path, key_path = resolve_certificate_pair(args.cert, args.key)
            details = describe_certificate(cert_path)
            table = Table(title="Certificate", show_header=True, header_style="bold magenta")
            table.add_column("Field", style="dim")
            table.add_column("Value")
            table.add_row("Path", cert_path)
            table.add_row("Common name", details["common_name"])
            table.add_row("Subject", details["subject"])
            table.add_row("Issuer", details["issuer"])
            table.add_row("Self-signed", "yes" if details["self_signed"] else "no")
            table.add_row("Valid from", _format_certificate_time(details["not_before"]))
            table.add_row("Valid until", _format_certificate_time(details["not_after"]))
            table.add_row("Expired", "yes" if details["expired"] else "no")
            table.add_row("DNS names", ", ".join(details["dns_names"]) or "-")
            table.add_row("IP addresses", ", ".join(details["ip_addresses"]) or "-")
            table.add_row("SHA-256", details["fingerprint_sha256"])
            if key_path and os.path.exists(key_path):
                matches = certificate_matches_key(cert_path, key_path)
                table.add_row("Key path", key_path)
                table.add_row("Key matches", "yes" if matches else "no")
            rprint(table)
        elif args.cert_command == "remove":
            cert_path, key_path = resolve_certificate_pair(args.cert, args.key)
            removed = remove_certificate_files(cert_path, key_path)
            for path in removed:
                rprint(f"[bold green]Removed[/] {path}")
    except CertificateError as exc:
        rprint(f"[bold red]Error:[/] {exc}")
        exit(1)


def build_parser():
    parser = argparse.ArgumentParser(description="Share files over the network.")
    parser.add_argument('--version', action='version', version="shareit, " + read_pyproject_toml())
    subparsers = parser.add_subparsers(dest='command', required=True, help='Sub-commands')

    # Share subparser
    share_parser = subparsers.add_parser('share', help='Share files or directories')
    share_group = share_parser.add_mutually_exclusive_group(required=True)
    share_group.add_argument('--dir', type=str, help='Directory to share')
    share_group.add_argument('--file', type=str, help='File to share')
    share_parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    share_parser.add_argument('--port', type=int, default=18338, help='Port to bind (default: 18338)')
    share_parser.add_argument('--username', type=str, default=None, help='Username for HTTP basic authentication')
    share_parser.add_argument('--password', type=str, default=None, help='Password for HTTP basic authentication')
    add_server_arguments(share_parser)

    # Upload subparser: others send files into a directory on this machine
    upload_parser = subparsers.add_parser('upload', help='Let others upload files into a directory')
    upload_parser.add_argument('--dir', type=str, required=True, help='Directory that receives uploaded files')
    upload_parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    upload_parser.add_argument('--port', type=int, default=18338, help='Port to bind (default: 18338)')
    upload_parser.add_argument('--username', type=str, default=None, help='Username for HTTP basic authentication')
    upload_parser.add_argument('--password', type=str, default=None, help='Password for HTTP basic authentication')
    upload_parser.add_argument('--max-upload-mb', type=int, default=512, help='Maximum total upload size in megabytes (default: 512)')
    add_server_arguments(upload_parser)

    cert_parser = subparsers.add_parser('cert', help='Create, inspect, or remove HTTPS certificates')
    cert_sub = cert_parser.add_subparsers(dest='cert_command', required=True)
    generate_parser = cert_sub.add_parser('generate', help='Create a self-signed certificate and private key')
    generate_parser.add_argument('--name', type=str, default='shareit', help='Common name (default: shareit)')
    generate_parser.add_argument('--days', type=int, default=365, help='Days the certificate is valid (default: 365)')
    generate_parser.add_argument('--cert', type=str, default=None, help='Certificate file to write (default: ~/.shareit/certs/shareit.crt)')
    generate_parser.add_argument('--key', type=str, default=None, help='Private key file to write (default: ~/.shareit/certs/shareit.key)')
    generate_parser.add_argument('--dns', action='append', default=[], help='Extra DNS name. Can be repeated')
    generate_parser.add_argument('--ip', action='append', default=[], help='Extra IP address. Can be repeated')
    generate_parser.add_argument('--skip-lan', action='store_true', help='Do not add this machine\'s local IP addresses')
    generate_parser.add_argument('--force', action='store_true', help='Replace an existing certificate and key')
    info_parser = cert_sub.add_parser('info', help='Show certificate details')
    info_parser.add_argument('--cert', type=str, default=None, help='Certificate file (default: ~/.shareit/certs/shareit.crt)')
    info_parser.add_argument('--key', type=str, default=None, help='Private key to check against the certificate')
    remove_parser = cert_sub.add_parser('remove', help='Delete a certificate and its private key')
    remove_parser.add_argument('--cert', type=str, default=None, help='Certificate file (default: ~/.shareit/certs/shareit.crt)')
    remove_parser.add_argument('--key', type=str, default=None, help='Private key file (default: ~/.shareit/certs/shareit.key)')

    # Recieve subparser
    recieve_parser = subparsers.add_parser('recieve', help='Recieve files from a sender')
    recieve_parser.add_argument('--host', type=str, required=True, help='Host to connect to')
    recieve_parser.add_argument('--port', type=int, default=18338, help='Port to connect to (default: 18338)')
    recieve_parser.add_argument('--dir', type=str, default='.', help='Directory to save received files (default: current directory)')
    recieve_parser.add_argument('--username', type=str, default=None, help='Username for HTTP basic authentication')
    recieve_parser.add_argument('--password', type=str, default=None, help='Password for HTTP basic authentication')
    return parser


def report_server_error(exc):
    logger.exception("Failed to start file sharing service")
    if isinstance(exc, OSError) and exc.errno == errno.EADDRINUSE:
        rprint("[bold red]Error:[/] That port is already in use. Choose another with --port.")
    elif isinstance(exc, OSError) and exc.errno in (errno.EACCES, errno.EPERM):
        rprint(f"[bold red]Error:[/] Permission denied: {exc}")
    elif isinstance(exc, CertificateError):
        rprint(f"[bold red]Error:[/] {exc}")
    else:
        rprint(f"[bold red]Error:[/] {exc}")
    rprint("[bold red]Failed to start file sharing service.[/]")
    exit(1)


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        configure_logging(getattr(args, "log_file", None))
    except OSError as exc:
        rprint(f"[bold red]Error:[/] Could not open the log file: {exc}")
        exit(1)
    welcome_message = f"""Welcome to Shareit CLI File Sharing Tool v{read_pyproject_toml()}"""
    rprint(f"[bold white]{welcome_message}[/]")
    rprint(f"[bold white]{'─'*len(welcome_message)}[/]")
    ip_addresses = ["0.0.0.0"]

    if args.command == 'cert':
        handle_cert_command(args)
        return

    if args.command in ('share', 'upload'):
        the_host = args.host
        if not is_valid_ip(args.host):
            rprint(f"[bold white]Provided host {args.host} is not a valid IP address. Using default host: 0.0.0.0")
            the_host = "0.0.0.0"

        for iface, ips in get_all_ip_addresses().items():
            for ip in ips:
                ip_addresses.append(ip)
        ip_addresses.remove("127.0.0.1") # Exclude loopback address
        if the_host not in ip_addresses:
            rprint("[bold white]Provided host is not a valid local IP address. Select appropriate host from the following:")

            table = Table(title="Available IP Addresses", show_header=True, header_style="bold magenta")
            table.add_column("Index", style="dim")
            table.add_column("IP Address")
            for idx, ip in enumerate(ip_addresses):
                table.add_row(str(idx), ip)
            rprint(table)

            ip_choice = Prompt.ask("[bold green]Enter the index of the IP address you want to use[/]")

            try:
                ip_choice = int(ip_choice)
                if 0 <= ip_choice < len(ip_addresses):
                    the_host = ip_addresses[ip_choice]
                else:
                    rprint("[bold white]Invalid index. Using default host.")
            except ValueError:
                rprint("[bold yellow]Invalid input. Using default host.")
                rprint(f"[bold yellow]Using host: {the_host}")
        try:
            tls = resolve_https_files(
                https=args.https,
                cert_path=args.cert,
                key_path=args.key,
                names=certificate_names(the_host),
            )
        except CertificateError as exc:
            rprint(f"[bold red]Error:[/] {exc}")
            exit(1)
        if tls["expired"]:
            rprint("[bold yellow]The certificate is expired.[/]")
        try:
            username, password = resolve_protection(args.protected, args.username, args.password)
        except ValueError as exc:
            rprint(f"[bold red]Error:[/] {exc}")
            exit(1)
        tls_args = {
            "cert_file": tls["cert"],
            "key_file": tls["key"],
            "tls_generated": tls["generated"],
            "tls_self_signed": tls["self_signed"],
            "allow_sensitive": args.allow_sensitive,
            "page_title": args.title,
        }
        try:
            if args.command == 'upload':
                file_share(
                    directory=args.dir,
                    host=the_host,
                    port=args.port,
                    username=username,
                    password=password,
                    upload=True,
                    max_upload_mb=args.max_upload_mb,
                    **tls_args,
                )
            elif args.dir:
                file_share(directory=args.dir, host=the_host, port=args.port, username=username, password=password, **tls_args)
            else:
                rprint(f"[bold white]Sharing file: {args.file}[/]")
                if not os.path.isfile(args.file):
                    rprint(f"[bold red]Error:[/] The file [yellow]{args.file}[/] does not exist or is not a file.")
                    exit(1)
                dir_path = generate_temporary_dir(the_path=".")
                file_share(directory=dir_path, file=args.file, host=the_host, port=args.port, username=username, password=password, **tls_args)
        except Exception as exc:
            report_server_error(exc)
    elif args.command == 'recieve':
        rprint("[bold green]Recieve feature is not implemented yet.[/]")

if __name__ == "__main__":
    main()
