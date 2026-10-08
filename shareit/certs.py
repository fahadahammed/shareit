"""Self-signed certificates for the local HTTPS server."""

import datetime
import ipaddress
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateError(Exception):
    """A certificate file is missing, invalid, or refused."""


def default_cert_dir():
    return os.path.join(os.path.expanduser("~"), ".shareit", "certs")


def default_cert_paths(directory=None):
    directory = directory or default_cert_dir()
    return (
        os.path.join(directory, "shareit.crt"),
        os.path.join(directory, "shareit.key"),
    )


def _utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _certificate_time(certificate, name):
    utc_value = getattr(certificate, f"{name}_utc", None)
    if utc_value is not None:
        return _utc(utc_value)
    return _utc(getattr(certificate, name))


def subject_alternative_names(names):
    """Build SAN entries from host names and IP addresses."""
    entries = []
    seen = set()
    for name in names:
        if name is None:
            continue
        name = str(name).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        try:
            ip_value = ipaddress.ip_address(name)
        except ValueError:
            if len(name) > 253 or any(character.isspace() for character in name):
                raise CertificateError(f"Invalid certificate name: {name}")
            try:
                entries.append(x509.DNSName(name))
            except ValueError as exc:
                raise CertificateError(f"Invalid certificate name: {name}") from exc
        else:
            if ip_value.is_unspecified:
                continue
            entries.append(x509.IPAddress(ip_value))
    if not entries:
        raise CertificateError("Certificate needs at least one host name or IP address")
    return entries


def generate_self_signed(
    cert_path,
    key_path,
    days=365,
    common_name="shareit",
    names=None,
    force=False,
    not_before=None,
    not_after=None,
):
    """Write a self-signed certificate and an unencrypted private key."""
    common_name = (common_name or "").strip()
    if not common_name or len(common_name) > 64:
        raise CertificateError("Certificate common name must be 1 to 64 characters.")
    if days <= 0:
        raise CertificateError("Certificate lifetime must be at least 1 day.")
    if days > 3650:
        raise CertificateError("Certificate lifetime cannot be longer than 3650 days.")
    if not force and (os.path.exists(cert_path) or os.path.exists(key_path)):
        raise CertificateError("Certificate already exists. Use --force to replace it.")

    now = datetime.datetime.now(datetime.timezone.utc)
    starts = _utc(not_before) if not_before else now
    ends = _utc(not_after) if not_after else starts + datetime.timedelta(days=days)
    if ends <= starts:
        raise CertificateError("Certificate expiry must be after the start time.")

    combined_names = ["localhost", "127.0.0.1", "::1", *(names or [])]
    alternative_names = subject_alternative_names(combined_names)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    distinguished_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(distinguished_name)
        .issuer_name(distinguished_name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(starts)
        .not_valid_after(ends)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(alternative_names), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    _write_certificate_pair(cert_path, key_path, certificate, private_key)
    return cert_path, key_path


def _ensure_directory(path):
    if os.path.isdir(path):
        return
    os.makedirs(path, exist_ok=True)
    os.chmod(path, 0o700)


def _write_certificate_pair(cert_path, key_path, certificate, private_key):
    _ensure_directory(os.path.dirname(os.path.abspath(cert_path)))
    _ensure_directory(os.path.dirname(os.path.abspath(key_path)))
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_private_file(key_path, key_bytes, 0o600)
    _write_private_file(cert_path, cert_bytes, 0o644)


def _write_private_file(path, data, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def load_certificate(cert_path):
    if not os.path.isfile(cert_path):
        raise CertificateError(f"Certificate not found: {cert_path}")
    try:
        with open(cert_path, "rb") as handle:
            return x509.load_pem_x509_certificate(handle.read())
    except ValueError as exc:
        raise CertificateError(f"Could not read certificate: {cert_path}") from exc


def load_private_key(key_path):
    if not os.path.isfile(key_path):
        raise CertificateError(f"Private key not found: {key_path}")
    try:
        with open(key_path, "rb") as handle:
            return serialization.load_pem_private_key(handle.read(), password=None)
    except TypeError as exc:
        raise CertificateError("Password-protected private keys are not supported.") from exc
    except ValueError as exc:
        raise CertificateError(f"Could not read private key: {key_path}") from exc


def certificate_matches_key(cert_path, key_path):
    certificate = load_certificate(cert_path)
    private_key = load_private_key(key_path)
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return certificate_public == key_public


def describe_certificate(cert_path):
    certificate = load_certificate(cert_path)
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    dns_names = []
    ip_addresses = []
    try:
        alternative_names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = list(alternative_names.get_values_for_type(x509.DNSName))
        ip_addresses = [str(ip) for ip in alternative_names.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    not_before = _certificate_time(certificate, "not_valid_before")
    not_after = _certificate_time(certificate, "not_valid_after")
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    return {
        "common_name": str(common_names[0].value) if common_names else "",
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "self_signed": certificate.issuer == certificate.subject,
        "not_before": not_before,
        "not_after": not_after,
        "expired": not_after <= datetime.datetime.now(datetime.timezone.utc),
        "dns_names": dns_names,
        "ip_addresses": ip_addresses,
        "fingerprint_sha256": ":".join(fingerprint[index:index + 2] for index in range(0, len(fingerprint), 2)),
    }


def ensure_server_certificate(cert_path, key_path, names, days=365, common_name="shareit"):
    """Reuse a current certificate pair, or write a new self-signed one."""
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        try:
            details = describe_certificate(cert_path)
            matches = certificate_matches_key(cert_path, key_path)
        except CertificateError:
            details = None
            matches = False
        if details and matches and not details["expired"]:
            return cert_path, key_path, False
    generate_self_signed(
        cert_path,
        key_path,
        days=days,
        common_name=common_name,
        names=names,
        force=True,
    )
    return cert_path, key_path, True


def resolve_certificate_pair(cert_path, key_path):
    """Return explicit paths, or the default pair when both are omitted."""
    if bool(cert_path) != bool(key_path):
        raise CertificateError("Provide both --cert and --key, or neither to use the default location.")
    if cert_path and key_path:
        return cert_path, key_path
    return default_cert_paths()


def resolve_https_files(https, cert_path, key_path, names, directory=None):
    """Choose the certificate pair for a server, generating one when needed."""
    if not https and not cert_path and not key_path:
        return {"cert": None, "key": None, "generated": False, "expired": False, "self_signed": False}
    if bool(cert_path) != bool(key_path):
        raise CertificateError("Provide both --cert and --key, or neither to use a generated certificate.")
    if cert_path and key_path:
        if not certificate_matches_key(cert_path, key_path):
            raise CertificateError("Certificate and private key do not match.")
        details = describe_certificate(cert_path)
        return {
            "cert": os.path.abspath(cert_path),
            "key": os.path.abspath(key_path),
            "generated": False,
            "expired": details["expired"],
            "self_signed": details["self_signed"],
        }
    default_cert, default_key = default_cert_paths(directory)
    saved_cert, saved_key, generated = ensure_server_certificate(default_cert, default_key, names)
    details = describe_certificate(saved_cert)
    return {
        "cert": saved_cert,
        "key": saved_key,
        "generated": generated,
        "expired": details["expired"],
        "self_signed": details["self_signed"],
    }


def remove_certificate_files(cert_path, key_path):
    """Delete a PEM certificate and its private key after checking both files."""
    if not os.path.exists(cert_path) and not os.path.exists(key_path):
        raise CertificateError("No certificate files found.")
    if os.path.exists(cert_path):
        load_certificate(cert_path)
    if os.path.exists(key_path):
        load_private_key(key_path)
    removed = []
    for path in (cert_path, key_path):
        if os.path.isfile(path):
            os.remove(path)
            removed.append(path)
    return removed


def configure_https(httpd, cert_path, key_path):
    """Wrap an already bound server socket in TLS."""
    if not certificate_matches_key(cert_path, key_path):
        raise CertificateError("Certificate and private key do not match.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
