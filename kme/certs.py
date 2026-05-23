"""Self-signed CA and certificate generation for KME mTLS.

ETSI GS QKD 014 mandates mutual TLS between an SAE and its KME, with the SAE
identified by the Common Name (CN) of its client certificate. This module
generates, entirely in Python via the ``cryptography`` library:

  * one local Certificate Authority (the trust root for the demo),
  * a server certificate for each KME,
  * a client certificate per SAE whose CN *is* the SAE ID.

No OpenSSL command line, no native build step -- everything is pure
``cryptography``, which keeps the project's "pure Python, pip-installable"
property intact. This is a demo CA: keys are unencrypted on disk and the CA is
not a real trust anchor, which is stated explicitly rather than implied.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_ONE_YEAR = datetime.timedelta(days=365)


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def create_ca(out_dir: Path) -> tuple[Path, Path]:
    """Create the demo CA. Returns ``(ca_cert_path, ca_key_path)``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ca_key = _new_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "qtls-qkd-demo-CA")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _ONE_YEAR)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_path = out_dir / "ca.crt"
    ca_key_path = out_dir / "ca.key"
    _write_cert(ca_cert_path, ca_cert)
    _write_key(ca_key_path, ca_key)
    return ca_cert_path, ca_key_path


def _load_ca(ca_cert_path: Path, ca_key_path: Path):
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(
        ca_key_path.read_bytes(), password=None
    )
    return ca_cert, ca_key


def issue_cert(
    out_dir: Path,
    common_name: str,
    ca_cert_path: Path,
    ca_key_path: Path,
    is_server: bool,
) -> tuple[Path, Path]:
    """Issue a leaf certificate signed by the demo CA.

    For server certs ``common_name`` is the host (e.g. ``localhost``); for SAE
    client certs ``common_name`` is the **SAE ID**, which the KME later reads
    back as the caller's identity. Returns ``(cert_path, key_path)``.
    """
    ca_cert, ca_key = _load_ca(ca_cert_path, ca_key_path)
    leaf_key = _new_key()
    now = datetime.datetime.now(datetime.timezone.utc)

    eku = (
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
        if is_server
        else x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _ONE_YEAR)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(eku, critical=False)
    )
    if is_server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )

    leaf_cert = builder.sign(ca_key, hashes.SHA256())

    safe_name = common_name.replace("/", "_")
    cert_path = out_dir / f"{safe_name}.crt"
    key_path = out_dir / f"{safe_name}.key"
    _write_cert(cert_path, leaf_cert)
    _write_key(key_path, leaf_key)
    return cert_path, key_path
