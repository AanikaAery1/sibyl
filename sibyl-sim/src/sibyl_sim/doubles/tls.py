"""Dev-only TLS for the doubles: a throwaway CA plus a leaf certificate, generated at start.

The snapshot contract requires `https://` provider base URLs, so the doubles serve TLS on
18082. Clients (the gateway in compose, tests) trust the CA at `ca_path`, which the sim
logs and serves at `GET /_sim/tls/ca.pem` on its control port. Keys never leave the
directory (mode 0600) and are regenerated on every start; nothing here is for production.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_HOSTS = ("127.0.0.1", "localhost", "sim", "::1")
VALIDITY = timedelta(days=30)


@dataclass(frozen=True)
class DevTls:
    ca_path: Path
    cert_path: Path
    key_path: Path


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sibyl-sim (dev only)"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _san(hosts: tuple[str, ...]) -> x509.SubjectAlternativeName:
    names: list[x509.GeneralName] = []
    for host in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    return x509.SubjectAlternativeName(names)


def _write(path: Path, data: bytes, mode: int) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def generate(directory: str | Path, hosts: tuple[str, ...] = DEFAULT_HOSTS) -> DevTls:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    now = datetime.now(UTC) - timedelta(minutes=5)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("sibyl-sim dev CA"))
        .issuer_name(_name("sibyl-sim dev CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name(hosts[0]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + VALIDITY)
        .add_extension(_san(hosts), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    tls = DevTls(out / "ca.pem", out / "server.pem", out / "server.key")
    _write(tls.ca_path, ca_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    _write(tls.cert_path, leaf.public_bytes(serialization.Encoding.PEM), 0o644)
    _write(
        tls.key_path,
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    return tls
