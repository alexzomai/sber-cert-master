"""TLS material: CA bundle, client certificate import/inspection, CSR generation (via openssl CLI)."""

from __future__ import annotations

import hashlib
import os
import re
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from importlib import resources

# Pinned SHA-256 fingerprints of trust anchors shipped in sber_cert_master/ca/.
# Sources: gu-st.ru (Минцифры), cdn-app.sberdevices.ru (chain_prom.zip, sberca-root-ext.crt from Sber API docs).
CA_PINS = {
    "russian_trusted_root_ca.pem": "d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31",
    "russian_trusted_sub_ca.pem": "bbbde2103e790b999ec62bd03cf625a5a2e7c316e10afe6a490eedead8b3fd9b",
    "sberca_root_ext.pem": "e77059cd24606a8a24043100ec7e23db917bfc85054ee08b79ca71b43b8f4690",
    "sberapi_root_ca.pem": "4908f11ad2cb9d2c8e92fec594accc208ea0e36f77a9179885d532fe48290681",
    "sberapi_ca.pem": "b0a88dc593160591b947c451793846f17f634d6e9a46140d382167dda7ea6d28",
}

# Official download locations, used by `update-ca`. Roots must match CA_PINS; others must chain to a pinned root.
CA_SOURCES = {
    "russian_trusted_root_ca.pem": "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt",
    "russian_trusted_sub_ca.pem": "https://gu-st.ru/content/lending/russian_trusted_sub_ca_pem.crt",
    "sberca_root_ext.pem": "https://cdn-app.sberdevices.ru/misc/0.0.0/assets/bsm-docs/6020194e_sberca-root-ext.crt",
}
ROOTS = {"russian_trusted_root_ca.pem", "sberca_root_ext.pem", "sberapi_root_ca.pem"}

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.S)


class TLSError(Exception):
    pass


def openssl(*args: str, input: bytes | None = None, env: dict | None = None) -> bytes:
    try:
        r = subprocess.run(["openssl", *args], input=input, capture_output=True, check=False,
                           env={**os.environ, **(env or {})}, timeout=60)
    except FileNotFoundError:
        raise TLSError("не найден openssl") from None
    if r.returncode != 0:
        raise TLSError(f"openssl {args[0]}: {r.stderr.decode(errors='replace').strip()[:500]}")
    return r.stdout


def split_pem(data: bytes) -> list[bytes]:
    """Normalise PEM blocks (bank files come with CRLF and without trailing newline)."""
    return [b.replace(b"\r\n", b"\n").strip() + b"\n" for b in PEM_RE.findall(data)]


def to_pem(data: bytes) -> bytes:
    blocks = split_pem(data)
    if blocks:
        return b"".join(blocks)
    return openssl("x509", "-inform", "DER", "-outform", "PEM", input=data)  # DER .cer


def fingerprint(pem_block: bytes) -> str:
    der = ssl.PEM_cert_to_DER_cert(pem_block.decode())
    return hashlib.sha256(der).hexdigest()


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    not_before: float
    not_after: float
    sha256: str


def cert_info(pem_block: bytes) -> CertInfo:
    out = openssl("x509", "-noout", "-subject", "-issuer", "-serial", "-startdate", "-enddate",
                  "-nameopt", "RFC2253", input=pem_block).decode()
    f = dict(line.split("=", 1) for line in out.strip().splitlines() if "=" in line)
    return CertInfo(
        subject=f.get("subject", ""), issuer=f.get("issuer", ""), serial=f.get("serial", ""),
        not_before=ssl.cert_time_to_seconds(f["notBefore"]), not_after=ssl.cert_time_to_seconds(f["notAfter"]),
        sha256=fingerprint(pem_block),
    )


def is_ca(pem_block: bytes) -> bool:
    out = openssl("x509", "-noout", "-ext", "basicConstraints", input=pem_block).decode()
    return "CA:TRUE" in out


def builtin_ca_bundle() -> bytes:
    pkg = resources.files("sber_cert_master") / "ca"
    out = []
    for name, pin in CA_PINS.items():
        block = split_pem((pkg / name).read_bytes())[0]
        if fingerprint(block) != pin:
            raise TLSError(f"встроенный сертификат {name} не совпадает с отпечатком")
        out.append(block)
    return b"".join(out)


def verify_chain(leaf: bytes, intermediates: bytes, ca_file: str) -> None:
    with tempfile.TemporaryDirectory(dir=os.path.dirname(ca_file) or None) as d:
        leaf_p, untr_p = os.path.join(d, "leaf.pem"), os.path.join(d, "untrusted.pem")
        with open(leaf_p, "wb") as f:
            f.write(leaf)
        # Only the given file is trusted: no system CA directory/store.
        args = ["verify", "-no-CApath", "-no-CAstore", "-CAfile", ca_file]
        if intermediates.strip():
            with open(untr_p, "wb") as f:
                f.write(intermediates)
            args += ["-untrusted", untr_p]
        openssl(*args, leaf_p)


def public_key(pem: bytes, is_key: bool) -> bytes:
    if is_key:
        return openssl("pkey", "-pubout", input=pem)
    return openssl("x509", "-noout", "-pubkey", input=pem)


@dataclass
class ClientMaterial:
    cert_chain: bytes  # leaf first, then intermediates
    key: bytes  # unencrypted PEM private key
    info: CertInfo


def load_p12(p12: bytes, password: str) -> ClientMaterial:
    env = {"SCM_P12_PASS": password}
    with tempfile.NamedTemporaryFile(prefix="scm-", suffix=".p12") as f:
        f.write(p12)
        f.flush()
        last = None
        for legacy in ([], ["-legacy"]):
            try:
                leaf = openssl("pkcs12", *legacy, "-in", f.name, "-passin", "env:SCM_P12_PASS",
                               "-clcerts", "-nokeys", env=env)
                cas = openssl("pkcs12", *legacy, "-in", f.name, "-passin", "env:SCM_P12_PASS",
                              "-cacerts", "-nokeys", env=env)
                key = openssl("pkcs12", *legacy, "-in", f.name, "-passin", "env:SCM_P12_PASS",
                              "-nocerts", "-noenc", env=env)
                break
            except TLSError as e:
                last = e
        else:
            raise TLSError(f"не удалось открыть .p12 (пароль?): {last}")
    key = openssl("pkey", input=key)  # strip bag attributes
    return build_material(leaf, cas, key)


def build_material(cert: bytes, extra_chain: bytes, key: bytes) -> ClientMaterial:
    blocks = split_pem(to_pem(cert))
    if not blocks:
        raise TLSError("нет сертификата")
    key = openssl("pkey", input=key)
    kpub = public_key(key, True)
    leaf = next((b for b in blocks if public_key(b, False) == kpub), None)
    if leaf is None:
        raise TLSError("закрытый ключ не соответствует сертификату")
    chain = [b for b in blocks if b != leaf] + [b for b in split_pem(extra_chain) if b not in blocks]
    # Send only intermediates (not self-signed roots) along with the leaf.
    inter = [b for b in chain if cert_info(b).subject != cert_info(b).issuer]
    return ClientMaterial(cert_chain=leaf + b"".join(inter), key=key, info=cert_info(leaf))


def make_csr(client_id: str, inn: str, ogrn: str, locality: str, region: str, key_out: str, csr_out: str) -> bytes:
    """RSA-2048 key + CSR with the attribute order required by Sber API (prod)."""
    for name, val in (("inn", inn), ("ogrn", ogrn), ("locality", locality), ("region", region), ("client_id", client_id)):
        if not re.fullmatch(r"[A-Za-z0-9 .\-]+", val):
            raise TLSError(f"{name}: допустимы только латинские буквы, цифры, пробел, точка, дефис")
    subj = (f"/CN=CI02745214-PROM-{client_id}/OU=sm/OU=sbbapi-client-1y/OU={inn}/OU=CI02741778"
            f"/OU={ogrn}/L={locality}/ST={region}/C=RU")
    old = os.umask(0o077)
    try:
        openssl("req", "-new", "-newkey", "rsa:2048", "-noenc", "-keyout", key_out, "-out", csr_out,
                "-subj", subj, "-sha256")
    finally:
        os.umask(old)
    return openssl("req", "-in", csr_out, "-noout", "-subject", "-nameopt", "RFC2253")
