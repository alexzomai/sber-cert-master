"""In-process fake of the Sber API OAuth endpoints, with mTLS and fault injection.

Models the documented behaviour: access_token 60 min, refresh_token rotates on each use and the used
one stays valid as a reserve for 2h, client_secret has a lifetime and can be changed via API.
"""

from __future__ import annotations

import json
import os
import secrets
import ssl
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_pki(d: str, p12_password: str = "p12pass") -> dict:
    """Test CA, server cert for 127.0.0.1, two client certs (one as .p12)."""
    def run(*a):
        subprocess.run(["openssl", *a], check=True, capture_output=True)

    j = lambda n: os.path.join(d, n)  # noqa: E731
    run("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-keyout", j("ca.key"), "-out", j("ca.pem"),
        "-days", "3650", "-subj", "/CN=Test SberAPI Root CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    with open(j("san.ext"), "w") as f:
        f.write("subjectAltName=IP:127.0.0.1,DNS:localhost\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n")
    with open(j("client.ext"), "w") as f:
        f.write("keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n"
                "authorityKeyIdentifier=keyid\n")
    run("req", "-newkey", "rsa:2048", "-noenc", "-keyout", j("server.key"), "-out", j("server.csr"), "-subj", "/CN=localhost")
    run("x509", "-req", "-in", j("server.csr"), "-CA", j("ca.pem"), "-CAkey", j("ca.key"), "-CAcreateserial",
        "-out", j("server.pem"), "-days", "365", "-extfile", j("san.ext"))
    for name, days in (("client", "365"), ("client2", "700"), ("client_short", "5")):
        run("req", "-newkey", "rsa:2048", "-noenc", "-keyout", j(f"{name}.key"), "-out", j(f"{name}.csr"),
            "-subj", f"/CN=CI02745214-PROM-12345/OU=sm/OU={name}")
        run("x509", "-req", "-in", j(f"{name}.csr"), "-CA", j("ca.pem"), "-CAkey", j("ca.key"), "-CAcreateserial",
            "-out", j(f"{name}.pem"), "-days", days, "-extfile", j("client.ext"))
    run("pkcs12", "-export", "-inkey", j("client.key"), "-in", j("client.pem"), "-certfile", j("ca.pem"),
        "-out", j("client.p12"), "-passout", f"pass:{p12_password}")
    return {k: j(k) for k in ("ca.pem", "server.pem", "server.key", "client.p12", "client.pem", "client.key",
                              "client2.pem", "client2.key", "client_short.pem", "client_short.key")}


class Bank:
    def __init__(self, clock, client_id="12345", secret="InitialSecret123", secret_lifetime=40 * 86400):
        self.clock = clock
        self.lock = threading.Lock()
        self.client_id = client_id
        self.secret_lifetime = secret_lifetime
        self.secrets = {secret: clock() + secret_lifetime}
        self.refresh_tokens: dict[str, dict] = {}
        self.access_tokens: dict[str, float] = {}
        self.calls: dict[str, int] = {}
        self.faults: list[str] = []  # 'drop' (apply, then drop connection), '500' (fail before applying)
        self.deferred_secret: str | None = None  # 'late' fault: change applied only when apply_deferred() is called
        self.echo_request_in_errors = False
        self.redirect_to: str | None = None
        self.token_delay = 0.0  # seconds; the token request is applied immediately, the answer comes late
        self.allowed_cert_serials: set[str] | None = None
        self.revoked = False

    def issue_refresh_token(self) -> str:
        rt = secrets.token_hex(19)
        self.refresh_tokens[rt] = {"status": "active", "issued_at": self.clock()}
        return rt

    def _pair(self) -> dict:
        # Like production: issuing a new pair immediately revokes previously issued access tokens.
        self.access_tokens.clear()
        at = secrets.token_hex(19)
        self.access_tokens[at] = self.clock() + 3600
        return {"access_token": at, "token_type": "Bearer", "expires_in": 3600,
                "refresh_token": self.issue_refresh_token(), "scope": "openid GET_STATEMENT_ACCOUNT", "id_token": "x.y.z"}

    def secret_ok(self, s: str) -> bool:
        exp = self.secrets.get(s)
        return exp is not None and (exp is True or exp > self.clock())

    def refresh(self, form: dict) -> tuple[int, dict]:
        if form.get("client_id") != self.client_id or not self.secret_ok(form.get("client_secret", "")):
            return 401, {"error": "invalid_client", "error_description": "bad client credentials"}
        if len(form.get("refresh_token", "")) > 256:
            return 400, {"error": "invalid_request", "error_description": "malformed request"}
        rt = self.refresh_tokens.get(form.get("refresh_token", ""))
        now = self.clock()
        if self.revoked or rt is None:
            return 400, {"error": "invalid_grant", "error_description": "unknown refresh_token"}
        if rt["status"] == "reserve" and now > rt["reserve_until"]:
            return 400, {"error": "invalid_grant", "error_description": "reserve expired"}
        if rt["status"] == "active" and now - rt["issued_at"] > 180 * 86400:
            return 400, {"error": "invalid_grant", "error_description": "refresh_token expired"}
        if rt["status"] == "active":
            rt["status"] = "reserve"
            rt["reserve_until"] = now + 2 * 3600
        return 200, self._pair()

    def change_secret(self, q: dict) -> tuple[int, dict]:
        if self.access_tokens.get(q.get("access_token", ""), 0) < self.clock():
            return 401, {"error": "invalid_token"}
        if not self.secret_ok(q.get("client_secret", "")):
            return 403, {"error": "invalid_client"}
        new = q.get("new_client_secret", "")
        if not 8 <= len(new) <= 256:
            return 400, {"error": "invalid_request"}
        self.secrets = {new: self.clock() + self.secret_lifetime}
        return 200, {"clientSecretExpiration": int(self.secret_lifetime / 86400)}

    def apply_deferred(self) -> None:
        if self.deferred_secret:
            self.secrets = {self.deferred_secret: self.clock() + self.secret_lifetime}
            self.deferred_secret = None

    def perpetual(self, body: dict) -> tuple[int, dict]:
        if not self.secret_ok(body.get("clientSecret", "")):
            return 403, {"cause": "CERTIFICATE_ACCESS_EXCEPTION", "message": "denied"}
        new = secrets.token_hex(19)
        self.secrets = {new: True}
        return 200, {"clientSecret": new}


class FakeSber:
    def __init__(self, pki: dict, bank: Bank):
        self.bank = bank
        bank_ref = bank

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, obj, ctype="application/json"):
                body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self, fn):
                b = bank_ref
                if b.allowed_cert_serials is not None:
                    cert = self.connection.getpeercert()
                    # compare serials as numbers: getpeercert() keeps leading zeros, other sources do not
                    def num(x):
                        try:
                            return int(x, 16)
                        except (TypeError, ValueError):
                            return None
                    allowed = {num(x) for x in b.allowed_cert_serials} - {None}
                    if num(cert.get("serialNumber")) not in allowed:
                        return self._send(403, {"cause": "CERTIFICATE_ACCESS_EXCEPTION"})
                with b.lock:
                    name = self.path.split("?")[0]
                    b.calls[name] = b.calls.get(name, 0) + 1
                    fault = b.faults.pop(0) if b.faults else None
                    if fault == "500":
                        return self._send(500, {"error": "unknown_exception"})
                    if fault == "late":  # request accepted, applied later, response never arrives
                        b.deferred_secret = dict(urllib.parse.parse_qsl(self.path.partition("?")[2])).get("new_client_secret")
                        self.connection.shutdown(2)
                        return
                    status, obj = fn()
                    if b.echo_request_in_errors and status >= 400:
                        obj = {"error": obj.get("error", ""), "error_description": "bad request: " + self.path + " " + self._raw}
                if name == "/ic/sso/api/v2/oauth/token" and b.token_delay:
                    import time as _t
                    _t.sleep(b.token_delay)
                if fault == "drop":
                    self.connection.shutdown(2)
                    return
                self._send(status, obj)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                self._raw = raw.decode(errors="replace")
                path, _, qs = self.path.partition("?")
                if path == "/ic/sso/api/v2/oauth/token":
                    form = dict(urllib.parse.parse_qsl(raw.decode()))
                    if form.get("grant_type") == "refresh_token":
                        return self._handle(lambda: bank_ref.refresh(form))
                    if form.get("grant_type") == "authorization_code":
                        def code():
                            if form.get("code") != "GOODCODE" or not bank_ref.secret_ok(form.get("client_secret", "")):
                                return 400, {"error": "invalid_grant"}
                            return 200, bank_ref._pair()
                        return self._handle(code)
                if path == "/ic/sso/api/v1/change-client-secret":
                    q = dict(urllib.parse.parse_qsl(qs))
                    return self._handle(lambda: bank_ref.change_secret(q))
                if path == "/fintech/api/applications/secrets/v1/refresh-client-secret":
                    body = json.loads(raw or b"{}")
                    return self._handle(lambda: bank_ref.perpetual(body))
                self._send(404, {"error": "not_found"})

            def do_GET(self):
                self._raw = ""
                if bank_ref.redirect_to:
                    self.send_response(302)
                    self.send_header("Location", bank_ref.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/fintech/api/ic/sso/api/v2/oauth/user-info":
                    tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ")

                    def ui():
                        if bank_ref.access_tokens.get(tok, 0) < bank_ref.clock():
                            return 401, {"error": "invalid_token"}
                        return 200, {"sub": "user"}
                    return self._handle(ui)
                self._send(404, {"error": "not_found"})

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pki["server.pem"], pki["server.key"])
        ctx.load_verify_locations(pki["ca.pem"])
        ctx.verify_mode = ssl.CERT_REQUIRED  # mTLS like the real gateway
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
