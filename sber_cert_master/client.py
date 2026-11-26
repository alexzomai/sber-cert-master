"""Minimal mTLS HTTP client for the Sber API endpoints this tool needs."""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request


class SberError(Exception):
    pass


class Transient(SberError):
    """Network error, timeout, 5xx, 429: the bank may or may not have applied the request."""


class Rejected(SberError):
    """Definitive 4xx answer from the bank."""

    def __init__(self, status: int, error: str, description: str = "", body: str = ""):
        self.status = status
        self.error = error  # allowlisted code or ""
        hint = HINTS.get(error, "")
        super().__init__(f"HTTP {status} {error}".strip() + (f" ({hint})" if hint else ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Credentials must never follow a redirect to another origin (or a downgrade)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError(3xx), handled as a rejection


# Error codes documented for the endpoints we call. Nothing else from a bank response ever reaches
# logs, state or alerts: descriptions and bodies may echo the request (which carries credentials).
KNOWN_ERRORS = frozenset({
    "invalid_request", "unsupported_grant_type", "invalid_grant", "invalid_client", "invalid_token",
    "unsupported_token_type", "unknown_exception", "bad_request", "access_denied", "unauthorized_client",
    "invalid_scope", "server_error", "temporarily_unavailable",
    "VALIDATION_FAULT", "CERTIFICATE_ACCESS_EXCEPTION", "UNKNOWN_EXCEPTION", "UNAUTHORIZED", "ACCESS_DENIED",
    "certificateNotFound",  # observed on prod: {"errorCode": "certificateNotFound", "errorMsg": ...}
})

# Operator hints for codes whose meaning is not obvious.
HINTS = {
    "certificateNotFound": "TLS-сертификат не привязан к этому client_id (ЛК Sber API -> Сертификаты шифрования)",
    "CERTIFICATE_ACCESS_EXCEPTION": "TLS-сертификат не в белом списке или истёк (ЛК Sber API -> Сертификаты шифрования)",
    "invalid_client": "client_secret отклонён",
    "invalid_grant": "refresh_token недействителен — нужна повторная авторизация",
}


class _ExplicitProxy(urllib.request.ProxyHandler):
    """Proxy from our config only: neither HTTPS_PROXY nor NO_PROXY from the environment applies."""

    def __init__(self, proxy: str):
        super().__init__({"https": proxy} if proxy else {})

    def proxy_open(self, req, proxy, type):
        orig_type = req.type
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)
        if proxy_type is None:
            proxy_type = orig_type
        if user or password:
            raise ValueError("учётные данные в proxy не поддерживаются")
        req.set_proxy(hostport, proxy_type)  # no proxy_bypass() check: config is authoritative
        return None


def _error_code(body: bytes) -> str:
    """Allowlisted error code from a bank response, or '' (unknown codes are not passed through)."""
    try:
        obj = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(obj, dict):
        return ""
    err = obj.get("error") or obj.get("cause") or obj.get("errorCode") or ""
    return err if isinstance(err, str) and err in KNOWN_ERRORS else ""


def _number(value, lo: float, hi: float) -> float | None:
    """Bank-supplied numeric metadata, or None if it is not a sane number (never echoed anywhere)."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        n = float(value)
    except (ValueError, OverflowError):
        return None
    return n if lo <= n <= hi else None


_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{8,4096}")
_SCOPE_RE = re.compile(r"[A-Za-z0-9_ .:-]{0,8000}")


def _transport_reason(exc: BaseException) -> str:
    """Locally generated description of a transport failure (never includes request data)."""
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return f"не удалось проверить сертификат банка ({reason.verify_message})"
    if isinstance(reason, ssl.SSLError):
        return f"ошибка TLS ({reason.reason or type(reason).__name__})"
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "таймаут"
    if isinstance(reason, OSError) and reason.errno:
        return f"{type(reason).__name__} errno={reason.errno}"
    return type(reason).__name__


class SberClient:
    def __init__(self, base_url: str, cert_file: str, key_file: str, ca_file: str, timeout: float = 30.0,
                 proxy: str = ""):
        if not base_url.lower().startswith("https://"):
            raise ValueError("Sber API base URL должен быть https://")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_file, key_file)
        # Proxy only when configured explicitly. Environment proxies (HTTPS_PROXY, ...) are ignored: a
        # general-purpose proxy can make the mTLS handshake to the bank slow enough to time out.
        self._opener = urllib.request.build_opener(_ExplicitProxy(proxy),
                                                   urllib.request.HTTPSHandler(context=ctx), _NoRedirect())

    def request(self, method: str, path: str, *, query: dict | None = None, form: dict | None = None,
                json_body: dict | None = None, headers: dict | None = None) -> tuple[int, bytes]:
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        hdrs = {"Accept": "application/json"}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            data = json.dumps(json_body).encode()
            hdrs["Content-Type"] = "application/json"
        elif method == "POST":
            data = b""
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            with e:
                body = e.read() or b""
            err = _error_code(body)
            if e.code >= 500 or e.code in (408, 425, 429):
                raise Transient(f"HTTP {e.code} от банка {err}".strip()) from None
            raise Rejected(e.code, err, "", "") from None
        except ValueError as e:  # http.client.InvalidURL etc.; message may embed the URL
            raise Transient(f"некорректный запрос: {type(e).__name__}") from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError, OSError,
                http.client.HTTPException) as e:
            raise Transient(f"сеть/TLS: {_transport_reason(e)}") from None

    def _json(self, status: int, body: bytes) -> dict:
        try:
            obj = json.loads(body)
        except ValueError:
            raise Transient(f"HTTP {status}: ответ не JSON") from None
        if not isinstance(obj, dict):
            raise Transient(f"HTTP {status}: неожиданный ответ")
        return obj

    # --- OAuth -----------------------------------------------------------------

    def token_refresh(self, client_id: str, client_secret: str, refresh_token: str) -> dict:
        st, body = self.request("POST", "/ic/sso/api/v2/oauth/token", form={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        })
        return self._token_response(st, body)

    def token_by_code(self, client_id: str, client_secret: str, code: str, redirect_uri: str,
                      code_verifier: str | None = None) -> dict:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            form["code_verifier"] = code_verifier
        st, body = self.request("POST", "/ic/sso/api/v2/oauth/token", form=form)
        return self._token_response(st, body)

    def _token_response(self, status: int, body: bytes) -> dict:
        obj = self._json(status, body)
        if not isinstance(obj.get("access_token"), str) or not isinstance(obj.get("refresh_token"), str) \
                or not obj["access_token"] or not obj["refresh_token"]:
            # 2xx without tokens: outcome unclear, treat as transient so we retry with the same refresh_token.
            raise Transient(f"HTTP {status}: в ответе нет токенов {_error_code(body)}".strip())
        if not _TOKEN_RE.fullmatch(obj["access_token"]) or not _TOKEN_RE.fullmatch(obj["refresh_token"]):
            raise Transient(f"HTTP {status}: токены в ответе имеют неожиданный формат")
        # Only validated, structured values leave this module.
        scope = obj.get("scope")
        return {
            "access_token": obj["access_token"],
            "refresh_token": obj["refresh_token"],
            "expires_in": _number(obj.get("expires_in"), 30, 31 * 86400) or 3600.0,
            "scope": scope if isinstance(scope, str) and _SCOPE_RE.fullmatch(scope) else None,
        }

    def change_client_secret(self, access_token: str, client_id: str, client_secret: str,
                             new_client_secret: str) -> dict:
        # Per spec all parameters are query parameters of a POST.
        st, body = self.request("POST", "/ic/sso/api/v1/change-client-secret", query={
            "access_token": access_token,
            "client_id": client_id,
            "client_secret": client_secret,
            "new_client_secret": new_client_secret,
        })
        days = None
        if body.strip():
            try:
                obj = json.loads(body)
                days = _number(obj.get("clientSecretExpiration"), 1, 3660) if isinstance(obj, dict) else None
            except ValueError:
                pass  # 2xx: the change is applied; the lifetime falls back to the documented 40 days
        return {"clientSecretExpiration": days}

    def user_info(self, access_token: str) -> bytes:
        _, body = self.request("GET", "/fintech/api/ic/sso/api/v2/oauth/user-info",
                               headers={"Authorization": f"Bearer {access_token}", "Accept": "application/jwt"})
        return body
