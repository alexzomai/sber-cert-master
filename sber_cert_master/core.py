"""Credential lifecycle for one Sber API profile (client_id + user).

Invariants:
  * Only this module ever sends refresh_token / client_secret to the bank, and always under an
    exclusive per-profile file lock -> no two refreshes race and invalidate each other's tokens.
  * A working credential is never overwritten by an unproven one. New candidates (imported
    refresh_token, new client_secret) are staged next to the live value and committed only after
    the bank accepted them; they are persisted *before* they are sent.
  * Every client_secret we ever generated or were given stays in a short history, so a change the
    bank applied late (lost/slow response) can still be recovered by trying the history.
  * After a transient failure the same refresh_token is retried (the bank keeps the used one as a
    reserve for 2h and asks to retry within 1h).
  * TLS material lives in immutable generation directories switched by one atomic symlink.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import os
import secrets
import shutil
import stat
import string
import time
import urllib.parse
import uuid

from . import __version__, fsutil, tls
from .telemetry import Telemetry, fp, scrub, trace
from .client import Rejected, SberClient, Transient
from .config import Config, Profile
from .notify import Notifier

log = logging.getLogger("sber-cert-master")
DAY = 86400.0
# A secret change whose outcome is unknown is kept as a candidate this long while the old secret still works.
PENDING_SETTLE_SECONDS = 6 * 3600
PENDING_RECHECK_SECONDS = 15 * 60
SECRET_HISTORY_DAYS = 14
GRANT_ERRORS = ("invalid_grant", "invalid_token")
KEEP_GENERATIONS = 3
IMPORT_RETRY_SECONDS = 3600
IMPORT_AMBIGUOUS_RETRY_SECONDS = 60
RESERVE_SECONDS = 2 * 3600  # the bank keeps a consumed refresh_token usable this long
MAX_REFRESH_TIMEOUT = 180.0
TLS_CHECK_SECONDS = 600


class NotInitialized(Exception):
    pass


class ImportRejected(ValueError):
    """The staged (imported) refresh_token got a grant-specific rejection; the live one is untouched."""


class ImportFailed(ValueError):
    """The staged refresh_token was not accepted (not a grant rejection); it stays journaled."""


class NeedsReauth(Exception):
    """refresh_token is gone/invalid: a user must log in again (auth-url + exchange-code or LK)."""


def generate_secret(length: int = 40) -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        s = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in s) and any(c.isupper() for c in s) and any(c.isdigit() for c in s):
            return s


def fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(ts))


def _material_id(m: tls.ClientMaterial) -> str:
    return hashlib.sha256(m.cert_chain + m.key).hexdigest()[:16]


class Manager:
    def __init__(self, cfg: Config, prof: Profile, notifier: Notifier | None = None, clock=time.time):
        self.cfg = cfg
        self.p = prof
        self.now = clock
        self.dir = os.path.join(cfg.state_dir, prof.name)
        self.state_path = os.path.join(self.dir, "state.json")
        self.lock_path = os.path.join(self.dir, ".lock")
        self.tls_dir = os.path.join(self.dir, "tls")
        self.ca_file = os.path.join(cfg.state_dir, "ca-bundle.pem")
        self.pub_dir = os.path.join(cfg.publish_dir, prof.name)
        self.notifier = notifier or Notifier(cfg.notify, cfg.state_dir)
        self._secrets: dict[str, None] = {}  # ordered, bounded: values the telemetry must never write
        self.gid = fsutil.resolve_gid(prof.publish_group)
        if self.gid is not None and os.geteuid() != 0 and self.gid not in (os.getegid(), *os.getgroups()):
            # Without membership chown() of published files fails -- catch it before any bank request.
            raise ValueError(
                f"пользователь службы не состоит в группе публикации {prof.publish_group!r}: выполните "
                f"`sudo usermod -a -G {prof.publish_group} <пользователь службы>` и перезапустите службу/сеанс "
                "(или установите с `sudo env AGENT_GROUP=<группа> ./deploy/install.sh`)")
        fsutil.ensure_dir(cfg.state_dir, 0o700)
        fsutil.ensure_dir(self.dir, 0o700)
        fsutil.ensure_dir(self.tls_dir, 0o700)
        self.tel = Telemetry(os.path.join(self.dir, "events.jsonl"), prof.name, lambda: set(self._secrets))
        if not os.path.exists(self.ca_file):
            fsutil.atomic_write(self.ca_file, tls.builtin_ca_bundle(), 0o644)

    # ---------------------------------------------------------------- storage

    @contextlib.contextmanager
    def locked(self):
        with fsutil.file_lock(self.lock_path, timeout=300):
            self._migrate_legacy_tls()
            yield

    def _migrate_legacy_tls(self) -> None:
        """v0 layout kept tls/client.{crt,key} directly; move a valid pair into a generation."""
        if os.path.islink(os.path.join(self.tls_dir, "current")):
            return
        crt, key = os.path.join(self.tls_dir, "client.crt"), os.path.join(self.tls_dir, "client.key")
        if not (os.path.isfile(crt) and os.path.isfile(key)):
            return
        with open(crt, "rb") as c, open(key, "rb") as k:
            material = tls.build_material(c.read(), b"", k.read())  # raises if the pair does not match
        self._activate_material(self._stage_material(material))
        for path in (crt, key, crt + ".prev", key + ".prev"):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
        log.info("[%s] TLS-материалы перенесены в новую раскладку", self.p.name)

    def load(self) -> dict:
        st = fsutil.read_json(self.state_path)
        if not st:
            raise NotInitialized(f"профиль {self.p.name} не инициализирован (sber-cert-master init)")
        self._remember_secrets(st)
        self._migrate_state(st)
        return st

    # Free-text fields that versions before 3 could fill with raw bank answers (which may echo a request
    # with credentials). They are diagnostics only; the logic uses the separate *_since / flag fields.
    _LEGACY_TEXT = ("refresh_error", "import_error", "secret_rotation_error", "probe_error")

    def _migrate_state(self, st: dict) -> None:
        if int(st.get("version", 1)) >= 3:
            return
        for k in self._LEGACY_TEXT:
            if st.get(k):
                st[k] = "ошибка из предыдущей версии (текст удалён при обновлении)"
        st["version"] = 3

    def save(self, st: dict) -> None:
        self._remember_secrets(st)
        fsutil.write_json(self.state_path, st, backup=True)

    @staticmethod
    def _secret_values(st: dict) -> set[str]:
        vals = {st.get("client_secret"), st.get("refresh_token"), st.get("access_token"),
                (st.get("pending_client_secret") or {}).get("value"), (st.get("import_refresh_token") or {}).get("value")}
        vals |= {h.get("value") for h in st.get("secret_history", [])}
        return {v for v in vals if v}

    def _remember_secrets(self, st: dict) -> None:
        """Values the telemetry scrubber must never let through."""
        vals = {st.get("client_secret"), st.get("refresh_token"), st.get("access_token"),
                (st.get("pending_client_secret") or {}).get("value"),
                (st.get("import_refresh_token") or {}).get("value")}
        vals |= {h.get("value") for h in st.get("secret_history", [])}
        for v in vals:
            if v:
                self._secrets.pop(v, None)
                self._secrets[v] = None
        while len(self._secrets) > 64:  # old values cannot reappear; keep the set bounded
            self._secrets.pop(next(iter(self._secrets)))

    @property
    def cert_file(self) -> str:
        return os.path.join(self.tls_dir, "current", "client.crt")

    @property
    def key_file(self) -> str:
        return os.path.join(self.tls_dir, "current", "client.key")

    def client(self, cert_file: str | None = None, key_file: str | None = None,
               timeout: float | None = None) -> SberClient:
        return SberClient(self.p.api_base, cert_file or self.cert_file, key_file or self.key_file,
                          self.ca_file, timeout or self.p.http_timeout, self.p.proxy)

    def _refresh_timeout(self, st: dict, is_import: bool = False) -> float:
        """A response lost to a timeout is retried with the same refresh_token; if the bank is slower than
        our timeout every time, each retry would be lost too until the 2h reserve runs out. So every
        consecutive transient failure OF THE GRANT BEING SENT doubles the timeout (capped)."""
        if is_import:
            n = int((st.get("import_refresh_token") or {}).get("transient_failures", 0))
        else:
            n = int(st.get("refresh_transient_failures", 0))
        return min(self.p.http_timeout * (2 ** min(n, 4)), MAX_REFRESH_TIMEOUT)

    def _alert(self, what: str, level: str, title: str, text: str = "") -> None:
        # defense in depth: alerts go to logs and external channels
        title, text = scrub(title, set(self._secrets)), scrub(text, set(self._secrets))
        sent = self.notifier.alert(f"{self.p.name}:{what}", level, f"[{self.p.name}] {title}", text)
        if sent:
            self.tel.event("alert", key=what, level=level, title=title, text=text[:500])

    def _resolve(self, what: str, title: str) -> None:
        if f"{self.p.name}:{what}" in self.notifier.open_alerts():
            self.tel.event("alert.resolved", key=what, title=title)
        self.notifier.resolve(f"{self.p.name}:{what}", f"[{self.p.name}] {title}")

    # ------------------------------------------------------------ TLS storage

    def _write_generation(self, base: str, name: str, files: dict[str, bytes], mode: int, gid: int | None) -> str:
        """Create base/name with files, atomically (temp dir + rename). Existing generation is reused."""
        final = os.path.join(base, name)
        dir_mode = 0o750 if mode & 0o040 else 0o700
        if os.path.isdir(final):
            # Content is immutable, metadata is not: publish_group or modes may have changed since.
            for path, want in [(final, dir_mode)] + [(os.path.join(final, f), mode) for f in files]:
                st = os.stat(path)
                if stat.S_IMODE(st.st_mode) != want:
                    os.chmod(path, want)
                if gid is not None and st.st_gid != gid:
                    os.chown(path, -1, gid)
            return final
        tmp = os.path.join(base, f".tmp-{name}-{os.getpid()}")
        shutil.rmtree(tmp, ignore_errors=True)
        os.mkdir(tmp, 0o700)
        os.chmod(tmp, dir_mode)  # explicit: mkdir honours umask
        if gid is not None:
            os.chown(tmp, -1, gid)
        for fname, data in files.items():
            fsutil.atomic_write(os.path.join(tmp, fname), data, mode, gid)
        os.rename(tmp, final)
        fsutil.fsync_dir(base)
        return final

    @staticmethod
    def _switch_symlink(link: str, target_name: str) -> None:
        tmp = f"{link}.tmp-{os.getpid()}"
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        os.symlink(target_name, tmp)
        os.replace(tmp, link)
        fsutil.fsync_dir(os.path.dirname(link))

    @staticmethod
    def _prune_generations(base: str, prefix: str, keep_names: set[str]) -> None:
        gens = sorted((e for e in os.scandir(base) if e.is_dir(follow_symlinks=False) and e.name.startswith(prefix)),
                      key=lambda e: e.stat(follow_symlinks=False).st_mtime, reverse=True)
        for e in gens[KEEP_GENERATIONS:]:
            if e.name not in keep_names:
                shutil.rmtree(e.path, ignore_errors=True)

    def _stage_material(self, m: tls.ClientMaterial) -> str:
        name = "gen-" + _material_id(m)
        return self._write_generation(self.tls_dir, name, {"client.crt": m.cert_chain, "client.key": m.key}, 0o600, None)

    def _activate_material(self, gen_path: str) -> None:
        name = os.path.basename(gen_path)
        self._switch_symlink(os.path.join(self.tls_dir, "current"), name)
        self._prune_generations(self.tls_dir, "gen-", {name})

    # -------------------------------------------------------------- bootstrap

    def init(self, client_secret: str, material: tls.ClientMaterial, secret_set_at: float | None,
             overwrite: bool = False) -> None:
        if not client_secret:
            raise ValueError("пустой client_secret")
        with self.locked():
            old = fsutil.read_json(self.state_path)
            if old and not overwrite and (old.get("refresh_token") or old.get("import_refresh_token")):
                # A grant (live or staged) may be the only copy of the user's authorization.
                raise FileExistsError(f"{self.state_path}: в профиле уже есть refresh_token — повторный init "
                                      "его потеряет (--force, только если он заведомо не нужен)")
            # No grant in the old state (e.g. a rollback after init, before import): safe to re-initialize.
            self._activate_material(self._stage_material(material))
            now = self.now()
            # Unknown issue date -> assume old, so the first tick rotates it right away.
            set_at = secret_set_at if secret_set_at is not None else now - self.p.secret_lifetime_days * DAY
            st = {
                "version": 3,
                "client_id": self.p.client_id,
                "client_secret": client_secret,
                "client_secret_set_at": set_at,
                "client_secret_expires_at": set_at + self.p.secret_lifetime_days * DAY,
                "secret_history": [{"value": client_secret, "created_at": now}],
                "created_at": now,
            }
            self.save(st)
            self.tel.event("init", cert_serial=material.info.serial, cert_not_after=fmt_ts(material.info.not_after),
                           secret_fp=fp(client_secret), secret_set_at=fmt_ts(set_at), reinit=bool(old))
            # Publish TLS files right away: proves the publication directory, group and modes work
            # before any OAuth request is made.
            self._publish(st)

    def auth_url(self, scope: str | None = None) -> tuple[str, str]:
        """Authorization link for a user of the organisation; PKCE verifier stored in state."""
        if not self.p.redirect_uri:
            raise ValueError("в профиле не задан redirect_uri")
        verifier = secrets.token_hex(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = {
            "response_type": "code",
            "client_id": self.p.client_id,
            "redirect_uri": self.p.redirect_uri,
            "scope": scope or self.p.scope,
            "state": str(uuid.uuid4()),
            "nonce": str(uuid.uuid4()),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        with self.locked():
            st = self.load()
            st["pkce"] = {"verifier": verifier, "state": q["state"], "created_at": self.now()}
            self.save(st)
        return self.p.auth_base + "/ic/sso/api/v2/oauth/authorize?" + urllib.parse.urlencode(q, quote_via=urllib.parse.quote), q["state"]

    def exchange_code(self, code: str, use_pkce: bool = True, client_secret: str | None = None) -> None:
        """Exchange a one-time code. Secret: explicit > staged candidate > current (code cannot be retried)."""
        if not code:
            raise ValueError("пустой код")
        with self.locked():
            st = self.load()
            if client_secret:
                self._remember_secret(st, client_secret)
                self.save(st)
            pending = (st.get("pending_client_secret") or {}).get("value")
            secret = client_secret or pending or st["client_secret"]
            verifier = (st.get("pkce") or {}).get("verifier") if use_pkce else None
            try:
                resp = self.client().token_by_code(self.p.client_id, secret, code, self.p.redirect_uri, verifier)
            except (Rejected, Transient) as e:
                self.tel.event("exchange_code", outcome=type(e).__name__.lower(), http=getattr(e, "status", None),
                               code=getattr(e, "error", None) or None, pkce=bool(verifier), secret_fp=fp(secret))
                raise
            self.tel.event("exchange_code", outcome="ok", pkce=bool(verifier), secret_fp=fp(secret),
                           new_rt_fp=fp(resp["refresh_token"]))
            self._store_tokens(st, resp)
            if secret != st["client_secret"]:
                self._commit_secret(st, secret, None)
            st.pop("pkce", None)
            self.save(st)
            self._publish(st)
        self._resolve("reauth", "доступ восстановлен")

    def import_refresh_token(self, refresh_token: str, replace: bool = False) -> None:
        """Adopt a refresh_token (e.g. from the personal cabinet). The live one is kept until the bank accepts it."""
        refresh_token = refresh_token.strip()
        if not refresh_token:
            raise ValueError("пустой refresh_token")
        with self.locked():
            st = self.load()
            prev = st.get("import_refresh_token")
            if prev and prev["value"] != refresh_token and not replace:
                # The earlier candidate may already have been consumed by the bank (lost response); it is the
                # only token able to recover that pair, so it must not be replaced until it settles.
                raise ValueError("предыдущий импорт refresh_token ещё не завершён (ответ банка не получен); "
                                 "повторите импорт ТОГО ЖЕ токена. Заменить его другим можно только с --replace: "
                                 "прежний кандидат при этом будет потерян")
            if not prev or prev["value"] != refresh_token:
                st["import_refresh_token"] = {"value": refresh_token, "created_at": self.now()}
            self.tel.event("import.begin", rt_fp=fp(refresh_token), same_as_pending=bool(prev and prev["value"] == refresh_token),
                           replaced=bool(prev and prev["value"] != refresh_token), has_live=bool(st.get("refresh_token")))
            # An explicit (re)import always submits the candidate, even after an earlier rejection.
            st["import_refresh_token"]["explicit_retry"] = True
            st["import_refresh_token"].pop("rejected_at", None)
            st.pop("import_error", None)
            self.save(st)  # staged before it is sent
            self._refresh(st, force=True)
            self._publish(st)
            if st.get("import_error"):
                # The candidate was not accepted (the live grant may have been refreshed instead).
                if st.get("import_refresh_token"):
                    raise ImportFailed(f"импортированный refresh_token не принят: {st['import_error']}; "
                                       "кандидат сохранён, повторите импорт того же файла")
                raise ImportRejected(f"{st['import_error']}; прежний refresh_token сохранён")
        self._resolve("reauth", "доступ восстановлен")

    def _store_tokens(self, st: dict, resp: dict, used_import: bool = True) -> None:
        now = self.now()
        st["refresh_token"] = resp["refresh_token"]
        st["refresh_token_set_at"] = now
        st["access_token"] = resp["access_token"]
        st["access_token_set_at"] = now
        st["access_token_expires_at"] = now + float(resp.get("expires_in") or 3600)
        if resp.get("scope"):
            st["scope"] = resp["scope"]
        st["last_refresh_at"] = now
        for k in ("refresh_failing_since", "refresh_next_try_at", "refresh_error",
                  "refresh_transient_failures", "refresh_ambiguous_since"):
            st.pop(k, None)
        if used_import:
            st.pop("import_refresh_token", None)
            st.pop("import_error", None)
        # else: a definitively rejected candidate stays journaled for repair, separate from the live grant

    # ---------------------------------------------------------------- tokens

    def ensure_fresh(self, force: bool = False) -> dict:
        with self.locked():
            st = self.load()
            self._refresh(st, force=force)
            self._publish(st)
            return st

    def _token_due(self, st: dict) -> bool:
        left = st.get("access_token_expires_at", 0) - self.now()
        return not st.get("access_token") or left < self.p.refresh_margin_seconds

    def _pending_check_due(self, st: dict) -> bool:
        pending = st.get("pending_client_secret")
        return bool(pending) and self.now() - pending.get("checked_at", 0) >= PENDING_RECHECK_SECONDS

    def _secret_candidates(self, st: dict) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        pending = st.get("pending_client_secret")
        if pending:
            out.append(("pending", pending["value"]))  # an unconfirmed change may have been applied
        out.append(("current", st["client_secret"]))
        for h in sorted(st.get("secret_history", []), key=lambda h: h["created_at"], reverse=True):
            out.append(("history", h["value"]))
        seen, uniq = set(), []
        for which, val in out:
            if val not in seen:
                seen.add(val)
                uniq.append((which, val))
        return uniq

    def _refresh(self, st: dict, force: bool = False, tls_paths: tuple[str, str] | None = None) -> bool:
        """Refresh tokens if due/forced/needed to settle something. Lock must be held.

        Two grants can exist: the live refresh_token and a staged import candidate. Each has its own
        in-flight/ambiguity marker. The candidate is tried first when it is due; whenever it fails and the
        live grant needs refreshing, the live grant is refreshed in the same pass -- a candidate can never
        starve the live grant. `tls_paths` = (cert, key) of staged TLS material to use instead of the active one."""
        now = self.now()
        # State written by an older version: a counted transient failure without the marker is ambiguous.
        if st.get("refresh_transient_failures") and not st.get("refresh_ambiguous_since"):
            st["refresh_ambiguous_since"] = st.get("refresh_failing_since") or now
        imp = st.get("import_refresh_token")
        live = st.get("refresh_token")
        # A candidate whose answer was lost may have been consumed; the bank keeps it usable for 2h.
        imp_ambiguous = bool(imp and imp.get("ambiguous_since") and now - imp["ambiguous_since"] < RESERVE_SECONDS)
        if imp and imp.pop("explicit_retry", False):
            imp_due = True  # operator re-submitted it
        elif imp_ambiguous:
            # retry a possibly consumed candidate promptly, but not on every 15 s pass
            imp_due = now - imp.get("last_attempt_at", 0) >= IMPORT_AMBIGUOUS_RETRY_SECONDS
        else:
            imp_due = bool(imp) and (not live or not imp.get("rejected_at")
                                     or now - imp["rejected_at"] >= IMPORT_RETRY_SECONDS)
        # If the candidate may have been consumed, the published bearer may be revoked: refresh the live
        # grant once for that episode, so agents get a valid bearer again.
        live_resync = imp_ambiguous and imp.get("live_synced_for") != imp.get("ambiguous_since")
        live_due = bool(live) and (force or live_resync or bool(st.get("refresh_ambiguous_since"))
                                   or self._pending_check_due(st) or self._token_due(st))
        if not imp and not live:
            raise NeedsReauth("нет refresh_token")
        if not (imp_due or live_due):
            return False
        self.tel.event("refresh.decide", force=force, import_due=imp_due, live_due=live_due,
                       live_unfinished=bool(st.get("refresh_ambiguous_since")), import_ambiguous=imp_ambiguous,
                       token_left_s=int(st.get("access_token_expires_at", 0) - now),
                       pending_secret=bool(st.get("pending_client_secret")), staged_tls=tls_paths is not None)
        staged_client = tls_paths is not None

        def client_for(is_import: bool) -> SberClient:  # per grant: its own timeout budget
            cert, key = tls_paths or (None, None)
            return self.client(cert, key, timeout=self._refresh_timeout(st, is_import))

        if imp_due:
            try:
                return self._attempt(st, client_for(True), imp["value"], is_import=True, publish=not staged_client)
            except (Rejected, Transient, ImportRejected) as e:
                if not (live and (live_due or self._token_due(st))):
                    if isinstance(e, ImportRejected):
                        raise
                    raise ImportFailed(f"импортированный refresh_token не принят: {e}") from e
                log.warning("[%s] импортированный refresh_token не принят (%s); обновляем рабочий", self.p.name, e)
        done = self._attempt(st, client_for(False), live, is_import=False, publish=not staged_client)
        imp = st.get("import_refresh_token")
        if imp and imp.get("ambiguous_since"):
            imp["live_synced_for"] = imp["ambiguous_since"]
            self.save(st)
        return done

    def _attempt(self, st: dict, cl: SberClient, rt: str, is_import: bool, publish: bool) -> bool:
        """One refresh attempt with one grant, trying the known client_secret candidates."""
        now = self.now()
        imp = st.get("import_refresh_token") if is_import else None
        pending = st.get("pending_client_secret")
        if pending:
            pending["checked_at"] = now
        # In-flight marker for THIS grant, durable BEFORE the request (survives kill -9 / reboot).
        # An ambiguity left by an earlier attempt must survive a definitive answer to this one.
        if is_import:
            prior_ambiguous = bool(imp.get("ambiguous_since"))
            imp["last_attempt_at"] = now
            imp.setdefault("ambiguous_since", now)
        else:
            prior_ambiguous = "refresh_ambiguous_since" in st
            st.setdefault("refresh_ambiguous_since", now)
        self.save(st)

        grant = "import" if is_import else "live"
        errors: list[tuple[str, Rejected]] = []
        for which, secret in self._secret_candidates(st):
            t0 = time.monotonic()
            base = dict(grant=grant, rt_fp=fp(rt), secret=which, secret_fp=fp(secret), timeout_s=cl.timeout,
                        prior_ambiguous=prior_ambiguous)
            try:
                resp = cl.token_refresh(self.p.client_id, secret, rt)
            except Rejected as e:
                self.tel.event("refresh.try", outcome="rejected", http=e.status, code=e.error or None,
                               ms=int((time.monotonic() - t0) * 1000), **base)
                errors.append((which, e))
                if e.error in GRANT_ERRORS:
                    break  # the refresh_token itself is bad; other secrets will not help
                continue
            except Transient as e:
                self.tel.event("refresh.try", outcome="transient", error=str(e),
                               ms=int((time.monotonic() - t0) * 1000), **base)
                if is_import:
                    imp["transient_failures"] = int(imp.get("transient_failures", 0)) + 1
                    st["import_error"] = str(e)
                else:
                    st.setdefault("refresh_failing_since", now)
                    st["refresh_transient_failures"] = int(st.get("refresh_transient_failures", 0)) + 1
                    st["refresh_error"] = str(e)
                    st.pop("refresh_next_try_at", None)  # ambiguous: retry next pass, never wait a backoff
                self.save(st)
                raise
            self._store_tokens(st, resp, used_import=is_import)  # persist new pair first
            self.tel.event("refresh.try", outcome="ok", ms=int((time.monotonic() - t0) * 1000),
                           new_rt_fp=fp(resp["refresh_token"]), new_at_fp=fp(resp["access_token"]),
                           expires_in=resp.get("expires_in"), **base)
            if which == "current":
                if pending:
                    pend_rejected = any(w == "pending" for w, _ in errors)
                    if pending.get("kind") == "manual" and pend_rejected:
                        st.pop("pending_client_secret", None)
                        st["manual_secret_rejected"] = True
                    elif now - pending["created_at"] > PENDING_SETTLE_SECONDS:
                        log.info("[%s] смена client_secret не применена банком за %dч, кандидат снят",
                                 self.p.name, PENDING_SETTLE_SECONDS // 3600)
                        st.pop("pending_client_secret", None)
            else:
                log.warning("[%s] банк принимает другой client_secret (%s) — переключаемся на него", self.p.name, which)
                expires_days = pending.get("expires_days") if which == "pending" and pending else None
                self._commit_secret(st, secret, expires_days)
            self.save(st)
            log.info("[%s] токены обновлены%s, access_token до %s", self.p.name,
                     " (импортированный refresh_token)" if is_import else "", fmt_ts(st["access_token_expires_at"]))
            # The previous access token is already revoked by the bank: publish the new one right away,
            # before any other (network) work of the caller. Not for a staged TLS client: install_cert
            # publishes after the new certificate is active, so token and certificate match.
            if publish:
                try:
                    self._publish(st)
                except Exception as e:  # noqa: BLE001 - tick publishes again and alerts
                    log.error("[%s] публикация после обновления не удалась: %r", self.p.name, e)
            return True

        _, e = errors[-1]
        if is_import:
            if e.error in GRANT_ERRORS:
                # The staged refresh_token is dead; the live one stays untouched.
                st.pop("import_refresh_token", None)
                st["import_error"] = f"импортированный refresh_token отклонён: {e}"
                self.save(st)
                self.tel.event("refresh.failed", grant="import", conclusion="candidate_dropped", http=e.status,
                               code=e.error or None)
                raise ImportRejected(f"банк отклонил импортированный refresh_token ({e}); прежний сохранён") from e
            # Not about the grant (request format, certificate, client): keep it journaled for repair and
            # an hourly retry. Its earlier possible consumption (if any) stays recorded until the reserve ends.
            imp["rejected_at"] = now
            if not prior_ambiguous:
                imp.pop("ambiguous_since", None)
            st["import_error"] = str(e)
            self.save(st)
            self.tel.event("refresh.failed", grant="import", conclusion="candidate_kept", http=e.status,
                           code=e.error or None, still_ambiguous=bool(imp.get("ambiguous_since")))
            raise e
        # A definitive answer means THIS attempt issued no pair. An earlier ambiguous attempt is not
        # resolved by it (e.g. 403 certificateNotFound during a TLS repair), unless the grant itself is dead.
        if not prior_ambiguous or e.error in GRANT_ERRORS:
            st.pop("refresh_ambiguous_since", None)
        st["refresh_error"] = str(e)
        st.setdefault("refresh_failing_since", now)
        st["refresh_next_try_at"] = now + 600
        self.save(st)
        self.tel.event("refresh.failed", grant="live", conclusion="needs_reauth" if e.error in GRANT_ERRORS else "backoff",
                       http=e.status, code=e.error or None, still_ambiguous="refresh_ambiguous_since" in st)
        if e.error in GRANT_ERRORS:
            raise NeedsReauth(f"банк отклонил refresh_token: {e}") from e
        raise e

    # --------------------------------------------------------- client_secret

    def _remember_secret(self, st: dict, value: str) -> None:
        now = self.now()
        hist = [h for h in st.get("secret_history", [])
                if h["value"] != value and now - h["created_at"] < SECRET_HISTORY_DAYS * DAY]
        hist.append({"value": value, "created_at": now})
        st["secret_history"] = hist[-12:]

    def _commit_secret(self, st: dict, value: str, expires_days) -> None:
        now = self.now()
        st["client_secret"] = value
        st["client_secret_set_at"] = now
        days = float(expires_days or self.p.secret_lifetime_days)
        st["client_secret_expires_at"] = now + days * DAY
        self._remember_secret(st, value)
        for k in ("pending_client_secret", "secret_rotation_error", "secret_next_try_at", "manual_secret_rejected"):
            st.pop(k, None)

    def secret_due(self, st: dict) -> bool:
        age = (self.now() - st.get("client_secret_set_at", 0)) / DAY
        left = (st.get("client_secret_expires_at") or 0) - self.now()
        return age >= self.p.secret_rotate_after_days or left < 5 * DAY

    def rotate_secret(self, force: bool = False) -> bool:
        with self.locked():
            st = self.load()
            done = self._rotate_secret(st, force=force)
            self._publish(st)
            return done

    def _rotate_secret(self, st: dict, force: bool = False) -> bool:
        if st.get("pending_client_secret"):
            self._refresh(st)  # periodic settlement attempt (rate-limited)
            if st.get("pending_client_secret"):
                if not force:
                    return False  # never stack a new change on an unresolved one
                st.pop("pending_client_secret", None)  # still recoverable via secret_history
        if not force:
            if not self.secret_due(st) or self.now() < st.get("secret_next_try_at", 0):
                return False
        self._refresh(st)  # need a valid access_token of our own user
        new = generate_secret()
        st["pending_client_secret"] = {"value": new, "created_at": self.now(), "kind": "change",
                                       "checked_at": self.now()}
        self._remember_secret(st, new)
        self.save(st)  # persisted BEFORE the bank sees it
        t0 = time.monotonic()
        self.tel.event("secret.rotate.begin", forced=force, old_fp=fp(st["client_secret"]), new_fp=fp(new),
                       age_days=round((self.now() - st.get("client_secret_set_at", 0)) / DAY, 2))
        try:
            resp = self.client().change_client_secret(st["access_token"], self.p.client_id, st["client_secret"], new)
        except (Rejected, Transient) as e:
            # Outcome not provably negative: keep the candidate; refreshes try it first until it settles.
            st["secret_rotation_error"] = str(e)
            st["secret_next_try_at"] = self.now() + 3600
            self.save(st)
            self.tel.event("secret.rotate.result", outcome=type(e).__name__.lower(), error=str(e),
                           http=getattr(e, "status", None), ms=int((time.monotonic() - t0) * 1000),
                           pending_kept=True)
            raise
        st["pending_client_secret"]["expires_days"] = resp.get("clientSecretExpiration")
        self._commit_secret(st, new, resp.get("clientSecretExpiration"))
        self.save(st)
        self.tel.event("secret.rotate.result", outcome="ok", ms=int((time.monotonic() - t0) * 1000),
                       new_fp=fp(new), lifetime_days=resp.get("clientSecretExpiration"))
        log.info("[%s] client_secret обновлён, истекает %s", self.p.name, fmt_ts(st["client_secret_expires_at"]))
        self._refresh(st, force=True)  # prove the new secret works right away
        return True

    def set_secret(self, value: str, set_at: float | None = None) -> None:
        """Adopt a secret changed by hand in the personal cabinet; committed only if the bank accepts it."""
        value = value.strip()
        if not value:
            raise ValueError("пустой client_secret")
        with self.locked():
            st = self.load()
            if not st.get("refresh_token") and not st.get("import_refresh_token"):
                # No grant to verify it with: store it as the current secret; `preflight` checks it.
                self._commit_secret(st, value, None)
                if set_at is not None:
                    st["client_secret_set_at"] = set_at
                    st["client_secret_expires_at"] = set_at + self.p.secret_lifetime_days * DAY
                self.save(st)
                self.tel.event("set_secret", secret_fp=fp(value), has_grant=False, verified=False)
                log.warning("[%s] client_secret сохранён без проверки (в профиле нет гранта); "
                            "проверьте: sber-cert-master preflight %s", self.p.name, self.p.name)
                return
            self.tel.event("set_secret", secret_fp=fp(value), has_grant=True)
            st["pending_client_secret"] = {"value": value, "created_at": self.now(), "kind": "manual"}
            self._remember_secret(st, value)
            st.pop("manual_secret_rejected", None)
            self.save(st)
            try:
                self._refresh(st, force=True)
            except NeedsReauth:
                raise NeedsReauth("секрет сохранён кандидатом, но refresh_token недействителен: выполните "
                                  f"auth-url и exchange-code {self.p.name} CODE — будет использован новый секрет") from None
            if st["client_secret"] != value:
                st.pop("manual_secret_rejected", None)
                self.save(st)
                raise ValueError("банк не принял указанный client_secret, оставлен прежний")
            if set_at is not None:
                st["client_secret_set_at"] = set_at
                st["client_secret_expires_at"] = set_at + self.p.secret_lifetime_days * DAY
                self.save(st)
            self._publish(st)

    # ------------------------------------------------------------------- TLS

    def install_cert(self, material: tls.ClientMaterial, skip_probe: bool = False) -> None:
        """Stage a new client certificate, prove it works against the bank, then switch atomically."""
        blocks = tls.split_pem(material.cert_chain)
        tls.verify_chain(blocks[0], b"".join(blocks[1:]), self.ca_file)
        if material.info.not_after < self.now():
            raise tls.TLSError("сертификат уже истёк")
        with self.locked():
            st = self.load()
            gen = self._stage_material(material)
            self.tel.event("install_cert.begin", cert_serial=material.info.serial,
                           cert_not_after=fmt_ts(material.info.not_after), skip_probe=skip_probe)
            if not skip_probe:
                # Everything goes through the staged pair: the active certificate may already be dead.
                paths = (os.path.join(gen, "client.crt"), os.path.join(gen, "client.key"))
                staged = self.client(*paths)
                try:
                    try:
                        self._refresh(st, tls_paths=paths)  # new tokens (if any) are saved before the next request
                    except ImportRejected:
                        # A staged import was definitively rejected (and cleared); go on with the live grant.
                        self._refresh(st, tls_paths=paths)
                    try:
                        staged.user_info(st["access_token"])
                    except Rejected as e:
                        if e.status != 401:
                            raise
                        self._refresh(st, force=True, tls_paths=paths)
                        staged.user_info(st["access_token"])
                except NeedsReauth as e:
                    # The bank answered an OAuth-level "grant invalid" over the staged pair: mTLS with the
                    # new certificate works. Activate it so that exchange-code / import can run through it.
                    self._activate_material(gen)
                    st["tls_installed_at"] = self.now()
                    self.save(st)
                    self._publish(st)
                    raise NeedsReauth(f"сертификат установлен, но {e}. Выполните auth-url и exchange-code "
                                      "(или import-refresh-token) — они пойдут уже через новый сертификат") from None
            self._activate_material(gen)
            st["tls_installed_at"] = self.now()
            self.save(st)
            self._publish(st)
            self.tel.event("install_cert.result", outcome="ok", cert_serial=material.info.serial)
        log.info("[%s] установлен новый TLS-сертификат, действует до %s", self.p.name, fmt_ts(material.info.not_after))

    def cert_status(self) -> tls.CertInfo:
        with open(self.cert_file, "rb") as f:
            return tls.cert_info(tls.split_pem(f.read())[0])

    def _check_tls(self) -> None:
        info = self.cert_status()
        days = (info.not_after - self.now()) / DAY
        warn = self.p.cert_warn_days
        if days > warn[0]:
            self._resolve("tls-expiry", "TLS-сертификат обновлён")
        else:
            level = "critical" if days <= 7 else "warning" if days <= 30 else "info"
            self._alert("tls-expiry", level, f"TLS-сертификат истекает через {days:.0f} дн. ({fmt_ts(info.not_after)})",
                        "Выпустите новый (ЛК Sber API -> «Сгенерировать сертификат», или sber-cert-master csr -> "
                        "письмо в supportdbo2@sberbank.ru), ПРИВЯЖИТЕ его к client_id в ЛК, и только затем "
                        "sber-cert-master install-cert. Старый продолжит работать до своей даты.")
        with open(self.ca_file, "rb") as f:
            soonest = min((tls.cert_info(b).not_after, tls.cert_info(b).subject) for b in tls.split_pem(f.read()))
        cdays = (soonest[0] - self.now()) / DAY
        self.tel.event("tls.check", cert_days_left=round(days, 1), cert_serial=info.serial,
                       ca_min_days_left=round(cdays, 1), ca_soonest=soonest[1])
        if cdays < 90:
            self._alert("ca-expiry", "warning" if cdays > 14 else "critical",
                        f"доверенный CA истекает через {cdays:.0f} дн.: {soonest[1]}",
                        "Выполните sber-cert-master update-ca")
        else:
            self._resolve("ca-expiry", "CA-сертификаты в порядке")

    # ------------------------------------------------------------- publishing

    def _publish(self, st: dict) -> None:
        """Expose to agents only what they need to call the bank directly.

        TLS files go to an immutable directory tls-<id>/ (cert, key and combined client.pem); `env`
        and the `tls` symlink are switched atomically afterwards, so a reader never mixes generations.
        """
        fsutil.ensure_dir(self.cfg.publish_dir, 0o755)
        fsutil.ensure_dir(self.pub_dir, 0o750, self.gid)
        mode = 0o640
        with open(self.cert_file, "rb") as f:
            cert = f.read()
        with open(self.key_file, "rb") as f:
            key = f.read()
        with open(self.ca_file, "rb") as f:
            ca = f.read()
        j = os.path.join
        gen_name = "tls-" + hashlib.sha256(cert + key).hexdigest()[:16]
        gen = self._write_generation(self.pub_dir, gen_name, {
            "client.crt": cert, "client.key": key, "client.pem": key + cert,
        }, mode, self.gid)
        fsutil.write_if_changed(j(self.pub_dir, "ca-bundle.pem"), ca, mode if self.gid is not None else 0o644, self.gid)
        env = "".join(f"{k}={v}\n" for k, v in {
            "SBER_API_BASE": self.p.api_base,
            "SBER_CLIENT_ID": self.p.client_id,
            "SBER_ACCESS_TOKEN_FILE": j(self.pub_dir, "access_token"),
            "SBER_TOKEN_JSON": j(self.pub_dir, "token.json"),
            "SBER_CLIENT_CERT": j(gen, "client.crt"),
            "SBER_CLIENT_KEY": j(gen, "client.key"),
            "SBER_CLIENT_PEM": j(gen, "client.pem"),
            "SBER_CA_BUNDLE": j(self.pub_dir, "ca-bundle.pem"),
        }.items())
        fsutil.write_if_changed(j(self.pub_dir, "env"), env, mode, self.gid)
        link = j(self.pub_dir, "tls")
        if not (os.path.islink(link) and os.readlink(link) == gen_name):
            self._switch_symlink(link, gen_name)
        # v0 published client.crt/client.key as regular files here; keep those paths alive (and current)
        # for agents still configured with them. Done after `tls` exists so the links never dangle.
        for legacy in ("client.crt", "client.key"):
            lp = j(self.pub_dir, legacy)
            if os.path.isfile(lp) and not os.path.islink(lp):
                self._switch_symlink(lp, j("tls", legacy))
        self._prune_generations(self.pub_dir, "tls-", {gen_name})
        tok = st.get("access_token")
        if tok and st.get("access_token_expires_at", 0) > self.now():
            fsutil.write_if_changed(j(self.pub_dir, "token.json"), json.dumps({
                "access_token": tok,
                "token_type": "Bearer",
                "expires_at": int(st["access_token_expires_at"]),
                "issued_at": int(st.get("access_token_set_at", 0)),
                "client_id": self.p.client_id,
                "api_base": self.p.api_base,
            }, indent=2) + "\n", mode, self.gid)
            if fsutil.write_if_changed(j(self.pub_dir, "access_token"), tok + "\n", mode, self.gid):
                self.tel.event("publish", at_fp=fp(tok), expires_at=int(st["access_token_expires_at"]), tls=gen_name)
        try:
            h = self.health(st)
            body = json.dumps({k: v for k, v in h.items() if k not in ("generated_at", "generated_t")},
                              ensure_ascii=False, sort_keys=True)
            hp = j(self.pub_dir, "health.json")
            # rewrite only when something changed, or every minute (agents use generated_t as liveness)
            stale = not os.path.exists(hp) or time.time() - os.path.getmtime(hp) >= 60
            if stale or body != getattr(self, "_last_health", None):
                fsutil.atomic_write(hp, json.dumps(h, ensure_ascii=False, indent=2) + "\n", mode, self.gid)
                self._last_health = body
        except Exception as e:  # noqa: BLE001 - diagnostics must not break publication
            log.error("[%s] health.json: %r", self.p.name, type(e).__name__)

    def health(self, st: dict) -> dict:
        """Secret-free snapshot for agents (who cannot read the state). Built ONLY from structured fields:
        flags, timestamps, HTTP statuses and allowlisted bank codes -- never from stored free text, which
        older versions may have filled with bank answers echoing a request."""
        now = self.now()
        imp = st.get("import_refresh_token") or {}
        ev = self.tel.tail(40)
        last_live = next((e for e in reversed(ev) if e.get("kind") == "refresh.try" and e.get("grant") == "live"), {})
        safe = ("ts", "kind", "grant", "outcome", "http", "code", "conclusion", "level", "key", "ms", "secret")
        return {
            "generated_at": fmt_ts(now), "generated_t": int(now), "version": __version__,
            "profile": self.p.name, "client_id": self.p.client_id, "api_base": self.p.api_base,
            "access_token_fp": fp(st.get("access_token")),
            "access_token_expires_at": int(st.get("access_token_expires_at", 0)),
            "refresh_unfinished": bool(st.get("refresh_ambiguous_since")),
            "refresh_failing_since": st.get("refresh_failing_since"),
            "last_refresh": {k: last_live.get(k) for k in ("ts", "outcome", "http", "code")} if last_live else None,
            "import_pending": bool(imp), "import_rejected_at": imp.get("rejected_at"),
            "client_secret_expires_at": st.get("client_secret_expires_at"),
            "secret_rotation_failing": bool(st.get("secret_rotation_error")),
            "last_tick_at": st.get("last_tick_at"), "last_probe_ok_at": st.get("last_probe_ok_at"),
            "probe_failing_since": st.get("probe_failing_since"),
            "open_alerts": [{"key": k.split(":", 1)[-1], "level": v.get("level")}
                            for k, v in self.notifier.open_alerts().items() if k.startswith(self.p.name + ":")],
            "recent_events": [{k: e.get(k) for k in safe if e.get(k) is not None} for e in ev],
        }

    # ------------------------------------------------------------------ probe

    def _probe(self, st: dict) -> None:
        if not self.p.probe_interval_seconds:
            return
        if self.now() - st.get("last_probe_at", 0) < self.p.probe_interval_seconds:
            return
        st["last_probe_at"] = self.now()
        t0 = time.monotonic()
        try:
            try:
                self.client().user_info(st["access_token"])
            except Rejected as e:
                if e.status != 401:
                    raise
                # Our fresh token was revoked by the bank: usually someone else refreshed with our grant.
                self.tel.event("probe", outcome="rejected", http=401, code=e.error or None,
                               at_fp=fp(st.get("access_token")), recovered_by="forced_refresh",
                               token_left_s=int(st.get("access_token_expires_at", 0) - self.now()))
                self._refresh(st, force=True)  # token revoked/expired on bank side
                self.client().user_info(st["access_token"])
        except (Rejected, Transient) as e:
            self.tel.event("probe", outcome=type(e).__name__.lower(), http=getattr(e, "status", None),
                           code=getattr(e, "error", None) or None, error=str(e), at_fp=fp(st.get("access_token")),
                           ms=int((time.monotonic() - t0) * 1000))
            st["probe_error"] = str(e)
            st.setdefault("probe_failing_since", self.now())
            self.save(st)
            failing = self.now() - st["probe_failing_since"]
            if isinstance(e, Rejected) or failing > 1800:
                self._alert("probe", "critical" if isinstance(e, Rejected) else "warning",
                            "проверочный запрос user-info не проходит", str(e))
            return
        self.tel.event("probe", outcome="ok", at_fp=fp(st.get("access_token")), ms=int((time.monotonic() - t0) * 1000))
        st.pop("probe_error", None)
        st.pop("probe_failing_since", None)
        st["last_probe_ok_at"] = self.now()
        self.save(st)
        self._resolve("probe", "проверочный запрос проходит")

    # ------------------------------------------------------------------- tick

    def tick(self) -> dict:
        """One maintenance pass. Never raises for bank/network problems; reports via alerts."""
        with trace("tick"):
            t0 = time.monotonic()
            try:
                st = self._tick()
            except Exception as e:  # noqa: BLE001 - recorded for diagnosis, then re-raised to the daemon
                self.tel.event("tick.crash", error=repr(e)[:500])
                raise
            ms = int((time.monotonic() - t0) * 1000)
            hb_path = os.path.join(self.dir, "heartbeat")
            try:
                last_hb = os.path.getmtime(hb_path)
            except OSError:
                last_hb = 0
            # heartbeat every 10 min (wall clock), more often only when something is slow
            if ms > 5000 or time.time() - last_hb >= 600:
                self.tel.event("tick", ms=ms, token_left_s=int(st.get("access_token_expires_at", 0) - self.now()),
                               failing=bool(st.get("refresh_failing_since")), unfinished=bool(st.get("refresh_ambiguous_since")),
                               import_pending=bool(st.get("import_refresh_token")),
                               secret_age_days=round((self.now() - st.get("client_secret_set_at", 0)) / DAY, 2))
                with contextlib.suppress(OSError):
                    fsutil.atomic_write(hb_path, str(int(time.time())), 0o600)
            return st

    def _tick(self) -> dict:
        with self.locked():
            st = self.load()
            if self.now() - st.get("last_tls_check_at", 0) >= TLS_CHECK_SECONDS:
                try:
                    self._check_tls()
                    st["last_tls_check_at"] = self.now()
                except Exception as e:  # noqa: BLE001
                    self._alert("tls-check", "warning", "не удалось проверить TLS-материалы", repr(e))

            try:
                if self.now() >= st.get("refresh_next_try_at", 0) or self._token_expiring_soon(st) \
                        or st.get("refresh_ambiguous_since") or st.get("refresh_transient_failures") \
                        or (st.get("import_refresh_token") or {}).get("ambiguous_since"):
                    self._refresh(st)
                if not st.get("refresh_failing_since"):
                    self._resolve("refresh", "обновление токенов работает")
                    self._resolve("reauth", "доступ восстановлен")
            except NeedsReauth as e:
                self._alert("reauth", "critical", "нужна повторная авторизация пользователя в СберБизнес",
                            f"{e}\nВыполните: sber-cert-master auth-url {self.p.name} -> войти -> "
                            f"sber-cert-master exchange-code {self.p.name} CODE (код живёт 2 минуты), "
                            f"или выпустите токены в ЛК Sber API и sber-cert-master import-refresh-token.")
            except ValueError as e:  # import candidate not accepted (live grant is handled separately)
                self._alert("import", "warning", "импортированный refresh_token не принят", str(e))
            except (Rejected, Transient) as e:
                left = st.get("access_token_expires_at", 0) - self.now()
                failing = self.now() - st.get("refresh_failing_since", self.now())
                ambiguous = self.now() - st.get("refresh_ambiguous_since", self.now())
                if left < 10 * 60 or isinstance(e, Rejected):
                    self._alert("refresh", "critical", "не удаётся обновить access_token",
                                f"{e}; токен истекает {fmt_ts(st.get('access_token_expires_at'))}")
                elif ambiguous > 5 * 60:
                    # The bank may have issued a pair we never received: the published token is then
                    # already revoked and agents get 401 despite its expiry.
                    self._alert("refresh", "critical", "обновление токена не завершено — агенты, вероятно, получают 401",
                                f"{e}; повторяем на каждом проходе обслуживания тем же refresh_token (банк принимает повтор в течение часа)")
                elif failing > 15 * 60:
                    self._alert("refresh", "warning", "обновление access_token сбоит", str(e))

            try:
                if st.get("access_token") and (self.secret_due(st) or st.get("pending_client_secret")):
                    self._rotate_secret(st)
                self._check_secret_expiry(st, st.get("secret_rotation_error", "") if self.secret_due(st) else "")
            except NeedsReauth:
                pass  # already alerted above
            except (Rejected, Transient) as e:
                self._check_secret_expiry(st, str(e))

            try:
                if st.get("access_token"):
                    self._probe(st)
            except NeedsReauth:
                pass

            try:
                self._publish(st)
            except Exception as e:  # noqa: BLE001
                self._alert("publish", "critical", "не удалось опубликовать файлы для агентов", repr(e))
            st["last_tick_at"] = self.now()
            self.save(st)
            return st

    def _token_expiring_soon(self, st: dict) -> bool:
        return st.get("access_token_expires_at", 0) - self.now() < 5 * 60

    def _check_secret_expiry(self, st: dict, err: str = "") -> None:
        left = ((st.get("client_secret_expires_at") or 0) - self.now()) / DAY
        if err:
            level = "critical" if left < 5 else "warning"
            self._alert("secret", level, f"автоматическая смена client_secret не удалась, осталось {left:.1f} дн.",
                        f"{err}\nПовторим автоматически. Вручную: sber-cert-master rotate-secret {self.p.name} "
                        "или смените секрет в ЛК Sber API и выполните sber-cert-master set-secret.")
        elif left < 3:
            self._alert("secret", "critical", f"client_secret истекает через {left:.1f} дн.", "")
        else:
            self._resolve("secret", "client_secret обновлён")

    # ----------------------------------------------------------------- status

    def status(self) -> dict:
        st = fsutil.read_json(self.state_path) or {}
        out = {
            "profile": self.p.name,
            "initialized": bool(st),
            "client_id": self.p.client_id,
            "api_base": self.p.api_base,
        }
        if not st:
            return out
        now = self.now()
        out.update({
            "access_token_expires_at": fmt_ts(st.get("access_token_expires_at")),
            "access_token_valid_min": round((st.get("access_token_expires_at", 0) - now) / 60, 1),
            "refresh_token_age_days": round((now - st.get("refresh_token_set_at", now)) / DAY, 1) if st.get("refresh_token") else None,
            "client_secret_age_days": round((now - st.get("client_secret_set_at", now)) / DAY, 1),
            "client_secret_expires_at": fmt_ts(st.get("client_secret_expires_at")),
            "pending_client_secret": bool(st.get("pending_client_secret")),
            "import_pending": bool(st.get("import_refresh_token")),
            "import_rejected_at": fmt_ts((st.get("import_refresh_token") or {}).get("rejected_at")) if st.get("import_refresh_token") else None,
            "refresh_unfinished": bool(st.get("refresh_ambiguous_since")),
            "last_tick_at": fmt_ts(st.get("last_tick_at")),
            "last_probe_ok_at": fmt_ts(st.get("last_probe_ok_at")),
            "errors": scrub({k: st[k] for k in ("refresh_error", "secret_rotation_error", "probe_error") if st.get(k)},
                            set(self._secrets) | self._secret_values(st)),
        })
        try:
            info = self.cert_status()
            out["tls_cert"] = {"subject": info.subject, "serial": info.serial, "not_after": fmt_ts(info.not_after),
                               "days_left": round((info.not_after - now) / DAY, 1)}
        except (OSError, tls.TLSError, IndexError) as e:
            out["tls_cert"] = f"ошибка: {e}"
        return out

    def readiness(self, min_valid: float = 600, probe: bool = True) -> list[str]:
        """Why agents should NOT be switched to the published files yet (empty list = ready).

        Settled refresh, the published bearer is the committed one, enough lifetime left, and (probe) the
        bank accepts it right now. Read-only; meant for the service account."""
        st = fsutil.read_json(self.state_path) or {}
        now = self.now()
        if not st:
            return ["профиль не инициализирован"]
        why = []
        if st.get("refresh_ambiguous_since"):
            why.append("обновление токена не завершено (ответ банка не получен)")
        imp = st.get("import_refresh_token") or {}
        if imp.get("ambiguous_since") and now - imp["ambiguous_since"] < RESERVE_SECONDS:
            why.append("импорт refresh_token не завершён")
        left = st.get("access_token_expires_at", 0) - now
        if not st.get("access_token") or left < min_valid:
            why.append(f"токену осталось {max(left, 0) / 60:.0f} мин (нужно ≥ {min_valid / 60:.0f})")
        pub = fsutil.read_json(os.path.join(self.pub_dir, "token.json")) or {}
        if pub.get("access_token") != st.get("access_token"):
            why.append("опубликован не тот токен, что в состоянии службы")
        if probe and not why:
            try:
                self.client().user_info(st["access_token"])
            except (Rejected, Transient) as e:
                why.append(f"банк не принимает опубликованный токен: {e}")
        return why

    def watchdog(self) -> list[str]:
        """Checks that need no bank access and work even if the daemon is dead."""
        problems = []
        st = fsutil.read_json(self.state_path) or {}
        now = self.now()
        if not st:
            return [f"[{self.p.name}] не инициализирован"]
        if now - st.get("last_tick_at", 0) > self.cfg.stale_tick_seconds:
            problems.append(f"[{self.p.name}] демон не работал с {fmt_ts(st.get('last_tick_at'))}")
        if st.get("access_token_expires_at", 0) - now < 5 * 60:
            problems.append(f"[{self.p.name}] access_token истекает/истёк {fmt_ts(st.get('access_token_expires_at'))}")
        if problems:
            self.notifier.alert(f"{self.p.name}:watchdog", "critical", "; ".join(problems),
                                "Проверьте: systemctl status sber-cert-master; journalctl -u sber-cert-master")
        else:
            self.notifier.resolve(f"{self.p.name}:watchdog", f"[{self.p.name}] демон работает")
        return problems
