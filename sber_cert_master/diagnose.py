"""`sber-cert-master diagnose`: collect everything needed to understand a failure, detect known problems,
and render a secret-free report that an agent can read, act on, or attach to a bug report.

Two modes, chosen automatically:
  * keeper  -- run as the service account (state readable): full picture, incl. events and preflight;
  * agent   -- run by an agent (only the published directory is readable): what the agent sees.
"""

from __future__ import annotations

import email.utils
import grp
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

from . import __version__, config, fsutil, tls
from .client import Rejected, SberClient, Transient
from .telemetry import fp, scrub

ERRORS_DOC = "docs/ERRORS.md"


def _run(cmd: list[str], timeout: int = 10) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return (r.stdout + r.stderr).strip()[-6000:]
    except (OSError, subprocess.SubprocessError):
        return None


def _env_proxies() -> dict:
    keys = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
    no_proxy = os.environ.get("NO_PROXY", "") + "," + os.environ.get("no_proxy", "")
    return {"set": [k for k in keys if os.environ.get(k)], "no_proxy_has_sberbank": "sberbank.ru" in no_proxy}


def _clock_skew(api_base: str, ca_file: str, cert: str | None, key: str | None) -> dict:
    """Compare local time with the bank's HTTP Date header (any HTTP answer will do)."""
    try:
        ctx = ssl.create_default_context(cafile=ca_file)
        if cert and key:
            ctx.load_cert_chain(cert, key)
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
        t0 = time.time()
        try:
            resp = op.open(urllib.request.Request(api_base + "/", method="GET"), timeout=20)
            date = resp.headers.get("Date")
        except urllib.error.HTTPError as e:
            date = e.headers.get("Date")
        t1 = time.time()
        if not date:
            return {"ok": False, "error": "no Date header"}
        bank = email.utils.parsedate_to_datetime(date).timestamp()
        return {"ok": True, "skew_s": round((t0 + t1) / 2 - bank, 1), "rtt_ms": int((t1 - t0) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {getattr(e, 'reason', e)}"[:200]}


def _file_info(path: str) -> dict:
    try:
        st = os.stat(path)
    except OSError as e:
        return {"path": path, "exists": False, "error": type(e).__name__}
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return {"path": path, "exists": True, "mode": oct(st.st_mode & 0o777), "gid": st.st_gid, "group": group,
            "readable": os.access(path, os.R_OK), "mtime": int(st.st_mtime)}


def _identity() -> dict:
    groups = sorted(set(os.getgroups()) | {os.getegid()})
    return {"uid": os.geteuid(), "gid": os.getegid(), "groups": groups}


# --------------------------------------------------------------------------------------------- collect

def collect_keeper(cfg: config.Config, prof: config.Profile, network: bool, include_journal: bool = False) -> dict:
    from .core import Manager  # local import: avoid a cycle
    m = Manager(cfg, prof)
    st = fsutil.read_json(m.state_path) or {}
    m._remember_secrets(st)  # everything the scrubber must remove
    rep: dict = {"mode": "keeper", "profile": prof.name}
    rep["config"] = {
        "path": cfg.path, "env": prof.env, "client_id": prof.client_id, "api_base": prof.api_base,
        "proxy_configured": bool(prof.proxy), "publish_group": prof.publish_group,
        "tick_interval_s": cfg.tick_interval_seconds, "probe_interval_s": prof.probe_interval_seconds,
        "http_timeout_s": prof.http_timeout, "secret_rotate_after_days": prof.secret_rotate_after_days,
        "notify_channels": [k for k in ("command", "webhook_url", "telegram_chat_id") if cfg.notify.get(k)],
    }
    rep["status"] = m.status()
    # Structured fields only: stored free-text errors may come from older versions that kept bank answers.
    imp = st.get("import_refresh_token") or {}
    pend = st.get("pending_client_secret") or {}
    rep["state_flags"] = {
        "refresh_ambiguous_since": st.get("refresh_ambiguous_since"),
        "refresh_failing_since": st.get("refresh_failing_since"),
        "refresh_transient_failures": st.get("refresh_transient_failures"),
        "refresh_next_try_at": st.get("refresh_next_try_at"),
        "import": {k: imp.get(k) for k in ("created_at", "last_attempt_at", "rejected_at", "ambiguous_since",
                                           "transient_failures")} if imp else None,
        "import_rt_fp": fp(imp.get("value")),
        "pending_client_secret": {k: pend.get(k) for k in ("created_at", "kind", "checked_at")} if pend else None,
        "secret_rotation_failing": bool(st.get("secret_rotation_error")),
        "probe_failing_since": st.get("probe_failing_since"),
        "access_token_fp": fp(st.get("access_token")), "refresh_token_fp": fp(st.get("refresh_token")),
        "secret_fp": fp(st.get("client_secret")), "secret_history_len": len(st.get("secret_history", [])),
        "last_tick_t": st.get("last_tick_at"),
    }
    pub = fsutil.read_json(os.path.join(m.pub_dir, "token.json")) or {}
    rep["publication"] = {
        "dir": _file_info(m.pub_dir),
        "files": [_file_info(os.path.join(m.pub_dir, f)) for f in ("token.json", "access_token", "env", "ca-bundle.pem",
                                                                     "health.json", "tls", "tls/client.pem")],
        "published_token_fp": fp(pub.get("access_token")), "published_expires_at": pub.get("expires_at"),
        "matches_state": bool(pub) and pub.get("access_token") == st.get("access_token"),
    }
    try:
        info = m.cert_status()
        with open(m.cert_file, "rb") as f:
            blocks = tls.split_pem(f.read())
        chain = "ok"
        try:
            tls.verify_chain(blocks[0], b"".join(blocks[1:]), m.ca_file)
        except tls.TLSError as e:
            chain = str(e)[:300]
        with open(m.ca_file, "rb") as f:
            cas = [tls.cert_info(b) for b in tls.split_pem(f.read())]
        rep["tls"] = {"subject": info.subject, "serial": info.serial, "not_after": int(info.not_after),
                      "days_left": round((info.not_after - time.time()) / 86400, 1), "chain_verify": chain,
                      "ca": [{"subject": c.subject, "days_left": round((c.not_after - time.time()) / 86400, 1)} for c in cas]}
    except Exception as e:  # noqa: BLE001
        rep["tls"] = {"error": repr(e)[:300]}
    rep["alerts_open"] = {k: v for k, v in m.notifier.open_alerts().items() if k.startswith(prof.name + ":")}
    rep["events"] = m.tel.tail(150)
    if network:
        rep["readiness"] = m.readiness()
        rep["preflight"] = _preflight(m, st)
        if rep["preflight"].get("result") == "secret_rejected":
            # the keeper may have committed/changed its secret meanwhile, or a change is still settling
            now_st = fsutil.read_json(m.state_path) or {}
            if now_st.get("client_secret") != st.get("client_secret") or now_st.get("pending_client_secret"):
                rep["preflight"] = {"result": "inconclusive", "reason": "смена client_secret в процессе"}
        rep["clock"] = _clock_skew(prof.api_base, m.ca_file, m.cert_file, m.key_file)
    props = "LoadState,ActiveState,SubState,NRestarts,ExecMainStatus,ActiveEnterTimestamp"
    show = _run(["systemctl", "show", "sber-cert-master", "-p", props]) or ""
    scope = "system"
    if "LoadState=loaded" not in show:
        user_show = _run(["systemctl", "--user", "show", "sber-cert-master", "-p", props]) or ""
        if "LoadState=loaded" in user_show:
            show, scope = user_show, "user"
    rep["systemd"] = {"scope": scope if "LoadState=loaded" in show else "none", "show": show}
    if include_journal:  # raw process output: for local use only, never in a shared report by default
        rep["systemd"]["journal"] = _run(["journalctl"] + (["--user"] if scope == "user" else [])
                                         + ["-u", "sber-cert-master", "-n", "60", "--no-pager", "-o", "short-iso"])
    return scrub(rep, set(m._secrets))


def _preflight(m, st: dict) -> dict:
    if not st.get("client_secret"):
        return {"result": "skipped", "reason": "no client_secret"}
    try:
        m.client().token_refresh(m.p.client_id, st["client_secret"], "0" * 38)
        return {"result": "unexpected_accept"}
    except Rejected as e:
        return {"result": {"invalid_grant": "ok", "invalid_client": "secret_rejected"}.get(
            e.error, "cert_not_bound" if e.status == 403 else "rejected"), "http": e.status, "code": e.error}
    except Transient as e:
        return {"result": "network", "error": str(e)}


def collect_agent(publish_dir: str, profile: str, network: bool) -> dict:
    d = os.path.join(publish_dir, profile)
    rep: dict = {"mode": "agent", "profile": profile, "publish_dir": d}
    rep["identity"] = _identity()
    rep["files"] = [_file_info(os.path.join(d, f)) for f in ("", "token.json", "access_token", "env", "ca-bundle.pem",
                                                              "health.json", "tls", "tls/client.pem")]
    raw = fsutil.read_json(os.path.join(d, "health.json")) if os.access(os.path.join(d, "health.json"), os.R_OK) else None
    # Only known structured fields: a health.json written by an older version may carry free text.
    keep = ("generated_at", "generated_t", "version", "profile", "client_id", "api_base", "access_token_fp",
            "access_token_expires_at", "refresh_unfinished", "refresh_failing_since", "last_refresh", "import_pending",
            "import_rejected_at", "client_secret_expires_at", "secret_rotation_failing", "last_tick_at",
            "last_probe_ok_at", "probe_failing_since", "open_alerts", "recent_events")
    ev_keep = ("ts", "kind", "grant", "outcome", "http", "code", "conclusion", "level", "key", "ms", "secret")
    health = None
    if isinstance(raw, dict):
        health = {k: raw.get(k) for k in keep if k in raw}
        health["open_alerts"] = [{"key": a.get("key"), "level": a.get("level")} for a in raw.get("open_alerts") or []
                                 if isinstance(a, dict)]
        health["recent_events"] = [{k: e.get(k) for k in ev_keep if isinstance(e, dict) and e.get(k) is not None}
                                   for e in raw.get("recent_events") or []]
        lr = raw.get("last_refresh")
        health["last_refresh"] = {k: lr.get(k) for k in ("ts", "outcome", "http", "code")} if isinstance(lr, dict) else None
    rep["health"] = health
    tok = None
    try:
        tok = fsutil.read_json(os.path.join(d, "token.json"))
    except OSError as e:
        rep["token_error"] = type(e).__name__
    secrets = set()
    if tok:
        secrets.add(tok.get("access_token", ""))
        rep["token"] = {"fp": fp(tok.get("access_token")), "expires_at": tok.get("expires_at"),
                        "left_s": int(tok.get("expires_at", 0) - time.time()), "api_base": tok.get("api_base"),
                        "matches_health": bool(health) and health.get("access_token_fp") == fp(tok.get("access_token"))}
    if network and tok:
        ca, pem = os.path.join(d, "ca-bundle.pem"), os.path.join(d, "tls", "client.pem")
        try:
            cl = SberClient(tok["api_base"], pem, pem, ca, 30)
            t0 = time.monotonic()
            cl.user_info(tok["access_token"])
            rep["probe"] = {"result": "ok", "ms": int((time.monotonic() - t0) * 1000)}
        except Rejected as e:
            rep["probe"] = {"result": "rejected", "http": e.status, "code": e.error}
        except Transient as e:
            rep["probe"] = {"result": "network", "error": str(e)}
        except Exception as e:  # noqa: BLE001
            rep["probe"] = {"result": "local_error", "error": f"{type(e).__name__}: {e}"[:300]}
        rep["clock"] = _clock_skew(tok["api_base"], ca, pem if os.access(pem, os.R_OK) else None,
                                   pem if os.access(pem, os.R_OK) else None)
    return scrub(rep, secrets)


def collect(cfg_path: str | None, profile: str | None, publish_dir: str | None, network: bool,
            include_journal: bool = False) -> dict:
    meta = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), "version": __version__,
        "host": socket.gethostname(), "python": sys.version.split()[0], "platform": platform.platform(),
        "openssl": ssl.OPENSSL_VERSION, "argv0": sys.argv[0], "identity": _identity(), "env_proxies": _env_proxies(),
        "disk_free_mb": None,
    }
    rep = None
    try:
        cfg = config.load(cfg_path)
        prof = cfg.profile(profile)
        if os.access(os.path.join(cfg.state_dir, prof.name, "state.json"), os.R_OK):
            rep = collect_keeper(cfg, prof, network, include_journal)
            meta["disk_free_mb"] = shutil.disk_usage(cfg.state_dir).free // 2**20
        else:
            publish_dir = publish_dir or cfg.publish_dir
            profile = prof.name
    except (config.ConfigError, OSError):
        pass
    if rep is None:
        if not publish_dir:
            for cand in (os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"),
                                      "sber-cert-master", "public"), "/var/lib/sber-cert-master/public"):
                if os.path.isdir(cand):
                    publish_dir = cand
                    break
        if not publish_dir:
            return {"meta": meta, "mode": "none", "error": "не найден ни конфиг службы, ни каталог публикации"}
        if not profile:
            try:
                names = [e.name for e in os.scandir(publish_dir) if e.is_dir()]
            except OSError:
                names = []
            profile = names[0] if len(names) == 1 else "main"
        rep = collect_agent(publish_dir, profile, network)
    rep["meta"] = meta
    return rep


# --------------------------------------------------------------------------------------------- analyze

def _f(sev: str, title: str, evidence: str, action: str, ref: str = "") -> dict:
    return {"severity": sev, "title": title, "evidence": evidence, "action": action, "ref": ref}


def analyze(rep: dict) -> list[dict]:
    out: list[dict] = []
    now = time.time()
    meta = rep.get("meta", {})
    if rep.get("mode") == "none":
        return [_f("critical", "служба не найдена", rep.get("error", ""), "проверьте установку (docs/AGENT_INSTALL.md, шаг 0)")]
    clock = rep.get("clock") or {}
    if clock.get("ok") and abs(clock.get("skew_s", 0)) > 120:
        out.append(_f("warning", "часы расходятся с банком", f"расхождение {clock['skew_s']} с",
                      "включите синхронизацию времени (timedatectl set-ntp true / chrony)"))
    proxies = meta.get("env_proxies", {})
    if rep.get("mode") == "agent":
        out += _analyze_agent(rep, now, proxies)
    else:
        out += _analyze_keeper(rep, now)
    if not out:
        out.append(_f("ok", "проблем не найдено", "все проверки пройдены", "—"))
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    return sorted(out, key=lambda f: order.get(f["severity"], 9))


def _code_hint(code: str | None, http: int | None) -> tuple[str, str] | None:
    if code == "invalid_grant":
        return ("refresh_token недействителен", "[ЧЕЛОВЕК] повторная авторизация: import-refresh-token или auth-url + exchange-code")
    if code == "invalid_client":
        return ("client_secret отклонён банком", "[ЧЕЛОВЕК] действующий секрет из ЛК → sber-cert-master set-secret main --file <файл>")
    if code in ("certificateNotFound", "CERTIFICATE_ACCESS_EXCEPTION") or http == 403:
        return ("TLS-сертификат не привязан к client_id / не в белом списке", "[ЧЕЛОВЕК] ЛК Sber API → «Сертификаты шифрования»")
    return None


def _analyze_keeper(rep: dict, now: float) -> list[dict]:
    out = []
    st = rep.get("status", {})
    flags = rep.get("state_flags", {})
    sysd = (rep.get("systemd") or {}).get("show") or ""
    if "LoadState=loaded" in sysd and "ActiveState=active" not in sysd:
        out.append(_f("critical", "служба не запущена", sysd.replace("\n", "; "),
                      "systemctl enable --now sber-cert-master; затем sber-cert-master ready main", "ERRORS.md §3"))
    tick_s = rep.get("config", {}).get("tick_interval_s", 15)
    last_tick = flags.get("last_tick_t")
    if not last_tick or now - last_tick > max(300, tick_s * 20):
        out.append(_f("critical", "демон не делает проходы", f"last_tick_at={st.get('last_tick_at')}",
                      "служба не запущена, зависла или не может взять блокировку: systemctl status / journalctl -u "
                      "sber-cert-master", "ERRORS.md §3"))
    left = st.get("access_token_valid_min")
    if isinstance(left, (int, float)) and left < 5:
        out.append(_f("critical", "access_token истёк или истекает", f"осталось {left} мин",
                      "смотрите refresh_error ниже и журнал событий", "ERRORS.md §1"))
    if flags.get("refresh_ambiguous_since") and now - flags["refresh_ambiguous_since"] > 300:
        out.append(_f("critical", "обновление токена не завершено > 5 мин (ответ банка потерян)",
                      f"с {time.strftime('%H:%M:%S', time.gmtime(flags['refresh_ambiguous_since']))} UTC; ошибка: {flags.get('refresh_error')}",
                      "служба повторяет тем же refresh_token; проверьте сеть до fintech.sberbank.ru:9443 и прокси",
                      "ERRORS.md §2"))
    events = rep.get("events", [])
    # Current episode of the LIVE grant: attempts after its last success. Import attempts are separate.
    live = [e for e in events if e.get("kind") == "refresh.try" and e.get("grant") == "live"]
    last_ok = max((i for i, e in enumerate(live) if e.get("outcome") == "ok"), default=-1)
    episode = live[last_ok + 1:]
    if flags.get("refresh_failing_since") and episode:
        last = episode[-1]
        if last.get("outcome") == "rejected" and not flags.get("refresh_ambiguous_since"):
            hint = _code_hint(last.get("code"), last.get("http"))
            if hint:
                out.append(_f("critical", hint[0], f"refresh (рабочий грант): HTTP {last.get('http')} {last.get('code')}",
                              hint[1], "ERRORS.md §1"))
        else:
            slow = "таймаут" in str(last.get("error", ""))
            out.append(_f("warning", "временные ошибки обновления токена — служба повторяет тем же refresh_token",
                          f"{last.get('outcome')}: {last.get('error') or last.get('code')}",
                          ("банк отвечает медленнее таймаута — служба увеличивает таймаут сама; " if slow else "")
                          + "ничего не перевыпускайте; проверьте связь: openssl s_client -connect fintech.sberbank.ru:9443",
                          "ERRORS.md §2"))
    imp_ev = [e for e in events if e.get("kind") == "refresh.try" and e.get("grant") == "import"]
    if flags.get("import") and imp_ev:
        last = imp_ev[-1]
        out.append(_f("warning", "импортированный refresh_token не принят (рабочий грант не затронут)",
                      f"HTTP {last.get('http')} {last.get('code') or last.get('outcome')}",
                      "повторите импорт тем же файлом после устранения причины; рабочий грант не трогайте", "ERRORS.md §5"))
    # A second refresher revokes our tokens: user-info 401 on a fresh token we published, with no ambiguous
    # refresh of our own shortly before (a lost answer of ours would explain the 401 too).
    suspects = []
    for e in events:
        if e.get("kind") == "probe" and e.get("http") == 401 and e.get("recovered_by") and now - e.get("t", 0) < 86400:
            own = [x for x in live if 0 <= e.get("t", 0) - x.get("t", 0) < 7200 and x.get("outcome") == "transient"]
            if not own and e.get("token_left_s", 0) > 120:
                suspects.append(e)
    if suspects:
        later_ok = [e for e in events if e.get("kind") == "probe" and e.get("outcome") == "ok"
                    and e.get("t", 0) > suspects[-1].get("t", 0)]
        recovered = bool(later_ok)
        out.append(_f("warning" if recovered else "critical",
                      "похоже, токены обновляет ещё кто-то (второй «обновляльщик»)"
                      + (" — было, сейчас доступ работает" if recovered else ""),
                      f"{len(suspects)} раз за сутки банк отверг наш свежий токен (401) без нашего обновления; "
                      f"последний раз {suspects[-1].get('ts')}",
                      "найдите и отключите у агентов/cron любые вызовы /oauth/token (AGENT_INSTALL, шаг 3)", "ERRORS.md §6"))
    if flags.get("import") and not imp_ev:
        out.append(_f("warning", "импорт refresh_token не завершён", json.dumps(flags["import"]),
                      "если ответ банка не получен — повторите импорт тем же файлом; при 403 — привяжите сертификат",
                      "ERRORS.md §5"))
    if flags.get("secret_rotation_failing"):
        rot = [e for e in events if e.get("kind") == "secret.rotate.result" and e.get("outcome") != "ok"]
        out.append(_f("warning", "смена client_secret не удалась",
                      f"{rot[-1].get('outcome')} HTTP {rot[-1].get('http')}" if rot else "см. events",
                      "служба повторит; при < 5 дней до истечения: rotate-secret или set-secret", "ERRORS.md §3"))
    pf = rep.get("preflight") or {}
    if pf.get("result") in ("secret_rejected", "cert_not_bound"):
        h = _code_hint(pf.get("code"), pf.get("http"))
        out.append(_f("critical", "предпроверка: " + (h[0] if h else pf["result"]), json.dumps(pf, ensure_ascii=False),
                      h[1] if h else "", "ERRORS.md §1"))
    elif pf.get("result") == "network":
        out.append(_f("critical", "нет связи с банком", pf.get("error", ""), "сеть/файрвол/прокси до fintech.sberbank.ru:9443",
                      "ERRORS.md §2"))
    if rep.get("readiness"):
        out.append(_f("warning", "агентам пока нельзя пользоваться опубликованным токеном", "; ".join(rep["readiness"]),
                      "дождитесь/исправьте по причинам выше; затем sber-cert-master ready main", "AGENT_INSTALL шаг 7"))
    pub = rep.get("publication", {})
    if pub and not pub.get("matches_state"):
        out.append(_f("warning", "опубликован не тот токен, что в состоянии службы", json.dumps(
            {k: pub.get(k) for k in ("published_token_fp", "published_expires_at")}), "проверьте права каталога публикации и журнал"))
    t = rep.get("tls", {})
    if isinstance(t.get("days_left"), (int, float)) and t["days_left"] < 30:
        out.append(_f("warning" if t["days_left"] > 7 else "critical", f"TLS-сертификат истекает через {t['days_left']} дн.",
                      t.get("subject", ""), "выпустить, привязать к client_id, затем install-cert", "ERRORS.md §3"))
    if t.get("chain_verify") not in (None, "ok"):
        out.append(_f("critical", "цепочка клиентского сертификата не проверяется", t["chain_verify"], "update-ca / install-cert"))
    for ca in t.get("ca", []):
        if ca["days_left"] < 90:
            out.append(_f("warning", f"CA истекает через {ca['days_left']} дн.", ca["subject"], "sber-cert-master update-ca"))
    for k, v in (rep.get("alerts_open") or {}).items():
        out.append(_f("info", "открытый алерт: " + str(v.get("title")), f"{k} ({v.get('level')})", "см. выводы выше"))
    return out


def _invalid_grant_after_success(events: list[dict], now: float) -> str:
    last_ok = None
    for e in events:
        if e.get("kind") != "refresh.try" or e.get("grant") != "live" or now - e.get("t", 0) > 86400:
            continue
        if e.get("outcome") == "ok":
            last_ok = e
        elif e.get("code") == "invalid_grant" and last_ok and e.get("rt_fp") == last_ok.get("new_rt_fp") \
                and e.get("t", 0) - last_ok.get("t", 0) < 2 * 3600:
            return f"токен rt#{e.get('rt_fp')} выдан {last_ok.get('ts')}, отвергнут {e.get('ts')}"
    return ""


def _analyze_agent(rep: dict, now: float, proxies: dict) -> list[dict]:
    out = []
    files = {os.path.basename(f["path"].rstrip("/")) or "dir": f for f in rep.get("files", [])}
    unreadable = [f["path"] for f in rep.get("files", []) if f.get("exists") and not f.get("readable")]
    if unreadable:
        out.append(_f("critical", "нет прав на файлы службы", ", ".join(unreadable),
                      "у процесса агента нет группы publish_group: проверьте /proc/<pid>/status (AGENT_INSTALL шаг 1); "
                      "в Docker — publish_group = числовой GID процесса агента", "ERRORS.md §4"))
    if not files.get("token.json", {}).get("exists"):
        out.append(_f("critical", "token.json не опубликован", rep.get("publish_dir", ""),
                      "служба не получила токен: sber-cert-master status / diagnose от пользователя службы", "ERRORS.md §3"))
    h = rep.get("health") or {}
    if h:
        age = now - h.get("generated_t", 0)
        if age > 300:
            out.append(_f("critical", "служба не обновляла health.json " + f"{int(age)} с", h.get("generated_at", ""),
                          "служба остановлена или зависла: systemctl status sber-cert-master", "ERRORS.md §3"))
        lr = h.get("last_refresh") or {}
        if h.get("refresh_failing_since"):
            out.append(_f("warning", "служба сообщает ошибку обновления токена",
                          f"{lr.get('outcome')} HTTP {lr.get('http')} {lr.get('code') or ''}".strip(),
                          "запустите diagnose от пользователя службы"))
        if h.get("refresh_unfinished"):
            out.append(_f("warning", "обновление токена у службы не завершено (ответ банка потерян)", "",
                          "служба повторяет сама; перечитывайте token.json перед запросом"))
        for a in h.get("open_alerts", []):
            out.append(_f("info", "открытый алерт службы: " + str(a.get("key")), str(a.get("level")), "—"))
    tok = rep.get("token") or {}
    if tok and tok.get("left_s", 0) < 120:
        out.append(_f("critical", "опубликованный токен истёк", f"осталось {tok.get('left_s')} с", "служба не обновляет токен — см. health"))
    if tok and h and not tok.get("matches_health"):
        out.append(_f("info", "token.json и health.json от разных моментов", "обычно это гонка при обновлении",
                      "перечитайте и повторите через несколько секунд"))
    pr = rep.get("probe") or {}
    if pr.get("result") == "rejected":
        hint = _code_hint(pr.get("code"), pr.get("http"))
        if pr.get("http") == 401:
            out.append(_f("critical", "банк отверг опубликованный токен (401)", json.dumps(pr),
                          "перечитайте token.json через 30 с; если снова 401 — служба/второй обновляльщик: diagnose от службы",
                          "ERRORS.md §1"))
        elif hint:
            out.append(_f("critical", hint[0], json.dumps(pr), hint[1], "ERRORS.md §1"))
    elif pr.get("result") in ("network", "local_error"):
        slow = proxies.get("set") and not proxies.get("no_proxy_has_sberbank")
        out.append(_f("critical", "агент не может достучаться до банка", pr.get("error", ""),
                      ("в окружении задан прокси, а .sberbank.ru нет в NO_PROXY — добавьте; " if slow else "")
                      + "проверьте сеть до fintech.sberbank.ru:9443", "ERRORS.md §2"))
    if proxies.get("set") and not proxies.get("no_proxy_has_sberbank"):
        out.append(_f("warning", "прокси в окружении без исключения для Сбера", ",".join(proxies["set"]),
                      "добавьте .sberbank.ru в NO_PROXY/no_proxy (через прокси mTLS-рукопожатие может занимать 15-45 с)",
                      "ERRORS.md §2"))
    return out


# --------------------------------------------------------------------------------------------- render

def render_markdown(rep: dict, findings: list[dict]) -> str:
    meta = rep.get("meta", {})
    icon = {"critical": "🔴", "warning": "🟠", "info": "🔵", "ok": "🟢"}
    worst = findings[0]["severity"] if findings else "ok"
    lines = [f"# sber-cert-master diagnose — {icon.get(worst, '')} {worst}", "",
             f"`{meta.get('generated_at')}` · версия {meta.get('version')} · хост `{meta.get('host')}` · "
             f"режим **{rep.get('mode')}** · профиль `{rep.get('profile')}`", "", "## Выводы", ""]
    for f in findings:
        lines.append(f"- {icon.get(f['severity'], '')} **{f['title']}**")
        if f.get("evidence"):
            lines.append(f"  - факт: {f['evidence']}")
        if f.get("action") and f["action"] != "—":
            lines.append(f"  - что делать: {f['action']}")
        if f.get("ref"):
            lines.append(f"  - справка: {f['ref']} ({ERRORS_DOC})")
    lines += ["", "## Данные", "", "Секреты в отчёт не попадают: токены и секреты указаны отпечатками (`*_fp`), "
              "длинные токеноподобные строки вырезаны.", ""]
    for key in ("status", "state_flags", "readiness", "preflight", "clock", "config", "publication", "tls",
                "health", "token", "probe", "identity", "files", "alerts_open", "systemd", "meta"):
        if key in rep and rep[key] not in (None, {}, []):
            val = rep[key]
            if key == "systemd":
                lines += [f"### {key}", "", "```", (val.get("show") or "")[:2000], "", (val.get("journal") or "")[-5000:], "```", ""]
                continue
            lines += [f"### {key}", "", "```json", json.dumps(val, ensure_ascii=False, indent=2, default=str)[:8000], "```", ""]
    ev = rep.get("events") or (rep.get("health") or {}).get("recent_events") or []
    if ev:
        lines += ["### events (последние)", "", "```"]
        for e in ev[-120:]:
            extra = {k: v for k, v in e.items() if k not in ("ts", "t", "kind", "profile", "pid", "v")}
            lines.append(f"{e.get('ts')} {e.get('kind'):<22} {json.dumps(extra, ensure_ascii=False, default=str)}")
        lines += ["```", ""]
    lines += ["## Как отправить отчёт", "",
              "Если выводы выше не объясняют проблему, создайте issue (отчёт уже без секретов):", "",
              "```sh", "sber-cert-master diagnose main --issue <owner/repo>   # только приватный репозиторий: команда это проверяет",
              "```", "",
              "Без `gh` сохраните отчёт в файл и передайте человеку. В отчёте есть client_id, ИНН и имя хоста — "
              "никогда не публикуйте его в открытых местах.", ""]
    return "\n".join(lines)


def file_issue(repo: str, report_md: str, title: str) -> str:
    """Create a GitHub issue with gh; returns its URL. The report is already scrubbed."""
    vis = subprocess.run(["gh", "repo", "view", repo, "--json", "visibility", "-q", ".visibility"],
                         capture_output=True, text=True, timeout=30, check=False)
    if vis.returncode != 0 or vis.stdout.strip().upper() != "PRIVATE":
        raise RuntimeError(f"репозиторий {repo} не приватный или недоступен ({vis.stdout.strip() or vis.stderr.strip()[:200]}): "
                           "отчёт содержит client_id, ИНН и имя хоста — отправка только в приватный репозиторий")
    if len(report_md) > 60000:  # GitHub limit is 65536 characters
        report_md = report_md[:60000] + "\n\n…(отчёт обрезан; полный: sber-cert-master diagnose main > report.md)\n"
    r = subprocess.run(["gh", "issue", "create", "--repo", repo, "--title", title, "--body-file", "-"],
                       input=report_md, capture_output=True, text=True, timeout=60, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"gh issue create: {r.stderr.strip()[:300]}")
    return r.stdout.strip()
