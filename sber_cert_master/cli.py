"""Command line interface."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import logging
import os
import signal
import sys
import time
import urllib.request

from . import __version__, config, fsutil, tls
from .client import SberError
from .core import Manager, NeedsReauth, NotInitialized
from .notify import Notifier
from .telemetry import trace

log = logging.getLogger("sber-cert-master")


def _read_secret(prompt: str, from_file: str | None) -> str:
    if from_file:
        with open(from_file) as f:
            return f.read().strip()
    if not sys.stdin.isatty():
        return sys.stdin.readline().strip()
    return getpass.getpass(prompt).strip()


def _parse_date(s: str | None) -> float | None:
    if not s:
        return None
    d = dt.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.astimezone()  # naive -> local time
    return d.timestamp()


def _load_material(args) -> tls.ClientMaterial:
    if args.p12:
        with open(args.p12, "rb") as f:
            data = f.read()
        pw = _read_secret("Пароль .p12: ", args.p12_password_file)
        return tls.load_p12(data, pw)
    if not (args.cert and args.key):
        raise SystemExit("нужно --p12 или пара --cert/--key")
    with open(args.cert, "rb") as f:
        cert = f.read()
    with open(args.key, "rb") as f:
        key = f.read()
    chain = b""
    if args.chain:
        with open(args.chain, "rb") as f:
            chain = f.read()
    else:
        chain = tls.builtin_ca_bundle()
    return tls.build_material(cert, chain, key)


def _add_material_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--p12", help="контейнер .p12/.pfx из ЛК Sber API")
    p.add_argument("--p12-password-file", help="файл с паролем .p12 (иначе спросит)")
    p.add_argument("--cert", help="сертификат .cer/.pem от поддержки")
    p.add_argument("--key", help="закрытый ключ PEM (из команды csr)")
    p.add_argument("--chain", help="промежуточные сертификаты (по умолчанию встроенная цепочка SberAPI)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sber-cert-master",
                                 description="Автообновление токенов, client_secret и контроль TLS для Sber API")
    ap.add_argument("-c", "--config", help=f"конфиг (по умолчанию $SBER_CERT_MASTER_CONFIG или {config.DEFAULT_CONFIG})")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="первичная настройка профиля: client_secret + TLS-сертификат")
    p.add_argument("profile")
    _add_material_args(p)
    p.add_argument("--client-secret-file", help="файл с client_secret (иначе спросит/stdin)")
    p.add_argument("--secret-set-at", help="когда выпущен текущий client_secret (YYYY-MM-DD). "
                   "Если не указано — считаем старым и меняем при первом запуске")
    p.add_argument("--force", action="store_true", help="перезаписать существующее состояние")

    p = sub.add_parser("auth-url", help="ссылка авторизации пользователя (СберБизнес ID)")
    p.add_argument("profile", nargs="?")
    p.add_argument("--scope")

    p = sub.add_parser("exchange-code", help="обменять код авторизации на токены (в течение 2 минут)")
    p.add_argument("profile", nargs="?")
    p.add_argument("code")
    p.add_argument("--no-pkce", action="store_true", help="ссылка была сформирована без code_challenge")
    p.add_argument("--client-secret-file", help="использовать этот client_secret (если он был сменён в ЛК); "
                   "при успехе он станет текущим")

    p = sub.add_parser("import-refresh-token", help="принять refresh_token (например, из ЛК) со stdin")
    p.add_argument("profile", nargs="?")
    p.add_argument("--file")
    p.add_argument("--replace", action="store_true",
                   help="заменить незавершённый импорт другим токеном (прежний кандидат будет потерян)")

    p = sub.add_parser("run", help="демон: обслуживает все профили")
    p.add_argument("--once", action="store_true", help="один проход и выход")

    p = sub.add_parser("tick", help="один проход обслуживания")
    p.add_argument("profile", nargs="?")

    p = sub.add_parser("refresh", help="принудительно обновить токены")
    p.add_argument("profile", nargs="?")

    p = sub.add_parser("rotate-secret", help="сменить client_secret сейчас")
    p.add_argument("profile", nargs="?")

    p = sub.add_parser("set-secret", help="задать client_secret, изменённый вручную в ЛК (проверяется у банка)")
    p.add_argument("profile", nargs="?")
    p.add_argument("--file")
    p.add_argument("--set-at", help="дата выпуска (YYYY-MM-DD), по умолчанию сейчас")

    p = sub.add_parser("csr", help="сгенерировать ключ RSA-2048 и CSR для промышленного TLS-сертификата")
    p.add_argument("profile", nargs="?")
    p.add_argument("--inn", required=True)
    p.add_argument("--ogrn", required=True)
    p.add_argument("--locality", required=True, help="населённый пункт латиницей, напр. Moscow")
    p.add_argument("--region", required=True, help="регион латиницей, напр. Moscow")
    p.add_argument("--out", required=True, help="каталог для private.key и request.csr")

    p = sub.add_parser("install-cert", help="установить новый TLS-сертификат (с проверкой у банка)")
    p.add_argument("profile", nargs="?")
    _add_material_args(p)
    p.add_argument("--skip-probe", action="store_true", help="не проверять сертификат запросом к банку")

    p = sub.add_parser("update-ca", help="обновить корневые/промежуточные CA Минцифры и Сбера с официальных адресов")

    p = sub.add_parser("status", help="состояние профилей")
    p.add_argument("profile", nargs="?")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("check", help="сторож: тревога, если демон не работает или токен протух (для таймера)")

    p = sub.add_parser("preflight", help="проверить у банка сертификат и client_secret, не расходуя refresh_token")
    p.add_argument("profile", nargs="?")
    _add_material_args(p)
    p.add_argument("--client-secret-file", help="проверить этот client_secret (по умолчанию — из состояния службы)")

    p = sub.add_parser("ready", help="(ворота переключения агентов) ждать, пока токен обновлён, опубликован и принят банком")
    p.add_argument("profile", nargs="?")
    p.add_argument("--min-valid", type=int, default=600, help="минимальный остаток жизни токена, сек")
    p.add_argument("--wait", type=int, default=180, help="сколько ждать, сек")
    p.add_argument("--no-probe", action="store_true", help="не проверять токен запросом к банку")

    p = sub.add_parser("token", help="(для агентов) напечатать действующий access_token")
    p.add_argument("profile", nargs="?")
    p.add_argument("--min-valid", type=int, default=120, help="минимальный остаток жизни, сек")
    p.add_argument("--wait", type=int, default=60, help="сколько ждать свежий токен, сек")
    p.add_argument("--publish-dir", help="каталог публикации (если конфиг недоступен)")

    p = sub.add_parser("diagnose", help="самодиагностика: выводы + отчёт без секретов для багрепорта (служба и агенты)")
    p.add_argument("profile", nargs="?")
    p.add_argument("--json", action="store_true", help="машиночитаемый отчёт")
    p.add_argument("--no-network", action="store_true", help="без обращений к банку")
    p.add_argument("--publish-dir", help="каталог публикации (для агента, если конфиг недоступен)")
    p.add_argument("--issue", metavar="OWNER/REPO", help="создать issue в GitHub с этим отчётом (через gh)")
    p.add_argument("--title", help="заголовок issue")
    p.add_argument("--include-journal", action="store_true",
                   help="добавить сырой journalctl службы (только для локального просмотра; с --issue запрещено)")

    p = sub.add_parser("test-notify", help="отправить тестовое уведомление")

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s" if sys.stderr.isatty() else "%(levelname)s %(message)s")

    if args.cmd == "token":
        return cmd_token(args)
    if args.cmd == "diagnose":
        return cmd_diagnose(args)

    try:
        cfg = config.load(args.config)
        fsutil.ensure_dir(cfg.state_dir, 0o700)
        notifier = Notifier(cfg.notify, cfg.state_dir)
        with trace(args.cmd):
            rc = dispatch(args, cfg, notifier)
        return rc
    except (config.ConfigError, NotInitialized, FileExistsError, ValueError, tls.TLSError, NeedsReauth) as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return 2
    except SberError as e:
        print(f"ошибка банка/сети: {e}", file=sys.stderr)
        return 3


def dispatch(args, cfg: config.Config, notifier: Notifier) -> int:
    mgr = lambda: Manager(cfg, cfg.profile(getattr(args, "profile", None)), notifier)  # noqa: E731

    if args.cmd == "init":
        m = Manager(cfg, cfg.profile(args.profile), notifier)
        material = _load_material(args)
        secret = _read_secret("client_secret: ", args.client_secret_file)
        if not secret:
            raise ValueError("пустой client_secret")
        m.init(secret, material, _parse_date(args.secret_set_at), overwrite=args.force)
        print(f"профиль {args.profile} инициализирован; TLS до {time.strftime('%Y-%m-%d', time.localtime(material.info.not_after))}")
        print(f"дальше: sber-cert-master auth-url {args.profile}  (или import-refresh-token)")
        return 0
    if args.cmd == "auth-url":
        url, state = mgr().auth_url(args.scope)
        print(url)
        print(f"\nПосле входа пользователь попадёт на redirect_uri с ?code=...&state={state}\n"
              f"Код живёт 2 минуты: sber-cert-master exchange-code <profile> CODE", file=sys.stderr)
        return 0
    if args.cmd == "exchange-code":
        new_secret = _read_secret("", args.client_secret_file) if args.client_secret_file else None
        mgr().exchange_code(args.code, use_pkce=not args.no_pkce, client_secret=new_secret)
        print("токены получены и опубликованы")
        return 0
    if args.cmd == "import-refresh-token":
        rt = _read_secret("refresh_token: ", args.file)
        mgr().import_refresh_token(rt, replace=args.replace)
        print("refresh_token принят, токены обновлены и опубликованы")
        return 0
    if args.cmd == "run":
        return run_daemon(cfg, notifier, once=args.once)
    if args.cmd == "tick":
        mgr().tick()
        return 0
    if args.cmd == "refresh":
        st = mgr().ensure_fresh(force=True)
        print("access_token до", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st["access_token_expires_at"])))
        return 0
    if args.cmd == "rotate-secret":
        mgr().rotate_secret(force=True)
        print("client_secret обновлён")
        return 0
    if args.cmd == "set-secret":
        mgr().set_secret(_read_secret("новый client_secret: ", args.file), _parse_date(args.set_at))
        print("client_secret принят банком и сохранён")
        return 0
    if args.cmd == "csr":
        prof = cfg.profile(args.profile)
        os.makedirs(args.out, mode=0o700, exist_ok=True)
        key, csr = os.path.join(args.out, "private.key"), os.path.join(args.out, "request.csr")
        if os.path.exists(key):
            raise FileExistsError(f"{key} уже существует")
        subj = tls.make_csr(prof.client_id, args.inn, args.ogrn, args.locality, args.region, key, csr)
        print(subj.decode().strip())
        print(f"\nКлюч: {key} (храните!)\nCSR: {csr}\n"
              "Отправьте request.csr с почты уполномоченного лица на supportdbo2@sberbank.ru с просьбой выпустить "
              "TLS-сертификат Sber API. Полученный .cer установите:\n"
              f"  sber-cert-master install-cert {prof.name} --cert certificate.cer --key {key}")
        return 0
    if args.cmd == "install-cert":
        m = mgr()
        m.install_cert(_load_material(args), skip_probe=args.skip_probe)
        print("сертификат установлен:", m.cert_status().subject)
        return 0
    if args.cmd == "update-ca":
        return cmd_update_ca(cfg)
    if args.cmd == "status":
        profs = [cfg.profile(args.profile)] if args.profile else list(cfg.profiles.values())
        data = [Manager(cfg, p, notifier).status() for p in profs]
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            for d in data:
                print(f"== {d.pop('profile')}")
                for k, v in d.items():
                    print(f"  {k}: {v}")
        return 0
    if args.cmd == "check":
        problems = []
        for p in cfg.profiles.values():
            problems += Manager(cfg, p, notifier).watchdog()
        for line in problems:
            print(line)
        return 1 if problems else 0
    if args.cmd == "preflight":
        return cmd_preflight(args, cfg, notifier)
    if args.cmd == "ready":
        m = mgr()
        deadline = time.monotonic() + args.wait
        while True:
            why = m.readiness(args.min_valid, probe=not args.no_probe)
            if not why:
                print("TOKEN-READY")
                return 0
            if time.monotonic() >= deadline:
                for w in why:
                    print(f"не готово: {w}", file=sys.stderr)
                return 1
            time.sleep(3)
    if args.cmd == "test-notify":
        notifier.alert("test", "warning", "тестовое уведомление sber-cert-master", "если вы это видите — всё настроено", force=True)
        notifier.resolve("test", "тест")
        return 0
    raise SystemExit(f"unknown command {args.cmd}")


def run_daemon(cfg: config.Config, notifier: Notifier, once: bool = False) -> int:
    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    managers = [Manager(cfg, p, notifier) for p in cfg.profiles.values()]
    for m in managers:
        m.tel.event("daemon.start", tick_s=cfg.tick_interval_seconds, api_base=m.p.api_base,
                    proxy=bool(m.p.proxy), env_proxy=bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")),
                    python=sys.version.split()[0], probe_s=m.p.probe_interval_seconds)
    log.info("sber-cert-master %s: профили %s", __version__, ", ".join(m.p.name for m in managers))
    # READY right away (a slow first pass must not hit systemd's start timeout). Whether agents may be
    # switched is decided separately by `sber-cert-master ready`.
    _notify_systemd("READY=1")
    while not stop:
        for m in managers:
            try:
                m.tick()
            except NotInitialized as e:
                notifier.alert(f"{m.p.name}:init", "warning", str(e))
            except Exception as e:  # noqa: BLE001 - daemon must survive anything
                log.exception("[%s] tick failed", m.p.name)
                notifier.alert(f"{m.p.name}:crash", "critical", f"[{m.p.name}] внутренняя ошибка демона", repr(e))
        _notify_systemd("WATCHDOG=1")
        if once:
            break
        deadline = time.monotonic() + cfg.tick_interval_seconds
        while not stop and time.monotonic() < deadline:
            time.sleep(1)
    for m in managers:
        m.tel.event("daemon.stop")
    return 0


def _notify_systemd(msg: str) -> None:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    import socket
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(msg.encode(), addr)
    except OSError:
        pass


def cmd_preflight(args, cfg: config.Config, notifier: Notifier) -> int:
    """Send a deliberately invalid refresh_token. The bank checks certificate -> client -> grant, in this
    order (verified on production), so the answer tells what is wrong without consuming any grant."""
    import tempfile
    from .client import Rejected, SberClient, Transient
    m = Manager(cfg, cfg.profile(args.profile), notifier)
    st = fsutil.read_json(m.state_path) or {}
    secret = _read_secret("client_secret: ", args.client_secret_file) if args.client_secret_file else st.get("client_secret")
    if not secret:
        raise ValueError("нет client_secret: укажите --client-secret-file или выполните init")
    with tempfile.TemporaryDirectory(dir=m.dir) as d:
        if args.p12 or args.cert:
            material = _load_material(args)
            cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
            fsutil.atomic_write(cert, material.cert_chain, 0o600)
            fsutil.atomic_write(key, material.key, 0o600)
        else:
            cert, key = m.cert_file, m.key_file
        cl = SberClient(m.p.api_base, cert, key, m.ca_file, m.p.http_timeout, m.p.proxy)
        try:
            cl.token_refresh(m.p.client_id, secret, "0" * 38)
            print("неожиданно: банк принял заведомо негодный refresh_token", file=sys.stderr)
            return 2
        except Rejected as e:
            if e.error == "invalid_grant":
                print("PREFLIGHT-OK: сертификат привязан к client_id, client_secret принят")
                return 0
            if e.error == "invalid_client":
                print("ОШИБКА: client_secret отклонён (неверный или истёк) — сертификат при этом привязан", file=sys.stderr)
            elif e.error in ("certificateNotFound", "CERTIFICATE_ACCESS_EXCEPTION") or e.status == 403:
                print(f"ОШИБКА: сертификат не привязан к client_id {m.p.client_id} ({e}). "
                      "ЛК Sber API -> сервис -> «Сертификаты шифрования»", file=sys.stderr)
            else:
                print(f"ОШИБКА: {e}", file=sys.stderr)
            return 1
        except Transient as e:
            print(f"ОШИБКА сети/TLS: {e}", file=sys.stderr)
            return 3


def cmd_diagnose(args) -> int:
    """Works for the service account (full report) and for agents (published files only)."""
    from . import diagnose
    with trace("diagnose"):
        if args.issue and args.include_journal:
            print("ошибка: --include-journal нельзя отправлять в issue", file=sys.stderr)
            return 2
        rep = diagnose.collect(args.config, args.profile, args.publish_dir, network=not args.no_network,
                               include_journal=args.include_journal)
        findings = diagnose.analyze(rep)
    if args.json:
        print(json.dumps({"findings": findings, "report": rep}, ensure_ascii=False, indent=2, default=str))
    else:
        md = diagnose.render_markdown(rep, findings)
        print(md)
        if args.issue:
            worst = findings[0]
            title = args.title or f"[diagnose] {worst['severity']}: {worst['title']} ({rep.get('meta', {}).get('host')})"
            try:
                print("issue:", diagnose.file_issue(args.issue, md, title), file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print(f"ошибка: не удалось создать issue: {e}", file=sys.stderr)
                return 4
    worst = findings[0]["severity"] if findings else "ok"
    return {"ok": 0, "info": 0, "warning": 1, "critical": 2}.get(worst, 0)


def cmd_token(args) -> int:
    pub = args.publish_dir
    prof = args.profile
    if not pub:
        try:
            cfg = config.load(args.config)
            pub = cfg.publish_dir
            prof = cfg.profile(prof).name
        except (config.ConfigError, OSError):
            # Agents usually cannot read the service config: fall back to the standard publish dirs.
            state_home = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
            for cand in (os.path.join(state_home, "sber-cert-master", "public"), "/var/lib/sber-cert-master/public"):
                if os.path.isdir(cand):
                    pub = cand
                    break
            else:
                print("ошибка: конфиг недоступен и каталог публикации не найден; укажите --publish-dir", file=sys.stderr)
                return 2
    if not prof:
        try:
            names = [e.name for e in os.scandir(pub) if e.is_dir()]
        except OSError:
            names = []
        if len(names) != 1:
            print("ошибка: укажите профиль", file=sys.stderr)
            return 2
        prof = names[0]
    path = os.path.join(pub, prof, "token.json")
    deadline = time.monotonic() + args.wait
    while True:
        try:
            with open(path) as f:
                tok = json.load(f)
            if tok["expires_at"] - time.time() >= args.min_valid:
                print(tok["access_token"])
                return 0
        except (OSError, ValueError, KeyError):
            pass
        if time.monotonic() >= deadline:
            print(f"ошибка: нет действующего токена в {path}", file=sys.stderr)
            return 1
        time.sleep(2)


def cmd_update_ca(cfg: config.Config) -> int:
    """Fetch CA certs from official URLs; accept only pinned roots and certs chaining to them."""
    builtin = tls.builtin_ca_bundle()
    current_path = os.path.join(cfg.state_dir, "ca-bundle.pem")
    try:
        with open(current_path, "rb") as f:
            current = f.read()
    except FileNotFoundError:
        current = builtin
    pinned_roots = {tls.CA_PINS[n] for n in tls.ROOTS}
    pinned_all = set(tls.CA_PINS.values())
    blocks = tls.split_pem(builtin)
    roots_only = b"".join(b for b in blocks if tls.fingerprint(b) in pinned_roots)
    roots_path = current_path + ".roots"
    fsutil.atomic_write(roots_path, roots_only, 0o644)
    changed = False

    def acceptable(b: bytes) -> bool:
        """Non-pinned certs must be CA certs chaining to a pinned root (isolated trust store)."""
        if tls.fingerprint(b) in pinned_all:
            return True
        info = tls.cert_info(b)
        if info.subject == info.issuer or not tls.is_ca(b):
            return False
        try:
            tls.verify_chain(b, b"", roots_path)
        except tls.TLSError:
            return False
        return True

    # Certificates kept from the previous bundle are re-validated under the same policy.
    for b in tls.split_pem(current):
        if not any(tls.fingerprint(x) == tls.fingerprint(b) for x in blocks):
            if acceptable(b):
                blocks.append(b)
            else:
                changed = True
                print(f"удалён недоверенный сертификат из bundle: {tls.cert_info(b).subject}", file=sys.stderr)
    for name, url in tls.CA_SOURCES.items():
        try:
            data = _fetch(url, current_path)
            for b in tls.split_pem(tls.to_pem(data)):
                fp = tls.fingerprint(b)
                if any(tls.fingerprint(x) == fp for x in blocks):
                    continue
                info = tls.cert_info(b)
                if not acceptable(b):
                    print(f"{name}: сертификат {info.subject} не закреплён и не выстраивается к закреплённому корню — пропущен", file=sys.stderr)
                    continue
                blocks.append(b)
                changed = True
                print(f"{name}: добавлен {info.subject}, до {time.strftime('%Y-%m-%d', time.gmtime(info.not_after))}")
        except Exception as e:  # noqa: BLE001
            print(f"{name}: не удалось обновить: {e}", file=sys.stderr)
    os.unlink(roots_path)
    now = time.time()
    uniq, seen = [], set()
    for b in blocks:
        fp = tls.fingerprint(b)
        if fp in seen or tls.cert_info(b).not_after < now:
            continue
        seen.add(fp)
        uniq.append(b)
    fsutil.atomic_write(current_path, b"".join(uniq), 0o644)
    print("CA bundle:", current_path, "обновлён" if changed else "без изменений", f"({len(uniq)} серт.)")
    return 0


def _fetch(url: str, ca_file: str) -> bytes:
    import ssl
    ctx = ssl.create_default_context()
    try:
        ctx.load_verify_locations(ca_file)  # gu-st.ru itself may be signed by Минцифры
    except (OSError, ssl.SSLError):
        pass
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60, context=ctx) as r:
                return r.read()
        except OSError:
            if attempt == 2:
                raise
            time.sleep(5)
    raise AssertionError("unreachable")


if __name__ == "__main__":
    sys.exit(main())
