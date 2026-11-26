"""Configuration (TOML)."""

from __future__ import annotations

import os
import tomllib
import urllib.parse
from dataclasses import dataclass, field

DEFAULT_CONFIG = "/etc/sber-cert-master/config.toml"

ENVIRONMENTS = {
    # api_base: TLS/mTLS API host; auth_base: browser authorization (SberBusiness ID)
    "prod": {
        "api_base": "https://fintech.sberbank.ru:9443",
        "auth_base": "https://sbi.sberbank.ru:9443",
    },
    "sandbox": {
        "api_base": "https://fintech-test.sberbank.ru:9443",
        "auth_base": "https://sbi.sberbank.ru:9443",
    },
}


class ConfigError(Exception):
    pass


@dataclass
class Profile:
    name: str
    client_id: str
    env: str = "prod"
    api_base: str = ""
    auth_base: str = ""
    redirect_uri: str = ""
    scope: str = "openid"
    # Refresh the access token when less than this is left (agents always get >= margin).
    refresh_margin_seconds: int = 20 * 60
    # Bank: client_secret lives 40 days, recommends rotating on day 35-38.
    secret_rotate_after_days: float = 30
    secret_lifetime_days: float = 40
    # Cheap authenticated GET to confirm mTLS + token really work. 0 disables.
    # A revoked token (e.g. a second refresher used our grant) is only noticed by this probe: keep it short.
    probe_interval_seconds: int = 300
    cert_warn_days: tuple[int, ...] = (60, 30, 14, 7, 3, 1)
    publish_group: str | None = None  # group name or numeric GID
    http_timeout: float = 30.0
    # HTTP CONNECT proxy for bank requests (http://host:port). Empty = direct; env proxies are ignored.
    proxy: str = ""


@dataclass
class Config:
    state_dir: str = "/var/lib/sber-cert-master/state"
    publish_dir: str = "/var/lib/sber-cert-master/public"
    # Short on purpose: an unfinished refresh (the bank may already have revoked the published token) is
    # retried at the next tick. Ticks are cheap; certificate checks run at most every TLS_CHECK_SECONDS.
    tick_interval_seconds: int = 15
    # Watchdog (`check`) alarms when the daemon has not ticked for this long.
    stale_tick_seconds: int = 15 * 60
    notify: dict = field(default_factory=dict)
    profiles: dict[str, Profile] = field(default_factory=dict)
    path: str = ""

    def profile(self, name: str | None) -> Profile:
        if name is None:
            if len(self.profiles) == 1:
                return next(iter(self.profiles.values()))
            raise ConfigError("укажите профиль: " + ", ".join(self.profiles) if self.profiles else "в конфиге нет профилей")
        try:
            return self.profiles[name]
        except KeyError:
            raise ConfigError(f"профиль {name!r} не найден в {self.path}") from None


_PROFILE_KEYS = set(Profile.__dataclass_fields__) - {"name"}


def load(path: str | None = None) -> Config:
    path = path or os.environ.get("SBER_CERT_MASTER_CONFIG") or DEFAULT_CONFIG
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"нет файла конфигурации {path}") from None
    cfg = Config(path=path)
    for key in ("state_dir", "publish_dir", "tick_interval_seconds", "stale_tick_seconds"):
        if key in raw:
            setattr(cfg, key, raw[key])
    cfg.notify = dict(raw.get("notify", {}))
    for name, p in (raw.get("profiles") or {}).items():
        unknown = set(p) - _PROFILE_KEYS
        if unknown:
            raise ConfigError(f"профиль {name}: неизвестные ключи {sorted(unknown)}")
        if "client_id" not in p:
            raise ConfigError(f"профиль {name}: нужен client_id")
        prof = Profile(name=name, **{k: v for k, v in p.items()})
        prof.client_id = str(prof.client_id)
        if prof.publish_group is not None:
            prof.publish_group = str(prof.publish_group)
        if prof.env not in ENVIRONMENTS and not (prof.api_base and prof.auth_base):
            raise ConfigError(f"профиль {name}: env должен быть prod или sandbox")
        defaults = ENVIRONMENTS.get(prof.env, {})
        prof.api_base = (prof.api_base or defaults["api_base"]).rstrip("/")
        prof.auth_base = (prof.auth_base or defaults["auth_base"]).rstrip("/")
        for key in ("api_base", "auth_base"):
            u = urllib.parse.urlsplit(getattr(prof, key))
            if u.scheme != "https" or not u.hostname or u.username or u.query or u.fragment:
                raise ConfigError(f"профиль {name}: {key} должен быть https://host[:port]")
        if prof.proxy:
            pu = urllib.parse.urlsplit(prof.proxy)
            if pu.scheme != "http" or not pu.hostname or pu.username or pu.password \
                    or pu.path not in ("", "/") or pu.query or pu.fragment:
                raise ConfigError(f"профиль {name}: proxy должен быть http://host:port (без логина и пароля)")
        prof.cert_warn_days = tuple(sorted(prof.cert_warn_days, reverse=True))
        # client_secret belongs to the client_id: two profiles rotating it independently would lock each other out.
        def origin(p: Profile) -> tuple:
            u = urllib.parse.urlsplit(p.api_base)
            return (u.hostname.lower().rstrip("."), u.port or 443, p.client_id)

        for other in cfg.profiles.values():
            if origin(other) == origin(prof):
                raise ConfigError(f"профили {other.name} и {name} используют один client_id {prof.client_id}: "
                                  "client_secret общий для client_id, поэтому на один client_id допустим один профиль "
                                  "(для второго пользователя выпустите отдельный client_id в ЛК Sber API)")
        cfg.profiles[name] = prof
    return cfg
