"""Alerts with de-duplication: log (journald), external command, webhook, Telegram."""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import time
import urllib.request

from . import fsutil

log = logging.getLogger("sber-cert-master")

LEVELS = {"info": 0, "warning": 1, "critical": 2}
# How often an unresolved alert is repeated.
REPEAT = {"info": None, "warning": 24 * 3600, "critical": 3 * 3600}


class Notifier:
    def __init__(self, notify_cfg: dict, state_dir: str):
        self.cfg = notify_cfg or {}
        self.path = os.path.join(state_dir, "alerts.json")
        self.lock = os.path.join(state_dir, ".alerts.lock")
        self.host = socket.gethostname()

    def alert(self, key: str, level: str, title: str, text: str = "", force: bool = False) -> bool:
        """Send unless the same alert (key+level) was already sent recently. Returns True if sent."""
        now = time.time()
        with fsutil.file_lock(self.lock):
            db = fsutil.read_json(self.path, {})
            prev = db.get(key)
            if prev and not force and prev.get("level") == level:
                repeat = REPEAT.get(level)
                if repeat is None or now - prev.get("sent_at", 0) < repeat:
                    return False
            db[key] = {"level": level, "title": title, "sent_at": now}
            fsutil.write_json(self.path, db)
        self._send(level, title, text)
        return True

    def resolve(self, key: str, title: str) -> None:
        """If an alert for key is open, clear it and announce recovery."""
        with fsutil.file_lock(self.lock):
            db = fsutil.read_json(self.path, {})
            prev = db.pop(key, None)
            if prev is None:
                return
            fsutil.write_json(self.path, db)
        if prev.get("level") != "info":
            self._send("info", "Восстановлено: " + title, f"было: {prev.get('title')}")

    def open_alerts(self) -> dict:
        return fsutil.read_json(self.path, {})

    def _send(self, level: str, title: str, text: str) -> None:
        msg = f"[sber-cert-master@{self.host}] {level.upper()}: {title}"
        if text:
            msg += "\n" + text
        getattr(log, {"info": "info", "warning": "warning", "critical": "error"}[level])(msg.replace("\n", " | "))
        min_level = LEVELS.get(self.cfg.get("min_level", "warning"), 1)
        if LEVELS[level] < min_level:
            return
        cmd = self.cfg.get("command")
        if cmd:
            try:
                subprocess.run(cmd, shell=True, input=msg.encode(), timeout=30, check=False,
                               env={**os.environ, "SCM_LEVEL": level, "SCM_TITLE": title, "SCM_TEXT": text})
            except Exception as e:  # noqa: BLE001 - alerting must never break the daemon
                log.error("notify command failed: %s", e)
        url = self.cfg.get("webhook_url")
        if url:
            self._post(url, {"level": level, "title": title, "text": text, "host": self.host, "message": msg})
        token = self._telegram_token()
        chat = self.cfg.get("telegram_chat_id")
        if token and chat:
            self._post(f"https://api.telegram.org/bot{token}/sendMessage", {"chat_id": chat, "text": msg})

    def _telegram_token(self) -> str | None:
        p = self.cfg.get("telegram_bot_token_file")
        if not p:
            return None
        try:
            with open(p) as f:
                return f.read().strip()
        except OSError as e:
            log.error("cannot read telegram token: %s", e)
            return None

    @staticmethod
    def _post(url: str, payload: dict) -> None:
        req = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=15).read()
        except Exception as e:  # noqa: BLE001
            log.error("notify POST failed: %s", type(e).__name__)
