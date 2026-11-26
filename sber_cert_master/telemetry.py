"""Structured event journal (JSON lines) for diagnosis and bug reports.

Every operation that talks to the bank or changes state writes one event. Events never contain
credentials: tokens and secrets are referred to by a short one-way fingerprint (`fp`), and every event
is scrubbed against the profile's known secret values and a generic long-token pattern before writing.
Writing an event never raises.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import re
import socket
import time
import uuid

from . import __version__

MAX_BYTES = 5 * 1024 * 1024
KEEP_FILES = 3
# Bank tokens/secrets are long runs of letters and digits (38 hex chars in production). Paths and words
# with separators are left alone.
_TOKENISH = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{32,}(?![A-Za-z0-9])")

trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")


def fp(value: str | None) -> str | None:
    """Short one-way fingerprint for correlating a token across events without revealing it."""
    if not value:
        return None
    return hashlib.sha256(value.encode()).hexdigest()[:10]


@contextlib.contextmanager
def trace(prefix: str = ""):
    """Give all events inside the block a common trace id (one per tick / command)."""
    tok = trace_id.set((prefix + "-" if prefix else "") + uuid.uuid4().hex[:8])
    try:
        yield trace_id.get()
    finally:
        trace_id.reset(tok)


def scrub_text(text: str, secrets: set[str]) -> str:
    for s in sorted((s for s in secrets if s and len(s) >= 6), key=len, reverse=True):
        if s in text:
            text = text.replace(s, "***")
    return _TOKENISH.sub(lambda m: f"<redacted:{len(m.group(0))}>", text)


def scrub(obj, secrets: set[str]):
    if isinstance(obj, str):
        return scrub_text(obj, secrets)
    if isinstance(obj, dict):
        return {k: scrub(v, secrets) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub(v, secrets) for v in obj]
    return obj


class Telemetry:
    def __init__(self, path: str, profile: str, secrets=lambda: set()):
        self.path = path
        self.profile = profile
        self.secrets = secrets
        self.host = socket.gethostname()

    def event(self, kind: str, **fields) -> None:
        try:
            ev = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "t": round(time.time(), 3),
                "kind": kind,
                "profile": self.profile,
                "trace": trace_id.get() or None,
                "pid": os.getpid(),
                "v": __version__,
            }
            ev.update({k: v for k, v in fields.items() if v is not None})
            line = json.dumps(scrub(ev, self.secrets()), ensure_ascii=False, default=str) + "\n"
            self._rotate_if_needed(len(line))
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)
        except Exception:  # noqa: BLE001 - telemetry must never break the service
            pass

    def _rotate_if_needed(self, incoming: int) -> None:
        try:
            if os.path.getsize(self.path) + incoming <= MAX_BYTES:
                return
        except FileNotFoundError:
            return
        for i in range(KEEP_FILES - 1, 0, -1):  # events.jsonl.{i} -> .{i+1}; the oldest is overwritten
            if os.path.exists(f"{self.path}.{i}"):
                os.replace(f"{self.path}.{i}", f"{self.path}.{i + 1}")
        os.replace(self.path, self.path + ".1")

    def tail(self, n: int = 200) -> list[dict]:
        """Last n events, reading files from the end (cheap even for a 5 MB journal)."""
        out: list[dict] = []
        for path in [self.path] + [f"{self.path}.{i}" for i in range(1, KEEP_FILES + 1)]:
            for line in _read_lines_reversed(path):
                with contextlib.suppress(ValueError):
                    out.append(json.loads(line))
                if len(out) >= n:
                    return list(reversed(out))
        return list(reversed(out))


def _read_lines_reversed(path: str, chunk: int = 65536):
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return
    with f:
        f.seek(0, os.SEEK_END)
        pos, rest = f.tell(), b""
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + rest
            lines = data.split(b"\n")
            rest = lines[0]
            for line in reversed(lines[1:]):
                if line.strip():
                    yield line.decode("utf-8", "replace")
        if rest.strip():
            yield rest.decode("utf-8", "replace")
