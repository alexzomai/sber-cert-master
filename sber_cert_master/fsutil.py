"""Crash-safe file helpers: atomic writes, inter-process locks, JSON state."""

from __future__ import annotations

import contextlib
import errno
import fcntl
import grp
import json
import os
import shutil
import tempfile
import time


def resolve_gid(group: str | None) -> int | None:
    if not group:
        return None
    if str(group).isdigit():
        # Numeric GID: needed in containers, where the agent's group may not exist by name.
        return int(group)
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        raise ValueError(f"группа {group!r} не существует") from None


def ensure_dir(path: str, mode: int = 0o700, gid: int | None = None) -> None:
    os.makedirs(path, mode=mode, exist_ok=True)
    os.chmod(path, mode)
    if gid is not None:
        os.chown(path, -1, gid)


def fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: str, data: bytes | str, mode: int = 0o600, gid: int | None = None) -> None:
    """Write via temp file + fsync + rename: readers never see a partial file."""
    if isinstance(data, str):
        data = data.encode()
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            if gid is not None:
                os.fchown(f.fileno(), -1, gid)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    fsync_dir(directory)


def write_if_changed(path: str, data: bytes | str, mode: int = 0o600, gid: int | None = None) -> bool:
    if isinstance(data, str):
        data = data.encode()
    try:
        with open(path, "rb") as f:
            if f.read() == data:
                st = os.stat(path)
                if (st.st_mode & 0o777) == mode and (gid is None or st.st_gid == gid):
                    return False
    except FileNotFoundError:
        pass
    atomic_write(path, data, mode, gid)
    return True


class LockTimeout(Exception):
    pass


@contextlib.contextmanager
def file_lock(path: str, timeout: float = 120.0):
    """Exclusive flock; released automatically if the process dies."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
                if time.monotonic() > deadline:
                    raise LockTimeout(f"не удалось взять блокировку {path} за {timeout:.0f}с") from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def read_json(path: str, default=None):
    try:
        with open(path, "rb") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(path: str, obj, mode: int = 0o600, gid: int | None = None, backup: bool = False) -> None:
    if backup and os.path.exists(path):
        # Previous version survives a bad write / bad logic; restore by hand if needed.
        shutil.copy2(path, path + ".prev")
        os.chmod(path + ".prev", 0o600)
    atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", mode, gid)
