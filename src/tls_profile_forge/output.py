"""Create one new bounded file with every path component held by descriptor."""

import os
import stat


def write_new(path, text):
    if not isinstance(path, str) or not path or len(path) > 4096 or "\0" in path:
        raise ValueError("output_path")
    if not isinstance(text, str):
        raise ValueError("output_text")
    raw = text.encode("utf-8")
    if not raw or len(raw) > 65536:
        raise ValueError("output_budget")
    if (
        any(type(getattr(os, x, None)) is not int or getattr(os, x, 0) <= 0
                for x in ("O_NOFOLLOW", "O_DIRECTORY"))
        or type(getattr(os, "supports_dir_fd", None)) not in (set, frozenset)
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or type(getattr(os, "supports_follow_symlinks", None)) not in (set, frozenset)
        or os.stat not in os.supports_follow_symlinks
    ):
        raise ValueError("output_facility")
    parts = path.split("/")
    if path.startswith("/"):
        parts = parts[1:]
    if any(p in {"", ".", ".."} for p in parts):
        raise ValueError("output_path")
    parent = os.open("/" if path.startswith("/") else ".", os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for part in parts[:-1]:
            nxt = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            os.close(parent)
            parent = nxt
        fd = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        identity = os.fstat(fd)
        if not stat.S_ISREG(identity.st_mode):
            raise ValueError("output_type")
        pos = 0
        while pos < len(raw):
            count = os.write(fd, raw[pos:])
            if count <= 0:
                raise OSError("output_write")
            pos += count
        os.fsync(fd)
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise OSError("output_path_changed")
        # Never unlink after failure: stat-then-unlink cannot condition deletion
        # atomically on identity. A failed new write can leave a partial file.
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
