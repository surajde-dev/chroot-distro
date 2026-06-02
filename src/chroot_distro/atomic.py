import contextlib
import os
import tempfile


@contextlib.contextmanager
def atomic_replace(path: str, *, suffix: str = ".tmp", mode: int | None = None):
    """Yield a tmp path next to *path*; rename on success, remove on error.

    When *mode* is set it is applied to the temp file before rename (``mkstemp``
    creates mode ``0o600`` by default).
    """
    dest_dir = os.path.dirname(path) or "."
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".",
        suffix=suffix,
        dir=dest_dir,
    )
    os.close(fd)
    try:
        yield tmp
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
