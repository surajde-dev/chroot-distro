from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import subprocess
from typing import TYPE_CHECKING

from chroot_distro.constants import IS_TERMUX, TERMUX_PREFIX
from chroot_distro.exceptions import MountError
from chroot_distro.message import warn

if TYPE_CHECKING:
    from chroot_distro.helpers.namespace import NamespaceHolder

log = logging.getLogger(__name__)


def _resolve_mount() -> str:
    if IS_TERMUX:
        termux_mount = os.path.join(TERMUX_PREFIX, "bin", "mount")
        if os.path.isfile(termux_mount):
            return termux_mount
    resolved = shutil.which("mount")
    if not resolved:
        raise MountError(
            "Required executable 'mount' not found on the system. Please install mount-utils or ensure it is in your PATH."
        )
    return resolved


def _resolve_umount() -> str:
    if IS_TERMUX:
        termux_umount = os.path.join(TERMUX_PREFIX, "bin", "umount")
        if os.path.isfile(termux_umount):
            return termux_umount
    resolved = shutil.which("umount")
    if not resolved:
        raise MountError(
            "Required executable 'umount' not found on the system. Please install mount-utils or ensure it is in your PATH."
        )
    return resolved


def decode_mount_path(path: str) -> str:
    """Decode octal escape sequences (like \\040 for space) in /proc/mounts paths."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def _mounts_under_rootfs_from_lines(lines: list[str], rootfs: str) -> list[str]:
    rootfs_abs = os.path.realpath(rootfs)
    active_mounts: list[str] = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        mount_point = decode_mount_path(parts[1])
        try:
            mount_point_abs = os.path.realpath(mount_point)
        except OSError:
            continue
        if mount_point_abs == rootfs_abs or mount_point_abs.startswith(rootfs_abs + os.sep):
            active_mounts.append(mount_point_abs)
    active_mounts.sort(key=lambda p: len(p.split(os.sep)), reverse=True)
    return active_mounts


def _read_proc_mounts_lines(holder: NamespaceHolder | None) -> list[str]:
    if holder is not None:
        text = holder.get_proc_mounts()
        return text.splitlines() if text else []
    if not os.path.exists("/proc/mounts"):
        return []
    try:
        with open("/proc/mounts") as f:
            return f.readlines()
    except OSError as e:
        raise MountError(f"Failed to read /proc/mounts: {e}") from e


def get_active_mounts(rootfs: str, holder: NamespaceHolder | None = None) -> list[str]:
    """Parse /proc/mounts and return mount points under rootfs (deepest first)."""
    lines = _read_proc_mounts_lines(holder)
    return _mounts_under_rootfs_from_lines(lines, rootfs)


def is_mounted(target: str, holder: NamespaceHolder | None = None) -> bool:
    """Check if a specific path is currently a mount point."""
    if holder is not None:
        return holder.is_mounted(target)

    target_abs = os.path.realpath(target)
    if not os.path.exists("/proc/mounts"):
        return False

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                mount_point = decode_mount_path(parts[1])
                if os.path.realpath(mount_point) == target_abs:
                    return True
    except OSError:
        pass
    return False


def _run_mount_cmd(cmd: list[str], holder: NamespaceHolder | None) -> subprocess.CompletedProcess:
    if holder is not None:
        return holder.run(cmd, capture_output=True, text=True)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def safe_mount(
    source: str,
    target: str,
    holder: NamespaceHolder | None = None,
    recursive: bool = False,
) -> None:
    """Safely mount source to target using bind mount.

    Creates target directory or file if they do not exist.
    """
    source_abs = os.path.realpath(source)
    if not os.path.exists(source_abs):
        raise MountError(f"Mount source does not exist: {source}")

    if os.path.isdir(source_abs):
        os.makedirs(target, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if not os.path.exists(target):
            open(target, "a").close()

    if is_mounted(target, holder=holder):
        return

    try:
        cmd = [_resolve_mount(), "--rbind" if recursive else "--bind", source_abs, target]
        result = _run_mount_cmd(cmd, holder)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.args,
                result.stdout,
                result.stderr,
            )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        raise MountError(f"Failed to mount {source} to {target}: {stderr}") from e


def bind_ptmx_to_pts(rootfs: str, holder: NamespaceHolder | None = None) -> bool:
    """Point <rootfs>/dev/ptmx at the freshly mounted devpts instance.

    After a `newinstance` devpts is mounted at <rootfs>/dev/pts, programs that
    open /dev/ptmx must reach *that* instance's multiplexer to allocate a pty
    whose slave appears in <rootfs>/dev/pts (with the correct device major).
    Bind <rootfs>/dev/pts/ptmx over <rootfs>/dev/ptmx to achieve this.

    Returns True on success, False on failure (non-fatal).
    """
    pts_ptmx = os.path.join(rootfs, "dev", "pts", "ptmx")
    dev_ptmx = os.path.join(rootfs, "dev", "ptmx")
    if not os.path.exists(pts_ptmx):
        log.debug("bind_ptmx_to_pts: %s does not exist", pts_ptmx)
        return False
    try:
        # /dev/ptmx may be a symlink (-> pts/ptmx) or a real node; ensure a
        # plain file/node target exists for the bind mount.
        if os.path.islink(dev_ptmx):
            with contextlib.suppress(OSError):
                os.remove(dev_ptmx)
        if not os.path.exists(dev_ptmx):
            with contextlib.suppress(OSError):
                open(dev_ptmx, "a").close()
        result = _run_mount_cmd([_resolve_mount(), "--bind", pts_ptmx, dev_ptmx], holder)
        if result.returncode != 0:
            log.debug("bind_ptmx_to_pts failed: %s", (result.stderr or "").strip())
            return False
    except Exception:
        log.debug("bind_ptmx_to_pts exception", exc_info=True)
        return False
    return True


def make_rslave(target: str, holder: NamespaceHolder | None = None) -> bool:
    """Set recursive slave mount propagation on *target*.

    This ensures that new mounts on the host (e.g. sockets created in
    /run/user/<uid> after the bind mount) propagate into the chroot,
    matching distrobox's ``--volume /run:/run:rslave`` behaviour.

    Returns True on success, False on failure (non-fatal).
    """
    target_abs = os.path.realpath(target)
    if not is_mounted(target_abs, holder=holder):
        return False
    try:
        result = _run_mount_cmd([_resolve_mount(), "--make-rslave", target_abs], holder)
        if result.returncode != 0:
            log.debug(
                "make-rslave failed for %s: %s",
                target_abs,
                (result.stderr or "").strip(),
            )
            return False
    except Exception:
        log.debug("make-rslave exception for %s", target_abs, exc_info=True)
        return False
    log.debug("Set rslave propagation on %s", target_abs)
    return True


# Recursive bind targets (/dev, /run and friends) frequently report
# "target is busy" on logout because nested submounts or short-lived handles
# linger. This is benign: the lazy umount below always succeeds. Suppress the
# alarming warning for these and clean up quietly.
_RECURSIVE_BIND_BASENAMES = frozenset(
    {
        "dev",
        "run",
        "proc",
        "sys",
        # Android system trees come in as nested binds; unmount them as a
        # subtree to avoid per-submount EINVAL ("Invalid argument").
        "system",
        "system_ext",
        "vendor",
        "product",
        "odm",
        "apex",
        "data",
    }
)


def _is_recursive_bind_target(target: str) -> bool:
    base = os.path.basename(os.path.realpath(target).rstrip(os.sep))
    return base in _RECURSIVE_BIND_BASENAMES


def safe_unmount(target: str, holder: NamespaceHolder | None = None, recursive: bool = False) -> None:
    """Safely unmount a target path.

    Falls back to lazy unmount if normal unmount fails. For recursive bind
    targets a "target is busy" or "Invalid argument" (EINVAL) failure is
    expected (host-owned submounts such as /run/user/<uid>, or nested Android
    binds like /system/product), so it is logged at debug level instead of
    warning the user, and we go straight to a lazy/recursive unmount.

    When *recursive* is True the whole subtree is detached in one go
    (``umount -R``) which is the correct way to tear down an ``--rbind`` mount
    without walking into submounts the host still holds open.
    """
    if not is_mounted(target, holder=holder):
        return

    umount = _resolve_umount()
    base_cmd = [umount, "-R", target] if recursive else [umount, target]
    quiet = recursive or _is_recursive_bind_target(target)

    try:
        result = _run_mount_cmd(base_cmd, holder)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.args,
                result.stdout,
                result.stderr,
            )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        if quiet:
            log.debug("Standard umount failed for %s (%s); using lazy umount.", target, stderr)
        else:
            warn(f"Standard umount failed for {target} ({stderr}). Trying lazy umount...")
        lazy_cmd = [umount, "-R", "-l", target] if recursive else [umount, "-l", target]
        try:
            result = _run_mount_cmd(lazy_cmd, holder)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    result.args,
                    result.stdout,
                    result.stderr,
                )
        except subprocess.CalledProcessError as e_lazy:
            lazy_stderr = (e_lazy.stderr or "").strip() if hasattr(e_lazy, "stderr") else ""
            # A target that is no longer a mountpoint (already gone via a parent
            # recursive unmount) is success, not failure.
            if not is_mounted(target, holder=holder):
                log.debug("%s already unmounted after recursive teardown.", target)
                return
            raise MountError(f"Failed to unmount {target} (lazy umount also failed): {lazy_stderr}") from e_lazy


def unmount_all(rootfs: str, holder: NamespaceHolder | None = None) -> None:
    """Unmount all active mount points nested under rootfs in correct order.

    Recursive-bind roots (``/run``, ``/dev``, ``/system`` and friends) are
    detached as a whole subtree with ``umount -R`` so we never walk into
    host-owned submounts (e.g. ``/run/user/<uid>``) or nested Android binds
    (e.g. ``/system/product``) that report "busy" / "Invalid argument" when
    unmounted individually. Submounts already covered by such a recursive
    unmount are skipped.
    """
    rootfs_abs = os.path.realpath(rootfs)
    mounts = get_active_mounts(rootfs, holder=holder)

    # A recursive-bind root is a mount exactly one level under rootfs whose
    # name is a known recursive-bind basename (e.g. <rootfs>/run, <rootfs>/dev,
    # <rootfs>/system). Its children (e.g. <rootfs>/run/user/1000) must NOT be
    # treated as roots; they are torn down by the parent's recursive umount.
    recursive_roots: list[str] = []
    for m in mounts:
        rel = os.path.relpath(m, rootfs_abs)
        if rel == os.curdir or os.sep in rel:
            continue  # rootfs itself, or a nested submount — not a top-level root
        if rel in _RECURSIVE_BIND_BASENAMES:
            recursive_roots.append(m)

    # Detach recursive subtrees first so their submounts vanish in one go.
    for root in recursive_roots:
        safe_unmount(root, holder=holder, recursive=True)

    # Then unmount everything that still remains (deepest-first ordering is
    # preserved from get_active_mounts), skipping anything already gone via a
    # recursive teardown above.
    for m in mounts:
        if any(m == root or m.startswith(root + os.sep) for root in recursive_roots):
            continue
        safe_unmount(m, holder=holder)


def ensure_no_mounts(rootfs: str, holder: NamespaceHolder | None = None) -> None:
    """Verify that no mount points exist under rootfs.

    Attempts to clean up if some are found. Raises MountError if any remain.
    """
    mounts = get_active_mounts(rootfs, holder=holder)
    if not mounts:
        return

    warn(f"Active mounts found under rootfs: {mounts}. Attempting automatic unmount...")
    with contextlib.suppress(MountError):
        unmount_all(rootfs, holder=holder)

    remaining = get_active_mounts(rootfs, holder=holder)
    if remaining:
        raise MountError(
            f"Safety check failed: Active mount points remain under {rootfs}: {remaining}. "
            "Refusing to delete or modify files in this directory to prevent host filesystem data loss."
        )


def _fs_supported(fstype: str) -> bool:
    """Return True if the kernel reports support for the given filesystem type."""
    try:
        with open("/proc/filesystems") as f:
            return fstype in f.read()
    except OSError:
        return False


def apply_special_mount(rootfs: str, sm, holder: NamespaceHolder | None = None) -> bool:
    """Execute a single SpecialMount inside rootfs.

    Returns True on success, False on failure (when optional=True).
    Raises RuntimeError on failure when optional=False.
    """
    if sm.check and not _fs_supported(sm.check):
        log.debug(f"Skipping {sm.fstype} mount: '{sm.check}' not in /proc/filesystems")
        return False

    target = os.path.join(rootfs, sm.target.lstrip("/"))

    if sm.mkdir:
        try:
            os.makedirs(target, exist_ok=True)
        except OSError as e:
            msg = f"Failed to create mount target directory {target}: {e}"
            if sm.optional:
                log.debug(msg)
                return False
            raise RuntimeError(msg) from e
    elif not os.path.exists(target):
        log.debug(f"Mount target {target} does not exist and mkdir=False, skipping")
        return False

    if is_mounted(target, holder=holder):
        return True

    cmd = [_resolve_mount(), "-t", sm.fstype]
    if sm.options:
        cmd += ["-o", sm.options]
    cmd += [sm.source, target]

    try:
        if holder is not None:
            result = holder.run(cmd, capture_output=True, text=True, timeout=15)
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        msg = f"mount timeout for {sm.fstype} at {target}"
        if sm.optional:
            log.debug(msg)
            return False
        raise RuntimeError(msg) from exc

    if result.returncode != 0:
        msg = f"mount -t {sm.fstype} failed: {result.stderr.strip()}"
        if sm.optional:
            log.debug(msg)
            return False
        raise RuntimeError(msg)

    log.debug(f"Mounted {sm.fstype} at {sm.target}")
    return True
