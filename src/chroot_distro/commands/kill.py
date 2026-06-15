import contextlib
import os
import signal
import sys
import time

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, log_info, warn
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_rootfs

_SIGTERM_GRACE_SECS = 1.0
_SIGKILL_WAIT_SECS = 2.0


def _wait_until_gone(container_name: str, timeout: float) -> list[int]:
    """Poll for active chroot PIDs until none remain or *timeout* elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = session.get_active_chroot_pids(container_name)
        if not remaining:
            return []
        time.sleep(0.1)
    return session.get_active_chroot_pids(container_name)


def command_kill(args) -> None:
    """Forcibly stop all processes in a container and tear it down.

    The abrupt counterpart to ``unmount``: send SIGTERM, then SIGKILL after a
    short grace period, then unmount and release the namespace holder.
    """
    container_name = args.container_name
    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)
    if not os.path.isdir(rootfs_dir):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    with ContainerLock(container_name, exclusive=True, command="kill"):
        active_pids = session.get_active_chroot_pids(container_name)
        holder = namespace.get_live_holder(container_name)

        if not active_pids and holder is None and not mount_manager.get_active_mounts(rootfs_dir):
            log_info(f"Container '{container_name}' is not running.")
            return

        if active_pids:
            log_info(f"Killing {len(active_pids)} process(es) in container '{container_name}' (PIDs: {active_pids})...")
            for pid in active_pids:
                with contextlib.suppress(OSError):
                    os.kill(pid, signal.SIGTERM)

            remaining = _wait_until_gone(container_name, _SIGTERM_GRACE_SECS)
            if remaining:
                log_info(f"Processes {remaining} did not exit; sending SIGKILL...")
                for pid in remaining:
                    with contextlib.suppress(OSError):
                        os.kill(pid, signal.SIGKILL)
                remaining = _wait_until_gone(container_name, _SIGKILL_WAIT_SECS)
                if remaining:
                    warn(f"Some processes could not be killed: {remaining}")

        session.reset(container_name)

        log_info("Unmounting active mount points under rootfs...")
        try:
            mount_manager.unmount_all(rootfs_dir, holder=holder)
        except Exception as e:
            crit_error(f"Failed to unmount: {e}")
            sys.exit(1)

        if holder is not None:
            namespace.release_holder(container_name)
            namespace.clear_isolation_mode(container_name)

        remaining_mounts = mount_manager.get_active_mounts(rootfs_dir)
        if remaining_mounts:
            warn(f"Some active mounts remain: {remaining_mounts}")
        else:
            log_info(f"Container '{container_name}' killed and unmounted.")


__all__ = ("command_kill",)
