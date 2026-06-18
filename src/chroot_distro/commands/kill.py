import contextlib
import os
import signal
import subprocess
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

    First try standard unmount, then lazy unmount. If mounts remain or processes
    are active, kill all processes and retry unmounting. If still failing,
    try forceful unmount and print a detailed error if mounts remain.
    """
    container_name = args.container_name
    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)
    if not os.path.isdir(rootfs_dir):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    holder = namespace.get_live_holder(container_name)

    active_pids = session.get_active_chroot_pids(container_name)
    active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
    if not active_pids and holder is None and not active_mounts:
        log_info(f"Container '{container_name}' is not running.")
        return

    umount_bin = mount_manager._resolve_umount()

    def run_umount(target_path: str, flags: list[str] | None = None) -> bool:
        cmd = [umount_bin]
        if flags:
            cmd.extend(flags)
        cmd.append(target_path)

        if holder is not None:
            res = holder.run(cmd, capture_output=True, text=True)
        else:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return res.returncode == 0

    lock = ContainerLock(container_name, exclusive=True, command="kill")
    acquired = lock.acquire()
    if not acquired:
        log_info(f"Container '{container_name}' is busy (active sessions exist). Forcing cleanup...")

    try:
        # Step 1: Try standard unmount
        active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
        if active_mounts:
            log_info("Attempting standard unmount of active mount points...")
            for m in active_mounts:
                run_umount(m)

        # Step 2: Try lazy unmount if mounts remain
        active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
        if active_mounts:
            log_info("Some mounts remain busy. Attempting lazy unmount...")
            for m in active_mounts:
                run_umount(m, ["-l"])

        # Step 3: Kill processes and unmount again if active PIDs or mounts remain
        active_pids = session.get_active_chroot_pids(container_name)
        active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
        if active_pids or active_mounts:
            if active_pids:
                log_info(
                    f"Killing {len(active_pids)} process(es) in container '{container_name}' (PIDs: {active_pids})..."
                )
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

            # Now that processes have been signaled, attempt to acquire the exclusive lock
            if not acquired:
                acquired = lock.acquire()

            # Retry unmounting after killing processes
            active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
            if active_mounts:
                log_info("Retrying standard unmount after killing processes...")
                for m in active_mounts:
                    run_umount(m)

                active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
                if active_mounts:
                    log_info("Retrying lazy unmount after killing processes...")
                    for m in active_mounts:
                        run_umount(m, ["-l"])

        # Step 4: Forceful unmount and detailed error if still failed
        active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
        if active_mounts:
            log_info("Some mounts still remain. Attempting forceful unmount...")
            for m in active_mounts:
                run_umount(m, ["-f"])

            active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
            if active_mounts:
                active_pids = session.get_active_chroot_pids(container_name)
                crit_error(
                    f"Failed to kill and unmount container '{container_name}'.\n"
                    f"Remaining active mounts:\n" + "\n".join(f"  - {m}" for m in active_mounts) + "\n"
                    f"Remaining active process PIDs: {active_pids if active_pids else 'None'}"
                )
                sys.exit(1)

        # Cleanup namespace and sessions
        session.reset(container_name)
        if holder is not None:
            namespace.release_holder(container_name)
            namespace.clear_isolation_mode(container_name)

        log_info(f"Container '{container_name}' successfully killed and unmounted.")

    finally:
        if acquired:
            lock.release()


__all__ = ("command_kill",)
