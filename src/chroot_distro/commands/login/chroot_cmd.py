import logging
import os
import shlex
import shutil

from chroot_distro.constants import IS_TERMUX, TERMUX_PREFIX

log = logging.getLogger(__name__)


def _find_rootfs_shell(rootfs: str) -> str | None:
    """Find a usable shell inside the container rootfs, returning its guest path.

    Follows one level of symlink to handle systems with symlinked/moved shells.
    """
    for guest_path in ("/bin/sh", f"{TERMUX_PREFIX}/bin/sh", f"{TERMUX_PREFIX}/bin/bash"):
        sh_path = os.path.join(rootfs, guest_path.lstrip("/"))
        if os.path.isfile(sh_path):
            return guest_path
        try:
            resolved = os.path.realpath(sh_path)
            if os.path.isfile(resolved):
                return guest_path
        except OSError:
            pass
    return None


def build_chroot_args(
    rootfs: str,
    login_uid: str | None = None,
    login_gid: str | None = None,
    groups: list[str] | None = None,
    workdir: str = "",
    inner_cmd: list[str] | None = None,
) -> list[str]:
    """Build the command line arguments for the GNU chroot command.

    GNU chroot's ``--skip-chdir`` is only valid when NEWROOT is ``/``,
    so we cannot use it for our containers.  Instead, when *workdir* is
    set we wrap the inner command with ``sh -c 'cd <dir> && exec …'``
    so the directory change happens **inside** the chroot namespace.

    For distroless / rootless images that lack ``/bin/sh``, the ``cd``
    wrapper is skipped and the command is executed directly (with the
    working directory defaulting to ``/``).
    """
    chroot_exe = shutil.which("chroot") or "chroot"
    if IS_TERMUX:
        termux_chroot = os.path.join(TERMUX_PREFIX, "bin", "chroot")
        if os.path.isfile(termux_chroot):
            chroot_exe = termux_chroot

    args = [chroot_exe]

    # 1. Handle user and group specifications
    if login_uid is not None:
        userspec = str(login_uid)
        if login_gid is not None:
            userspec += f":{login_gid}"
        args.append(f"--userspec={userspec}")

    # 2. Handle supplementary groups
    if groups:
        # Convert all to strings and join by commas
        group_str = ",".join(str(g) for g in groups)
        args.append(f"--groups={group_str}")

    # 3. Rootfs target directory
    args.append(rootfs)

    # 4. Inner command — optionally prefixed with a cd into workdir
    cmd = list(inner_cmd) if inner_cmd else []
    if workdir and workdir != "/":
        shell_path = _find_rootfs_shell(rootfs)
        if shell_path:
            # Wrap the inner command so 'cd' happens inside the chroot.
            # If the directory doesn't exist or is inaccessible, we fall back to /
            # to ensure the shell still starts successfully.
            # exec replaces the shell process to keep the PID tree clean.
            quoted_workdir = shlex.quote(workdir)
            wrapped = (
                f"cd {quoted_workdir} 2>/dev/null || cd /; exec {shlex.join(cmd)}"
                if cmd
                else f"cd {quoted_workdir} 2>/dev/null || cd /"
            )
            args.extend([shell_path, "-c", wrapped])
        else:
            # Distroless / rootless image without a shell — cannot wrap
            # with a shell to change directory.  Run the command directly;
            # the working directory will default to /.
            log.debug(
                "No usable shell in rootfs %s; skipping workdir cd to %s",
                rootfs,
                workdir,
            )
            args.extend(cmd)
    else:
        args.extend(cmd)

    return args
