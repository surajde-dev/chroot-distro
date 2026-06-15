import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
from chroot_distro.commands.list_cmd import _container_row, _format_table, _iter_container_names
from chroot_distro.constants import PROGRAM_NAME
from chroot_distro.message import C, msg
from chroot_distro.progress import loading_line


def _is_running(name: str) -> bool:
    """Return True when the container has live processes or a namespace holder."""
    if session.get_active_chroot_pids(name):
        return True
    return namespace.get_live_holder(name) is not None


def command_ps(args) -> None:
    """List running containers (or all with --all)."""
    show_all = getattr(args, "all", False)
    quiet = getattr(args, "quiet", False)

    entries = _iter_container_names()
    if not show_all:
        entries = [name for name in entries if _is_running(name)]

    if quiet:
        for name in entries:
            print(name)
        return

    msg()
    if not entries:
        if show_all:
            msg(f"{C['YELLOW']}No containers are installed.{C['RST']}")
        else:
            msg(f"{C['YELLOW']}No running containers.{C['RST']}")
        msg()
        return

    rows = []
    total = len(entries)
    with loading_line("Gathering container info...") as update:
        for index, name in enumerate(entries, start=1):
            update(f"Scanning {name} ({index}/{total})...")
            rows.append(_container_row(name))

    label = "Containers" if show_all else "Running containers"
    msg(f"{C['CYAN']}{label}:{C['RST']}")
    msg()
    for line in _format_table(rows):
        msg(line)
    msg()
    msg(f"{C['CYAN']}Stop one with: {C['GREEN']}{PROGRAM_NAME} kill <name>{C['RST']}")
    msg()


__all__ = ("command_ps",)
