"""Tests for --bind mount-option parsing and safe_mount remount handling."""

from unittest.mock import MagicMock, patch

from chroot_distro.commands.login.bindings import (
    parse_bind_options,
    strip_bind_options,
)
from chroot_distro.helpers import mount_manager as mm


def test_strip_bind_options_forms():
    assert strip_bind_options(None) == []
    assert strip_bind_options([]) == []
    # host only
    assert strip_bind_options(["/host"]) == ["/host"]
    # host:guest
    assert strip_bind_options(["/host:/guest"]) == ["/host:/guest"]
    # host:guest:ro -> options stripped
    assert strip_bind_options(["/host:/guest:ro"]) == ["/host:/guest"]
    # host:guest:ro,nosuid -> options stripped
    assert strip_bind_options(["/host:/guest:ro,nosuid"]) == ["/host:/guest"]


def test_parse_bind_options_only_when_present():
    # No options -> not in the map
    assert parse_bind_options(["/host:/guest"]) == {}
    assert parse_bind_options(["/host"]) == {}
    # Options present -> keyed by normalized guest dst
    assert parse_bind_options(["/host:/guest:ro"]) == {"/guest": "ro"}
    assert parse_bind_options(["/host:/guest/:ro,z"]) == {"/guest": "ro,z"}


def test_parse_bind_options_multiple():
    result = parse_bind_options(
        [
            "/a:/mnt/a:ro",
            "/b:/mnt/b",
            "/c:/mnt/c:rw,nosuid",
        ]
    )
    assert result == {"/mnt/a": "ro", "/mnt/c": "rw,nosuid"}


def test_filter_bind_options_drops_selinux_flags():
    assert mm._filter_bind_options("ro") == "ro"
    assert mm._filter_bind_options("ro,z") == "ro"
    assert mm._filter_bind_options("z") == ""
    assert mm._filter_bind_options("Z,ro,nosuid") == "ro,nosuid"
    assert mm._filter_bind_options("") == ""


@patch("chroot_distro.helpers.mount_manager._run_mount_cmd")
def test_safe_mount_no_options_is_single_bind(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    holder = MagicMock()
    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
        patch("shutil.which", return_value="/bin/mount"),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder)
    # Only the initial bind, no remount
    assert mock_run.call_count == 1
    assert mock_run.call_args[0][0][1:] == ["--bind", "/host/src", "/tmp/rootfs/mnt"]


@patch("chroot_distro.helpers.mount_manager._run_mount_cmd")
def test_safe_mount_ro_issues_remount(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    holder = MagicMock()
    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
        patch("shutil.which", return_value="/bin/mount"),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder, options="ro")
    assert mock_run.call_count == 2
    first = mock_run.call_args_list[0][0][0]
    second = mock_run.call_args_list[1][0][0]
    assert first[1:] == ["--bind", "/host/src", "/tmp/rootfs/mnt"]
    assert second[1:] == ["-o", "remount,bind,ro", "/tmp/rootfs/mnt"]


@patch("chroot_distro.helpers.mount_manager._run_mount_cmd")
def test_safe_mount_only_selinux_option_skips_remount(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    holder = MagicMock()
    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
        patch("shutil.which", return_value="/bin/mount"),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder, options="z")
    # z is dropped -> no kernel options -> no remount
    assert mock_run.call_count == 1


@patch("chroot_distro.helpers.mount_manager._run_mount_cmd")
def test_safe_mount_recursive_ro_uses_rbind_remount(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    holder = MagicMock()
    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
        patch("shutil.which", return_value="/bin/mount"),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder, recursive=True, options="ro")
    second = mock_run.call_args_list[1][0][0]
    assert second[1:] == ["-o", "remount,rbind,ro", "/tmp/rootfs/mnt"]
