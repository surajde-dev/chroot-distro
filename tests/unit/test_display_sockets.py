"""Tests for --shared-display /run narrowing and socket discovery."""

from unittest.mock import patch

from chroot_distro.commands.login.bindings import get_bindings
from chroot_distro.helpers.display import (
    _socket_from_dbus_address,
    _socket_from_pulse_server,
    resolve_display_socket_binds,
)


def test_socket_from_pulse_server():
    assert _socket_from_pulse_server("unix:/run/user/1000/pulse/native") == "/run/user/1000/pulse/native"
    assert _socket_from_pulse_server("unix:path=/run/user/1000/pulse/native") == "/run/user/1000/pulse/native"
    assert _socket_from_pulse_server("tcp:127.0.0.1:4713") is None
    assert _socket_from_pulse_server("127.0.0.1") is None


def test_socket_from_dbus_address():
    assert _socket_from_dbus_address("unix:path=/run/user/1000/bus") == "/run/user/1000/bus"
    assert _socket_from_dbus_address("unix:path=/run/user/1000/bus,guid=abc") == "/run/user/1000/bus"
    assert _socket_from_dbus_address("tcp:host=localhost,port=1") is None


def test_resolve_display_socket_binds_filters_to_existing():
    env = {
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "WAYLAND_DISPLAY": "wayland-0",
        "PULSE_SERVER": "unix:/run/user/1000/pulse/native",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
    }
    present = {
        "/run/user/1000",
        "/run/user/1000/wayland-0",
        "/run/user/1000/pulse/native",
        "/run/user/1000/bus",
    }
    with (
        patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1000),
        patch("os.path.isdir", side_effect=lambda p: p == "/run/user/1000"),
        patch("os.path.exists", side_effect=lambda p: p in present),
    ):
        binds = resolve_display_socket_binds(env)
    assert binds[0] == "/run/user/1000"
    assert "/run/user/1000/wayland-0" in binds
    assert "/run/user/1000/pulse/native" in binds
    assert "/run/user/1000/bus" in binds
    # pipewire-0 socket absent -> excluded
    assert "/run/user/1000/pipewire-0" not in binds


def test_resolve_display_socket_binds_skips_tcp_pulse():
    env = {
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "PULSE_SERVER": "tcp:127.0.0.1:4713",
    }
    with (
        patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1000),
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=False),
    ):
        binds = resolve_display_socket_binds(env)
    # Only the runtime dir, no socket existed
    assert binds == ["/run/user/1000"]


def test_get_bindings_narrows_run_with_shared_display():
    sockets = ["/run/user/1000", "/run/user/1000/wayland-0", "/run/user/1000/bus"]
    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, rslave = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_display=True,
            display_socket_binds=sockets,
        )
    srcs = {src for src, _ in binds}
    # Whole /run is NOT bound
    assert "/run" not in srcs
    # No rslave on /run
    assert not any(t.endswith("/run") for t in rslave)
    # Specific sockets are bound
    assert "/run/user/1000/wayland-0" in srcs
    assert "/run/user/1000/bus" in srcs
    assert "/run/user/1000" in srcs


def test_get_bindings_keeps_whole_run_without_shared_display():
    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, rslave = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_display=False,
        )
    srcs = {src for src, _ in binds}
    assert "/run" in srcs
    assert any(t.endswith("/run") for t in rslave)


def test_get_bindings_keeps_whole_run_when_no_sockets_resolved():
    # shared_display on but no sockets discovered -> fall back to whole /run
    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, rslave = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_display=True,
            display_socket_binds=[],
        )
    srcs = {src for src, _ in binds}
    assert "/run" in srcs
    assert any(t.endswith("/run") for t in rslave)
