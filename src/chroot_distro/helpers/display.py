"""Unified display environment resolver for chroot sessions.

Aggregates X11, Wayland, sound, and D-Bus env vars from the host
into a single interface used by the login command.
"""

from __future__ import annotations

import os

from chroot_distro.helpers.sound import resolve_sound_env
from chroot_distro.helpers.wayland import resolve_wayland_env
from chroot_distro.helpers.x11 import (
    get_host_env_var,
    resolve_host_x11_env,
    resolve_invoking_uid,
)


def _runtime_dir(uid: int) -> str:
    """Return the XDG_RUNTIME_DIR path for *uid*."""
    return f"/run/user/{uid}"


def _resolve_dbus_env() -> dict[str, str]:
    """Return D-Bus session bus env vars from the host.

    Resolved variables:
    - ``DBUS_SESSION_BUS_ADDRESS``: from host ``$DBUS_SESSION_BUS_ADDRESS``,
      fallback ``unix:path=/run/user/<uid>/bus`` if the socket exists.
    """
    uid = resolve_invoking_uid()
    runtime = get_host_env_var("XDG_RUNTIME_DIR") or _runtime_dir(uid)
    env: dict[str, str] = {}

    dbus_addr = get_host_env_var("DBUS_SESSION_BUS_ADDRESS")
    if dbus_addr:
        env["DBUS_SESSION_BUS_ADDRESS"] = dbus_addr
    else:
        bus_socket = os.path.join(runtime, "bus")
        if os.path.exists(bus_socket):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_socket}"

    return env


def _socket_from_pulse_server(pulse_server: str) -> str | None:
    """Extract a unix socket path from a PULSE_SERVER value, if any.

    Accepts forms like ``unix:/run/user/1000/pulse/native`` and
    ``unix:path=/run/user/1000/pulse/native``. Returns None for network
    (tcp:) servers or unparseable values.
    """
    if not pulse_server.startswith("unix:"):
        return None
    rest = pulse_server[len("unix:") :]
    if rest.startswith("path="):
        rest = rest[len("path=") :]
    rest = rest.split(",", 1)[0]
    return rest or None


def _socket_from_dbus_address(dbus_addr: str) -> str | None:
    """Extract a unix socket path from a DBUS_SESSION_BUS_ADDRESS value."""
    if "unix:path=" not in dbus_addr:
        return None
    after = dbus_addr.split("unix:path=", 1)[1]
    return after.split(",", 1)[0] or None


def resolve_display_socket_binds(env: dict[str, str]) -> list[str]:
    """Return concrete host socket paths to bind for --shared-display.

    Instead of bind-mounting the whole host /run (which exposes
    NetworkManager, systemd-notify and other unrelated runtime sockets),
    bind only the sockets a GUI session actually needs:
      - Wayland compositor socket (XDG_RUNTIME_DIR/<WAYLAND_DISPLAY>)
      - PulseAudio socket (from PULSE_SERVER or the default location)
      - PipeWire socket (XDG_RUNTIME_DIR/pipewire-0)
      - D-Bus session bus socket (from DBUS_SESSION_BUS_ADDRESS or default)

    Only paths that exist on the host are returned. The runtime dir itself
    is included so the parent directory exists inside the container before
    the socket binds are applied.
    """
    uid = resolve_invoking_uid()
    runtime = env.get("XDG_RUNTIME_DIR") or get_host_env_var("XDG_RUNTIME_DIR") or _runtime_dir(uid)

    candidates: list[str] = []

    # Wayland socket (and its absolute form if WAYLAND_DISPLAY is a path)
    wayland_display = env.get("WAYLAND_DISPLAY", "")
    if wayland_display:
        if os.path.isabs(wayland_display):
            candidates.append(wayland_display)
        else:
            candidates.append(os.path.join(runtime, wayland_display))

    # PulseAudio socket
    pulse_server = env.get("PULSE_SERVER", "")
    pulse_socket = _socket_from_pulse_server(pulse_server) if pulse_server else None
    if pulse_socket is None:
        pulse_socket = os.path.join(runtime, "pulse", "native")
    candidates.append(pulse_socket)

    # PipeWire socket (no env var; discovered by location)
    candidates.append(os.path.join(runtime, "pipewire-0"))

    # D-Bus session bus socket
    dbus_addr = env.get("DBUS_SESSION_BUS_ADDRESS", "")
    dbus_socket = _socket_from_dbus_address(dbus_addr) if dbus_addr else None
    if dbus_socket is None:
        dbus_socket = os.path.join(runtime, "bus")
    candidates.append(dbus_socket)

    binds: list[str] = []
    if os.path.isdir(runtime):
        binds.append(runtime.rstrip("/"))
    seen = set(binds)
    for path in candidates:
        if path and path not in seen and os.path.exists(path):
            binds.append(path)
            seen.add(path)
    return binds


def resolve_display_env() -> tuple[dict[str, str], list[str]]:
    """Return all display/sound/dbus env vars and bind paths for auth files.

    Combines:
    - X11 env (DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR) + auth bind paths
    - Wayland env (WAYLAND_DISPLAY, XDG_SESSION_TYPE, XDG_CURRENT_DESKTOP, DESKTOP_SESSION)
    - Sound env (PULSE_SERVER)
    - D-Bus env (DBUS_SESSION_BUS_ADDRESS)

    Returns:
        (env_dict, bind_paths) — env_dict maps var names to values,
        bind_paths lists host paths that must be bind-mounted for X11 auth.
    """
    # X11 (existing, returns env + bind paths)
    env, bind_paths = resolve_host_x11_env()

    # Wayland
    wayland_env = resolve_wayland_env()
    for key, val in wayland_env.items():
        if key not in env:
            env[key] = val

    # Sound
    sound_env = resolve_sound_env()
    for key, val in sound_env.items():
        if key not in env:
            env[key] = val

    # D-Bus
    dbus_env = _resolve_dbus_env()
    for key, val in dbus_env.items():
        if key not in env:
            env[key] = val

    return env, bind_paths
