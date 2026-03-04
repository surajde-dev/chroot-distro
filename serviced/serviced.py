#!/usr/bin/env python3
"""
serviced.py - Lightweight service manager for systemd .service files
              Runs services as background processes without systemd.

Designed for chroot environments and systems without systemd.

Usage:
    serviced.py <command> [options] [service]

Commands:
    start     <service>   Start a service
    stop      <service>   Stop a service
    restart   <service>   Restart a service
    enable    <service>   Enable service to start on boot
    disable   <service>   Disable service from starting on boot
    status    <service>   Show service status
    log       <service>   Show service log (last 50 lines)
    list                  List all discovered services
    list-running          List only currently running services

Options:
    --dry-run             Show what would be done without doing it
    -v, --verbose         Show debug output
    -n, --lines NUM       Number of log lines to show (default: 50)
"""

from __future__ import print_function

import argparse
import datetime
import grp
import json
import os
import pwd
import re
import shlex
import signal
import socket as socketmod
import subprocess
import sys
import time

VERSION = "0.1.5"

UNIT_PATHS = [
    "/etc/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
]

STATE_DIR = "/tmp/serviced"
PID_DIR = os.path.join(STATE_DIR, "pids")
LOG_DIR = os.path.join(STATE_DIR, "logs")
STATUS_DIR = os.path.join(STATE_DIR, "status")

ENABLED_DIR = "/var/lib/serviced/enabled"
ACTION_LOG_FILE = "/var/lib/serviced/serviced.log"

SYSTEM_BUS_SOCKET = "/run/dbus/system_bus_socket"

CRITICAL_SERVICES = {
    # systemd internals
    "systemd-journald",
    "systemd-logind",
    "systemd-udevd",
    "systemd-resolved",
    "systemd-networkd",
    "systemd-timesyncd",
    "systemd-tmpfiles-setup",
    "systemd-tmpfiles-clean",
    "systemd-sysctl",
    "systemd-modules-load",
    "systemd-remount-fs",
    "systemd-update-utmp",
    "systemd-random-seed",
    "systemd-hibernate-resume",
    "systemd-suspend",
    "systemd-halt",
    "systemd-poweroff",
    "systemd-reboot",
    "systemd-kexec",
    "systemd-machine-id-commit",
    "systemd-binfmt",
    "systemd-coredump",
    "systemd-ask-password-console",
    "systemd-ask-password-wall",
    "systemd-boot-random-seed",
    "systemd-fsck",
    "systemd-growfs",
    "systemd-makefs",
    "systemd-pstore",
    "systemd-quotacheck",
    "systemd-vconsole-setup",
    "systemd-firstboot",
    "systemd-sysusers",
    "systemd-homed",
    "systemd-userdbd",
    "systemd-oomd",
    # core system
    "init",
    "udev",
    "eudev",
    "mdev",
    # login / session
    "getty@tty1",
    "serial-getty@",
    # mount / filesystem
    "local-fs.target",
    "remote-fs.target",
    "swap.target",
    "tmp.mount",
    "dev-hugepages.mount",
    "dev-mqueue.mount",
    "sys-kernel-debug.mount",
    "sys-kernel-tracing.mount",
    "sys-fs-fuse-connections.mount",
}

UNSUPPORTED_TYPES = set()

CRITICAL_PREFIXES = (
    "systemd-",
    "initrd-",
    "rescue.",
    "emergency.",
    "halt.",
    "poweroff.",
    "reboot.",
    "kexec.",
)

VERBOSE = False


# ======================================================================
#  Logging helpers
# ======================================================================


def log_info(msg, *args):
    print("[INFO]", msg % args if args else msg)


def log_warn(msg, *args):
    print("[WARN]", msg % args if args else msg, file=sys.stderr)


def log_error(msg, *args):
    print("[ERROR]", msg % args if args else msg, file=sys.stderr)


def log_debug(msg, *args):
    if VERBOSE:
        print("[DEBUG]", msg % args if args else msg, file=sys.stderr)


def log_action(msg, *args):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = msg % args if args else msg
        with open(ACTION_LOG_FILE, "a") as f:
            f.write("[%s] %s\n" % (timestamp, formatted_msg))
    except (IOError, OSError):
        pass


# ======================================================================
#  Utility functions
# ======================================================================


def ensure_dirs():
    for d in [STATE_DIR, PID_DIR, LOG_DIR, STATUS_DIR]:
        os.makedirs(d, mode=0o755, exist_ok=True)
    try:
        os.makedirs(ENABLED_DIR, mode=0o755, exist_ok=True)
    except PermissionError:
        pass


def is_critical_service(name):
    base = name.replace(".service", "")
    if base in CRITICAL_SERVICES:
        return True
    if name.startswith(CRITICAL_PREFIXES):
        return True
    if "@." in name:
        return True
    return False


def pid_exists(pid):
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("State:"):
                    return "Z" not in line
    except (IOError, OSError):
        pass
    return True


def is_socket_alive(path):
    """Check if a unix socket has a listener (not stale).

    Tries SOCK_STREAM first (most common), then SOCK_DGRAM.
    Returns False if no process is accepting connections.
    """
    if not os.path.exists(path):
        return False
    for stype in (socketmod.SOCK_STREAM, socketmod.SOCK_DGRAM):
        try:
            s = socketmod.socket(socketmod.AF_UNIX, stype)
            s.settimeout(1)
            s.connect(path)
            s.close()
            return True
        except (socketmod.error, OSError):
            continue
    return False


# ======================================================================
#  Unit file parser
# ======================================================================


class UnitFile:
    """Parses a systemd unit file (.service or .socket)."""

    def __init__(self, path=None):
        self.path = path
        self._data = {}
        if path:
            self.parse(path)

    def parse(self, path):
        self.path = path
        self._data = {}
        section = None
        try:
            with open(path, "r") as f:
                prev_line = ""
                for raw_line in f:
                    line = raw_line.rstrip("\n")
                    if line.endswith("\\"):
                        prev_line += line[:-1].strip() + " "
                        continue
                    if prev_line:
                        line = prev_line + line.strip()
                        prev_line = ""
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    m = re.match(r"^\[(.+)\]$", line)
                    if m:
                        section = m.group(1)
                        if section not in self._data:
                            self._data[section] = {}
                        continue
                    if section and "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip()
                        if key not in self._data[section]:
                            self._data[section][key] = []
                        if value == "":
                            self._data[section][key] = []
                        else:
                            self._data[section][key].append(value)
        except (IOError, OSError) as e:
            log_debug("Failed to parse %s: %s", path, e)

    def get(self, section, key, default=""):
        try:
            values = self._data[section][key]
            return values[-1] if values else default
        except KeyError:
            return default

    def getlist(self, section, key):
        try:
            return list(self._data[section][key])
        except KeyError:
            return []

    def getbool(self, section, key, default=False):
        val = self.get(section, key, "")
        if not val:
            return default
        return val.lower() in ("yes", "true", "1", "on")

    def has_section(self, section):
        return section in self._data

    @property
    def description(self):
        return self.get("Unit", "Description", os.path.basename(self.path or "unknown"))

    @property
    def requires(self):
        val = self.get("Unit", "Requires", "")
        return val.split() if val else []

    @property
    def wants(self):
        val = self.get("Unit", "Wants", "")
        return val.split() if val else []

    @property
    def after(self):
        val = self.get("Unit", "After", "")
        return val.split() if val else []

    @property
    def binds_to(self):
        val = self.get("Unit", "BindsTo", "")
        return val.split() if val else []

    @property
    def part_of(self):
        val = self.get("Unit", "PartOf", "")
        return val.split() if val else []

    @property
    def condition_path_exists(self):
        return self.get("Unit", "ConditionPathExists", "")

    # ---- [Service] properties ----

    @property
    def service_type(self):
        return self.get("Service", "Type", "simple").lower()

    @property
    def exec_start(self):
        return self.getlist("Service", "ExecStart")

    @property
    def exec_stop(self):
        return self.getlist("Service", "ExecStop")

    @property
    def exec_start_pre(self):
        return self.getlist("Service", "ExecStartPre")

    @property
    def exec_start_post(self):
        return self.getlist("Service", "ExecStartPost")

    @property
    def pid_file(self):
        return self.get("Service", "PIDFile", "")

    @property
    def working_directory(self):
        return self.get("Service", "WorkingDirectory", "")

    @property
    def user(self):
        return self.get("Service", "User", "")

    @property
    def group(self):
        return self.get("Service", "Group", "")

    @property
    def environment(self):
        env = {}
        for val in self.getlist("Service", "Environment"):
            val = val.strip('"').strip("'")
            if "=" in val:
                k, _, v = val.partition("=")
                env[k.strip()] = v.strip()
        return env

    @property
    def environment_file(self):
        return self.get("Service", "EnvironmentFile", "")

    @property
    def remain_after_exit(self):
        return self.getbool("Service", "RemainAfterExit", False)

    @property
    def bus_name(self):
        return self.get("Service", "BusName", "")

    @property
    def sockets(self):
        """Sockets= directive — which socket units this service uses."""
        val = self.get("Service", "Sockets", "")
        return val.split() if val else []

    # ---- [Socket] properties ----

    @property
    def listen_stream(self):
        """ListenStream= values from [Socket] section."""
        return self.getlist("Socket", "ListenStream")

    @property
    def socket_service(self):
        """Service= directive from [Socket] section — explicit service link."""
        return self.get("Socket", "Service", "")


# ======================================================================
#  Command parsing helpers
# ======================================================================


def parse_exec_cmd(cmd_str):
    cmd = cmd_str.strip()
    check_errors = True
    while cmd and cmd[0] in "-+!@:":
        if cmd[0] == "-":
            check_errors = False
        cmd = cmd[1:]
    cmd = cmd.strip()
    if not cmd:
        return check_errors, []
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()
    return check_errors, parts


def expand_env(cmd_parts, env):
    result = []
    for part in cmd_parts:
        expanded = part
        for m in re.finditer(r"\$\{([^}]+)\}", part):
            var = m.group(1)
            val = env.get(var, os.environ.get(var, ""))
            expanded = expanded.replace(m.group(0), val)
        for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)", expanded):
            var = m.group(1)
            val = env.get(var, os.environ.get(var, ""))
            expanded = expanded.replace(m.group(0), val)
        if expanded == "" and part != expanded:
            continue
        result.append(expanded)
    return result


def strip_socket_activation(cmd_parts):
    """Remove -H fd:// from command args."""
    result = []
    skip_next = False
    for i, part in enumerate(cmd_parts):
        if skip_next:
            skip_next = False
            continue
        if (
            part == "-H"
            and i + 1 < len(cmd_parts)
            and cmd_parts[i + 1].startswith("fd://")
        ):
            log_debug("Stripping socket activation: -H %s", cmd_parts[i + 1])
            skip_next = True
            continue
        if part.startswith("-H=fd://") or part == "--host=fd://":
            log_debug("Stripping socket activation: %s", part)
            continue
        result.append(part)
    return result


def strip_systemd_args(cmd_parts):
    """Remove systemd-specific flags from ANY service command.

    --address=systemd:    Receive listening socket from systemd.
    --systemd-activation  Let systemd handle activation of helpers.

    These flags are not specific to any one service. Any binary
    that speaks the systemd socket-activation or bus-activation
    protocol may use them. Without systemd they are meaningless,
    so we strip them universally.
    """
    if not cmd_parts:
        return cmd_parts
    result = []
    for part in cmd_parts:
        if part.startswith("--address=systemd:"):
            log_debug("Stripping systemd arg: %s", part)
            continue
        if part == "--systemd-activation":
            log_debug("Stripping systemd arg: %s", part)
            continue
        result.append(part)
    return result


def load_environment_file(path):
    env = {}
    optional = False
    if path.startswith("-"):
        optional = True
        path = path[1:].strip()
    if not os.path.isfile(path):
        if not optional:
            log_warn("EnvironmentFile not found: %s", path)
        return env
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    env[key.strip()] = value.strip().strip('"').strip("'")
    except (IOError, OSError) as e:
        if not optional:
            log_warn("Failed to read EnvironmentFile %s: %s", path, e)
    return env


# ======================================================================
#  Bus-name helpers (used by _start_dbus for Type=dbus readiness)
# ======================================================================


def check_dbus_bus_name(bus_name, timeout=5.0):
    """Check if a D-Bus bus name is registered on the system bus."""
    if not bus_name:
        return False
    try:
        result = subprocess.run(
            [
                "dbus-send",
                "--system",
                "--print-reply",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.NameHasOwner",
                "string:%s" % bus_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return b"true" in result.stdout.lower()
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False


def wait_for_dbus_name(bus_name, pid, timeout=10.0):
    """Wait until a D-Bus bus name appears or the process dies."""
    if not bus_name:
        return True
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_exists(pid):
            return False
        if check_dbus_bus_name(bus_name):
            log_debug("D-Bus name '%s' acquired by PID %d", bus_name, pid)
            return True
        time.sleep(0.3)
    return False


# ======================================================================
#  Service Manager
# ======================================================================


class ServiceManager:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self._units = {}  # name.service -> UnitFile
        self._sockets = {}  # name.socket  -> UnitFile
        self._discovered = False

    def discover_services(self):
        """Scan unit directories for .service AND .socket files."""
        if self._discovered:
            return
        seen = set()
        for unit_dir in UNIT_PATHS:
            if not os.path.isdir(unit_dir):
                continue
            for fname in sorted(os.listdir(unit_dir)):
                is_svc = fname.endswith(".service")
                is_sock = fname.endswith(".socket")
                if not is_svc and not is_sock:
                    continue
                if fname in seen:
                    continue
                seen.add(fname)
                fpath = os.path.join(unit_dir, fname)
                if os.path.islink(fpath):
                    target = os.readlink(fpath)
                    if target == "/dev/null":
                        continue
                    if not os.path.isabs(target):
                        target = os.path.join(unit_dir, target)
                    if not os.path.exists(target):
                        continue
                    fpath = target
                try:
                    unit = UnitFile(fpath)
                    if is_svc:
                        self._units[fname] = unit
                    else:
                        self._sockets[fname] = unit
                except Exception as e:
                    log_debug("Failed to load %s: %s", fpath, e)
        self._discovered = True
        log_debug(
            "Discovered %d services, %d sockets", len(self._units), len(self._sockets)
        )

    def get_unit(self, name):
        self.discover_services()
        if not name.endswith(".service"):
            name += ".service"
        return self._units.get(name)

    def resolve_name(self, name):
        if not name.endswith(".service"):
            name += ".service"
        return name

    # ------------------------------------------------------------------
    #  PID / status / log paths
    # ------------------------------------------------------------------

    def _pid_path(self, name):
        return os.path.join(PID_DIR, name + ".pid")

    def _log_path(self, name):
        return os.path.join(LOG_DIR, name + ".log")

    def _status_path(self, name):
        return os.path.join(STATUS_DIR, name + ".json")

    def _read_pid(self, name):
        try:
            with open(self._pid_path(name)) as f:
                return int(f.read().strip())
        except (IOError, OSError, ValueError):
            return 0

    def _write_pid(self, name, pid):
        ensure_dirs()
        with open(self._pid_path(name), "w") as f:
            f.write(str(pid))

    def _remove_pid(self, name):
        try:
            os.unlink(self._pid_path(name))
        except (IOError, OSError):
            pass

    def _write_status(self, name, state, pid=0, msg=""):
        ensure_dirs()
        data = {
            "state": state,
            "pid": pid,
            "message": msg,
            "timestamp": datetime.datetime.now().isoformat(),
        }
        with open(self._status_path(name), "w") as f:
            json.dump(data, f)

    def _read_status(self, name):
        try:
            with open(self._status_path(name)) as f:
                return json.load(f)
        except (IOError, OSError, ValueError):
            return None

    def _remove_status(self, name):
        try:
            os.unlink(self._status_path(name))
        except (IOError, OSError):
            pass

    def _build_env(self, unit):
        env = dict(os.environ)
        ef = unit.environment_file
        if ef:
            env.update(load_environment_file(ef))
        env.update(unit.environment)
        return env

    # ------------------------------------------------------------------
    #
    #  It parse .socket unit files to dynamically discover:
    #    - which directories to create
    #    - what ownership to set
    #    - which stale sockets to clean
    #    - which provider service to auto-start
    # ------------------------------------------------------------------

    def _find_related_sockets(self, name, unit):
        """Find .socket units related to a .service unit.

        Checks three sources:
          1. Sockets= directive in [Service]
          2. Requires=X.socket / Wants=X.socket in [Unit]
          3. Name match: X.service -> X.socket

        Returns a set of socket unit names (e.g. {'dbus.socket'}).
        """
        self.discover_services()
        result = set()

        # 1. Explicit Sockets= directive
        for s in unit.sockets:
            sock = s if s.endswith(".socket") else s + ".socket"
            if sock in self._sockets:
                result.add(sock)

        # 2. Requires= / Wants= ending in .socket
        for dep in unit.requires + unit.wants:
            if dep.endswith(".socket") and dep in self._sockets:
                result.add(dep)

        # 3. Matching name
        base = name.replace(".service", "")
        matching = base + ".socket"
        if matching in self._sockets:
            result.add(matching)

        return result

    def _get_socket_paths(self, socket_name):
        """Get filesystem listen paths from a .socket unit.

        Parses ListenStream= and returns only unix-socket paths
        (starting with /).  TCP port numbers and abstract sockets
        (starting with @) are skipped.
        """
        sock_unit = self._sockets.get(socket_name)
        if not sock_unit:
            return []
        return [v.strip() for v in sock_unit.listen_stream if v.strip().startswith("/")]

    def _find_service_for_socket(self, socket_name):
        """Find which .service a .socket unit activates.

        Checks:
          1. Service= directive in the [Socket] section
          2. Name match: X.socket -> X.service
        """
        sock_unit = self._sockets.get(socket_name)
        if sock_unit:
            explicit = sock_unit.socket_service
            if explicit:
                return (
                    explicit if explicit.endswith(".service") else explicit + ".service"
                )
        return socket_name.replace(".socket", ".service")

    def _build_socket_path_map(self):
        """Map filesystem socket paths to (socket_name, service_name).

        Scans every discovered .socket unit.  Cached after first call.

        Example result:
          {'/run/dbus/system_bus_socket': ('dbus.socket', 'dbus.service')}
        """
        if hasattr(self, "_socket_path_map"):
            return self._socket_path_map
        self.discover_services()
        self._socket_path_map = {}
        for sock_name in self._sockets:
            svc_name = self._find_service_for_socket(sock_name)
            for p in self._get_socket_paths(sock_name):
                self._socket_path_map[p] = (sock_name, svc_name)
        log_debug("Socket path map: %s", self._socket_path_map)
        return self._socket_path_map

    def _ensure_socket_dirs(self, name, unit):
        """Create directories and clean stale sockets for related socket units.

        For any service with related .socket units this:
          1. Creates the parent directory of each ListenStream= path
          2. Sets ownership to match the service's User=/Group=
          3. Removes stale socket files left by crashed daemons

        Works for dbus, postgres, docker, mysql — any service that
        has a corresponding .socket unit.
        """
        if self.dry_run:
            return

        for sock_name in self._find_related_sockets(name, unit):
            for sock_path in self._get_socket_paths(sock_name):
                parent = os.path.dirname(sock_path)

                # Create parent directory
                if not os.path.isdir(parent):
                    try:
                        os.makedirs(parent, mode=0o755, exist_ok=True)
                        log_debug("Created socket dir %s (for %s)", parent, sock_name)
                    except OSError as e:
                        log_warn("Cannot create %s: %s (need root?)", parent, e)
                        continue

                # Set ownership from the service's User=/Group=
                svc_user = unit.user
                if svc_user:
                    try:
                        pw = pwd.getpwnam(svc_user)
                        uid, gid = pw.pw_uid, pw.pw_gid
                        if unit.group:
                            try:
                                gid = grp.getgrnam(unit.group).gr_gid
                            except KeyError:
                                pass
                        os.chown(parent, uid, gid)
                        log_debug(
                            "Set %s ownership to %s (uid=%d gid=%d)",
                            parent,
                            svc_user,
                            uid,
                            gid,
                        )
                    except KeyError:
                        log_warn(
                            "User '%s' not found — cannot chown %s. "
                            "Create with: useradd -r -s /usr/sbin/nologin %s",
                            svc_user,
                            parent,
                            svc_user,
                        )
                    except OSError as e:
                        log_debug("chown %s failed: %s", parent, e)

                # Remove stale socket
                if os.path.exists(sock_path):
                    if is_socket_alive(sock_path):
                        log_debug("Socket %s is alive", sock_path)
                    else:
                        try:
                            os.unlink(sock_path)
                            log_debug("Removed stale socket %s", sock_path)
                        except OSError as e:
                            log_warn("Cannot remove stale socket %s: %s", sock_path, e)

    def _ensure_socket_services(self, name, unit):
        """Ensure services that provide required sockets are running.

        For any service with socket dependencies (Requires=X.socket,
        Wants=X.socket) or implicit socket needs (BusName= implies
        the D-Bus system bus socket), this:
          1. Discovers which socket paths are needed
          2. Checks whether each socket path is alive
          3. Finds the service that provides each dead socket
          4. Starts that service and waits for the socket to appear

        Handles recursion (A needs B's socket, B needs A's socket)
        via a guard set.
        """
        if not hasattr(self, "_ensuring_sockets"):
            self._ensuring_sockets = set()
        if name in self._ensuring_sockets:
            return True
        self._ensuring_sockets.add(name)
        try:
            return self._do_ensure_socket_services(name, unit)
        finally:
            self._ensuring_sockets.discard(name)

    def _do_ensure_socket_services(self, name, unit):
        self.discover_services()

        # Collect needed sockets: socket_name -> [filesystem paths]
        needed = {}

        # 1. Explicit socket dependencies from Requires= / Wants=
        for dep in unit.requires + unit.wants:
            if dep.endswith(".socket") and dep in self._sockets:
                paths = self._get_socket_paths(dep)
                if paths:
                    needed[dep] = paths

        # 2. Implicit: BusName= or Type=dbus -> needs the system bus socket
        if unit.bus_name or unit.service_type == "dbus":
            if not (
                os.path.exists(SYSTEM_BUS_SOCKET) and is_socket_alive(SYSTEM_BUS_SOCKET)
            ):
                # Look up which socket unit provides the system bus
                sock_map = self._build_socket_path_map()
                if SYSTEM_BUS_SOCKET in sock_map:
                    sock_name, _ = sock_map[SYSTEM_BUS_SOCKET]
                    needed.setdefault(sock_name, [SYSTEM_BUS_SOCKET])
                else:
                    # Fallback: scan for any .socket with this path
                    for sn in self._sockets:
                        if SYSTEM_BUS_SOCKET in self._get_socket_paths(sn):
                            needed.setdefault(sn, [SYSTEM_BUS_SOCKET])
                            break

        if not needed:
            return True

        all_ok = True
        for sock_name, paths in needed.items():
            # Already alive?
            if any(os.path.exists(p) and is_socket_alive(p) for p in paths):
                log_debug("Socket %s already available", sock_name)
                continue

            # Find the service that provides this socket
            svc_name = self._find_service_for_socket(sock_name)
            if svc_name == name:
                continue  # don't start ourselves

            svc_unit = self.get_unit(svc_name)
            if not svc_unit:
                log_warn(
                    "Service %s (provides socket %s) not found", svc_name, sock_name
                )
                all_ok = False
                continue

            # Already running? Wait for socket.
            svc_pid = self._read_pid(svc_name)
            if svc_pid and pid_exists(svc_pid):
                found = False
                for _ in range(15):
                    if any(os.path.exists(p) and is_socket_alive(p) for p in paths):
                        found = True
                        break
                    time.sleep(0.2)
                if not found:
                    log_warn(
                        "%s running (PID %d) but socket %s not available",
                        svc_name,
                        svc_pid,
                        sock_name,
                    )
                    all_ok = False
                continue

            log_info(
                "Starting %s (provides socket %s needed by %s)...",
                svc_name,
                sock_name,
                name,
            )
            success = self.start(svc_name)
            if success:
                found = False
                for _ in range(20):
                    if any(os.path.exists(p) and is_socket_alive(p) for p in paths):
                        found = True
                        break
                    time.sleep(0.2)
                if found:
                    log_debug("Socket %s is now available", sock_name)
                else:
                    log_warn(
                        "%s started but socket %s not available yet",
                        svc_name,
                        sock_name,
                    )
                    all_ok = False
            else:
                log_warn("Failed to start %s (provides socket %s)", svc_name, sock_name)
                all_ok = False

        return all_ok

    def _fix_bus_activation_files(self, name, unit):
        """Remove SystemdService= from D-Bus activation files.

        Any service with BusName= may have a companion file in
        /usr/share/dbus-1/system-services/ that tells dbus-daemon
        how to auto-start it.  If the file contains SystemdService=,
        dbus-daemon delegates to systemd (which we don't have).

        Removing that line makes dbus-daemon fall back to the Exec=
        line for direct fork/exec activation.

        Triggered generically: runs for EVERY service with BusName=,
        not just dbus itself.
        """
        if self.dry_run:
            return
        bus_name = unit.bus_name
        if not bus_name:
            return

        activation_dirs = [
            "/usr/share/dbus-1/system-services",
            "/usr/share/dbus-1/services",
            "/usr/local/share/dbus-1/system-services",
            "/usr/local/share/dbus-1/services",
        ]
        for act_dir in activation_dirs:
            if not os.path.isdir(act_dir):
                continue
            for fname in os.listdir(act_dir):
                if not fname.endswith(".service"):
                    continue
                fpath = os.path.join(act_dir, fname)
                try:
                    with open(fpath, "r") as f:
                        content = f.read()
                    if "SystemdService=" not in content:
                        continue
                    if bus_name in content or name.replace(".service", "") in fname:
                        new = (
                            "\n".join(
                                l
                                for l in content.splitlines()
                                if not l.strip().startswith("SystemdService=")
                            )
                            + "\n"
                        )
                        if new != content:
                            with open(fpath, "w") as f:
                                f.write(new)
                            log_debug("Removed SystemdService= from %s", fpath)
                except PermissionError:
                    log_debug("Cannot modify %s (permission denied)", fpath)
                except (IOError, OSError) as e:
                    log_debug("Error processing %s: %s", fpath, e)


    def _build_service_binary_map(self):
        if hasattr(self, "_binary_map"):
            return self._binary_map
        self.discover_services()
        bmap = {}
        for svc_name, svc_unit in self._units.items():
            cmds = svc_unit.exec_start
            if not cmds:
                continue
            try:
                parts = shlex.split(cmds[0])
            except ValueError:
                parts = cmds[0].split()
            if parts:
                binary = os.path.basename(parts[0])
                if binary not in ("bash", "sh", "python", "python3", "perl", "ruby"):
                    bmap[binary] = svc_name
        self._binary_map = bmap
        return bmap

    def _find_exec_dep_services(self, name, unit):
        deps = set()
        cmds = unit.exec_start
        if not cmds:
            return deps
        binary_map = self._build_service_binary_map()
        for cmd_str in cmds:
            try:
                parts = shlex.split(cmd_str)
            except ValueError:
                parts = cmd_str.split()
            for part in parts:
                m = re.match(r"^--?[\w-]+=(.+)$", part)
                if m:
                    for candidate in self._extract_binary_candidates(m.group(1)):
                        if candidate in binary_map:
                            dep_name = binary_map[candidate]
                            if dep_name != name:
                                deps.add(dep_name)
        return deps

    @staticmethod
    def _extract_binary_candidates(value):
        candidates = set()
        basename = os.path.basename(value)
        if basename:
            candidates.add(basename)
            no_ext = re.sub(r"\.(sock|socket|pid|lock|conf|cfg|log)$", "", basename)
            if no_ext and no_ext != basename:
                candidates.add(no_ext)
        parent = os.path.basename(os.path.dirname(value))
        if parent and parent not in (
            "run",
            "var",
            "tmp",
            "etc",
            "lib",
            "usr",
            "bin",
            "sbin",
        ):
            candidates.add(parent)
        return candidates

    def _find_reverse_dependents(self, name):
        self.discover_services()
        dependents = set()
        for svc_name, svc_unit in self._units.items():
            if svc_name == name:
                continue
            for dep in svc_unit.part_of + svc_unit.binds_to:
                d = dep if dep.endswith(".service") else dep + ".service"
                if d == name:
                    dependents.add(svc_name)
        return dependents

    def _collect_stop_dependencies(self, name, unit):
        all_deps = set()
        for dep in unit.requires + unit.wants + unit.binds_to:
            if dep.endswith(".service"):
                all_deps.add(dep)
            elif "." not in dep:
                all_deps.add(dep + ".service")
        all_deps.update(self._find_reverse_dependents(name))
        all_deps.update(self._find_exec_dep_services(name, unit))
        all_deps.discard(name)

        reverse_deps = self._find_reverse_dependents(name)
        safe = []
        for dep in all_deps:
            if is_critical_service(dep):
                continue
            dp = self._read_pid(dep)
            if not dp or not pid_exists(dp):
                continue
            if self._is_needed_by_others(dep, exclude={name}):
                continue
            safe.append(dep)

        ordered = []
        for dep in safe:
            if dep in reverse_deps:
                ordered.insert(0, dep)
            else:
                ordered.append(dep)
        return ordered

    def _is_needed_by_others(self, dep_name, exclude=None):
        exclude = exclude or set()
        self.discover_services()
        for svc_name, svc_unit in self._units.items():
            if svc_name in exclude or svc_name == dep_name:
                continue
            sp = self._read_pid(svc_name)
            if not sp or not pid_exists(sp):
                continue
            for d in svc_unit.requires + svc_unit.wants + svc_unit.binds_to:
                dr = d if d.endswith(".service") else d + ".service"
                if dr == dep_name:
                    return True
            if dep_name in self._find_exec_dep_services(svc_name, svc_unit):
                return True
        return False

    # ------------------------------------------------------------------
    #  Process management
    # ------------------------------------------------------------------

    def _pkill_service(self, name, unit):
        pid = self._read_pid(name)
        if pid and pid_exists(pid):
            log_debug("Killing tracked PID %d for %s", pid, name)
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            time.sleep(0.1)
            if pid_exists(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            self._remove_pid(name)

        cmds = unit.exec_start
        if not cmds:
            return
        try:
            cmd_parts = shlex.split(cmds[0])
        except ValueError:
            cmd_parts = cmds[0].split()
        if not cmd_parts:
            return
        binary = os.path.basename(cmd_parts[0])
        if binary in ("bash", "sh", "python", "python3", "perl", "ruby"):
            return
        log_debug("Attempting pkill for '%s'", binary)
        try:
            subprocess.run(
                ["pkill", "-x", binary],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            pass

        for dep_name in self._collect_stop_dependencies(name, unit):
            dep_unit = self.get_unit(dep_name)
            if dep_unit:
                dp = self._read_pid(dep_name)
                if dp and pid_exists(dp):
                    log_debug("Killing dependency PID %d for %s", dp, dep_name)
                    try:
                        os.kill(dp, signal.SIGTERM)
                    except OSError:
                        pass
                    time.sleep(0.1)
                    if pid_exists(dp):
                        try:
                            os.kill(dp, signal.SIGKILL)
                        except OSError:
                            pass
                    self._remove_pid(dep_name)
                    self._write_status(dep_name, "inactive")

    def _run_cmd(self, cmd_str, env, unit, wait=True, log_file=None):
        check, parts = parse_exec_cmd(cmd_str)
        if not parts:
            return (0, 0)
        parts = expand_env(parts, env)
        parts = strip_socket_activation(parts)
        parts = strip_systemd_args(parts)
        if not parts:
            return (0, 0)
        log_debug("Running: %s", " ".join(parts))

        if self.dry_run:
            log_info("[DRY RUN] Would execute: %s", " ".join(parts))
            return (0, 12345)

        cwd = unit.working_directory or None
        if cwd and not os.path.isdir(cwd):
            cwd = None

        uid = gid = None
        if unit.user:
            try:
                pw = pwd.getpwnam(unit.user)
                uid, gid = pw.pw_uid, pw.pw_gid
            except KeyError:
                log_warn("User '%s' not found, running as current user", unit.user)
        if unit.group:
            try:
                gid = grp.getgrnam(unit.group).gr_gid
            except KeyError:
                log_warn("Group '%s' not found", unit.group)

        def preexec():
            os.setsid()
            if gid is not None:
                try:
                    os.setgid(gid)
                except OSError:
                    pass
            if uid is not None:
                try:
                    os.setuid(uid)
                except OSError:
                    pass

        try:
            if wait:
                result = subprocess.run(
                    parts,
                    env=env,
                    cwd=cwd,
                    preexec_fn=preexec if (uid or gid) else None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=120,
                )
                if result.returncode != 0:
                    err = result.stderr.decode("utf-8", errors="replace").strip()
                    if err:
                        log_debug("stderr: %s", err)
                    if log_file and err:
                        try:
                            with open(log_file, "a") as lf:
                                lf.write(err + "\n")
                        except (IOError, OSError):
                            pass
                return (result.returncode, 0)
            else:
                lf = open(log_file, "a") if log_file else open(os.devnull, "w")
                proc = subprocess.Popen(
                    parts,
                    env=env,
                    cwd=cwd,
                    preexec_fn=preexec if (uid or gid) else os.setsid,
                    stdout=lf,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                )
                return (None, proc.pid)
        except FileNotFoundError:
            log_error("Command not found: %s", parts[0])
            return (127, 0)
        except PermissionError:
            log_error("Permission denied: %s", parts[0])
            return (126, 0)
        except Exception as e:
            log_error("Failed to execute %s: %s", parts[0], e)
            return (1, 0)

    # ------------------------------------------------------------------
    #  Start
    # ------------------------------------------------------------------

    def _start_dependencies(self, name, unit):
        if not hasattr(self, "_starting"):
            self._starting = set()
        if name in self._starting:
            return
        self._starting.add(name)
        for dep in unit.requires + unit.wants:
            if dep.endswith(".service") and dep != name:
                dp = self._read_pid(dep)
                if dp and pid_exists(dp):
                    continue
                if is_critical_service(dep):
                    continue
                du = self.get_unit(dep)
                if not du or du.service_type in UNSUPPORTED_TYPES:
                    continue
                ok = self.start(dep)
                msg = "[\033[32m  OK  \033[0m]" if ok else "[\033[31mFAILED\033[0m]"
                print("%s %s %s." % (msg, "Started" if ok else "Failed to start", dep))
        self._starting.discard(name)

    def start(self, name):
        name = self.resolve_name(name)
        log_action("START request for %s", name)

        if is_critical_service(name):
            log_error("Refusing to manage critical service: %s", name)
            return False

        unit = self.get_unit(name)
        if not unit:
            log_error("Service not found: %s", name)
            return False

        stype = unit.service_type
        if stype in UNSUPPORTED_TYPES:
            log_error("Unsupported service type '%s' for %s", stype, name)
            return False

        self._pkill_service(name, unit)

        cond = unit.condition_path_exists
        if cond:
            negate = cond.startswith("!")
            cp = cond.lstrip("!")
            exists = os.path.exists(cp)
            if (negate and exists) or (not negate and not exists):
                if VERBOSE:
                    log_warn("ConditionPathExists failed for %s: %s", name, cond)
                return False

        if not self._ensure_socket_services(name, unit):
            log_error("Cannot start %s: required socket services not available", name)
            return False

        if unit.bus_name:
            self._fix_bus_activation_files(name, unit)

        self._start_dependencies(name, unit)

        if VERBOSE:
            log_info("Starting %s (%s)...", name, unit.description)

        env = self._build_env(unit)
        ensure_dirs()

        log_file = self._log_path(name)
        if not self.dry_run:
            with open(log_file, "a") as lf:
                lf.write(
                    "\n--- %s START %s ---\n"
                    % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), name)
                )

        for cmd in unit.exec_start_pre:
            chk, _ = parse_exec_cmd(cmd)
            rc, _ = self._run_cmd(cmd, env, unit, wait=True)
            if rc and chk:
                log_error("ExecStartPre failed for %s (exit %d)", name, rc)
                if not self.dry_run:
                    self._write_status(name, "failed", msg="ExecStartPre failed")
                return False

        self._ensure_socket_dirs(name, unit)

        if stype == "oneshot":
            return self._start_oneshot(name, unit, env)
        elif stype == "forking":
            return self._start_forking(name, unit, env)
        elif stype == "dbus":
            return self._start_dbus(name, unit, env)
        else:
            return self._start_simple(name, unit, env)

    def _start_simple(self, name, unit, env):
        log_file = self._log_path(name)
        cmds = unit.exec_start
        if not cmds:
            log_error("No ExecStart defined for %s", name)
            self._write_status(name, "failed", msg="No ExecStart")
            return False

        env["MAINPID"] = ""
        rc, pid = self._run_cmd(cmds[-1], env, unit, wait=False, log_file=log_file)
        if pid <= 0 and not self.dry_run:
            log_error("Failed to start %s", name)
            self._write_status(name, "failed", msg="Failed to start process")
            return False

        if not self.dry_run:
            self._write_pid(name, pid)
            self._write_status(name, "active", pid=pid)
        env["MAINPID"] = str(pid)

        if not self.dry_run:
            wt = 1.5 if unit.service_type in ("notify", "notify-reload") else 0.5
            time.sleep(wt)
            if not pid_exists(pid):
                if unit.remain_after_exit:
                    log_info("%s started and exited (RemainAfterExit=yes)", name)
                    self._write_status(
                        name, "active", pid=0, msg="Exited (RemainAfterExit)"
                    )
                else:
                    log_error("%s started but exited immediately", name)
                    self._write_status(name, "failed", pid=0, msg="Exited immediately")
                    self._remove_pid(name)
                    return False

        if VERBOSE:
            log_info("%s started (PID %d)", name, pid)
        for cmd in unit.exec_start_post:
            self._run_cmd(cmd, env, unit, wait=True)
        return True

    def _start_dbus(self, name, unit, env):
        """Start a Type=dbus service.

        Like simple, but waits for the BusName= to appear on the
        system bus before declaring the service ready.  This is
        the systemd-defined behaviour for Type=dbus.
        """
        log_file = self._log_path(name)
        cmds = unit.exec_start
        if not cmds:
            log_error("No ExecStart defined for %s", name)
            self._write_status(name, "failed", msg="No ExecStart")
            return False

        env["MAINPID"] = ""
        rc, pid = self._run_cmd(cmds[-1], env, unit, wait=False, log_file=log_file)
        if pid <= 0 and not self.dry_run:
            log_error("Failed to start %s", name)
            self._write_status(name, "failed", msg="Failed to start process")
            return False

        if not self.dry_run:
            self._write_pid(name, pid)
            self._write_status(name, "active", pid=pid)
        env["MAINPID"] = str(pid)

        if not self.dry_run:
            bn = unit.bus_name
            if bn:
                log_debug("Waiting for %s to acquire bus name '%s'...", name, bn)
                if wait_for_dbus_name(bn, pid, timeout=10.0):
                    log_debug("%s acquired bus name '%s'", name, bn)
                elif pid_exists(pid):
                    log_warn(
                        "%s running (PID %d) but bus name '%s' not yet acquired",
                        name,
                        pid,
                        bn,
                    )
                else:
                    log_error("%s exited before acquiring bus name '%s'", name, bn)
                    self._write_status(
                        name, "failed", pid=0, msg="Exited before acquiring BusName"
                    )
                    self._remove_pid(name)
                    return False
            else:
                time.sleep(0.5)
                if not pid_exists(pid):
                    if unit.remain_after_exit:
                        self._write_status(
                            name, "active", pid=0, msg="Exited (RemainAfterExit)"
                        )
                    else:
                        log_error("%s started but exited immediately", name)
                        self._write_status(
                            name, "failed", pid=0, msg="Exited immediately"
                        )
                        self._remove_pid(name)
                        return False

        if VERBOSE:
            log_info("%s started (PID %d, Type=dbus)", name, pid)
        for cmd in unit.exec_start_post:
            self._run_cmd(cmd, env, unit, wait=True)
        return True

    def _start_forking(self, name, unit, env):
        log_file = self._log_path(name)
        cmds = unit.exec_start
        if not cmds:
            log_error("No ExecStart defined for %s", name)
            return False
        for cmd in cmds:
            rc, _ = self._run_cmd(cmd, env, unit, wait=True, log_file=log_file)
            chk, _ = parse_exec_cmd(cmd)
            if rc and chk:
                log_error("ExecStart failed for %s (exit %d)", name, rc)
                self._write_status(name, "failed", msg="ExecStart failed")
                return False

        pid = 0
        pf = unit.pid_file
        if pf:
            for _ in range(20):
                if os.path.isfile(pf):
                    try:
                        with open(pf) as f:
                            pid = int(f.read().strip())
                        break
                    except (IOError, ValueError):
                        pass
                if not self.dry_run:
                    time.sleep(0.2)

        if pid and pid_exists(pid):
            if not self.dry_run:
                self._write_pid(name, pid)
                self._write_status(name, "active", pid=pid)
            if VERBOSE:
                log_info("%s started (PID %d from PIDFile)", name, pid)
        else:
            if VERBOSE:
                log_warn("%s: forking service started but no PID tracked", name)
            if not self.dry_run:
                self._write_status(name, "active", pid=0, msg="PID unknown")
        for cmd in unit.exec_start_post:
            self._run_cmd(cmd, env, unit, wait=True)
        return True

    def _start_oneshot(self, name, unit, env):
        log_file = self._log_path(name)
        cmds = unit.exec_start
        if not cmds:
            log_error("No ExecStart defined for %s", name)
            return False
        for cmd in cmds:
            chk, _ = parse_exec_cmd(cmd)
            rc, _ = self._run_cmd(cmd, env, unit, wait=True, log_file=log_file)
            if rc and chk:
                log_error("ExecStart failed for %s (exit %d)", name, rc)
                self._write_status(
                    name, "failed", msg="ExecStart failed (exit %d)" % rc
                )
                return False

        if unit.remain_after_exit:
            if not self.dry_run:
                self._write_status(
                    name, "active", pid=0, msg="Completed (RemainAfterExit)"
                )
        else:
            if not self.dry_run:
                self._write_status(
                    name, "inactive", pid=0, msg="Completed successfully"
                )
        log_info("%s completed", name)
        for cmd in unit.exec_start_post:
            self._run_cmd(cmd, env, unit, wait=True)
        return True

    # ------------------------------------------------------------------
    #  Stop
    # ------------------------------------------------------------------

    def stop(self, name):
        name = self.resolve_name(name)
        log_action("STOP request for %s", name)

        if is_critical_service(name):
            log_error("Refusing to manage critical service: %s", name)
            return False
        unit = self.get_unit(name)
        if not unit:
            log_error("Service not found: %s", name)
            return False

        stop_deps = self._collect_stop_dependencies(name, unit)

        pid = self._read_pid(name)
        if not pid or not pid_exists(pid):
            if VERBOSE:
                log_info("%s is not running", name)
            self._remove_pid(name)
            self._write_status(name, "inactive")
            self._stop_dependencies(name, stop_deps)
            return True

        if pid in (1, 2):
            log_error("Refusing to kill PID %d", pid)
            return False
        if VERBOSE:
            log_info("Stopping %s (PID %d)...", name, pid)

        if self.dry_run:
            log_info("[DRY RUN] Would stop PID %d", pid)
            return True

        if pid_exists(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                log_error("Permission denied killing PID %d", pid)
                return False
            for _ in range(25):
                if not pid_exists(pid):
                    break
                time.sleep(0.2)

        if pid_exists(pid):
            try:
                os.kill(pid, signal.SIGKILL)
                log_warn("Sent SIGKILL to PID %d", pid)
            except (ProcessLookupError, PermissionError):
                pass
            time.sleep(0.5)

        if pid_exists(pid):
            log_error("Failed to stop %s (PID %d still alive)", name, pid)
            self._write_status(name, "failed", pid=pid, msg="Could not kill")
            return False

        self._remove_pid(name)
        self._write_status(name, "inactive")
        log_info("%s stopped", name)
        self._stop_dependencies(name, stop_deps)
        return True

    def _stop_dependencies(self, parent, dep_list):
        if not dep_list:
            return
        if not hasattr(self, "_stopping"):
            self._stopping = set()
        if parent in self._stopping:
            return
        self._stopping.add(parent)
        for dep in dep_list:
            if dep in self._stopping:
                continue
            dp = self._read_pid(dep)
            if not dp or not pid_exists(dp):
                continue
            if self._is_needed_by_others(dep, exclude={parent}):
                continue
            ok = self.stop(dep)
            msg = "[\033[32m  OK  \033[0m]" if ok else "[\033[31mFAILED\033[0m]"
            print("%s %s %s." % (msg, "Stopped" if ok else "Failed to stop", dep))
        self._stopping.discard(parent)

    def restart(self, name):
        name = self.resolve_name(name)
        self.stop(name)
        time.sleep(0.5)
        return self.start(name)

    # ------------------------------------------------------------------
    #  Enable / disable
    # ------------------------------------------------------------------

    def enable(self, name):
        name = self.resolve_name(name)
        unit = self.get_unit(name)
        if not unit:
            log_error("Service not found: %s", name)
            return False
        ensure_dirs()
        target = os.path.join(ENABLED_DIR, name)
        if not os.path.isdir(ENABLED_DIR):
            try:
                os.makedirs(ENABLED_DIR, mode=0o755, exist_ok=True)
            except OSError as e:
                log_error("Failed to create %s: %s", ENABLED_DIR, e)
                return False
        if os.path.exists(target):
            log_info("%s is already enabled", name)
            return True
        try:
            if unit.path:
                os.symlink(unit.path, target)
            else:
                with open(target, "w") as f:
                    f.write("# enabled")
            log_info("Enabled %s", name)
            return True
        except PermissionError:
            log_error("Permission denied: cannot enable %s (need root?)", name)
            return False
        except OSError as e:
            log_error("Failed to enable %s: %s", name, e)
            return False

    def disable(self, name):
        name = self.resolve_name(name)
        target = os.path.join(ENABLED_DIR, name)
        if not os.path.isdir(ENABLED_DIR):
            log_info("%s is not enabled", name)
            return True
        if not os.path.exists(target) and not os.path.islink(target):
            log_info("%s is not enabled", name)
            return True
        try:
            os.unlink(target)
            log_info("Disabled %s", name)
            return True
        except PermissionError:
            log_error("Permission denied: cannot disable %s (need root?)", name)
            return False
        except OSError as e:
            log_error("Failed to disable %s: %s", name, e)
            return False

    def is_enabled(self, name):
        return os.path.exists(os.path.join(ENABLED_DIR, name))

    def start_all_enabled(self):
        if not os.path.isdir(ENABLED_DIR):
            print("No enabled services found.")
            return
        enabled = sorted(os.listdir(ENABLED_DIR))
        if not enabled:
            print("No enabled services.")
            return
        for name in enabled:
            if not name.endswith(".service"):
                continue
            ok = self.start(name)
            msg = "[\033[32m  OK  \033[0m]" if ok else "[\033[31mFAILED\033[0m]"
            print("%s %s %s." % (msg, "Started" if ok else "Failed to start", name))

    # ------------------------------------------------------------------
    #  Status / log / list
    # ------------------------------------------------------------------

    def status(self, name):
        name = self.resolve_name(name)
        unit = self.get_unit(name)
        if not unit:
            print("%s - not found" % name)
            return 4

        print("● %s - %s" % (name, unit.description))
        print("   Loaded: loaded (%s)" % (unit.path or "unknown"))

        if unit.bus_name:
            ba = check_dbus_bus_name(unit.bus_name, timeout=2.0)
            print(
                "  BusName: %s (%s)"
                % (unit.bus_name, "acquired" if ba else "not on bus")
            )

        # Show related socket paths and their state
        for sock_name in self._find_related_sockets(name, unit):
            for sp in self._get_socket_paths(sock_name):
                alive = is_socket_alive(sp)
                print(
                    "   Socket: %s (%s)"
                    % (sp, "\033[32malive\033[0m" if alive else "dead")
                )

        pid = self._read_pid(name)
        sd = self._read_status(name)

        if pid and pid_exists(pid):
            print("   Active: \033[32mactive (running)\033[0m")
            print("      PID: %d" % pid)
            try:
                st = os.stat("/proc/%d" % pid)
                started = datetime.datetime.fromtimestamp(st.st_mtime)
                uptime = datetime.datetime.now() - started
                print(
                    "    Since: %s (%s ago)"
                    % (started.strftime("%Y-%m-%d %H:%M:%S"), str(uptime).split(".")[0])
                )
            except (OSError, IOError):
                pass
            return 0
        elif sd:
            state = sd.get("state", "inactive")
            if state == "active":
                print("   Active: \033[32m%s\033[0m" % state)
            elif state == "failed":
                print("   Active: \033[31m%s\033[0m" % state)
            else:
                print("   Active: %s" % state)
            if sd.get("message"):
                print("   Status: %s" % sd["message"])
            if sd.get("timestamp"):
                print("    Since: %s" % sd["timestamp"])
            return 0 if state == "active" else 3
        else:
            print("   Active: inactive (dead)")
            return 3

    def show_log(self, name, lines=50):
        name = self.resolve_name(name)
        log_file = self._log_path(name)
        if not os.path.isfile(log_file):
            log_info("No logs found for %s", name)
            return
        try:
            with open(log_file) as f:
                all_lines = f.readlines()
            for line in all_lines[-lines:]:
                print(line, end="")
            if not all_lines:
                print("(empty log)")
        except (IOError, OSError) as e:
            log_error("Failed to read log for %s: %s", name, e)

    def list_services(self, running_only=False):
        self.discover_services()
        rows = []
        for name in sorted(self._units.keys()):
            unit = self._units[name]
            stype = unit.service_type
            pid = self._read_pid(name)
            is_running = pid > 0 and pid_exists(pid)
            if running_only and not is_running:
                continue
            critical = is_critical_service(name)
            unsupported = stype in UNSUPPORTED_TYPES

            if is_running:
                state = "\033[32mrunning\033[0m"
            else:
                sd = self._read_status(name)
                if sd and sd.get("state") == "failed":
                    state = "\033[31mfailed\033[0m"
                else:
                    state = "stopped"

            flags = ""
            if critical:
                flags = " [CRITICAL]"
            elif unsupported:
                flags = " [UNSUPPORTED:%s]" % stype

            rows.append(
                (
                    name,
                    stype,
                    state,
                    str(pid) if is_running else "-",
                    unit.description[:50],
                    flags,
                )
            )

        if not rows:
            print("No services found." if not running_only else "No running services.")
            return
        print(
            "%-40s %-10s %-12s %-8s %s"
            % ("SERVICE", "TYPE", "STATE", "PID", "DESCRIPTION")
        )
        print("-" * 110)
        for nm, st, state, ps, desc, flags in rows:
            em = "*" if self.is_enabled(nm) else " "
            print(
                "%s %-40s %-10s %-12s %-8s %s%s" % (em, nm, st, state, ps, desc, flags)
            )
        print("\nTotal: %d services (* = enabled)" % len(rows))


# ======================================================================
#  CLI
# ======================================================================


def main():
    global VERBOSE

    parser = argparse.ArgumentParser(
        prog="serviced",
        description="Lightweight service manager for systemd .service files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                        List all services
  %(prog)s list-running                List running services
  %(prog)s start sshd                  Start sshd service
  %(prog)s stop sshd                   Stop sshd service
  %(prog)s restart sshd                Restart sshd service
  %(prog)s status sshd                 Show sshd status
  %(prog)s log sshd                    Show sshd logs
  %(prog)s --dry-run start ssh         Preview without executing
  %(prog)s version                     Show version info
  %(prog)s enable sshd                 Enable to start on boot
  %(prog)s disable sshd                Disable from starting on boot
  %(prog)s start                       Start all enabled services
  %(prog)s start dbus                  Start D-Bus (auto-creates /run/dbus)
  %(prog)s start flatpak-system-helper Auto-starts dbus if needed
        """,
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug output")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("start", help="Start a service or all enabled")
    p.add_argument("service", nargs="?", help="Service name")

    p = sub.add_parser("stop", help="Stop a service")
    p.add_argument("service", help="Service name")

    p = sub.add_parser("restart", help="Restart a service")
    p.add_argument("service", help="Service name")

    p = sub.add_parser("enable", help="Enable a service")
    p.add_argument("service", help="Service name")

    p = sub.add_parser("disable", help="Disable a service")
    p.add_argument("service", help="Service name")

    p = sub.add_parser("status", help="Show service status")
    p.add_argument("service", help="Service name")

    p = sub.add_parser("log", help="Show service log")
    p.add_argument("service", help="Service name")
    p.add_argument("-n", "--lines", type=int, default=50, help="Lines (default: 50)")

    sub.add_parser("list", help="List all services")
    sub.add_parser("list-running", help="List running services")
    sub.add_parser("version", help="Show version")

    args = parser.parse_args()
    VERBOSE = args.verbose
    mgr = ServiceManager(dry_run=args.dry_run)
    ensure_dirs()

    if args.command == "start":
        if args.service:
            ok = mgr.start(args.service)
            if not VERBOSE:
                m = "[\033[32m  OK  \033[0m]" if ok else "[\033[31mFAILED\033[0m]"
                a = "Started" if ok else "Failed to start"
                print("%s %s %s." % (m, a, args.service))
            if not ok:
                sys.exit(1)
        else:
            mgr.start_all_enabled()
    elif args.command == "stop":
        ok = mgr.stop(args.service)
        if not VERBOSE:
            m = "[\033[32m  OK  \033[0m]" if ok else "[\033[31mFAILED\033[0m]"
            a = "Stopped" if ok else "Failed to stop"
            print("%s %s %s." % (m, a, args.service))
        if not ok:
            sys.exit(1)
    elif args.command == "restart":
        mgr.stop(args.service)
        ok = mgr.start(args.service)
        if not VERBOSE:
            m = "[\033[32m  OK  \033[0m]" if ok else "[\033[31mFAILED\033[0m]"
            a = "Restarted" if ok else "Failed to restart"
            print("%s %s %s." % (m, a, args.service))
        if not ok:
            sys.exit(1)
    elif args.command == "enable":
        if not mgr.enable(args.service):
            sys.exit(1)
    elif args.command == "disable":
        if not mgr.disable(args.service):
            sys.exit(1)
    elif args.command == "status":
        sys.exit(mgr.status(args.service))
    elif args.command == "log":
        mgr.show_log(args.service, lines=args.lines)
    elif args.command == "list":
        mgr.list_services(running_only=False)
    elif args.command == "list-running":
        mgr.list_services(running_only=True)
    elif args.command == "version":
        print("serviced v%s - lightweight service manager" % VERSION)


if __name__ == "__main__":
    main()
