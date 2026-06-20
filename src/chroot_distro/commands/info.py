import json
import os
import platform
import subprocess
from dataclasses import dataclass, field

from chroot_distro.arch import detect_installed_arch, get_device_cpu_arch, supports_32bit
from chroot_distro.commands.list_cmd import (
    _ensure_manifest_readable,
    _iter_container_names,
    _read_image_source,
    _rootfs_size_bytes,
)
from chroot_distro.constants import (
    CANONICAL_PROGRAM_NAME,
    IS_TERMUX,
    PROGRAM_NAME,
    PROGRAM_VERSION,
    RUNTIME_DIR,
    TERMUX_APP_PACKAGE,
)
from chroot_distro.locking import container_busy_status
from chroot_distro.message import C, msg
from chroot_distro.paths import container_manifest, container_rootfs
from chroot_distro.progress import fmt_size, loading_line

_NA = "unknown"


@dataclass(frozen=True)
class _HostInfo:
    """Platform facts shared by Termux/Android and regular Linux hosts."""

    kind: str  # "Termux / Android" or "Linux"
    fields: list[tuple[str, str]]


@dataclass
class _ImageInfo:
    """Per-container facts plus any analysis findings."""

    name: str
    size: str = "?"
    size_bytes: int = 0
    arch: str = _NA
    source: str = _NA
    status: str = _NA
    source_url: str = ""
    image_type: str = ""
    findings: list[str] = field(default_factory=list)


def _read_os_release() -> dict[str, str]:
    """Parse /etc/os-release into a dict, tolerating missing files."""
    data: dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    data[key.strip()] = value.strip().strip('"').strip("'")
            if data:
                return data
        except OSError:
            continue
    return data


def _read_build_prop(keys: tuple[str, ...]) -> dict[str, str]:
    """Read selected getprop-style keys from Android, falling back to file."""
    found: dict[str, str] = {}
    try:
        out = subprocess.check_output(["getprop"], stderr=subprocess.DEVNULL, text=True, timeout=5)
        for line in out.splitlines():
            # Format: [key]: [value]
            if "]: [" not in line:
                continue
            key, _, value = line.partition("]: [")
            key = key.lstrip("[").strip()
            value = value.rstrip("]").strip()
            if key in keys and value:
                found[key] = value
    except (OSError, subprocess.SubprocessError):
        pass
    if all(k in found for k in keys):
        return found
    try:
        with open("/system/build.prop", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key in keys and key not in found and value.strip():
                    found[key] = value.strip()
    except OSError:
        pass
    return found


def _termux_host_info() -> _HostInfo:
    """Collect Termux app + Android OS facts."""
    fields: list[tuple[str, str]] = []

    termux_version = (
        os.environ.get("TERMUX_APP__APP_VERSION_NAME") or os.environ.get("TERMUX_VERSION") or _NA
    )
    fields.append(("Termux version", termux_version))
    fields.append(("Termux package", TERMUX_APP_PACKAGE))

    props = _read_build_prop(
        (
            "ro.build.version.release",
            "ro.build.version.sdk",
            "ro.product.manufacturer",
            "ro.product.model",
            "ro.product.device",
        )
    )
    android_release = props.get("ro.build.version.release", _NA)
    android_sdk = props.get("ro.build.version.sdk", "")
    android_label = android_release
    if android_sdk:
        android_label = f"{android_release} (API {android_sdk})"
    fields.append(("Android version", android_label))

    manufacturer = props.get("ro.product.manufacturer", "")
    model = props.get("ro.product.model", "")
    device = props.get("ro.product.device", "")
    device_label = " ".join(p for p in (manufacturer, model) if p) or _NA
    if device and device not in device_label:
        device_label = f"{device_label} ({device})"
    fields.append(("Device", device_label))

    fields.append(("Kernel", platform.release() or _NA))
    return _HostInfo(kind="Termux / Android", fields=fields)


def _linux_host_info() -> _HostInfo:
    """Collect regular Linux distribution + kernel facts."""
    fields: list[tuple[str, str]] = []
    os_release = _read_os_release()

    pretty = os_release.get("PRETTY_NAME", "")
    if not pretty:
        name = os_release.get("NAME", "")
        version = os_release.get("VERSION", os_release.get("VERSION_ID", ""))
        pretty = " ".join(p for p in (name, version) if p)
    fields.append(("Distribution", pretty or _NA))

    version_id = os_release.get("VERSION_ID", "")
    if version_id:
        fields.append(("Version", version_id))

    fields.append(("Kernel", platform.release() or _NA))
    fields.append(("Platform", platform.platform() or _NA))
    libc_name, libc_version = platform.libc_ver()
    if libc_name:
        fields.append(("libc", f"{libc_name} {libc_version}".strip()))
    return _HostInfo(kind="Linux", fields=fields)


def _gather_host_info() -> _HostInfo:
    return _termux_host_info() if IS_TERMUX else _linux_host_info()


def _read_manifest_labels(name: str) -> tuple[str, str]:
    """Return (source_url, image_type) from the manifest config labels."""
    manifest_path = container_manifest(name)
    if not os.path.isfile(manifest_path):
        return "", ""
    _ensure_manifest_readable(manifest_path)
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            data = json.loads(fh.read() or "{}")
    except (OSError, json.JSONDecodeError):
        return "", ""
    cfg = (data.get("image_config") or {}).get("config") or {}
    labels = cfg.get("Labels") or {}
    return (
        labels.get("org.opencontainers.image.source", ""),
        labels.get("IMAGE_TYPE", ""),
    )


def _analyze_image(info: _ImageInfo, host_arch: str) -> None:
    """Populate findings that help spot why an image may misbehave."""
    rootfs = container_rootfs(info.name)

    if not os.path.isfile(container_manifest(info.name)):
        info.findings.append("no manifest.json (reset/diff/run unavailable)")

    if info.size_bytes == 0:
        info.findings.append("rootfs is empty (install may be incomplete)")
    elif not os.path.isfile(os.path.join(rootfs, "etc", "os-release")) and not os.path.isfile(
        os.path.join(rootfs, "etc", "passwd")
    ):
        info.findings.append("no /etc/os-release or /etc/passwd (unusual rootfs)")

    if info.arch not in (_NA, "") and host_arch not in (_NA, ""):
        if info.arch != host_arch and not (host_arch in ("x86_64", "aarch64") and info.arch in ("i686", "arm")):
            info.findings.append(f"arch '{info.arch}' differs from host '{host_arch}' (needs emulation)")


def _gather_images(host_arch: str) -> list[_ImageInfo]:
    names = _iter_container_names()
    images: list[_ImageInfo] = []
    total = len(names)
    with loading_line("Gathering image info...") as update:
        for index, name in enumerate(names, start=1):
            update(f"Scanning {name} ({index}/{total})...")
            info = _ImageInfo(name=name)
            try:
                info.size_bytes = _rootfs_size_bytes(container_rootfs(name))
                info.size = fmt_size(info.size_bytes)
            except OSError:
                info.size = "?"
            info.arch = detect_installed_arch(name)
            info.source = _read_image_source(name)
            info.status = container_busy_status(name)
            info.source_url, info.image_type = _read_manifest_labels(name)
            _analyze_image(info, host_arch)
            images.append(info)
    return images


def _kv(label: str, value: str, label_w: int) -> str:
    return f"  {C['CYAN']}{label + ':':<{label_w}}{C['RST']} {C['WHITE']}{value}{C['RST']}"


def _render_section(title: str) -> None:
    msg()
    msg(f"{C['UBCYAN']}{title}{C['RST']}")
    msg()


def _render_basic() -> None:
    label_w = 16
    _render_section(f"{CANONICAL_PROGRAM_NAME}")
    msg(_kv("Program", PROGRAM_NAME, label_w))
    msg(_kv("Version", PROGRAM_VERSION, label_w))
    msg(_kv("Python", platform.python_version(), label_w))
    msg(_kv("Data location", RUNTIME_DIR, label_w))


def _render_host(host: _HostInfo, host_arch: str) -> None:
    label_w = 16
    _render_section("HOST")
    msg(_kv("Type", host.kind, label_w))
    arch_value = host_arch
    if host_arch in ("aarch64", "x86_64"):
        arch_value = f"{host_arch} ({'supports' if supports_32bit() else 'no'} 32-bit)"
    msg(_kv("Architecture", arch_value, label_w))
    for label, value in host.fields:
        msg(_kv(label, value, label_w))


def _format_image_table(images: list[_ImageInfo]) -> list[str]:
    name_w = max(len("NAME"), *(len(i.name) for i in images))
    size_w = max(len("SIZE"), *(len(i.size) for i in images))
    arch_w = max(len("ARCH"), *(len(i.arch) for i in images))
    source_w = max(len("SOURCE"), *(len(i.source) for i in images))
    status_w = max(len("STATUS"), *(len(i.status) for i in images))

    lines = [
        f"  {C['BCYAN']}{'NAME':<{name_w}}  {'SIZE':>{size_w}}  "
        f"{'ARCH':<{arch_w}}  {'SOURCE':<{source_w}}  {'STATUS':<{status_w}}{C['RST']}",
    ]
    for img in images:
        status_color = "YELLOW" if img.status.startswith("in use") else "GREEN"
        lines.append(
            f"  {C['GREEN']}{img.name:<{name_w}}{C['RST']}  "
            f"{C['CYAN']}{img.size:>{size_w}}{C['RST']}  "
            f"{img.arch:<{arch_w}}  "
            f"{img.source:<{source_w}}  "
            f"{C[status_color]}{img.status:<{status_w}}{C['RST']}"
        )
    return lines


def _render_images(images: list[_ImageInfo]) -> None:
    _render_section("INSTALLED IMAGES")
    if not images:
        msg(f"  {C['YELLOW']}No containers are installed.{C['RST']}")
        msg()
        msg(f"  {C['CYAN']}Install one with: {C['GREEN']}{PROGRAM_NAME} install ubuntu:25.10{C['RST']}")
        return

    total_bytes = sum(i.size_bytes for i in images)
    msg(f"  {C['CYAN']}{len(images)} container(s), {fmt_size(total_bytes)} total{C['RST']}")
    msg()
    for line in _format_image_table(images):
        msg(line)

    detailed = [i for i in images if i.source_url or i.image_type]
    if detailed:
        msg()
        for img in detailed:
            msg(f"  {C['GREEN']}{img.name}{C['RST']}:")
            if img.source_url:
                msg(f"    {C['CYAN']}Source URL:{C['RST']} {img.source_url}")
            if img.image_type:
                msg(f"    {C['CYAN']}Image type:{C['RST']} {img.image_type}")


def _render_analysis(images: list[_ImageInfo]) -> None:
    flagged = [i for i in images if i.findings]
    _render_section("ANALYSIS")
    if not images:
        msg(f"  {C['CYAN']}Nothing to analyze.{C['RST']}")
        return
    if not flagged:
        msg(f"  {C['GREEN']}No issues detected across {len(images)} container(s).{C['RST']}")
        return
    for img in flagged:
        msg(f"  {C['YELLOW']}{img.name}{C['RST']}:")
        for finding in img.findings:
            msg(f"    {C['RED']}\u2718{C['RST']} {C['WHITE']}{finding}{C['RST']}")


def command_info(args) -> None:
    """Print a structured diagnostics report for bug reports and support.

    Read-only: collects program, host (Linux distro or Termux/Android), and
    per-image facts plus lightweight analysis. Never requires root.
    """
    host_arch = get_device_cpu_arch()
    host = _gather_host_info()
    images = _gather_images(host_arch)

    _render_basic()
    _render_host(host, host_arch)
    _render_images(images)
    _render_analysis(images)

    msg()
    msg(
        f"  {C['CYAN']}Report issues at "
        f"https://github.com/sabamdarif/chroot-distro/issues{C['RST']}"
    )
    msg()


__all__ = ("command_info",)
