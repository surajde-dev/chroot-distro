"""Generic (AMD/Intel/Mesa) GPU ICD and loader-config discovery.

NVIDIA driver integration lives in :mod:`chroot_distro.helpers.nvidia`.
This module covers the open Mesa stack (AMD/Intel and friends): the GPU
device nodes themselves arrive via the default /dev bind, but Vulkan,
EGL/GLVND and OpenCL loaders need their ICD descriptor files to enumerate
the hardware. Container distros that do not ship their own ICD JSONs fail
to see the GPU even though /dev/dri is present. Bind the host's ICD and
loader-config directories read-only so the loaders find the descriptors.
"""

from __future__ import annotations

import glob
import logging
import os

from chroot_distro.helpers.nvidia import (
    _detect_guest_lib_dirs,
    _host_lib_to_guest_path,
)

log = logging.getLogger(__name__)

# Mesa / open-stack userspace driver shared objects (case-insensitive).
# These cover the AMD (radeonsi/r600), Intel (iris/crocus), software
# (swrast/llvmpipe) Gallium drivers plus the GL/EGL/GBM/Vulkan loaders the
# guest needs to actually drive /dev/dri when its own rootfs lacks them.
_MESA_LIB_PATTERNS = (
    "*radeonsi*",
    "*r600*",
    "*iris*",
    "*crocus*",
    "*swrast*",
    "libGL.so*",
    "libEGL.so*",
    "libgbm.so*",
    "libvulkan_*.so*",
)

# Host directories that hold userspace driver libraries.
_HOST_LIB_DIRS = (
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/i386-linux-gnu",
    "/usr/lib64",
    "/usr/lib32",
    "/usr/lib",
)


def find_mesa_libraries(rootfs: str) -> list[tuple[str, str]]:
    """Return ``(host_path, guest_path)`` pairs for Mesa/Vulkan userspace libs.

    Locates the host's open-stack GPU driver ``.so`` files and maps them to
    the guest's library directories. Files that already exist inside the
    rootfs are skipped so the container's own Mesa stack always wins; this
    only fills gaps. Symlinks are resolved to their real target.
    """
    lib64, lib32 = _detect_guest_lib_dirs(rootfs)
    binds: list[tuple[str, str]] = []
    seen_guests: set[str] = set()

    host_lib_dirs = sorted({d for d in _HOST_LIB_DIRS if os.path.isdir(d)})
    for lib_dir in host_lib_dirs:
        for pattern in _MESA_LIB_PATTERNS:
            for lib_path in glob.glob(os.path.join(lib_dir, "**", pattern), recursive=True):
                if not os.path.isfile(lib_path):
                    continue
                real_path = lib_path
                if os.path.islink(lib_path):
                    real_path = os.path.realpath(lib_path)
                    if not os.path.isfile(real_path):
                        continue

                guest_path = _host_lib_to_guest_path(lib_path, lib64, lib32)
                if guest_path in seen_guests:
                    continue
                seen_guests.add(guest_path)

                # Do not shadow a Mesa stack the container already ships.
                guest_abs = os.path.join(rootfs, guest_path.lstrip("/"))
                if os.path.exists(guest_abs):
                    continue

                binds.append((real_path, guest_path))

    if binds:
        log.debug("Mesa GPU integration: %d userspace driver lib(s) bound", len(binds))
    return binds

# Host directories and files holding GPU ICD / loader configuration.
# Directories are bound whole; individual files are bound when present.
_GPU_ICD_PATHS = (
    # Vulkan loader: installable client drivers and layers
    "/usr/share/vulkan/icd.d",
    "/usr/share/vulkan/implicit_layer.d",
    "/usr/share/vulkan/explicit_layer.d",
    # GLVND EGL vendor descriptors (Mesa, etc.)
    "/usr/share/glvnd/egl_vendor.d",
    # EGL external platform + GBM backends (Wayland/headless)
    "/usr/share/egl/egl_external_platform.d",
    "/usr/share/gbm",
    # OpenCL ICD vendor descriptors
    "/etc/OpenCL/vendors",
    # Mesa DRI runtime configuration
    "/etc/drirc",
    "/usr/share/drirc.d",
)


def find_gpu_icd_binds(rootfs: str) -> list[tuple[str, str]]:
    """Return ``(host_path, guest_path)`` pairs for GPU ICD/loader config.

    Only host paths that exist are returned. Paths already present inside
    the rootfs are skipped so the container's own descriptors win.
    Guest paths mirror the host paths.
    """
    binds: list[tuple[str, str]] = []
    for path in _GPU_ICD_PATHS:
        if not os.path.exists(path):
            continue
        guest_abs = os.path.join(rootfs, path.lstrip("/"))
        if os.path.exists(guest_abs):
            # Container ships its own config here; do not shadow it.
            continue
        binds.append((path, path))
    if binds:
        log.debug("GPU ICD integration: %d config path(s) bound read-only", len(binds))
    return binds
