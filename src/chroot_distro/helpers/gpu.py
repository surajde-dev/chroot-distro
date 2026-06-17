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

import logging
import os

log = logging.getLogger(__name__)

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
