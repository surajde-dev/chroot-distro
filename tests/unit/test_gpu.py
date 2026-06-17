"""Tests for generic (AMD/Intel/Mesa) GPU ICD discovery."""

import os
from unittest.mock import patch

from chroot_distro.helpers.gpu import find_gpu_icd_binds, find_mesa_libraries


def test_find_gpu_icd_binds_existing_host_paths():
    host_present = {
        "/usr/share/vulkan/icd.d",
        "/usr/share/glvnd/egl_vendor.d",
        "/etc/OpenCL/vendors",
    }

    def fake_exists(p):
        # host paths present; nothing under rootfs present
        if p.startswith("/fake/rootfs"):
            return False
        return p in host_present

    with patch("os.path.exists", side_effect=fake_exists):
        binds = find_gpu_icd_binds("/fake/rootfs")
    srcs = {src for src, _ in binds}
    assert srcs == host_present
    # guest path mirrors host path
    for src, dst in binds:
        assert src == dst


def test_find_gpu_icd_binds_skips_absent_host_paths():
    with patch("os.path.exists", return_value=False):
        assert find_gpu_icd_binds("/fake/rootfs") == []


def test_find_gpu_icd_binds_skips_when_container_ships_config():
    # Host has the dir AND the rootfs already ships it -> skipped
    def fake_exists(p):
        if p == "/usr/share/vulkan/icd.d":
            return True
        if p == "/fake/rootfs/usr/share/vulkan/icd.d":
            return True
        return False

    with patch("os.path.exists", side_effect=fake_exists):
        binds = find_gpu_icd_binds("/fake/rootfs")
    assert binds == []


def test_find_mesa_libraries_maps_and_gap_fills():
    host_lib = "/usr/lib/x86_64-linux-gnu"
    host_file = os.path.join(host_lib, "libradeonsi_dri.so")

    def fake_isdir(p):
        # only the multiarch host lib dir and guest multiarch dir exist
        return p in (host_lib, "/fake/rootfs/usr/lib/x86_64-linux-gnu")

    def fake_glob(pattern, recursive=False):
        return [host_file] if "radeonsi" in pattern else []

    def fake_isfile(p):
        return p == host_file

    def fake_islink(p):
        return False

    def fake_exists(p):
        # guest does NOT already ship the lib -> must be bound
        return False

    with (
        patch("chroot_distro.helpers.gpu.os.path.isdir", side_effect=fake_isdir),
        patch("chroot_distro.helpers.gpu.glob.glob", side_effect=fake_glob),
        patch("chroot_distro.helpers.gpu.os.path.isfile", side_effect=fake_isfile),
        patch("chroot_distro.helpers.gpu.os.path.islink", side_effect=fake_islink),
        patch("chroot_distro.helpers.gpu.os.path.exists", side_effect=fake_exists),
    ):
        binds = find_mesa_libraries("/fake/rootfs")

    assert (host_file, "/usr/lib/x86_64-linux-gnu/libradeonsi_dri.so") in binds


def test_find_mesa_libraries_skips_when_guest_has_lib():
    host_lib = "/usr/lib/x86_64-linux-gnu"
    host_file = os.path.join(host_lib, "libGL.so.1")

    with (
        patch("chroot_distro.helpers.gpu.os.path.isdir", side_effect=lambda p: p in (host_lib, "/fake/rootfs/usr/lib/x86_64-linux-gnu")),
        patch("chroot_distro.helpers.gpu.glob.glob", side_effect=lambda pat, recursive=False: [host_file] if "libGL" in pat else []),
        patch("chroot_distro.helpers.gpu.os.path.isfile", side_effect=lambda p: p == host_file),
        patch("chroot_distro.helpers.gpu.os.path.islink", return_value=False),
        # guest already ships the lib -> skipped
        patch("chroot_distro.helpers.gpu.os.path.exists", return_value=True),
    ):
        binds = find_mesa_libraries("/fake/rootfs")

    assert binds == []
