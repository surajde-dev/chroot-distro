"""Tests for generic (AMD/Intel/Mesa) GPU ICD discovery."""

from unittest.mock import patch

from chroot_distro.helpers.gpu import find_gpu_icd_binds


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
