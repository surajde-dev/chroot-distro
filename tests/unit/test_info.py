from unittest.mock import MagicMock, patch

import chroot_distro.commands.info as info


def test_read_os_release_parses_quoted_values(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('PRETTY_NAME="Ubuntu 25.10"\nVERSION_ID="25.10"\n# comment\nNAME=Ubuntu\n')
    with patch.object(info, "open", create=False):
        pass
    # Patch the candidate paths to point at our temp file.
    with patch("builtins.open", side_effect=lambda *a, **k: open(f, *a[1:], **k)):
        data = info._read_os_release()
    assert data["PRETTY_NAME"] == "Ubuntu 25.10"
    assert data["VERSION_ID"] == "25.10"
    assert data["NAME"] == "Ubuntu"


def test_linux_host_info_uses_pretty_name():
    with patch.object(
        info,
        "_read_os_release",
        return_value={"PRETTY_NAME": "Debian GNU/Linux 13", "VERSION_ID": "13"},
    ):
        host = info._linux_host_info()
    assert host.kind == "Linux"
    field_dict = dict(host.fields)
    assert field_dict["Distribution"] == "Debian GNU/Linux 13"
    assert field_dict["Version"] == "13"


def test_termux_host_info_reports_android_version(monkeypatch):
    monkeypatch.setenv("TERMUX_VERSION", "0.118.1")
    props = {
        "ro.build.version.release": "14",
        "ro.build.version.sdk": "34",
        "ro.product.manufacturer": "Google",
        "ro.product.model": "Pixel 8",
        "ro.product.device": "shiba",
    }
    with patch.object(info, "_read_build_prop", return_value=props):
        host = info._termux_host_info()
    field_dict = dict(host.fields)
    assert host.kind == "Termux / Android"
    assert field_dict["Termux version"] == "0.118.1"
    assert field_dict["Android version"] == "14 (API 34)"
    assert "Google Pixel 8" in field_dict["Device"]


def test_analyze_image_flags_arch_mismatch():
    img = info._ImageInfo(name="alpine", size_bytes=1024, arch="x86_64")
    with (
        patch("os.path.isfile", return_value=True),
        patch("chroot_distro.commands.info.container_manifest", return_value="/x/manifest.json"),
        patch("chroot_distro.commands.info.container_rootfs", return_value="/x/rootfs"),
    ):
        info._analyze_image(img, host_arch="aarch64")
    assert any("differs from host" in f for f in img.findings)


def test_analyze_image_flags_empty_rootfs():
    img = info._ImageInfo(name="broken", size_bytes=0, arch="aarch64")
    with (
        patch("os.path.isfile", return_value=True),
        patch("chroot_distro.commands.info.container_manifest", return_value="/x/manifest.json"),
        patch("chroot_distro.commands.info.container_rootfs", return_value="/x/rootfs"),
    ):
        info._analyze_image(img, host_arch="aarch64")
    assert any("rootfs is empty" in f for f in img.findings)


def test_analyze_image_no_arch_flag_for_compatible_32bit():
    img = info._ImageInfo(name="i386", size_bytes=2048, arch="i686")
    with (
        patch("os.path.isfile", return_value=True),
        patch("chroot_distro.commands.info.container_manifest", return_value="/x/manifest.json"),
        patch("chroot_distro.commands.info.container_rootfs", return_value="/x/rootfs"),
    ):
        info._analyze_image(img, host_arch="x86_64")
    assert not any("differs from host" in f for f in img.findings)


def test_command_info_runs_without_containers():
    with (
        patch.object(info, "_iter_container_names", return_value=[]),
        patch.object(info, "get_device_cpu_arch", return_value="aarch64"),
        patch.object(info, "_gather_host_info", return_value=info._HostInfo("Linux", [("Kernel", "6.0")])),
        patch.object(info, "supports_32bit", return_value=True),
        patch.object(info, "msg") as mock_msg,
    ):
        info.command_info(MagicMock())
    # Report rendered something to stderr via msg().
    assert mock_msg.called
    rendered = " ".join(str(c.args[0]) for c in mock_msg.call_args_list if c.args)
    assert "No containers are installed." in rendered
