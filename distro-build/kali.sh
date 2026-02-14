dist_version="2025.4"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/kali-*.tar.xz

	for arch in arm64 armhf; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		local kali_arch
		if [ "$arch" = "arm64" ]; then
			kali_arch="arm64"
		else
			kali_arch="armhf"
		fi

		curl --fail --location \
			--output "${WORKDIR}/kali-${kali_arch}.tar.xz" \
			"http://kali.download/nethunter-images/current/rootfs/kali-nethunter-rootfs-minimal-${kali_arch}.tar.xz"

		sudo rm -rf "${WORKDIR}/kali-$(translate_arch "$arch")"
		sudo mkdir -m 755 "${WORKDIR}/kali-$(translate_arch "$arch")"
		sudo tar -Jxp --acls --xattrs --xattrs-include='*' \
			-f "${WORKDIR}/kali-${kali_arch}.tar.xz" \
			-C "${WORKDIR}/kali-$(translate_arch "$arch")"

		archive_rootfs "${ROOTFS_DIR}/kali-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"kali-$(translate_arch "$arch")"
	done
	unset arch
}
