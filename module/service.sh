#!/system/bin/sh

MODDIR=${0%/*}
RUNTIME_DIR="/data/local/chroot-distro"
DATA_DIR="${RUNTIME_DIR}/data"
MOUNT_DIR="${DATA_DIR}/mounts"
INSTALLED_ROOTFS_DIR="${RUNTIME_DIR}/installed-rootfs"
PROP_FILE="$MODDIR/module.prop"
PROP_BAK="$MODDIR/module.prop.bak"

# Wait for boot completion
boot_prop="$(getprop sys.boot_completed 2>/dev/null)"
if [ -n "$boot_prop" ]; then
	until [ "$boot_prop" = "1" ]; do
		sleep 1
		boot_prop="$(getprop sys.boot_completed 2>/dev/null)"
	done
fi

BUSYBOXPATH="$(command -v busybox 2>/dev/null)"
[ -z "$BUSYBOXPATH" ] && exit 1
busybox() { "$BUSYBOXPATH" "$@"; }

update_description() {
	installed_count=0
	mounted_count=0
	distro_details=""
	mounted_distros=""
	installed_distros=""
	string=""

	# Count installed distributions
	if [ -d "$INSTALLED_ROOTFS_DIR" ]; then
		for distro_dir in "$INSTALLED_ROOTFS_DIR"/*; do
			if [ -d "$distro_dir" ] && [ -e "$distro_dir/etc" ]; then
				installed_count=$((installed_count + 1))
				distro_name=$(basename "$distro_dir")
				if [ -z "$installed_distros" ]; then
					installed_distros="$distro_name"
				else
					installed_distros="$installed_distros, $distro_name"
				fi
			fi
		done
	fi

	# Check mounted distributions and active sessions
	if [ -d "${RUNTIME_DIR}/data" ]; then
		for distro_data in "${RUNTIME_DIR}/data"/*; do
			[ ! -d "$distro_data" ] && continue
			distro_name=$(basename "$distro_data")
			[ "$distro_name" = "mounts" ] && continue

			is_mounted=0
			distro_sessions=0

			mount_tracker="${MOUNT_DIR}/${distro_name}/mount.points"
			if [ -f "$mount_tracker" ] && [ -s "$mount_tracker" ]; then
				is_mounted=1
			fi

			session_file="${RUNTIME_DIR}/data/${distro_name}/sessions"
			if [ -f "$session_file" ]; then
				sessions=$(cat "$session_file" 2>/dev/null || echo "0")
				if echo "$sessions" | busybox grep -qE '^[0-9]+$'; then
					distro_sessions=$sessions
				fi
			fi

			if [ $is_mounted -eq 1 ]; then
				mounted_count=$((mounted_count + 1))

				if [ -z "$mounted_distros" ]; then
					mounted_distros="$distro_name"
				else
					mounted_distros="$mounted_distros, $distro_name"
				fi

				if [ "$distro_sessions" -eq 1 ]; then
					session_text="1 session"
				elif [ "$distro_sessions" -gt 1 ]; then
					session_text="${distro_sessions} sessions"
				else
					session_text="no active sessions"
				fi

				if [ -z "$distro_details" ]; then
					distro_details="📦 ${distro_name}: ${session_text}"
				else
					distro_details="${distro_details} \\n 📦 ${distro_name}: ${session_text}"
				fi
			fi
		done
	fi

	if [ $installed_count -eq 0 ]; then
		string="Status: No distros installed 📦"
	elif [ $mounted_count -eq 0 ]; then
		if [ $installed_count -eq 1 ]; then
			string="Status: ${installed_count} distro installed, none active 💤 \\n Installed: ${installed_distros}"
		else
			string="Status: ${installed_count} distros installed, none active 💤 \\n Installed: ${installed_distros}"
		fi
	else
		if [ $mounted_count -eq 1 ]; then
			main_status="Status: ${mounted_count}/${installed_count} is activated 🚀 | Mounted: ${mounted_distros}"
		else
			main_status="Status: ${mounted_count}/${installed_count} are activated 🚀 | Mounted: ${mounted_distros}"
		fi
		string="${main_status} \\n ${distro_details}"
	fi

	if ! grep -q "^id=" "$PROP_FILE"; then
		[ -f "$PROP_BAK" ] && cp "$PROP_BAK" "$PROP_FILE"
	fi

	escaped=$(printf '%s' "$string" | busybox sed 's/[\/&\\]/\\&/g')
	busybox sed -i "s/^description=.*/description=${escaped}/" "$PROP_FILE"
}
update_description

# Clean up stale session files on boot (if exist)
# This ensures session counts are accurate after reboots
# if you rebbot then all the distro will be unmounted
# that's why we should do this
if [ -d "${RUNTIME_DIR}/data" ]; then
	for distro_data in "${RUNTIME_DIR}/data"/*; do
		if [ -d "$distro_data" ]; then
			[ "$(basename "$distro_data")" = "mounts" ] && continue
			session_file="${distro_data}/sessions"
			if [ -f "$session_file" ]; then
				# Reset session count on boot
				rm -f "$session_file"
			fi
		fi
	done
fi

# # Configure network for chroot environments
# # Enable ping for all users
# if [ -w /proc/sys/net/ipv4/ping_group_range ]; then
# 	echo '0 2147483647' >/proc/sys/net/ipv4/ping_group_range 2>/dev/null
# fi
#
# # Enable USB device authorization if available
# if [ -w /sys/module/usbcore/parameters/authorized_default ]; then
# 	echo 1 >/sys/module/usbcore/parameters/authorized_default 2>/dev/null
# fi
#
exit 0
