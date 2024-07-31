root_was_shared="no"

# systemd mounts / and everything under it MS_SHARED. This breaks
# pivot_root and mount "move" operations entirely, so attempt to
# detect it, and remount / MS_PRIVATE temporarily.
FINDMNT=/bin/findmnt
if [ -x "${FINDMNT}" ] && ${FINDMNT} -no PROPAGATION / > /dev/null 2>&1 ; then
	if [ "$(${FINDMNT} -no PROPAGATION /)" = "shared" ] ; then
		root_was_shared="yes"
	fi
elif [ "$(ps hp1  -ocomm)" = "systemd" ] ; then
	# no findmnt or findmnt doesn't know the PROPAGATION column,
	# but init is systemd so assume rootfs is shared
	root_was_shared="yes"
fi
if [ "${root_was_shared}" = "yes" ] ; then
	[ -n "$VERBOSE" ] && echo 'notice: re-mounting / as private'
	mount --make-private /
fi

prop_cleanup() {
	if [ "${root_was_shared}" = "yes" ] ; then
		[ -n "$VERBOSE" ] && echo 'notice: re-mounting / as shared'
		mount --make-shared /
	fi
}
