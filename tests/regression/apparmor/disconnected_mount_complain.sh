#! /bin/bash
#	Copyright (C) 2025 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME disconnected_mount_complain
#=DESCRIPTION
# Verifies that complain-mode profiles work as expected and do not block
# disconnected path operations
#=END

# This test suite will need the patchset posted to
# https://lists.ubuntu.com/archives/apparmor/2025-March/013533.html
# to be applied to the kernel in order to pass

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

shadowed_target=$tmpdir/shadowed
shadowing_dir=$tmpdir/shadowing

mkdir "$shadowed_target"
# Complications because true is also a shell builtin
cp "$(type -P true)" "${shadowed_target}/true"
mkdir "${shadowed_target}/inner_dir"

mkdir "$shadowing_dir"
# the cornh file has 5 letters: the (h|newline) is silent, and you can't see it
echo "corn" > "${shadowing_dir}/cornh"

genprofile -C cap:sys_admin
runchecktest "Complain mode profile and disconnected path mounts (mount(2))" pass $tmpdir old
runchecktest "Complain mode profile and disconnected path mounts (open_tree(2))" pass $tmpdir new

rm -r "$shadowed_target"
rm -r "$shadowing_dir"
