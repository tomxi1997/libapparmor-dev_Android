# ----------------------------------------------------------------------
#    Copyright (C) 2024 Canonical, Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------
import re

from apparmor.common import AppArmorBug, AppArmorException

from apparmor.regex import RE_PROFILE_MOUNT, RE_PROFILE_PATH_OR_VAR, strip_parenthesis
#from apparmor.rule import AARE
from apparmor.rule import BaseRule, BaseRuleset, parse_modifiers, logprof_value_or_all, check_and_split_list

from apparmor.translations import init_translation

_ = init_translation()

# TODO :
#   - match correctly AARE on every field
#   - Find the actual list of supported filesystems. This one comes from /proc/filesystems
#   - Support path that begin by { (e.g. {,/usr}/lib/...) This syntax is not a valid AARE but is used by usr.lib.snapd.snap-confine.real in Ubuntu and will currently raise an error in genprof if these lines are not modified.
#   - Apparmor remount logs are displayed as mount (with remount flag). Profiles generated with aa-genprof are therefore mount rules. It could be interesting to make them remount rules.

valid_fs = [
    'sysfs', 'tmpfs', 'bdevfs', 'procfs', 'cgroup', 'cgroup2', 'cpuset', 'devtmpfs', 'configfs', 'debugfs', 'tracefs',
    'securityfs', 'sockfs', 'bpf', 'npipefs', 'ramfs', 'hugetlbfs', 'devpts', 'ext3', 'ext2', 'ext4', 'squashfs',
    'vfat', 'ecryptfs', 'fuseblk', 'fuse', 'fusectl', 'efivarfs', 'mqueue', 'store', 'autofs', 'binfmt_misc', 'overlay',
    'none', 'bdev', 'proc', 'pipefs', 'pstore', 'btrfs', 'xfs',
]
flags_keywords = [
    'ro', 'rw', 'nosuid', 'suid', 'nodev', 'dev', 'noexec', 'exec', 'sync', 'async', 'remount', 'mand', 'nomand',
    'dirsync', 'noatime', 'atime', 'nodiratime', 'diratime', 'bind', 'rbind', 'move', 'verbose', 'silent', 'loud',
    'acl', 'noacl', 'unbindable', 'runbindable', 'private', 'rprivate', 'slave', 'rslave', 'shared', 'rshared',
    'relatime', 'norelatime', 'iversion', 'noiversion', 'strictatime', 'nostrictatime', 'lazytime', 'nolazytime',
    'nouser', 'user', 'symfollow', 'nosymfollow', '([A-Za-z0-9]|AARE)',  # TODO: handle AARE
]
join_valid_flags = '|'.join(flags_keywords)
join_valid_fs = '|'.join(valid_fs)

sep = r"\s*[\s,]\s*"

fs_type_pattern = r"\b(?P<fstype_or_vfstype>fstype|vfstype)\b\s*(?P<fstype_equals_or_in>=|in)\s*"\
        r"(?P<fstype>\(\s*(" + join_valid_fs + ")(" + sep + "(" + join_valid_fs + "))*\s*\)|"\
        r"\{\s*(" + join_valid_fs + ")(" + sep + "(" + join_valid_fs + r"))*\s*\}|(\s*" + join_valid_fs + "))"\


option_pattern = r"\s*(\boption(s?)\b\s*(?P<options_equals_or_in>=|in)\s*"\
        r"(?P<options>\(\s*(" + join_valid_flags + ")(" + sep + "(" + join_valid_flags + r"))*\s*\)|" \
        "(\s*" + join_valid_flags + ")"\
        "))?"
mount_condition_pattern = rf"({fs_type_pattern})?\s*({option_pattern})?"

# Source can either be
# - A path          : /foo
# - A filesystem    : sysfs         (sudo mount -t tmpfs tmpfs /tmp/bar)
# - Any label       : mntlabel      (sudo mount -t tmpfs mntlabel /tmp/bar)
source_fileglob_pattern = r"(\s*" + (RE_PROFILE_PATH_OR_VAR % "source_file")[:-1] + "|" + r"\w+" + "))"
dest_fileglob_pattern = r"(\s*" + RE_PROFILE_PATH_OR_VAR % "dest_file" + ')'

RE_MOUNT_DETAILS = re.compile(r"^\s*" + mount_condition_pattern + rf"(\s+{source_fileglob_pattern})?" + rf"(\s+->\s+{dest_fileglob_pattern})?\s*" +"$")
RE_UMOUNT_DETAILS = re.compile(r"^\s*" + mount_condition_pattern + rf"(\s+{dest_fileglob_pattern})?\s*" +"$")

class MountRule(BaseRule):
    '''Class to handle and store a single mount rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field MountRule.ALL
    class __MountAll(object):
        pass

    ALL = __MountAll

    rule_name = 'mount'
    _match_re = RE_PROFILE_MOUNT

    def __init__(self, operation, fstype, options, source, dest, audit=False, deny=False, allow_keyword=False, comment='', log_event=None):

        super().__init__(audit=audit, deny=deny,
                         allow_keyword=allow_keyword,
                         comment=comment,
                         log_event=log_event)

        self.operation = operation

        self.fstype, self.all_fstype, unknown_items = check_and_split_list(fstype[1] if fstype != self.ALL else fstype, valid_fs, self.ALL, type(self).__name__, 'fstype')
        self.is_fstype_equal = fstype[0] if not self.all_fstype else None

        self.options, self.all_options, unknown_items = check_and_split_list(options[1] if options != self.ALL else options, flags_keywords, self.ALL, type(self).__name__, 'options')
        self.is_options_equal = options[0] if not self.all_options else None

        if source != self.ALL and source[0].isalpha():
            self.source = source
            self.all_source = False
            self.source_is_path = False
        else:
            self.source_is_path = True
            self.source, self.all_source = self._aare_or_all(source, 'source', is_path=self.source_is_path, log_event=log_event)

        if not self.all_fstype and self.is_fstype_equal != "=" and self.is_fstype_equal != "in":
            raise AppArmorBug(f'Invalid is_fstype_equal : {self.is_fstype_equal}')
        if not self.all_options and self.is_options_equal != "=" and self.is_options_equal != "in":
            raise AppArmorBug(f'Invalid is_options_equal : {self.is_options_equal}')
        if self.operation != 'mount' and not self.all_source:
            raise AppArmorException(f'Operation {self.operation} cannot have a source')

        flags_forbidden_with_source = {'remount', 'unbindable', 'shared', 'private', 'slave', 'runbindable', 'rshared', 'rprivate', 'rslave'}
        if self.operation == 'mount' and not self.all_source and not self.all_options and flags_forbidden_with_source & self.options != set():
            raise AppArmorException(f'Operation {flags_forbidden_with_source & self.options} cannot have a source. Source = {self.source}')

        self.dest, self.all_dest = self._aare_or_all(dest, 'dest', is_path=True, log_event=log_event)

        self.can_glob = not self.all_source and not self.all_dest and not self.all_options


    @classmethod
    def _create_instance(cls, raw_rule, matches):
        '''parse raw_rule and return instance of this class'''

        audit, deny, allow_keyword, comment = parse_modifiers(matches)

        operation = matches.group('operation')

        rule_details = ''
        if matches.group('details'):
            rule_details = matches.group('details')

            if operation == "mount":
                parsed = RE_MOUNT_DETAILS.search(rule_details)
            else:
                parsed = RE_UMOUNT_DETAILS.search(rule_details)

            r = parsed.groupdict() if parsed else None
            if not r:
                raise AppArmorException('Can\'t parse mount rule ' + raw_rule)

            if r['fstype'] is not None:
                is_fstype_equal = r['fstype_equals_or_in']
                fstype = strip_parenthesis(r['fstype']).replace(',', ' ').split()
            else:
                is_fstype_equal = None
                fstype = cls.ALL

            if r['options'] is not None:
                is_options_equal = r['options_equals_or_in']
                options = strip_parenthesis(r['options']).replace(',', ' ').split()
            else:
                is_options_equal =None
                options = cls.ALL

            if operation == 'mount' and r['source_file'] is not None:  # Umount cannot have a source
                source = r['source_file']
            else:
                source = cls.ALL

            if r['dest_file'] is not None:
                dest = r['dest_file']
            else:
                dest = cls.ALL

        else:
            is_fstype_equal = None
            is_options_equal = None
            fstype  = cls.ALL
            options = cls.ALL
            source  = cls.ALL
            dest    = cls.ALL

        return cls(operation=operation, fstype=(is_fstype_equal, fstype), options=(is_options_equal, options), source=source, dest=dest, audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment)

    def get_clean(self, depth=0):
        space = '  ' * depth

        fstype = ' fstype%s(%s)' % (self.is_fstype_equal, ', '.join(sorted(self.fstype))) if not self.all_fstype else ''
        options = ' options%s(%s)' % (self.is_options_equal, ', '.join(sorted(self.options))) if not self.all_options else ''

        if self.operation == 'mount':
            return ('%s%s%s%s%s%s%s,%s' % ( self.modifiers_str(),
                                            space,
                                            self.operation,
                                            fstype,
                                            options,
                                            " " + str(self.source.regex) if not self.all_source else '',
                                            " -> " + str(self.dest.regex) if not self.all_dest else '',
                                            self.comment,
            ))
        else:
            return ('%s%s%s%s%s%s,%s' % (   self.modifiers_str(),
                                            space,
                                            self.operation,
                                            fstype,
                                            options,
                                            " " + str(self.dest.regex) if not self.all_dest else '',
                                            self.comment,
            ))

    def _is_covered_localvars(self, other_rule):
        if self.operation != other_rule.operation:
            return False
        if self.is_fstype_equal != other_rule.is_fstype_equal:
            return False
        if self.is_options_equal != other_rule.is_options_equal:
            return False
        if not self._is_covered_list(self.fstype, self.all_fstype, other_rule.fstype, other_rule.all_fstype, 'fstype'):
            return False
        if not self._is_covered_list(self.options, self.all_options, other_rule.options, other_rule.all_options, 'options'):
            return False
        if not self.source_is_path and not other_rule.source_is_path:
            if self.source != other_rule.source:
                return False
        elif self.source_is_path != other_rule.source_is_path:
            return False
        elif not self._is_covered_aare(self.source, self.all_source, other_rule.source, other_rule.all_source, 'source'):
            return False
        if not self._is_covered_aare(self.dest, self.all_dest, other_rule.dest, other_rule.all_dest, 'dest'):
            return False

        return True

    def _is_equal_localvars(self, rule_obj, strict):
        if self.operation != rule_obj.operation:
            return False
        if self.is_fstype_equal != rule_obj.is_fstype_equal:
            return False
        if self.is_options_equal != rule_obj.is_options_equal:
            return False
        if self.fstype != rule_obj.fstype or self.options != rule_obj.options:
            return False
        if not self.source_is_path and not rule_obj.source_is_path:
            if self.source != rule_obj.source:
                return False
        elif self.source_is_path != rule_obj.source_is_path:
            return False
        elif not self._is_equal_aare(self.source, self.all_source, rule_obj.source, rule_obj.all_source, 'source'):
            return False
        if not self._is_equal_aare(self.dest, self.all_dest, rule_obj.dest, rule_obj.all_dest, 'dest'):
            return False

        return True

    def glob(self):
        '''Change path to next possible glob'''
        if self.all_source and self.all_options:
            return

        if not self.all_dest:
            self.all_dest = True
            self.dest = self.ALL
        elif not self.all_source and type(self.source) is not str:
            self.source = self.source.glob_path()
            if self.source.is_equal('/**/'):
                self.all_source= True
                self.source=self.ALL

        else:
            self.options = self.ALL
            self.all_options = True
        self.raw_rule = None

    def _logprof_header_localvars(self):
        operation = self.operation
        fstype = logprof_value_or_all(self.fstype, self.all_fstype)
        options = logprof_value_or_all(self.options, self.all_options)
        source = logprof_value_or_all(self.source, self.all_source)
        dest = logprof_value_or_all(self.dest, self.all_dest)

        return (
            _('Operation'), operation,
            _('Fstype'), (self.is_fstype_equal, fstype) if fstype != 'ALL' else fstype ,
            _('Options'), (self.is_options_equal, options) if options != 'ALL'  else options ,
            _('Source'), source,
            _('Destination'), dest,

        )

class MountRuleset(BaseRuleset):
    '''Class to handle and store a collection of Mount rules'''



