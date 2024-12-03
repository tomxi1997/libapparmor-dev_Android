#!/usr/bin/python3

import subprocess
import sys

# TODO: transform this script to a package to use local imports so that if called with ./aa-notify, we use ./apparmor.*
from apparmor import aa
from apparmor.logparser import ReadLog

from apparmor.translations import init_translation
_ = init_translation()


def create_userns(template_path, name, bin_path, profile_path, decision):
    with open(template_path, 'r') as f:
        profile_template = f.read()

    rule = 'userns create' if decision == 'allow' else 'audit deny userns create'
    profile = profile_template.format(rule=rule, name=name, path=bin_path)

    with open(profile_path, 'w') as file:
        file.write(profile)

    try:
        subprocess.run(['apparmor_parser', '-r', profile_path], check=True)
    except subprocess.CalledProcessError:
        exit(_('Cannot reload updated profile'))


def add_to_profile(rule, profile_name):
    aa.init_aa()
    aa.update_profiles()

    rule_type, rule_class = ReadLog('', '', '').get_rule_type(rule)

    rule_obj = rule_class.create_instance(rule)

    if profile_name not in aa.aa or profile_name not in aa.aa[profile_name]:
        exit(_('Cannot find {} in profiles').format(profile_name))
    aa.aa[profile_name][profile_name][rule_type].add(rule_obj, cleanup=True)

    # Save changes
    aa.write_profile_ui_feedback(profile_name)
    aa.reload_base(profile_name)


def usage(is_help):
    print('This tool is a low level tool - do not use it directly')
    print('{} create_userns <template_path> <name> <bin_path> <profile_path> <decision>'.format(sys.argv[0]))
    print('{} add_rule <rule> <profile_name>'.format(sys.argv[0]))
    print('{} from_file <file>'.format(sys.argv[0]))
    if is_help:
        exit(0)
    else:
        exit(1)


def create_from_file(file_path):
    with open(file_path) as file:
        for line in file:
            args = line[:-1].split('\t')
            if len(args) > 1:
                command = args[0]
            else:
                command = None  # Handle the case where no command is provided
            do_command(command, args)


def do_command(command, args):
    if command == 'from_file':
        if not len(args) == 2:
            usage(False)
        create_from_file(args[1])
    elif command == 'create_userns':
        if not len(args) == 6:
            usage(False)
        create_userns(args[1], args[2], args[3], args[4], args[5])
    elif command == 'add_rule':
        if not len(args) == 3:
            usage(False)
        add_to_profile(args[1], args[2])
    elif command == 'help':
        usage(True)
    else:
        usage(False)


def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        command = None  # Handle the case where no command is provided

    do_command(command, sys.argv[1:])


if __name__ == '__main__':
    main()
