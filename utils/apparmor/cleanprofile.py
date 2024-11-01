# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014-2024 Christian Boltz <apparmor@cboltz.de>
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
import apparmor.aa as apparmor


class Prof:
    def __init__(self, filename):
        apparmor.init_aa()
        self.active_profiles = apparmor.active_profiles
        self.include = apparmor.include
        self.filename = filename


class CleanProf:
    def __init__(self, same_file, profile, other):
        # If same_file we're basically comparing the file against itself to check superfluous rules
        self.same_file = same_file
        self.profile = profile
        self.other = other

    def compare_profiles(self):
        deleted = 0

        deleted += self.other.active_profiles.delete_preamble_duplicates(self.other.filename)

        for profile in self.profile.active_profiles.get_all_profiles():
            deleted += self.remove_duplicate_rules(profile)

        return deleted

    def remove_duplicate_rules(self, program):
        # Process the profile of the program

        deleted = 0

        # remove duplicate rules from the preamble
        deleted += self.profile.active_profiles.delete_preamble_duplicates(self.profile.filename)

        # Process every hat in the profile individually
        for full_profile in sorted(self.profile.active_profiles.get_profile_and_childs(program)):
            includes = self.profile.active_profiles[full_profile]['inc_ie'].get_all_full_paths(apparmor.profile_dir)

            # Clean up superfluous rules from includes in the other profile
            for inc in includes:
                if not self.profile.include.get(inc, {}).get(inc, False):
                    apparmor.load_include(inc)
                if self.other.active_profiles.profile_exists(full_profile):
                    deleted += apparmor.delete_all_duplicates(self.other.active_profiles[full_profile], inc, apparmor.ruletypes)

            # Clean duplicate rules in other profile
            for ruletype in apparmor.ruletypes:
                if not self.same_file:
                    if self.other.active_profiles.profile_exists(full_profile):
                        deleted += self.other.active_profiles[full_profile][ruletype].delete_duplicates(self.profile.active_profiles[full_profile][ruletype])
                else:
                    deleted += self.other.active_profiles[full_profile][ruletype].delete_duplicates(None)

        return deleted
