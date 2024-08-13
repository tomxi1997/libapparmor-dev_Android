import os
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as messagebox
import tkinter.font as font
import subprocess
import ttkthemes

import apparmor.aa as aa
import apparmor.update_profile as update_profile
from apparmor.common import AppArmorException

from apparmor.translations import init_translation

_ = init_translation()

notification_custom_msg = {
    'userns': _('Application {0} wants to create an user namespace which could be used to compromise your system\nDo you want to allow it next time {0} is run?\nApplication path is {1}')
}

global interface_theme


class GUI:
    def __init__(self):
        try:
            self.master = tk.Tk()
        except tk.TclError:
            print(_('ERROR: Cannot initialize Tkinter. Please check that your terminal can use a graphical interface'))
            os._exit(1)

        style = ttkthemes.ThemedStyle(self.master)
        style.theme_use(interface_theme)
        self.bg_color = style.lookup('TLabel', 'background')
        self.master.configure(background=self.bg_color)

        self.label_frame = ttk.Frame(self.master, padding=(20, 10))
        self.label_frame.pack()

        self.button_frame = ttk.Frame(self.master, padding=(0, 10))
        self.button_frame.pack()


class AddProfileGUI(GUI):
    def __init__(self, rule, profile_name, dbg=None):
        self.dbg = dbg
        self.rule = rule
        self.profile_name = profile_name
        self.profile_path = aa.get_profile_filename_from_profile_name(profile_name)

        if not self.profile_path:
            raise AppArmorException('Cannot find profile for {}'.format(self.profile_name))
        super().__init__()

        self.master.title(_('AppArmor - Add rule to profile'))

        self.profile_label = ttk.Label(self.label_frame, text=_('Profile for: {}').format(self.profile_name))
        self.profile_label.pack()

        self.entry_frame = ttk.Frame(self.master)
        self.entry_frame.pack()

        self.rule = tk.StringVar(value=self.rule)
        self.rule_entry = ttk.Entry(self.entry_frame, font=font.nametofont("TkDefaultFont"), width=50, textvariable=self.rule)
        self.rule_entry.pack(side=tk.LEFT)

        self.button_frame = ttk.Frame(self.master, padding=(10, 10))
        self.button_frame.pack()

        self.add_to_profile_button = ttk.Button(self.button_frame, text=_('Add to Profile'), command=self.add_to_profile)
        self.add_to_profile_button.pack(side=tk.LEFT)

        self.show_profile_button = ttk.Button(self.button_frame, text=_('Show Current Profile'), command=lambda: open_with_default_editor(self.profile_path))
        self.show_profile_button.pack(side=tk.LEFT)

        self.cancel_button = ttk.Button(self.button_frame, text=_('Cancel'), command=self.master.destroy)
        self.cancel_button.pack(side=tk.LEFT)

    def add_to_profile(self):
        if self.dbg:
            self.dbg.debug('Adding rule \'{}\' to profile at: {}'.format(self.rule.get(), self.profile_name))

        # We get update_profile.py through this import so that it works in all cases
        update_profile_path = update_profile.__file__
        command = ['pkexec', '--keep-cwd', update_profile_path,  'add_rule', self.rule.get(), self.profile_name]
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            if e.returncode != 126:  # return code 126 means the user cancelled the request
                ErrorGUI(_('Failed to add rule {} to {}\n Error code = {}').format(self.rule.get(), self.profile_name, e.returncode), False).show()

        self.master.destroy()

    def show(self):
        self.master.mainloop()

    @staticmethod
    def show_error_cannot_find_profile(profile_name):
        ErrorGUI(
            _(
                'Cannot find profile for {}\n\n'
                'It is likely that the profile was not stored in {} or was removed.'
            ).format(profile_name, aa.profile_dir),
            False
        ).show()


class ShowMoreGUI(GUI):
    def __init__(self, profile_path, msg, profile_found=True):
        self.profile_path = profile_path
        self.msg = msg
        self.profile_found = profile_found

        super().__init__()

        self.master.title(_('AppArmor - More info'))

        self.label = tk.Label(self.label_frame, background=self.bg_color, text=self.msg, anchor='w', justify=tk.LEFT, wraplength=460)
        self.label.pack()

        if self.profile_found:
            self.show_profile_button = ttk.Button(self.button_frame, text=_('Show Current Profile'), command=lambda: open_with_default_editor(self.profile_path))
            self.show_profile_button.pack()

    def show(self):
        self.master.mainloop()


class UsernsGUI(GUI):
    def __init__(self, name, path):
        self.name = name
        self.path = path
        self.result = None

        super().__init__()

        self.master.title(_('AppArmor - User namespace creation restricted'))

        label_text = notification_custom_msg['userns'].format(name, path)
        self.label = ttk.Label(self.label_frame, text=label_text, wraplength=460)
        self.label.pack()
        link = ttk.Label(self.master, text=_('More information'), foreground='blue', cursor='hand2')
        link.pack()
        link.bind('<Button-1>', self.more_info)

        self.add_policy_button = ttk.Button(self.master, text=_('Allow'), command=lambda: self.set_result("allow"))
        self.add_policy_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.never_ask_button = ttk.Button(self.master, text=_('Deny'), command=lambda: self.set_result("deny"))
        self.never_ask_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.do_nothing_button = ttk.Button(self.master, text=_('Do nothing'), command=self.master.destroy)
        self.do_nothing_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    @staticmethod
    def more_info(ev):
        more_info_text = _("""
In Linux, user namespaces enable non-root users to perform certain privileged operations. This feature can be useful for several legitimate use cases.

However, this feature also introduces security risks, (e.g. privilege escalation exploits).

This dialog allows you to choose whether you want to enable user namespaces for this application.""")
        messagebox.showinfo(
            _('AppArmor: More info'),
            more_info_text,
        )

    def set_result(self, result):
        self.result = result
        self.master.destroy()

    def show(self):
        self.master.mainloop()
        return self.result

    @staticmethod
    def show_error_cannot_reload_profile(profile_path, error):
        ErrorGUI(_('Failed to create or load profile {}\n Error code = {}').format(profile_path, error), False).show()

    @staticmethod
    def show_error_cannot_find_execpath(name, template_path):
        ErrorGUI(
            _(
                'Application {0} wants to create an user namespace which could be used to compromise your system\n\n'
                'However, apparmor cannot find {0}. If you want to allow it, please create a profile for it.\n\n'
                'A profile template is in {1}\n Profiles are in {2}'
            ).format(name, template_path, aa.profile_dir),
            False
        ).show()


class ErrorGUI(GUI):
    def __init__(self, msg, is_fatal):
        self.msg = msg
        self.is_fatal = is_fatal

        super().__init__()

        self.master.title('AppArmor Error')

        # Create label to display the error message
        self.label = ttk.Label(self.label_frame, background=self.bg_color, text=self.msg, wraplength=460)
        self.label.pack()

        # Create a button to close the dialog
        self.button = ttk.Button(self.button_frame, text="OK", command=self.destroy)
        self.button.pack()

    def destroy(self):
        self.master.destroy()

        if self.is_fatal:
            os._exit(1)

    def show(self):
        self.master.mainloop()
        if self.is_fatal:
            os._exit(1)


def set_interface_theme(theme):
    global interface_theme
    interface_theme = theme


def open_with_default_editor(profile_path):
    try:
        default_app = subprocess.run(['xdg-mime', 'query', 'default', 'text/plain'], capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(['gtk-launch', default_app, profile_path], check=True)
    except subprocess.CalledProcessError:
        ErrorGUI(_('Failed to launch default editor'), False).show()
    except FileNotFoundError as e:
        ErrorGUI(_('Failed to open file: {}').format(e), False).show()
