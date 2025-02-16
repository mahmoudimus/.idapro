import re
import sys

from PyQt5 import QtWidgets

import ida_kernwin

# this plugin requires Python 3
SUPPORTED_PYTHON = sys.version_info[0] == 3

# this plugin requires IDA 7.6 or newer
try:
    import ida_pro
    import ida_idaapi

    IDA_GLOBAL_SCOPE = sys.modules["__main__"]
    SUPPORTED_IDA = ida_pro.IDA_SDK_VERSION >= 760
except:
    SUPPORTED_IDA = False

# is this deemed to be a compatible environment for the plugin to load?
SUPPORTED_ENVIRONMENT = bool(SUPPORTED_IDA and SUPPORTED_PYTHON)

# ------------------------------------------------------------------------------
# IDA Plugin Stub
# ------------------------------------------------------------------------------

class KeyHooker(ida_kernwin.UI_Hooks):
    _TILDE_PATTERN_rgx = re.compile(r"~(.*?)~")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.LABEL_TO_ACTION = {}
        self.ACTIONS = {}        

    def enumerate_actions(self):
        # Get the instance of the QApplication
        main_window = QtWidgets.QApplication.instance()

        widgets = [main_window]
        while widgets:
            widget = widgets.pop(0)
            widgets.extend(list(widget.findChildren(QtWidgets.QAction)))
            if not isinstance(widget, QtWidgets.QAction):
                continue
            if widget.shortcut().isEmpty():
                continue

            self.LABEL_TO_ACTION[widget.text()] = widget

    @staticmethod
    def replace_tilde_with_ampersand(text):
        # Define a pattern that matches text between ~ and ~
        # The lambda function prefixes the matched text (group 1) with &
        replaced_text = KeyHooker._TILDE_PATTERN_rgx.sub(lambda match: f"&{match.group(1)}", text)
        return replaced_text

    def run(self):
        # ida_kernwin.update_action_shortcut("JumpOpXref", "Meta+g, x")
        self.enumerate_actions()
        for action_name in ida_kernwin.get_registered_actions():
            if not ida_kernwin.get_action_shortcut(action_name):
                continue
            # labels have ~ between the mnemonic shortkey identifier
            label = ida_kernwin.get_action_label(action_name)
            label = self.replace_tilde_with_ampersand(label)
            action = self.LABEL_TO_ACTION.get(label)
            if not action:
                print(
                    "WARNING: action ",
                    action_name,
                    "(",
                    label,
                    ") not found in action widgets.",
                )
            else:
                self.ACTIONS[action_name] = action

        print(f"[+] {KeybinderPlugin.wanted_name} by mahmoudimus. Setting shortcuts.")

        # Now proceed to set shortcuts
        self.set_shortcut("ChooserEdit", "Meta+E, C")
        self.set_shortcut("EditEnum", "Meta+E, N")
        self.set_shortcut("EditSegment", "Meta+E, S")
        self.set_shortcut("ExpandStruct", "Meta+E, E")
        self.set_shortcut("SetSegmentRegister", "Meta+E, R")

        self.set_shortcut("Edit/Plugins/IDA Patcher", "Meta+P, P")
        self.set_shortcut("Edit/Plugins/Signature Maker", "Meta+P, S")

    def set_shortcut(self, action_name, shortcut_key):
        try:
            self.ACTIONS[action_name].setShortcut(shortcut_key)
        except KeyError as ke:
            print(f"{action_name} not found, unable to set shortcut {shortcut_key}. is action loaded?")
            
    def ready_to_run(self):
        self.run()

    def get_lines_rendering_info(self, out, widget, rin):
        pass

    def populating_widget_popup(self, widget, popup, ctx):
        pass


class KeybinderPlugin(ida_idaapi.plugin_t):
    """
    The Keybinder plugin stub.
    """

    #
    # Plugin flags:
    # - PLUGIN_PROC: Load / unload this plugin when an IDB opens / closes
    # - PLUGIN_HIDE: Hide this plugin from the IDA plugin menu
    # - PLUGIN_UNL:  Unload the plugin after calling run()
    #
    
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
    comment = "A plugin to enable Emacs-like key sequences and key chord sequences in IDA"
    help = ""
    wanted_name = "Keybinder"
    wanted_hotkey = ""

    def __init__(self):
        self.__updated = getattr(IDA_GLOBAL_SCOPE, "RESTART_REQUIRED", False)

    # --------------------------------------------------------------------------
    # IDA Plugin Overloads
    # --------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        if not SUPPORTED_ENVIRONMENT or self.__updated:
            return ida_idaapi.PLUGIN_SKIP
        
        # defer loading via hook
        self._ui_hook = KeyHooker()
        self._ui_hook.hook()

        # mark the plugin as loaded
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        pass

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        pass


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython plugins.
    """
    if not SUPPORTED_ENVIRONMENT:
        print("plugin", KeybinderPlugin.wanted_name, "is not compatible with this IDA/Python version")
    return KeybinderPlugin()
