import sys

import ida_idaapi
import ida_kernwin
import mutilz
import mutilz.plugincore
from mutilz import reloader


class mutilz_t(ida_idaapi.plugin_t):

    #
    # Plugin flags:
    # - PLUGIN_PROC: Load/unload this plugin when an IDB opens / closes
    # - PLUGIN_HIDE: Hide this plugin from the IDA plugin menu
    #

    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = "mutilz"
    help = ""
    wanted_name = "mutilz"
    wanted_hotkey = ""

    # --------------------------------------------------------------------------
    # IDA Plugin Overloads
    # --------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # initialize the plugin
        self.core = mutilz.plugincore.PluginCore.deferred_load()

        # add plugin to the IDA python console scope, for test/dev/cli access
        setattr(sys.modules["__main__"], self.wanted_name, self)

        # mark the plugin as loaded
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        ida_kernwin.warning("%s cannot be run as a script in IDA." % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        self.core.unload()

    # --------------------------------------------------------------------------
    # Development Helpers
    # --------------------------------------------------------------------------

    def reload(self):
        """
        Hot-reload the plugin core.
        """
        print("Reloading...")
        self.core.unload()
        reloader.reload_package(mutilz)
        reloader.reload_plugin()
        self.core = mutilz.plugincore.PluginCore()

    def test(self):
        """
        Run some basic tests of the plugin core against this database.
        """
        self.reload()
        self.core.test()

    @property
    def reload_module(self):
        return reloader


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return mutilz_t()
