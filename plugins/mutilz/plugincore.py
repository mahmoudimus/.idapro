import collections
import importlib
import pkgutil
import sys
from dataclasses import dataclass, field
from typing import Collection

import ida_idaapi
import ida_kernwin
import mutilz.actions as actions

deque = collections.deque


class _UIHooks(ida_kernwin.UI_Hooks):
    def ready_to_run(self):
        pass


@dataclass
class PluginCore:
    """
    The plugin core constitutes the traditional 'main' plugin class.
    It hosts all of the plugin's objects and integrations, taking
    responsibility for their initialization, teardown, and lifetime.

    This pattern of splitting out the plugin core from the IDA plugin_t stub
    is primarily to help separate the plugin functionality from IDA's and
    make it easier to 'reload' for development / testing purposes.

    This concept is a combination of the two following projects:

    - @gaasedelen's lucid plugin (https://github.com/gaasedelen/lucid)
    - @thalium's symless plugin (https://github.com/thalium/symless)

    Thank you for the inspiration!
    """

    PLUGIN_NAME: str = "mutilz"
    PLUGIN_VERSION: str = "0.1.1"
    PLUGIN_AUTHORS: str = "mahmoudimus"
    PLUGIN_DATE: str = "2025"

    defer_load: bool = field(default=False)
    loaded: bool = field(default=False, init=False)
    _startup_hooks: _UIHooks = field(default_factory=_UIHooks, init=False)
    _ext: deque[actions.action_t] = field(default_factory=deque, init=False)

    @classmethod
    def deferred_load(cls):
        """
        Create a new instance of the plugin core, deferred.
        """
        return cls(defer_load=True)

    def __post_init__(self):
        """
        Post-initialization logic for the dataclass.
        """
        self._startup_hooks.ready_to_run = self.load

        if self.defer_load:
            self._startup_hooks.hook()
        else:
            self.load()

    # -------------------------------------------------------------------------
    # Initialization / Teardown
    # -------------------------------------------------------------------------

    def load(self):
        """
        Load the plugin core.
        """
        self._startup_hooks.unhook()
        self.find_extensions()
        # print plugin banner
        print(
            f"Loading {self.PLUGIN_NAME} v{self.PLUGIN_VERSION} - (c) {self.PLUGIN_AUTHORS}"
        )

        # initialize the the plugin integrations

        # all done, mark the core as loaded
        self.loaded = True

    # find and load extensions from the plugins folder
    def find_extensions(self):
        for mod_info in pkgutil.walk_packages(
            actions.__path__, prefix=f"{self.PLUGIN_NAME}.actions."
        ):
            if mod_info.ispkg:
                continue

            spec = mod_info.module_finder.find_spec(mod_info.name)
            module = importlib.util.module_from_spec(spec)

            # module is already loaded
            if module.__name__ in sys.modules:
                module = sys.modules[module.__name__]

            # load the module
            else:
                sys.modules[module.__name__] = module
                try:
                    spec.loader.exec_module(module)
                except BaseException as e:  # //NOSONAR
                    sys.modules.pop(module.__name__)
                    print(f"Error while loading extension {mod_info.name}: {e}")
                    continue

            # module defines an extension
            if not hasattr(module, "get_action"):
                continue

            ext: actions.action_t = module.get_action()
            self._ext.append(ext)

    def unload(self, from_ida=False):
        """
        Unload the plugin core.
        """
        self._startup_hooks.unhook()

        if not self.loaded:
            return

        action_count = 0
        for i, ext in enumerate(reversed(self._ext)):
            print(f"Unloading action {i} of {len(self._ext)}: {ext!r}")
            ext.term()
            action_count += 1
        self._ext.clear()

        print(f"Unloading {self.PLUGIN_NAME} with {action_count} actions...")

        self.loaded = False

    # --------------------------------------------------------------------------
    # Plugin Testing
    # --------------------------------------------------------------------------

    def test(self):
        """
        TODO/TESTING: move this to a dedicated module/file

        just some misc stuff for testing the plugin...
        """
        return False
