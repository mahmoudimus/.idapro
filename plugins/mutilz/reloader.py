"""
This module is modified but most of the code was shamelessly taken from:

- @gaasedelen's lucid plugin (https://github.com/gaasedelen/lucid)
- @thalium's symless plugin (https://github.com/thalium/symless)

"""

import importlib
import inspect
import sys
import types
import weakref

# ------------------------------------------------------------------------------
# Python Callback / Signals
# ------------------------------------------------------------------------------


def register_callback(callback_list, callback):
    """
    Register a callable function to the given callback_list.

    Adapted from http://stackoverflow.com/a/21941670
    """

    # create a weakref callback to an object method
    try:
        callback_ref = weakref.ref(callback.__func__), weakref.ref(callback.__self__)

    # create a wweakref callback to a stand alone function
    except AttributeError:
        callback_ref = weakref.ref(callback), None

    # 'register' the callback
    callback_list.append(callback_ref)


def notify_callback(callback_list, *args):
    """
    Notify the given list of registered callbacks of an event.

    The given list (callback_list) is a list of weakref'd callables
    registered through the register_callback() function. To notify the
    callbacks of an event, this function will simply loop through the list
    and call them.

    This routine self-heals by removing dead callbacks for deleted objects as
    it encounters them.

    Adapted from http://stackoverflow.com/a/21941670
    """
    cleanup = []

    #
    # loop through all the registered callbacks in the given callback_list,
    # notifying active callbacks, and removing dead ones.
    #

    for callback_ref in callback_list:
        callback, obj_ref = callback_ref[0](), callback_ref[1]

        #
        # if the callback is an instance method, deference the instance
        # (an object) first to check that it is still alive
        #

        if obj_ref:
            obj = obj_ref()

            # if the object instance is gone, mark this callback for cleanup
            if obj is None:
                cleanup.append(callback_ref)
                continue

            # call the object instance callback
            try:
                callback(obj, *args)

            # assume a Qt cleanup/deletion occurred
            except RuntimeError as e:
                cleanup.append(callback_ref)
                continue

        # if the callback is a static method...
        else:

            # if the static method is deleted, mark this callback for cleanup
            if callback is None:
                cleanup.append(callback_ref)
                continue

            # call the static callback
            callback(*args)

    # remove the deleted callbacks
    for callback_ref in cleanup:
        callback_list.remove(callback_ref)


# ------------------------------------------------------------------------------
# Module Reloading
# ------------------------------------------------------------------------------


def reload_package(target_module):
    """
    Recursively reload a 'stateless' python module / package.
    """
    target_name = target_module.__name__
    visited_modules = {target_name: target_module}
    _recursive_reload(target_module, target_name, visited_modules)


def _recursive_reload(module, target_name, visited):
    ignore = [
        "__builtins__",
        "__cached__",
        "__doc__",
        "__file__",
        "__loader__",
        "__name__",
        "__package__",
        "__spec__",
        "__path__",
    ]

    visited[module.__name__] = module

    for attribute_name in dir(module):

        # skip the stuff we don't care about
        if attribute_name in ignore:
            continue

        if attribute_name.startswith("ida_") or attribute_name == "idc":
            # skip ida builtins!
            continue

        attribute_value = getattr(module, attribute_name)

        if type(attribute_value) == types.ModuleType:
            attribute_module_name = attribute_value.__name__
            attribute_module = attribute_value
            # print("Found module %s" % attribute_module_name)
        elif callable(attribute_value):
            attribute_module_name = attribute_value.__module__
            attribute_module = sys.modules[attribute_module_name]
            # print("Found callable...", attribute_name)
        elif (
            isinstance(attribute_value, dict)
            or isinstance(attribute_value, list)
            or isinstance(attribute_value, int)
        ):
            # print("TODO: should probably try harder to reload this...", attribute_name, type(attribute_value))
            continue
        else:
            print("UNKNOWN TYPE TO RELOAD", attribute_name, type(attribute_value))
            raise ValueError("OH NOO RELOADING IS HARD")

        if target_name not in attribute_module_name:
            # print(" - Not a module of interest...")
            continue

        if "__plugins__" in attribute_module_name:
            # print(" - Skipping IDA base plugin module...")
            continue

        if attribute_module_name in visited:
            continue

        # print("going down...")
        _recursive_reload(attribute_module, target_name, visited)

    # print("Okay done with %s, reloading self!" % module.__name__)
    importlib.reload(module)


# reload one module, by first reloading all imports from that module
# to_reload contains all modules to reload
def reload_module(module, to_reload: set):
    if module not in to_reload:
        return

    # remove from set first, avoid infinite recursion if recursive imports
    to_reload.remove(module)

    # reload all imports first
    for _, dep in inspect.getmembers(module, lambda k: inspect.ismodule(k)):
        reload_module(dep, to_reload)

    # reload the module
    print(f"Reloading {module.__name__} ..")
    importlib.reload(module)


# reload all code
def reload_plugin():
    # list all modules to reload, unordered
    to_reload = set()
    for k, mod in sys.modules.items():
        if k.startswith("mutilz"):
            to_reload.add(mod)

    for mod in list(to_reload):  # copy to alter
        reload_module(mod, to_reload)
