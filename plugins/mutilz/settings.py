import configparser
import logging
import os
import pathlib
import typing

import idaapi
import idc

USER_IDADIR = pathlib.Path(idaapi.get_user_idadir())
USER_CFGDIR = USER_IDADIR / "cfg"
MUTILZ_CFG = USER_CFGDIR / "mutilz.cfg"
MUTILZ_JSON = USER_CFGDIR / "mutilz.json"
MUTILZ_TOML = USER_CFGDIR / "mutilz.toml"


class ActionSettings:
    """
    Provides access to configuration settings for a specific action,
    handling fallbacks to default values.
    """

    def __init__(
        self,
        action_name: str,
        config_parser: configparser.ConfigParser,
        config_path: pathlib.Path,
    ):
        self.action_name = action_name
        self._parser = config_parser
        self._config_path = config_path
        # Pre-calculate the merged settings dictionary on initialization
        self._settings_dict = self._merge_settings()

    def _merge_settings(self) -> typing.Dict[str, str]:
        """Merges default settings with action-specific settings."""
        # Start with defaults
        settings = dict(self._parser.defaults())
        # Override with action-specific settings if the section exists
        if self._parser.has_section(self.action_name):
            settings.update(self._parser.items(self.action_name))
        return settings

    def get(self, key: str, fallback: typing.Any = None) -> typing.Optional[str]:
        """Gets a setting value as a string."""
        return self._settings_dict.get(key, fallback)

    def get_log_level(self, key: str = "log_level", fallback: str = "INFO") -> int:
        level_name = self.get(key, fallback).upper()
        level_num = None
        try:
            # Use the recommended way to get the numeric level
            level_num = logging._checkLevel(level_name)
        except (ValueError, TypeError):
            # Invalid level name provided in config
            idc.warning(
                f"[mutilz] Invalid log level name '{level_name}' for [{self.action_name}] {key} in {self._config_path}. Using fallback: {fallback}"
            )
        
        if level_num is not None:
            return level_num
            
        # Return the numeric value of the fallback level name
        try:
            level_num = logging._checkLevel(fallback.upper())
        except ValueError:
            idc.msg(f"[mutilz] Internal error: Fallback log level '{fallback}' is invalid. Defaulting to INFO.")
            level_num = logging.INFO # Ultimate fallback
        
        return level_num

    def getboolean(self, key: str, fallback: bool = False) -> bool:
        """Gets a setting value as a boolean."""
        value_str = self._settings_dict.get(key)
        if value_str is None:
            return fallback
        try:
            # Use the parser's boolean conversion logic
            return self._parser._convert_to_boolean(value_str)
        except ValueError:
            idc.warning(
                f"[mutilz] Invalid boolean value for [{self.action_name}] {key}='{value_str}' in {self._config_path}. Using fallback: {fallback}"
            )
            return fallback

    def getint(self, key: str, fallback: int = 0) -> int:
        """Gets a setting value as an integer."""
        value_str = self._settings_dict.get(key)
        if value_str is None:
            return fallback
        try:
            return int(value_str)
        except ValueError:
            idc.warning(
                f"[mutilz] Invalid integer value for [{self.action_name}] {key}='{value_str}' in {self._config_path}. Using fallback: {fallback}"
            )
            return fallback

    def getfloat(self, key: str, fallback: float = 0.0) -> float:
        """Gets a setting value as a float."""
        value_str = self._settings_dict.get(key)
        if value_str is None:
            return fallback
        try:
            return float(value_str)
        except ValueError:
            idc.warning(
                f"[mutilz] Invalid float value for [{self.action_name}] {key}='{value_str}' in {self._config_path}. Using fallback: {fallback}"
            )
            return fallback

    def get_all(self) -> typing.Dict[str, str]:
        """Returns the merged dictionary of all settings for this action."""
        return self._settings_dict.copy()  # Return a copy

    def __contains__(self, key: str) -> bool:
        """Check if a key exists in the action's settings (including defaults)."""
        return key in self._settings_dict

    def __getitem__(self, key: str) -> str:
        """Direct dictionary-like access (raises KeyError if not found)."""
        return self._settings_dict[key]


class Settings:
    def __init__(self, config_path: pathlib.Path = MUTILZ_CFG):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self._load_config()
        self._ensure_defaults()

    def _load_config(self):
        if self.config_path.exists():
            try:
                with self.config_path.open("r") as fp:
                    self.config.read_file(fp)
            except Exception as e:
                idc.warning(
                    f"[mutilz] Failed to load settings from {self.config_path}: {e}"
                )

    def _ensure_defaults(self):
        updated = False
        # Check if default section exists, create if not
        if not self.config.has_section(configparser.DEFAULTSECT):
            # ConfigParser creates DEFAULT implicitly, but we ensure keys are there
            pass  # Not strictly needed as defaults{} handles it

        # Check for actions key in default section (example, can be extended)
        if not self.config.has_option(configparser.DEFAULTSECT, "actions"):
            self.config.set(configparser.DEFAULTSECT, "actions", "")
            updated = True

        self._write_if_updated(updated)

    # Removed from_cfg as it wasn't used and duplicated __init__ logic

    def _write_if_updated(self, updated: bool):
        if not updated:
            return

        try:
            USER_CFGDIR.mkdir(parents=True, exist_ok=True)
            with self.config_path.open("w+") as fp:
                self.config.write(fp)
            idc.msg(f"[mutilz] Updated settings file: {self.config_path}\n")
        except Exception as e:
            idc.warning(f"[mutilz] Failed to write settings to {self.config_path}: {e}")

    # --- Direct accessors retained for potential direct use ---
    def get(
        self, section: str, key: str, fallback: typing.Any = None
    ) -> typing.Optional[str]:
        """Gets a raw setting value as a string from a specific section."""
        return self.config.get(section, key, fallback=fallback)

    def getboolean(self, section: str, key: str, fallback: bool = False) -> bool:
        """Gets a setting value as a boolean from a specific section."""
        try:
            return self.config.getboolean(section, key, fallback=fallback)
        except ValueError:
            idc.warning(
                f"[mutilz] Invalid boolean value for [{section}] {key} in {self.config_path}. Using fallback: {fallback}"
            )
            return fallback

    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        """Gets a setting value as an integer from a specific section."""
        try:
            return self.config.getint(section, key, fallback=fallback)
        except ValueError:
            idc.warning(
                f"[mutilz] Invalid integer value for [{section}] {key} in {self.config_path}. Using fallback: {fallback}"
            )
            return fallback

    # --- Action-specific settings access ---
    def get_action_settings(self, action_name: str) -> ActionSettings:
        """
        Returns an ActionSettings object providing access to the
        merged configuration for the given action.
        """
        return ActionSettings(action_name, self.config, self.config_path)

    # Deprecated? get_action_setting might be less useful now, but keep for backward compatibility or specific cases
    def get_action_setting(
        self,
        action_name: str,
        key: str,
        fallback: typing.Any = None,
        type_converter: typing.Callable = str,
    ) -> typing.Any:
        """
        Retrieves a single setting for a specific action, applies type conversion.
        (Consider using get_action_settings(action_name).getboolean(...) etc. instead)
        """
        action_cfg = self.get_action_settings(action_name)
        value_str = action_cfg.get(key)

        if value_str is None:
            return fallback

        try:
            if type_converter == bool:
                # Use the ActionSettings helper which uses the parser's conversion
                return action_cfg.getboolean(
                    key, fallback=isinstance(fallback, bool) and fallback
                )
            elif type_converter == int:
                return action_cfg.getint(
                    key, fallback=isinstance(fallback, int) and fallback
                )
            elif type_converter == float:
                return action_cfg.getfloat(
                    key, fallback=isinstance(fallback, float) and fallback
                )
            else:
                # For str or other types
                return type_converter(value_str)
        except (ValueError, TypeError) as e:
            idc.warning(
                f"[mutilz] Failed to convert setting [{action_name}] {key}='{value_str}' using {type_converter.__name__}: {e}. Using fallback: {fallback}"
            )
            return fallback


# --- Global Instance and Accessor Function ---

# Global settings instance, loaded once.
_global_settings = Settings()


def reload():
    _global_settings._load_config()


def get_action_config(action_name: str) -> ActionSettings:
    """
    Retrieves the configuration settings specific to an action.

    Args:
        action_name: The name of the action (should match the section name in mutilz.cfg).

    Returns:
        An ActionSettings object for accessing the action's configuration.
    """
    return _global_settings.get_action_settings(action_name)


# Example usage (in another module):
# import mutilz.settings
#
# action_cfg = mutilz.settings.get_action_config('my_action')
# debug_enabled = action_cfg.getboolean('enable_debug_logging', fallback=False)
# max_items = action_cfg.getint('max_items_to_process', fallback=100)
# api_key = action_cfg.get('api_key') # Returns string or None
# if 'some_feature_flag' in action_cfg:
#    print("Feature flag is set")
