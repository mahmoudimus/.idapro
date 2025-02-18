r"""after digging into idapython3_64.dylib, it is possible to set an environment variable: IDAPYTHON_VENV_EXECUTABLE
This variable points to the venv python executable, then idapython will recognise the venv, and python packages in that venv will be found.

You can create an alias/script using Automator that would just be:

IDAPYTHON_VENV_EXECUTABLE=myvenvpath open -n /Applications/IDA.app

Another work around is in the $IDAUSER/idapythonrc.py file, you can override the sys.path variable.

You can set the idapythonrc.py content as the following:

import sys
sys.executable = "your_venv_py_interpreter"
import site
site.main()

then ida will find the venv python modules
"""

import os
import platform
import shlex
import subprocess


def init_sys_path():
    import sys

    sys.executable = os.path.expanduser("~/.pyenv/versions/idapro/bin/python")


def init_site():
    import site

    site.main()


def get_api_key(variable_name: str) -> str:
    """
    Retrieve an API key for the given variable name using a multi-stage evaluation strategy.

    The function performs the following steps:
      1. Environment Variable: Checks if the key exists as an environment variable.
      2. 1Password CLI: Uses the 1Password CLI (via 'op') to attempt retrieval with the path:
             "op://Private/{variable_name}/api key"
      3. macOS Keychain: If running on Darwin (macOS), uses the macOS Keychain to retrieve the key.

    Args:
        variable_name (str): The name or identifier of the API key to retrieve.

    Returns:
        str: The API key if found; otherwise, an empty string.
    """
    stages = [
        lambda var: os.environ.get(var),
        lambda var: _check_op(var),
        lambda var: _check_keychain(var),
    ]

    for stage in stages:
        key = stage(variable_name)
        if key:
            return key

    print(
        f"[WARNING] API key for '{variable_name}' not found in environment, 1Password, or macOS Keychain."
    )
    return ""


def _check_op(variable_name: str) -> str:
    """
    Attempt to retrieve the API key using the 1Password CLI in a shell environment
    appropriate for the current system.

    It builds an op query in the form of:
        op://Private/{variable_name}/api key

    On Darwin or Linux, the command is executed via a login shell (using the SHELL
    environment variable, defaulting to /bin/bash). On Windows, the command is executed
    via PowerShell.

    Args:
        variable_name (str): The key identifier used to form the 1Password path.

    Returns:
        str: The retrieved API key, or an empty string if not found.
    """
    key = ""
    op_path = f'"op://Private/{variable_name}/api key"'
    sys_platform = platform.system().lower()

    commands = []

    if sys_platform == "windows":
        # Build command for cmd.exe on Windows.
        commands.append(["cmd", "/c", f"op read {op_path}"])
        # If cmd is not found, try PowerShell on Windows
        commands.append(["powershell", "-Command", f"op read {op_path}"])
    elif sys_platform in ("darwin", "linux"):
        # Build command using a login shell on Darwin or Linux.
        login_shell = os.environ.get("SHELL", "/bin/bash")
        commands.append([login_shell, "-c", f"op read {op_path}"])
    else:
        # Build fallback command without specifying a shell.
        commands.append(["op", "read", op_path])

    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # If the op command failed, or the appropriate shell/binary is unavailable, try the next command.
            print(f"Error executing command: {command}. Exception: {e}")
            continue
        else:
            key = result.stdout.strip()
            break

    return key


def _check_keychain(variable_name: str) -> str:
    """
    Attempt to retrieve the API key from the macOS Keychain.

    This function only runs on macOS (Darwin). It looks up the key using the service name provided
    by the variable_name.

    Args:
        variable_name (str): The key used as the service name in Keychain.

    Returns:
        str: The API key if found, or an empty string otherwise.
    """
    if platform.system().lower() != "darwin":
        return ""

    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", variable_name, "-w"],
            capture_output=True,
            text=True,
            check=True,
        )
        key = result.stdout.strip()
        if key:
            return key
    except subprocess.CalledProcessError:
        # The Keychain item was not found.
        pass
    return ""


def configure_gepetto_api_keys():
    openai_api_key = get_api_key("OPENAI_API_KEY")
    if openai_api_key:
        os.environ["OPENAI_API_KEY"] = openai_api_key
    else:
        print("OpenAI API key not found. Gepetto may not function correctly.")


configure_gepetto_api_keys()
