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

def init_sys_path():
    import sys

    sys.executable = os.path.expanduser("~/.pyenv/versions/idapro/bin/python")


def init_site():
    import site

    site.main()


init_sys_path()
init_site()

print("Hello world!")
