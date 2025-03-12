import pathlib
import platform

import pyximport

__BUILD_DIR__ = str(pathlib.Path(__file__).parent / ".pyxbuild")
if platform.system() == "Windows":
    __BUILD_DIR__ = None

pyximport.install(
    pyimport=True, language_level=3, build_dir=__BUILD_DIR__, inplace=True
)
