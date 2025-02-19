import pathlib

import pyximport

__BUILD_DIR__ = str(pathlib.Path(__file__).parent / ".pyxbuild")


pyximport.install(pyimport=True, language_level=3, build_dir=__BUILD_DIR__)
