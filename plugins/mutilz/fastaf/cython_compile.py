import argparse
import sys
from pathlib import Path


def clean_build_files():
    """Remove generated C and HTML files from previous builds."""
    for pattern in ("*.c", "*.html"):
        for file in Path().glob(pattern):
            try:
                file.unlink()
            except FileNotFoundError:
                pass


def compile_cython(module_name: str, source_files: list, annotate: bool = True):
    """Compile a Cython module with the given parameters."""
    from Cython.Build import cythonize
    from setuptools import Extension, setup

    # Ensure compiled files are placed in the same directory as the source
    sys.argv = ["compile.py", "build_ext", "--inplace"]

    ext_modules = [Extension(module_name, source_files)]
    setup(name=module_name, ext_modules=cythonize(ext_modules, annotate=annotate))


def main():
    parser = argparse.ArgumentParser(description="Generic Cython compilation script.")
    parser.add_argument("module_name", help="Name of the module to compile")
    parser.add_argument(
        "source_files", nargs="+", help="List of source files for the module"
    )
    parser.add_argument(
        "--no-annotate", action="store_true", help="Disable Cython annotation"
    )

    args = parser.parse_args()

    clean_build_files()
    compile_cython(args.module_name, args.source_files, annotate=not args.no_annotate)


if __name__ == "__main__":
    main()
