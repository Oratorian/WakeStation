#!/usr/bin/env python3
"""!
********************************************************************************
@file   gen_version.py
@brief  Utility script to create version info files for PyInstaller executables
@author timounger ( https://github.com/timounger )
@modified by Mahesvara ( https://github.com/Oratorian )
@copyright timounger ( https://github.com/timounger )
********************************************************************************
"""

# autopep8: off
import sys
import os
import logging

from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo,
    FixedFileInfo,
    StringFileInfo,
    StringTable,
    StringStruct,
    VarFileInfo,
    VarStruct,
)

# Import all version information from version.py
from version import (
    VERSION_MAJOR,
    VERSION_MINOR,
    VERSION_PATCH,
    VERSION_BUILD,
    __company_name__,
    __title__,
    __description__,
    __version__,
    __copyright__,
    __internal_name__,
)

log = logging.getLogger("GenerateVersionFile")
# autopep8: on


def create_version_info(app_description=None, filename=None, product_name=None):
    """Create version info using values from version.py with optional overrides for shutdown daemon"""
    # Use values from version.py with shutdown daemon specific defaults
    final_description = app_description or __description__
    final_filename = filename or f"{__title__}.exe"
    final_product_name = product_name or __title__

    return VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_BUILD),
            prodvers=(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_BUILD),
            mask=0x3F,
            flags=0x0,
            OS=0x40004,  # Match the existing format exactly
            fileType=0x1,
            subtype=0x0,
            date=(0, 0),
        ),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",  # Match existing format (no u prefix)
                        [
                            StringStruct("CompanyName", __company_name__),
                            StringStruct("FileDescription", final_description),
                            StringStruct("FileVersion", __version__),
                            StringStruct("InternalName", __internal_name__),
                            StringStruct("LegalCopyright", __copyright__),
                            StringStruct("OriginalFilename", final_filename),
                            StringStruct("ProductName", final_product_name),
                            StringStruct("ProductVersion", __version__),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )


# Default version info (for backward compatibility)
versionInfo = create_version_info()


def generate_version_file(s_filename: str, s_workpath: str, version_info=None) -> None:
    """!
    @brief Generate version file
    @param s_filename : version file name
    @param s_workpath : workpath
    @param version_info : VSVersionInfo object to write (defaults to versionInfo)
    """
    if version_info is None:
        version_info = versionInfo

    s_version_file = os.path.join(s_workpath, s_filename)
    log.info("Generate version file %s (Version: %s)", s_version_file, __version__)
    if not os.path.exists(s_workpath):
        os.makedirs(s_workpath)
    else:
        log.info("Directory %s already exists", s_workpath)
    with open(s_version_file, mode="w", encoding="utf-8") as version_file:
        version_file.write(str(version_info))


def generate_gui_version_file(workpath: str) -> None:
    """Generate version file for GUI version - uses base description from version.py"""
    gui_version_info = create_version_info(filename="shutdown_daemon.exe")
    filename = "version_info.txt"
    generate_version_file(filename, workpath, gui_version_info)


def generate_cli_version_file(workpath: str) -> None:
    """Generate version file for CLI version"""
    cli_version_info = create_version_info(
        app_description=f"{__description__} (CLI)",  # Append CLI to the base description
        filename="shutdown_daemon-cli.exe",
    )
    filename = "version_info_cli.txt"
    generate_version_file(filename, workpath, cli_version_info)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate version info files for PyInstaller"
    )
    parser.add_argument("workpath", help="Output directory for version files")
    parser.add_argument(
        "--type",
        choices=["gui", "cli", "both"],
        default="both",
        help="Type of version file to generate",
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.type in ["gui", "both"]:
        generate_gui_version_file(args.workpath)

    if args.type in ["cli", "both"]:
        generate_cli_version_file(args.workpath)

    sys.exit()
