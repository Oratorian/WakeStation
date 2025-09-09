#!/usr/bin/env python3
"""!
********************************************************************************
@brief  Version and general information for WakeStation

@file   version.py
@author timounger ( https://github.com/timounger )
@modified by Mahesvara ( https://github.com/Oratorian )
@copyright timounger ( https://github.com/timounger )
********************************************************************************
"""

import os

# Get version from environment variables (set by CI/CD) or use defaults
VERSION_MAJOR = int(
    os.getenv("VERSION_MAJOR", "2")
)  # major changes/breaks at API (e.g incompatibility)
VERSION_MINOR = int(
    os.getenv("VERSION_MINOR", "7")
)  # minor changes/does not break the API (e.g new feature)
VERSION_PATCH = int(os.getenv("VERSION_PATCH", "1"))  # Bug fixes
VERSION_BUILD = int(os.getenv("VERSION_BUILD", "0"))  # build number (if available)


__title__ = "WakeStation"
__description__ = "WakeStation - Network Power Management Server"
__owner__ = "Mahesvara"
__copyright__ = f"©2025 {__owner__} Coding Co."
__internal_name__ = "WakeStation"
__company_name__ = f"{__owner__} Coding Co."


if VERSION_BUILD == 0:
    PRERELEASE_BUILD = False
    __version__ = f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}"
else:
    PRERELEASE_BUILD = True
    __version__ = f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}.{VERSION_BUILD}"
