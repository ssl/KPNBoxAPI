"""KPNBoxAPI - Python API for KPN Box routers."""

from importlib.metadata import PackageNotFoundError, version

from .client import KPNBoxAPI
from .exceptions import (
    APIError,
    AuthenticationError,
    ConnectionError,
    KPNBoxAPIError,
    KPNBoxConnectionError,
)

try:
    __version__ = version("kpnboxapi")
except PackageNotFoundError:  # running from a source checkout that is not installed
    __version__ = "0.0.0"

__all__ = [
    "KPNBoxAPI",
    "KPNBoxAPIError",
    "AuthenticationError",
    "KPNBoxConnectionError",
    "ConnectionError",
    "APIError",
]
