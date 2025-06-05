"""KPNBoxAPI - Python API for KPN Box routers."""

from .client import KPNBoxAPI
from .exceptions import KPNBoxAPIError, AuthenticationError, ConnectionError

__version__ = "0.1.1"
__all__ = ["KPNBoxAPI", "KPNBoxAPIError", "AuthenticationError", "ConnectionError"] 