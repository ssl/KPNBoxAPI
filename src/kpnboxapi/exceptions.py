"""Custom exceptions for KPNBoxAPI."""

from typing import Optional


class KPNBoxAPIError(Exception):
    """Base exception for KPNBoxAPI errors."""


class AuthenticationError(KPNBoxAPIError):
    """Raised when authentication fails."""


class KPNBoxConnectionError(KPNBoxAPIError):
    """Raised when the KPN Box cannot be reached (network error, timeout)."""


# Backwards compatible name. It shadows the Python builtin when imported with
# ``from kpnboxapi import ConnectionError``; prefer ``KPNBoxConnectionError``.
ConnectionError = KPNBoxConnectionError


class APIError(KPNBoxAPIError):
    """Raised when the KPN Box answers, but with an error."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code
