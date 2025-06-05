"""Custom exceptions for KPNBoxAPI."""


class KPNBoxAPIError(Exception):
    """Base exception for KPNBoxAPI errors."""
    pass


class AuthenticationError(KPNBoxAPIError):
    """Raised when authentication fails."""
    pass


class ConnectionError(KPNBoxAPIError):
    """Raised when connection to the KPN Box fails."""
    pass


class APIError(KPNBoxAPIError):
    """Raised when API call returns an error."""
    
    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.status_code = status_code 