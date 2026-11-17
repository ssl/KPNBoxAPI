"""Session handling shared by all KPNBoxAPI feature mixins."""

import logging
from types import TracebackType
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

import requests

from .exceptions import (
    APIError,
    AuthenticationError,
    KPNBoxConnectionError,
)

logger = logging.getLogger("kpnboxapi")

# Error code the router returns when the session context is no longer valid.
_PERMISSION_DENIED = 13

_Self = TypeVar("_Self", bound="KPNBoxBase")


class KPNBoxBase:
    """Authentication, request plumbing and response helpers."""

    def __init__(self, host: str = "192.168.2.254", timeout: int = 30):
        """
        Initialize the KPN Box API client.

        Args:
            host: IP address of the KPN Box (default: 192.168.2.254)
            timeout: Request timeout in seconds (default: 30)
        """
        self.host = host
        self.base_url = f"http://{host}"
        self.timeout = timeout
        self.session = requests.Session()
        self.context_id: Optional[str] = None
        self._username: Optional[str] = None
        self._password: Optional[str] = None

        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Origin": self.base_url,
                "Referer": f"{self.base_url}/",
                "Connection": "keep-alive",
            }
        )

    @property
    def _api_url(self) -> str:
        return f"{self.base_url}/ws/NeMo/Intf/lan:getMIBs"

    def login(self, username: str = "admin", password: str = "") -> bool:
        """
        Authenticate with the KPN Box.

        Args:
            username: Username (default: "admin")
            password: Password

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If authentication fails
            KPNBoxConnectionError: If unable to connect
        """
        login_data = {
            "service": "sah.Device.Information",
            "method": "createContext",
            "parameters": {
                "applicationName": "webui",
                "username": username,
                "password": password,
            },
        }

        headers = {
            "Content-Type": "application/x-sah-ws-4-call+js; charset=utf-8",
            "Authorization": "X-Sah-Login",
        }

        try:
            response = self.session.post(
                self._api_url, json=login_data, headers=headers, timeout=self.timeout
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise KPNBoxConnectionError(f"Failed to connect to KPN Box: {e}") from e

        try:
            data = response.json()
        except ValueError as e:
            raise AuthenticationError(f"Invalid response format: {e}") from e

        if not isinstance(data, dict) or data.get("status") != 0:
            status = data.get("status") if isinstance(data, dict) else data
            raise AuthenticationError(f"Login failed with status: {status}")

        context_id = (data.get("data") or {}).get("contextID")
        if not context_id:
            raise AuthenticationError("No context ID received from login response")
        self.context_id = context_id

        # Update session headers for authenticated requests
        self.session.headers.update(
            {
                "Content-Type": "application/x-sah-ws-4-call+json; charset=utf-8",
                "Authorization": f"X-Sah {context_id}",
                "X-Context": context_id,
            }
        )

        # Store credentials for automatic re-login when the session expires
        self._username = username
        self._password = password

        logger.debug("Logged in to %s as %s", self.host, username)
        return True

    def logout(self) -> None:
        """Forget the session context and the stored credentials."""
        self._clear_session()
        self._username = None
        self._password = None

    def close(self) -> None:
        """Log out and release the underlying HTTP connections."""
        self.logout()
        self.session.close()

    def _clear_session(self) -> None:
        self.context_id = None
        self.session.cookies.clear()
        self.session.headers.pop("Authorization", None)
        self.session.headers.pop("X-Context", None)

    def _make_api_call(
        self,
        service: str,
        method: str,
        parameters: Union[Dict[str, Any], str, None] = None,
        _retry: bool = True,
    ) -> Any:
        """Make an authenticated API call to the KPN Box with automatic session recovery.

        Raises:
            AuthenticationError: If login() has not been called
            KPNBoxConnectionError: If the router cannot be reached
            APIError: If the router answers with an HTTP error, an unreadable
                body, or refuses the call because the session expired
        """
        if not self.context_id:
            raise AuthenticationError("Not authenticated. Please call login() first.")

        data = {"service": service, "method": method, "parameters": parameters or {}}

        # Parameters are not logged: they can contain passwords.
        logger.debug("API call %s.%s", service, method)

        try:
            response = self.session.post(self._api_url, json=data, timeout=self.timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else None
            raise APIError(
                f"KPN Box returned HTTP {status_code} for {service}.{method}",
                status_code=status_code,
            ) from e
        except requests.exceptions.RequestException as e:
            raise KPNBoxConnectionError(f"Failed to make API call: {e}") from e

        try:
            result = response.json()
        except ValueError as e:
            raise APIError(f"Invalid response format: {e}") from e

        errors = result.get("errors") if isinstance(result, dict) else None
        if isinstance(errors, list) and errors:
            logger.debug("%s.%s returned errors: %s", service, method, errors)

            first = errors[0]
            if isinstance(first, dict) and first.get("error") == _PERMISSION_DENIED:
                return self._recover_session(service, method, parameters, _retry)

        return result

    def _recover_session(
        self,
        service: str,
        method: str,
        parameters: Union[Dict[str, Any], str, None],
        retry: bool,
    ) -> Any:
        """Re-login with the stored credentials and repeat the call once."""
        if not retry or self._username is None or self._password is None:
            raise APIError(f"Session expired. Permission denied for {service}")

        logger.info("Session expired, logging in again")
        self._clear_session()
        try:
            self.login(self._username, self._password)
        except AuthenticationError as e:
            raise APIError(
                f"Session expired and re-login failed. Permission denied for {service}"
            ) from e

        # _retry=False prevents an endless loop when the call itself is not permitted
        return self._make_api_call(service, method, parameters, _retry=False)

    @staticmethod
    def _has_errors(result: Any) -> bool:
        """True if the router reported errors for this call."""
        return isinstance(result, dict) and bool(result.get("errors"))

    @staticmethod
    def _status_dict(response: Any) -> Dict[str, Any]:
        """The ``status`` object of a response, or {} if it is missing or not an object."""
        status = response.get("status") if isinstance(response, dict) else None
        return status if isinstance(status, dict) else {}

    @staticmethod
    def _status_list(response: Any) -> List[Dict[str, Any]]:
        """The objects in a ``status`` list, or [] if ``status`` is not a list."""
        status = response.get("status") if isinstance(response, dict) else None
        if not isinstance(status, list):
            return []
        return [item for item in status if isinstance(item, dict)]

    @staticmethod
    def _status_str(response: Any, default: str = "") -> str:
        """A ``status`` string, or ``default`` if ``status`` is not a string."""
        status = response.get("status") if isinstance(response, dict) else None
        return status if isinstance(status, str) else default

    @staticmethod
    def _data_dict(response: Any) -> Dict[str, Any]:
        """The ``data`` object of a response, or {} if it is missing or not an object."""
        data = response.get("data") if isinstance(response, dict) else None
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _is_true(result: Any) -> bool:
        """For calls that answer ``{"status": true}`` on success."""
        return isinstance(result, dict) and result.get("status") == True  # noqa: E712

    @classmethod
    def _succeeded(cls, result: Any) -> bool:
        """For calls that answer ``null`` or ``{"status": null}`` on success.

        Anything counts as success except a reported error or ``status: false``.
        """
        if result is None:
            return True
        if not isinstance(result, dict):
            return False
        return not cls._has_errors(result) and result.get("status") is not False

    def __enter__(self: _Self) -> _Self:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Context manager exit - forget session data and close connections."""
        self.close()
