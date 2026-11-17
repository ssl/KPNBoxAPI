import logging

import pytest
import requests

import kpnboxapi
from conftest import HOST, LOGIN, PERMISSION_DENIED
from kpnboxapi import (
    APIError,
    AuthenticationError,
    KPNBoxAPI,
    KPNBoxAPIError,
    KPNBoxConnectionError,
)


def test_public_exports():
    assert kpnboxapi.ConnectionError is KPNBoxConnectionError
    assert issubclass(APIError, KPNBoxAPIError)
    assert set(kpnboxapi.__all__) <= set(dir(kpnboxapi))
    assert kpnboxapi.__version__


def test_login_stores_context_and_sends_credentials(router, api):
    assert api.context_id == "ctx-1"
    assert api.session.headers["Authorization"] == "X-Sah ctx-1"
    assert api.session.headers["X-Context"] == "ctx-1"

    assert router.calls_to(*LOGIN) == [
        {"applicationName": "webui", "username": "admin", "password": "secret"}
    ]
    login_request = router.requests[0]
    assert login_request.headers["Authorization"] == "X-Sah-Login"
    assert int(login_request.headers["Content-Length"]) == len(login_request.body)


@pytest.mark.parametrize(
    "reply",
    [
        {"status": 1},
        {"status": 0, "data": {}},
        {"status": 0},
        (200, "<html>not json</html>"),
        ["unexpected"],
    ],
)
def test_login_rejected(router, reply):
    router.on(*LOGIN, reply)
    client = KPNBoxAPI(host=HOST)

    with pytest.raises(AuthenticationError):
        client.login("admin", "wrong")
    assert client.context_id is None


@pytest.mark.parametrize(
    "reply", [requests.exceptions.ConnectTimeout("timed out"), (500, "boom")]
)
def test_login_unreachable(router, reply):
    router.on(*LOGIN, reply)

    with pytest.raises(KPNBoxConnectionError) as excinfo:
        KPNBoxAPI(host=HOST).login()
    assert excinfo.value.__cause__ is not None


def test_call_requires_login(router):
    with pytest.raises(AuthenticationError):
        KPNBoxAPI(host=HOST).get_device_info()
    assert router.calls == []


def test_expired_session_logs_in_again_and_retries(router, api):
    router.on(*LOGIN, {"status": 0, "data": {"contextID": "ctx-2"}})
    router.on(
        "DeviceInfo", "get", PERMISSION_DENIED, {"status": {"ModelName": "Box 14"}}
    )

    assert api.get_device_info() == {"ModelName": "Box 14"}
    assert api.context_id == "ctx-2"
    assert router.requests[-1].headers["X-Context"] == "ctx-2"
    assert len(router.calls_to(*LOGIN)) == 2


def test_permission_denied_after_relogin_is_not_retried_forever(router, api):
    router.on("DeviceInfo", "get", PERMISSION_DENIED)

    with pytest.raises(APIError, match="Session expired"):
        api.get_device_info()
    assert len(router.calls_to("DeviceInfo", "get")) == 2


def test_failed_relogin_keeps_the_cause(router, api):
    router.on(*LOGIN, {"status": 1})
    router.on("DeviceInfo", "get", PERMISSION_DENIED)

    with pytest.raises(APIError, match="re-login failed") as excinfo:
        api.get_device_info()
    assert isinstance(excinfo.value.__cause__, AuthenticationError)


def test_http_error_is_an_api_error_with_status_code(router, api):
    router.on("DeviceInfo", "get", (500, "Internal Server Error"))

    with pytest.raises(APIError) as excinfo:
        api.get_device_info()
    assert excinfo.value.status_code == 500


def test_network_failure_is_a_connection_error(router, api):
    router.on("DeviceInfo", "get", requests.exceptions.ConnectionError("no route"))

    with pytest.raises(KPNBoxConnectionError):
        api.get_device_info()


def test_unreadable_body_is_an_api_error(router, api):
    router.on("DeviceInfo", "get", (200, "<html>"))

    with pytest.raises(APIError, match="Invalid response format"):
        api.get_device_info()


def test_context_manager_forgets_session_and_credentials(router):
    with KPNBoxAPI(host=HOST) as client:
        client.login("admin", "secret")

    assert client.context_id is None
    assert client._password is None
    assert "Authorization" not in client.session.headers
    with pytest.raises(AuthenticationError):
        client.get_device_info()


def test_passwords_are_not_logged(router, api, caplog):
    router.on("UserManagement", "changePasswordSec", {"status": True})

    with caplog.at_level(logging.DEBUG, logger="kpnboxapi"):
        api.change_password("n3w-pass", "secret")

    assert "UserManagement.changePasswordSec" in caplog.text
    assert "n3w-pass" not in caplog.text
    assert "secret" not in caplog.text


def test_connection_loss_during_relogin_is_a_connection_error(router, api):
    router.on(*LOGIN, requests.exceptions.ConnectionError("gone"))
    router.on("DeviceInfo", "get", PERMISSION_DENIED)

    with pytest.raises(KPNBoxConnectionError):
        api.get_device_info()
