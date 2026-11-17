import pytest
import requests

from conftest import LOGIN, PERMISSION_DENIED
from kpnboxapi import KPNBoxConnectionError

MAC = "AA:BB:CC:DD:EE:FF"
ERRORS = {"status": None, "errors": [{"error": 1, "description": "nope"}]}

COMMANDS = [
    ("reboot_system", "NMC", "reboot", {"reason": "API reboot"}),
    ("factory_reset_system", "NMC", "reset", {"reason": "API reset"}),
    ("factory_reset_wifi", "NMC.Wifi", "wififactoryReset", {}),
    ("restart_home_network", "NMC.GroupFunction", "reboot", {"reason": "API reboot"}),
    (
        "factory_reset_home_network",
        "NMC.GroupFunction",
        "factoryReset",
        {"reason": "API reset"},
    ),
]


@pytest.mark.parametrize("name, service, method, parameters", COMMANDS)
def test_system_commands(router, api, name, service, method, parameters):
    router.on(service, method, {"status": None}, ERRORS)

    assert getattr(api, name)() is True
    assert router.calls_to(service, method) == [parameters]
    assert getattr(api, name)() is False


@pytest.mark.parametrize("name, service, method, parameters", COMMANDS)
def test_system_commands_do_not_hide_connection_loss(
    router, api, name, service, method, parameters
):
    router.on(service, method, requests.exceptions.ConnectionError("gone"))

    with pytest.raises(KPNBoxConnectionError):
        getattr(api, name)()


def test_change_password_is_used_for_the_next_automatic_login(router, api):
    router.on("UserManagement", "changePasswordSec", {"status": True})
    router.on("DeviceInfo", "get", PERMISSION_DENIED, {"status": {}})

    assert api.change_password("n3w-pass", "secret") is True
    api.get_device_info()

    assert router.calls_to(*LOGIN)[-1]["password"] == "n3w-pass"


def test_rejected_password_change_keeps_the_old_password(router, api):
    router.on("UserManagement", "changePasswordSec", {"status": False})

    assert api.change_password("n3w-pass", "wrong") is False
    assert api._password == "secret"
    with pytest.raises(ValueError):
        api.change_password("", "secret")


def test_set_ntp_servers(router, api):
    router.on("Time", "setNTPServers", {"status": None}, ERRORS)

    assert api.set_ntp_servers({"1": "time.kpn.net"}) is True
    assert api.set_ntp_servers({"1": "time.kpn.net"}) is False
    with pytest.raises(ValueError):
        api.set_ntp_servers({})


def sysinfo_events(attributes):
    return {
        "status": {
            "events": [
                {"data": {"object": {"reason": "cpu", "attributes": {}}}},
                {"data": {"object": {"reason": "sysinfo", "attributes": attributes}}},
            ]
        }
    }


def test_get_system_stats_detects_router_mac(router, api):
    router.on("Devices.Device.HGW", "get", {"status": {"Key": "aa-bb-cc-dd-ee-ff"}})
    router.on(
        "eventmanager",
        "get_events",
        sysinfo_events(
            {
                MAC: {
                    "totalram": 1000,
                    "freeram": 250,
                    "uptime": 90061,
                    "loadaverage_1min": 1500,
                    "procs": 42,
                }
            }
        ),
    )

    stats = api.get_system_stats()

    assert stats["device_mac"] == MAC
    assert stats["uptime_formatted"] == "1d 1h 1m"
    assert stats["memory"]["used_bytes"] == 750
    assert stats["memory"]["used_percentage"] == 75.0
    assert stats["load_average"]["1min"] == 1.5
    assert stats["processes"] == 42


@pytest.mark.parametrize(
    "reply",
    [
        {"status": None},
        {"status": {"events": []}},
        sysinfo_events({}),
        sysinfo_events(None),
    ],
)
def test_get_system_stats_without_sysinfo(router, api, reply):
    router.on("eventmanager", "get_events", reply)

    assert api.get_system_stats(MAC) == {}


def test_get_system_stats_needs_a_mac(router, api):
    router.on("Devices.Device.HGW", "get", {"status": {}})

    with pytest.raises(ValueError, match="auto-detect"):
        api.get_system_stats()


def test_get_system_stats_does_not_hide_connection_loss(router, api):
    router.on("eventmanager", "get_events", requests.exceptions.ConnectionError("gone"))

    with pytest.raises(KPNBoxConnectionError):
        api.get_system_stats(MAC)
