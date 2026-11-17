"""No public method may crash on an unexpected answer from the router.

Every method is called against a router that answers each call with the same
awkward payload. Only the library's own exceptions and ValueError are allowed.
"""

import inspect
import json

import pytest
import responses

from conftest import HOST, URL
from kpnboxapi import KPNBoxAPI, KPNBoxAPIError

MAC = "AA:BB:CC:DD:EE:FF"

PAYLOADS = {
    "null-status": {"status": None},
    "true": {"status": True},
    "false": {"status": False},
    "errors": {"status": None, "errors": [{"error": 196618, "description": "x"}]},
    "false+errors": {"status": False, "errors": [{"error": 1, "description": "x"}]},
    "empty-object": {"status": {}},
    "empty-list": {"status": []},
    "string": {"status": "abc"},
    "number": {"status": 5},
    "null-data": {"data": None, "status": None},
    "junk-object": {
        "status": {"wlanvap": None, "default": None, "guest": [], "ppp": "x"}
    },
    "junk-list": {"status": [None, 1, "x", {}]},
    "empty-body": {},
    "top-level-list": [],
    "top-level-null": None,
}

# Arguments by parameter name; anything else is derived from the annotation.
ARGUMENTS = {
    "mac_address": MAC,
    "device_mac": MAC,
    "device_identifier": MAC,
    "mac_addresses": [MAC],
    "ip_address": "192.168.2.10",
    "destination_ip": "192.168.2.10",
    "servers": {"1": "time.kpn.net"},
    "action": "add",
    "control_type": "daily_limits",
    "protocol": "6",
}

METHODS = sorted(
    name
    for name, member in inspect.getmembers(KPNBoxAPI, inspect.isfunction)
    if not name.startswith("_") and name not in ("login", "logout", "close")
)


def required_arguments(method):
    arguments = {}
    for name, parameter in inspect.signature(method).parameters.items():
        if parameter.default is not parameter.empty or parameter.kind in (
            parameter.VAR_KEYWORD,
            parameter.VAR_POSITIONAL,
        ):
            continue
        if name in ARGUMENTS:
            arguments[name] = ARGUMENTS[name]
        elif "port" in name:
            arguments[name] = "80"
        elif "int" in str(parameter.annotation):
            arguments[name] = 1
        else:
            arguments[name] = "x"
    return arguments


@pytest.fixture(params=sorted(PAYLOADS))
def awkward_api(request):
    payload = PAYLOADS[request.param]

    def answer(http_request):
        if json.loads(http_request.body)["method"] == "createContext":
            return 200, {}, json.dumps({"status": 0, "data": {"contextID": "ctx"}})
        return 200, {}, json.dumps(payload)

    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        mock.add_callback(responses.POST, URL, callback=answer)
        client = KPNBoxAPI(host=HOST)
        client.login("admin", "secret")
        yield client


def test_methods_do_not_crash_on_awkward_answers(awkward_api):
    crashes = []
    for name in METHODS:
        method = getattr(awkward_api, name)
        try:
            method(**required_arguments(method))
        except (ValueError, KPNBoxAPIError):
            pass
        except Exception as e:  # noqa: BLE001 - collecting every crash is the point
            crashes.append(f"{name}: {type(e).__name__}: {e}")

    assert crashes == []


@pytest.mark.parametrize(
    "name, expected",
    [
        ("get_wan_status", {}),
        ("get_lan_ipv4_config", {}),
        ("get_hgw_device_info", {}),
        ("get_wifi_status", {}),
        ("get_voice_trunks", []),
        ("get_dyndns_hosts", []),
        ("get_ntp_servers", {}),
        ("get_router_time", ""),
        ("get_public_ipv6", ""),
        ("get_iptv_ip", ""),
        ("get_firewall_level", "Unknown"),
        ("is_connected", False),
        ("get_dns_servers", {"ipv4": "", "ipv6": ""}),
    ],
)
def test_getters_return_an_empty_value_of_the_documented_type(
    router, api, name, expected
):
    error = {
        "status": None,
        "errors": [{"error": 196618, "description": "Object not found"}],
    }
    for service_method in [
        ("NMC", "getWANStatus"),
        ("NetMaster.LAN.default.Bridge.lan", "getIPv4"),
        ("NetMaster.LAN.default.Bridge.lan", "getIPv6Configuration"),
        ("Devices.Device.HGW", "get"),
        ("NMC.Wifi", "get"),
        ("VoiceService.VoiceApplication", "listTrunks"),
        ("DynDNS", "getHosts"),
        ("Time", "getNTPServers"),
        ("Time", "getTime"),
        ("NeMo.Intf.data", "luckyAddrAddress"),
        ("NeMo.Intf.iptv", "luckyAddrAddress"),
        ("Firewall", "getFirewallLevel"),
    ]:
        router.on(*service_method, error)

    assert getattr(api, name)() == expected


def test_get_device_schedule_is_false_without_schedule(router, api):
    router.on(
        "Scheduler", "getSchedule", {"status": False}, {"status": {"enable": True}}
    )

    assert api.get_device_schedule(MAC) is False
    assert api.get_device_schedule(MAC) == {"enable": True}
