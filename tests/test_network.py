import pytest
import requests

from kpnboxapi import APIError, KPNBoxConnectionError

ERRORS = {
    "status": None,
    "errors": [{"error": 196618, "description": "Object not found"}],
}


def test_get_all_network_stats_marks_missing_interfaces(router, api):
    for name in ("ETH0", "ETH1", "eth4", "ppp_vdata"):
        router.on(f"NeMo.Intf.{name}", "getNetDevStats", {"status": {"RxBytes": 1}})
    router.on("NeMo.Intf.ETH2", "getNetDevStats", ERRORS)
    router.on("NeMo.Intf.ETH3", "getNetDevStats", (404, "not found"))

    stats = api.get_all_network_stats()

    assert stats["ETH0"] == {"RxBytes": 1, "Interface": "ETH0"}
    assert stats["ETH2"] == {"Interface": "ETH2", "Available": False}
    assert stats["ETH3"] == {"Interface": "ETH3", "Available": False}


def test_get_all_network_stats_does_not_hide_connection_loss(router, api):
    router.on(
        "NeMo.Intf.ETH0", "getNetDevStats", requests.exceptions.ConnectionError("gone")
    )

    with pytest.raises(KPNBoxConnectionError):
        api.get_all_network_stats()


def test_is_connected(router, api):
    router.on(
        "NMC",
        "getWANStatus",
        {"data": {"ConnectionState": "Connected"}},
        {"status": False},
    )

    assert api.is_connected() is True


def test_set_port4_guest_network_moves_port_between_bridges(router, api):
    router.on("NetMaster.LAN.default.Bridge.lan", "removeIntf", {"status": None})
    router.on("NetMaster.LAN.default.Bridge.guest", "addIntf", {"status": None})

    assert api.enable_port4_guest_network() is True
    assert [(c["service"], c["method"]) for c in router.calls[1:]] == [
        ("NetMaster.LAN.default.Bridge.lan", "removeIntf"),
        ("NetMaster.LAN.default.Bridge.guest", "addIntf"),
    ]


def test_set_port4_guest_network_fails_when_a_step_reports_errors(router, api):
    router.on("NetMaster.LAN.default.Bridge.guest", "removeIntf", {"status": None})
    router.on("NetMaster.LAN.default.Bridge.lan", "addIntf", ERRORS)

    assert api.disable_port4_guest_network() is False


def test_set_lan_ipv4_config_keeps_current_values(router, api):
    router.on(
        "NetMaster.LAN.default.Bridge.lan",
        "getIPv4",
        {
            "status": {
                "Address": "192.168.2.254",
                "DHCPEnable": True,
                "DHCPMinAddress": "192.168.2.100",
                "DHCPMaxAddress": "192.168.2.200",
                "PrefixLength": 24,
                "DNSServers": "",
            }
        },
    )
    router.on("NetMaster.LAN.default.Bridge.lan", "setIPv4", {"status": None}, ERRORS)

    assert api.set_lan_ipv4_config(dns_servers="9.9.9.9") is True
    (params,) = router.calls_to("NetMaster.LAN.default.Bridge.lan", "setIPv4")
    assert params["DNSServers"] == "9.9.9.9"
    assert params["Address"] == "192.168.2.254"

    assert api.set_lan_ipv4_config(dns_servers="9.9.9.9") is False


def test_add_dyndns_host_raises_with_router_description(router, api):
    router.on(
        "DynDNS",
        "addHost",
        {
            "status": False,
            "errors": [{"error": 1, "description": "Invalid service", "info": "foo"}],
        },
    )

    with pytest.raises(APIError, match="Invalid service"):
        api.add_dyndns_host("foo", "user", "host.example.com", "pw")


def test_manage_dyndns_service_validates_arguments(router, api):
    with pytest.raises(ValueError):
        api.manage_dyndns_service("add", "host.example.com", service="dyndns")
    with pytest.raises(ValueError):
        api.manage_dyndns_service("rename", "host.example.com")
    assert len(router.calls) == 1  # only the login


def test_ipv6_prefix_delegation_off(router, api):
    router.on(
        "NetMaster.LAN.default.Bridge.lan", "setIPv6Configuration", {"status": None}
    )
    router.on("NetMaster", "set", {"status": True})

    assert api.disable_ipv6_prefix_delegation() is True
    assert router.calls_to("NetMaster", "set") == [
        {"EnableIPv6": 1, "IPv6PrefixMode": "DHCPv6"}
    ]
