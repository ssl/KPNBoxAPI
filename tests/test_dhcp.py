import pytest
import requests

from kpnboxapi import APIError, KPNBoxConnectionError

POOL = {
    "status": {
        "default": {"MinAddress": "192.168.2.100", "MaxAddress": "192.168.2.104"}
    }
}
STATIC = {
    "status": [
        {"IPAddress": "192.168.2.100", "MACAddress": "AA:AA:AA:AA:AA:01"},
        {"IPAddress": "192.168.2.250", "MACAddress": "AA:AA:AA:AA:AA:02"},
    ]
}
LEASES = {
    "status": {
        "default": {
            "1": {
                "IPAddress": "192.168.2.102",
                "MACAddress": "AA:AA:AA:AA:AA:03",
                "Active": True,
            },
            "2": {
                "IPAddress": "192.168.2.103",
                "MACAddress": "AA:AA:AA:AA:AA:04",
                "Active": False,
            },
        }
    }
}


@pytest.fixture
def dhcp(router):
    router.on("DHCPv4.Server", "getDHCPServerPool", POOL)
    router.on("DHCPv4.Server.Pool.default", "getStaticLeases", STATIC)
    router.on("DHCPv4.Server.Pool.default", "getLeases", LEASES)


def test_get_dhcp_server(router, api, dhcp):
    assert api.get_dhcp_server() == {
        "MinAddress": "192.168.2.100",
        "MaxAddress": "192.168.2.104",
        "PoolID": "default",
    }
    with pytest.raises(ValueError):
        api.get_dhcp_server("lan")


def test_get_dhcp_server_with_error_response_returns_pool_id_only(router, api):
    router.on(
        "DHCPv4.Server", "getDHCPServerPool", {"status": None, "errors": [{"error": 1}]}
    )

    assert api.get_dhcp_server() == {"PoolID": "default"}


def test_add_static_lease(router, api):
    router.on("DHCPv4.Server.Pool.default", "addStaticLease", {"status": None})

    assert api.add_static_lease("AA:AA:AA:AA:AA:01", "192.168.2.150") is True
    assert router.calls_to("DHCPv4.Server.Pool.default", "addStaticLease") == [
        {"MACAddress": "AA:AA:AA:AA:AA:01", "IPAddress": "192.168.2.150"}
    ]


def test_add_static_lease_reports_router_errors(router, api):
    router.on(
        "DHCPv4.Server.Pool.default",
        "addStaticLease",
        {"status": None, "errors": [{"error": 393221, "description": "IP in use"}]},
    )

    assert api.add_static_lease("AA:AA:AA:AA:AA:01", "192.168.2.150") is False


@pytest.mark.parametrize(
    "mac, ip",
    [("AAAAAAAAAAAA", "192.168.2.150"), ("AA:AA:AA:AA:AA:01", "192.168.2.999")],
)
def test_add_static_lease_validates_input(router, api, mac, ip):
    with pytest.raises(ValueError):
        api.add_static_lease(mac, ip)
    assert len(router.calls) == 1  # only the login


def test_suggest_available_ips_skips_reserved_and_active_addresses(router, api, dhcp):
    assert api.suggest_available_ips(count=5) == [
        "192.168.2.101",
        "192.168.2.103",
        "192.168.2.104",
    ]
    assert api.suggest_available_ips(count=1) == ["192.168.2.101"]


def test_suggest_available_ips_does_not_guess_without_a_range(router, api, dhcp):
    router.on("DHCPv4.Server", "getDHCPServerPool", {"status": {"default": {}}})

    with pytest.raises(APIError, match="DHCP range"):
        api.suggest_available_ips()


def test_suggest_available_ips_does_not_hide_connection_loss(router, api):
    router.on(
        "DHCPv4.Server", "getDHCPServerPool", requests.exceptions.ReadTimeout("slow")
    )

    with pytest.raises(KPNBoxConnectionError):
        api.suggest_available_ips()


def test_get_device_ip_reservation_matches_case_insensitively(router, api, dhcp):
    reservation = api.get_device_ip_reservation("aa:aa:aa:aa:aa:01")

    assert reservation["ip_address"] == "192.168.2.100"
    assert reservation["IPAddress"] == "192.168.2.100"
    assert api.get_device_ip_reservation("AA:AA:AA:AA:AA:99") == {}


def test_list_ip_reservations_adds_device_info(router, api, dhcp):
    router.on(
        "Devices.Device.lan",
        "topology",
        {
            "status": [
                {
                    "Name": "nas",
                    "PhysAddress": "AA:AA:AA:AA:AA:01",
                    "Active": True,
                    "DeviceType": "NAS",
                },
            ]
        },
    )
    router.on("Scheduler", "getSchedule", {"status": False})

    known, unknown = api.list_ip_reservations()

    assert (known["device_name"], known["ip_address"], known["active"]) == (
        "nas",
        "192.168.2.100",
        True,
    )
    assert (unknown["device_name"], unknown["mac_address"]) == (
        "Unknown Device",
        "AA:AA:AA:AA:AA:02",
    )


def test_list_ip_reservations_without_device_info_makes_one_call(router, api, dhcp):
    reservations = api.list_ip_reservations(include_device_info=False)

    assert [r["ip_address"] for r in reservations] == ["192.168.2.100", "192.168.2.250"]
    assert len(router.calls) == 2  # login + getStaticLeases


def test_cleanup_invalid_reservations_finds_out_of_range_and_duplicates(
    router, api, dhcp
):
    router.on(
        "DHCPv4.Server.Pool.default",
        "getStaticLeases",
        {
            "status": [
                {"IPAddress": "192.168.2.100", "MACAddress": "AA:AA:AA:AA:AA:01"},
                {"IPAddress": "192.168.2.100", "MACAddress": "AA:AA:AA:AA:AA:02"},
                {"IPAddress": "192.168.2.250", "MACAddress": "AA:AA:AA:AA:AA:03"},
                {"IPAddress": "bogus", "MACAddress": "AA:AA:AA:AA:AA:04"},
            ]
        },
    )

    result = api.cleanup_invalid_reservations()

    assert [i["reason"] for i in result["invalid_range"]] == [
        "IP outside DHCP range",
        "Invalid IP format",
    ]
    assert list(result["duplicate_ips"]) == ["192.168.2.100"]
    assert result["total_issues"] == 3
    assert len(result["recommendations"]) == 2


def test_configure_network_isolation_reports_invalid_subnet(router, api):
    result = api.configure_network_isolation(home_subnet="not-a-subnet")

    assert result["home"] is False and result["guest"] is False
    assert "error" in result
    assert len(router.calls) == 1  # only the login


def test_configure_network_isolation_uses_last_host_as_gateway(router, api):
    router.on("NetMaster.LAN.default.Bridge.lan", "setIPv4", {"status": None})
    router.on("NetMaster.LAN.default.Bridge.guest", "setIPv4", {"status": None})

    assert api.configure_network_isolation() == {"home": True, "guest": True}
    (home,) = router.calls_to("NetMaster.LAN.default.Bridge.lan", "setIPv4")
    assert home["Address"] == "192.168.2.254"
    assert home["PrefixLength"] == 24
    assert home["LeaseTime"] == "14400"
