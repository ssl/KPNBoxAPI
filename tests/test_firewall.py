import pytest
import requests

from kpnboxapi import KPNBoxConnectionError

RULE = {
    "Id": "webui_ssh",
    "InternalPort": "22",
    "ExternalPort": "2222",
    "DestinationIPAddress": "192.168.2.10",
    "Enable": True,
    "Protocol": "6",
    "Description": "ssh",
}


def test_get_port_forwarding(router, api):
    router.on(
        "Firewall", "getPortForwarding", {"status": {"webui_ssh": RULE, "junk": "x"}}
    )

    assert api.get_port_forwarding() == [RULE]
    assert router.calls_to("Firewall", "getPortForwarding") == [{"origin": "webui"}]


@pytest.mark.parametrize("status", [None, False, []])
def test_get_port_forwarding_without_rules(router, api, status):
    router.on("Firewall", "getPortForwarding", {"status": status})

    assert api.get_port_forwarding() == []


def test_get_all_port_forwarding_skips_origins_the_router_rejects(router, api):
    router.on(
        "Firewall", "getPortForwarding", {"status": {"webui_ssh": RULE}}, (500, "nope")
    )

    assert api.get_all_port_forwarding() == {"webui": [RULE]}


def test_add_port_forwarding_rule(router, api):
    router.on("Firewall", "setPortForwarding", {"status": "webui_ssh"})

    assert (
        api.add_port_forwarding_rule(" ssh ", 22, 2222, "192.168.2.10") == "webui_ssh"
    )
    (params,) = router.calls_to("Firewall", "setPortForwarding")
    assert params["id"] == "ssh"
    assert (params["internalPort"], params["externalPort"]) == ("22", "2222")
    assert params["protocol"] == "6"


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "rule_id": "",
            "internal_port": "22",
            "external_port": "22",
            "destination_ip": "1.2.3.4",
        },
        {
            "rule_id": "x",
            "internal_port": "",
            "external_port": "22",
            "destination_ip": "1.2.3.4",
        },
        {
            "rule_id": "x",
            "internal_port": "22",
            "external_port": "22",
            "destination_ip": "",
        },
        {
            "rule_id": "x",
            "internal_port": "22",
            "external_port": "22",
            "destination_ip": "1.2.3.4",
            "protocol": "tcp",
        },
    ],
)
def test_add_port_forwarding_rule_validates_input(router, api, kwargs):
    with pytest.raises(ValueError):
        api.add_port_forwarding_rule(**kwargs)
    assert len(router.calls) == 1  # only the login


def test_disable_port_forwarding_rule_keeps_the_other_fields(router, api):
    router.on("Firewall", "getPortForwarding", {"status": {"webui_ssh": RULE}})
    router.on("Firewall", "setPortForwarding", {"status": "webui_ssh"})

    assert api.disable_port_forwarding_rule("ssh") is True
    (params,) = router.calls_to("Firewall", "setPortForwarding")
    assert params["enable"] is False
    assert params["id"] == "webui_ssh"
    assert params["externalPort"] == "2222"


def test_enable_port_forwarding_rule_returns_false_for_unknown_rule(router, api):
    router.on("Firewall", "getPortForwarding", {"status": {}})

    assert api.enable_port_forwarding_rule("missing") is False


def test_enable_port_forwarding_rule_does_not_hide_connection_loss(router, api):
    router.on(
        "Firewall", "getPortForwarding", requests.exceptions.ConnectionError("gone")
    )

    with pytest.raises(KPNBoxConnectionError):
        api.enable_port_forwarding_rule("ssh")


def test_delete_port_forwarding_rule_looks_up_destination(router, api):
    router.on("Firewall", "getPortForwarding", {"status": {"webui_ssh": RULE}})
    router.on("Firewall", "deletePortForwarding", {"status": True})

    assert api.delete_port_forwarding_rule("ssh") is True
    assert router.calls_to("Firewall", "deletePortForwarding") == [
        {"id": "webui_ssh", "origin": "webui", "destinationIPAddress": "192.168.2.10"}
    ]


def test_set_firewall_level(router, api):
    router.on("Firewall", "setFirewallLevel", {"status": True})
    router.on("Firewall", "setFirewallIPv6Level", {"status": False})

    assert api.set_firewall_level("High") == {"ipv4": True, "ipv6": False}
    with pytest.raises(ValueError):
        api.set_firewall_level("Paranoid")


def test_dmz_and_upnp_setters(router, api):
    router.on("Firewall", "setDMZ", {"status": "webui"}, {"status": None})
    router.on("Firewall", "deleteDMZ", {"status": True})
    router.on("Firewall", "set", {"status": True}, {"status": False})

    assert api.set_dmz_host("192.168.2.10") == "webui"
    assert api.set_dmz_host("192.168.2.10") == ""
    assert api.delete_dmz_host() is True
    assert api.set_upnp_enabled(True) is True
    assert api.set_upnp_enabled(False) is False


def test_saving_a_rule_returns_empty_string_when_the_router_refuses(router, api):
    refused = {"status": None, "errors": [{"error": 1, "description": "Invalid port"}]}
    router.on("Firewall", "getPortForwarding", {"status": {"webui_ssh": RULE}})
    router.on("Firewall", "setPortForwarding", refused)
    router.on("Firewall", "setPinhole", refused)
    router.on("Firewall", "setCustomRule", refused)

    assert api.add_port_forwarding_rule("ssh", 22, 2222, "192.168.2.10") == ""
    assert api.enable_port_forwarding_rule("ssh") is False
    assert api.add_ipv6_pinhole("2001:db8::1", "443") == ""
    assert api.add_custom_firewall_rule("web") == ""


def test_rule_id_falls_back_to_the_requested_id(router, api):
    router.on(
        "Firewall",
        "setPortForwarding",
        {"status": None},
        {"data": {"rule": {"Id": "webui_x"}}},
    )

    assert api.add_port_forwarding_rule("ssh", 22, 2222, "192.168.2.10") == "ssh"
    assert api.add_port_forwarding_rule("ssh", 22, 2222, "192.168.2.10") == "webui_x"


def test_toggling_a_custom_rule_reports_a_refusal(router, api):
    router.on(
        "Firewall",
        "getCustomRule",
        {"status": {"web": {"Id": "web", "Target": "Accept"}}},
    )
    router.on(
        "Firewall",
        "setCustomRule",
        {"status": "web"},
        {"status": None, "errors": [{"error": 1}]},
    )

    assert api.manage_custom_firewall_rule("disable", "web") is True
    assert api.manage_custom_firewall_rule("disable", "web") is False
    assert api.manage_custom_firewall_rule("enable", "unknown") is False
