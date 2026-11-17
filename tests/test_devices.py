from datetime import datetime, timedelta

import pytest
import requests

from kpnboxapi import KPNBoxConnectionError

TOPOLOGY = {
    "status": [
        {
            "Name": "lan",
            "PhysAddress": "00:00:00:00:00:01",
            "Children": [
                {
                    "Name": "ETH0",
                    "PhysAddress": "00:00:00:00:00:02",
                    "Children": [
                        {
                            "Name": "nas",
                            "PhysAddress": "AA:AA:AA:AA:AA:01",
                            "Active": True,
                        },
                    ],
                },
                {
                    "Name": "vap2g0priv",
                    "PhysAddress": "00:00:00:00:00:03",
                    "Children": [
                        {
                            "Name": "phone",
                            "PhysAddress": "AA:AA:AA:AA:AA:02",
                            "Active": False,
                        },
                    ],
                },
                {"Name": "no-mac"},
            ],
        }
    ]
}


def iso(days_ago):
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_get_devices_skips_interfaces_and_filters_on_activity(router, api):
    router.on("Devices.Device.lan", "topology", TOPOLOGY)

    assert [d["Name"] for d in api.get_devices()] == ["nas", "phone"]
    assert [d["Name"] for d in api.get_devices("active")] == ["nas"]
    assert [d["Name"] for d in api.get_devices("inactive")] == ["phone"]


def test_get_devices_rejects_unknown_filter(router, api):
    with pytest.raises(ValueError):
        api.get_devices("online")
    assert len(router.calls) == 1  # only the login


@pytest.fixture
def old_and_new_devices(router):
    router.on(
        "Devices.Device.lan",
        "topology",
        {
            "status": [
                {
                    "Name": "old",
                    "PhysAddress": "AA:AA:AA:AA:AA:01",
                    "Active": False,
                    "LastConnection": iso(60),
                },
                {
                    "Name": "recent",
                    "PhysAddress": "AA:AA:AA:AA:AA:02",
                    "Active": False,
                    "LastConnection": iso(2),
                },
                {
                    "Name": "online",
                    "PhysAddress": "AA:AA:AA:AA:AA:03",
                    "Active": True,
                    "LastConnection": iso(90),
                },
                {
                    "Name": "garbled",
                    "PhysAddress": "AA:AA:AA:AA:AA:04",
                    "Active": False,
                    "LastConnection": "T-not-a-date",
                },
                {"Name": "never", "PhysAddress": "AA:AA:AA:AA:AA:05", "Active": False},
            ]
        },
    )
    router.on("Scheduler", "getSchedule", {"status": False})


def test_cleanup_inactive_devices_only_deletes_devices_past_the_cutoff(
    router, api, old_and_new_devices
):
    router.on("Devices", "destroyDevice", {"status": True})

    result = api.cleanup_inactive_devices(days_inactive=30)

    assert router.calls_to("Devices", "destroyDevice") == [{"key": "AA:AA:AA:AA:AA:01"}]
    assert [d["name"] for d in result["deleted"]] == ["old"]
    assert result["total_failed"] == 0


def test_cleanup_inactive_devices_reports_refused_deletes(
    router, api, old_and_new_devices
):
    router.on("Devices", "destroyDevice", {"status": False})

    result = api.cleanup_inactive_devices(days_inactive=30)

    assert result["total_deleted"] == 0
    assert [d["name"] for d in result["failed"]] == ["old"]


def test_cleanup_inactive_devices_does_not_hide_connection_loss(
    router, api, old_and_new_devices
):
    router.on("Devices", "destroyDevice", requests.exceptions.ConnectionError("gone"))

    with pytest.raises(KPNBoxConnectionError):
        api.cleanup_inactive_devices(days_inactive=30)


def test_list_inactive_devices(router, api, old_and_new_devices):
    devices = {d["name"]: d["days_since_seen"] for d in api.list_inactive_devices(7)}

    assert devices == {"old": 60, "garbled": "Parse Error", "never": "Unknown"}


def test_device_setters_validate_mac_before_calling_the_router(router, api):
    for call in (
        lambda: api.set_device_name("not-a-mac", "tv"),
        lambda: api.delete_device(""),
        lambda: api.get_device_details("AABBCCDDEEFF"),
    ):
        with pytest.raises(ValueError, match="Invalid MAC address format"):
            call()
    assert len(router.calls) == 1  # only the login
