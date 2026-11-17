import pytest

from kpnboxapi import KPNBoxAPI
from kpnboxapi._utils import (
    bedtime_blocks,
    validate_hours,
    validate_ipv4,
    validate_mac,
    validate_pool,
    validate_protocol,
)

HOUR = 3600
DAY = 24 * HOUR


@pytest.mark.parametrize(
    "result, expected",
    [
        ({"status": True}, True),
        ({"status": 1}, True),
        ({"status": False}, False),
        ({"status": None}, False),
        ({}, False),
        (None, False),
        ([], False),
    ],
)
def test_is_true(result, expected):
    assert KPNBoxAPI._is_true(result) is expected


@pytest.mark.parametrize(
    "result, expected",
    [
        (None, True),
        ({"status": None}, True),
        ({"status": True}, True),
        ({"status": False}, False),
        ({"status": None, "errors": [{"error": 196618}]}, False),
        ({"status": None, "errors": []}, True),
        ("oops", False),
    ],
)
def test_succeeded(result, expected):
    assert KPNBoxAPI._succeeded(result) is expected


@pytest.mark.parametrize(
    "response, expected",
    [
        ({"status": {"a": 1}}, {"a": 1}),
        ({"status": None}, {}),
        ({"status": False}, {}),
        ({"status": [1]}, {}),
        (None, {}),
    ],
)
def test_status_dict(response, expected):
    assert KPNBoxAPI._status_dict(response) == expected


@pytest.mark.parametrize("mac", ["AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"])
def test_validate_mac_accepts(mac):
    validate_mac(mac)


@pytest.mark.parametrize("mac", ["", None, "AABBCCDDEEFF", 12])
def test_validate_mac_rejects(mac):
    with pytest.raises(ValueError, match="Invalid MAC address format"):
        validate_mac(mac)


@pytest.mark.parametrize(
    "ip", ["", None, "192.168.2", "192.168.2.256", "a.b.c.d", "::1"]
)
def test_validate_ipv4_rejects(ip):
    with pytest.raises(ValueError, match="Invalid IP address format"):
        validate_ipv4(ip)


def test_validators_accept_valid_values():
    validate_ipv4("192.168.2.100")
    validate_pool("guest")
    validate_protocol("6,17")
    validate_hours(0, 23)


@pytest.mark.parametrize(
    "check, value",
    [(validate_pool, "lan"), (validate_protocol, "tcp"), (validate_hours, 24)],
)
def test_validators_reject_invalid_values(check, value):
    with pytest.raises(ValueError):
        check(value)


def test_bedtime_blocks_split_at_midnight():
    assert bedtime_blocks(22, 6, [0]) == [
        {"begin": 22 * HOUR, "end": DAY},
        {"begin": DAY, "end": DAY + 6 * HOUR},
    ]


def test_bedtime_blocks_do_not_run_past_the_end_of_the_week():
    assert bedtime_blocks(22, 6, [6]) == [
        {"begin": 6 * DAY + 22 * HOUR, "end": 7 * DAY}
    ]


def test_bedtime_blocks_within_one_day():
    assert bedtime_blocks(1, 5, [2]) == [
        {"begin": 2 * DAY + 1 * HOUR, "end": 2 * DAY + 5 * HOUR}
    ]


def test_formatters():
    api = KPNBoxAPI()
    assert api.format_bytes(0) == "0.0 B"
    assert api.format_bytes(1536) == "1.5 KB"
    assert api.format_memory_size(0) == "0 B"
    assert api.format_memory_size(5 * 1024**3) == "5.0 GB"
    assert api.format_speed(999) == "999 Kbps"
    assert api.format_speed(250_000) == "250.0 Mbps"
    assert api.format_speed(1_500_000) == "1.5 Gbps"
    assert api.format_protocol("6,17") == "TCP,UDP"
    assert api.format_protocol("") == "Unknown"
    assert (
        api.format_time_seconds_to_readable(DAY + 22 * HOUR + 30 * 60)
        == "Tuesday 22:30"
    )
