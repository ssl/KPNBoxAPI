"""Shared validation and schedule helpers."""

import ipaddress
from typing import Any, Dict, Iterable, List

VALID_POOLS = ("default", "guest")
VALID_PROTOCOLS = frozenset({"6", "17", "6,17", "17,6"})

SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR


def validate_mac(mac_address: Any) -> None:
    """Reject values that are clearly not a MAC address.

    The check is deliberately loose (non-empty and colon separated): the router
    is the authority on which device keys exist.
    """
    if not mac_address or not isinstance(mac_address, str) or ":" not in mac_address:
        raise ValueError("Invalid MAC address format")


def validate_ipv4(ip_address: Any) -> None:
    """Raise ValueError unless ``ip_address`` is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_address)
    except ValueError:
        raise ValueError("Invalid IP address format") from None


def validate_pool(pool_id: str) -> None:
    """Raise ValueError unless ``pool_id`` is a known DHCP pool."""
    if pool_id not in VALID_POOLS:
        raise ValueError("pool_id must be 'default' or 'guest'")


def validate_protocol(protocol: str) -> None:
    """Raise ValueError unless ``protocol`` is TCP, UDP or both (as numbers)."""
    if protocol not in VALID_PROTOCOLS:
        raise ValueError(f"protocol must be one of: {sorted(VALID_PROTOCOLS)}")


def validate_hours(*hours: int) -> None:
    """Raise ValueError unless every value is an hour of the day (0-23)."""
    if not all(0 <= hour <= 23 for hour in hours):
        raise ValueError("Hours must be between 0 and 23")


def bedtime_blocks(
    bedtime_hour: int, wakeup_hour: int, days: Iterable[int]
) -> List[Dict[str, int]]:
    """Build weekly "disabled" blocks, in seconds since Monday 00:00.

    When bedtime is later than wakeup the block crosses midnight and is split
    in two: bedtime until midnight, and midnight until wakeup on the next day
    (skipped for Sunday, which would run past the end of the week).
    """
    blocks: List[Dict[str, int]] = []
    for day in days:
        day_start = day * SECONDS_PER_DAY
        begin = day_start + bedtime_hour * SECONDS_PER_HOUR

        if bedtime_hour > wakeup_hour:
            next_day_start = day_start + SECONDS_PER_DAY
            blocks.append({"begin": begin, "end": next_day_start})
            if day < 6:
                blocks.append(
                    {
                        "begin": next_day_start,
                        "end": next_day_start + wakeup_hour * SECONDS_PER_HOUR,
                    }
                )
        else:
            blocks.append(
                {"begin": begin, "end": day_start + wakeup_hour * SECONDS_PER_HOUR}
            )
    return blocks
