"""Main KPNBoxAPI client class."""

from ._dhcp import DhcpMixin
from ._firewall import FirewallMixin
from ._network import NetworkMixin
from ._parental import ParentalMixin
from ._system import SystemMixin
from ._wifi import WifiMixin


class KPNBoxAPI(
    WifiMixin,
    DhcpMixin,
    ParentalMixin,
    NetworkMixin,
    FirewallMixin,
    SystemMixin,
):
    """Client for interacting with KPN Box routers (tested with Box 14).

    The methods live in feature mixins (``_wifi``, ``_dhcp``, ``_firewall``,
    ...); session handling is in ``_base``.
    """
