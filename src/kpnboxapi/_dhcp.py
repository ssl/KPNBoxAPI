"""DHCP: server pools, leases and static IP reservations."""

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from ._devices import DevicesMixin
from ._utils import (
    validate_ipv4,
    validate_mac,
    validate_pool,
)
from .exceptions import APIError


def _lease_ip(lease: Dict[str, Any]) -> str:
    return lease.get("IPAddress") or lease.get("ip_address") or ""


def _lease_mac(lease: Dict[str, Any]) -> str:
    return lease.get("MACAddress") or lease.get("mac_address") or ""


def _with_aliases(lease: Dict[str, Any]) -> Dict[str, Any]:
    """Copy of a lease with snake_case ``ip_address`` / ``mac_address`` keys added."""
    aliased = dict(lease)
    aliased["ip_address"] = _lease_ip(lease)
    aliased["mac_address"] = _lease_mac(lease)
    return aliased


class DhcpMixin(DevicesMixin):
    """DHCP: server pools, leases and static IP reservations."""

    def get_dhcp_server(self, pool_id: str = "default") -> Dict[str, Any]:
        """
        Get DHCP server configuration for a specific pool.

        Args:
            pool_id: DHCP pool ID - "default" or "guest" (default: "default")

        Returns:
            Dictionary with DHCP server configuration including:
            - Enable: Whether DHCP server is enabled
            - Status: Current status ("Enabled" or "Disabled")
            - MinAddress: Start of IP address range
            - MaxAddress: End of IP address range
            - SubnetMask: Network subnet mask
            - IPRouters: Gateway IP address
            - Server: DHCP server IP address
            - LeaseTime: DHCP lease duration in seconds
            - DNSServers: DNS server addresses (comma-separated)
            - DomainName: Network domain name
            - Interface: Network interface (e.g., "bridge", "brguest")
            - LeaseNumberOfEntries: Number of active DHCP leases
            - StaticAddressNumberOfEntries: Number of static IP assignments
            - And many other DHCP configuration fields

        Raises:
            ValueError: If pool_id is not "default" or "guest"
        """
        validate_pool(pool_id)

        response = self._make_api_call(
            service="DHCPv4.Server",
            method="getDHCPServerPool",
            parameters={"id": pool_id},
        )

        # Extract DHCP configuration from response
        if isinstance(response, dict) and "status" in response:
            dhcp_data = self._status_dict(response).get(pool_id)
            if not isinstance(dhcp_data, dict):
                dhcp_data = {}
            # Add pool ID for reference
            dhcp_data["PoolID"] = pool_id
            return dhcp_data

        return {}

    def get_default_dhcp_server(self) -> Dict[str, Any]:
        """
        Get default network DHCP server configuration.

        Returns:
            Dictionary with default DHCP server configuration
        """
        return self.get_dhcp_server("default")

    def get_guest_dhcp_server(self) -> Dict[str, Any]:
        """
        Get guest network DHCP server configuration.

        Returns:
            Dictionary with guest DHCP server configuration
        """
        return self.get_dhcp_server("guest")

    def get_all_dhcp_servers(self) -> Dict[str, Dict[str, Any]]:
        """
        Get DHCP server information for all pools (default and guest).

        Returns:
            Dictionary with 'default' and 'guest' DHCP server information
        """
        return {
            "default": self.get_default_dhcp_server(),
            "guest": self.get_guest_dhcp_server(),
        }

    def set_dhcp_server_config(
        self,
        network: str = "lan",
        gateway_ip: Optional[str] = None,
        subnet_mask: Optional[int] = None,
        dhcp_enabled: Optional[bool] = None,
        dhcp_min_ip: Optional[str] = None,
        dhcp_max_ip: Optional[str] = None,
        lease_time_seconds: Optional[int] = None,
        dhcp_authoritative: Optional[bool] = None,
        dns_servers: Optional[str] = None,
    ) -> bool:
        """
        Configure DHCP server settings for a network.

        Args:
            network: Network to configure ("lan" for home, "guest" for guest network)
            gateway_ip: Gateway IP address (e.g., "192.168.2.254")
            subnet_mask: Subnet prefix length (e.g., 24 for /24)
            dhcp_enabled: Enable/disable DHCP server
            dhcp_min_ip: Minimum IP address for DHCP pool (e.g., "192.168.2.100")
            dhcp_max_ip: Maximum IP address for DHCP pool (e.g., "192.168.2.200")
            lease_time_seconds: DHCP lease time in seconds (e.g., 14400 for 4 hours)
            dhcp_authoritative: Whether DHCP server is authoritative
            dns_servers: DNS servers as comma-separated string (e.g., "9.9.9.9,149.112.112.112")

        Returns:
            True if configuration was successful

        Raises:
            ValueError: If network type is invalid

        Example:
            # Configure home network DHCP
            api.set_dhcp_server_config(
                network="lan",
                gateway_ip="192.168.2.254",
                subnet_mask=24,
                dhcp_enabled=True,
                dhcp_min_ip="192.168.2.100",
                dhcp_max_ip="192.168.2.200",
                lease_time_seconds=14400,
                dns_servers="9.9.9.9,149.112.112.112"
            )
        """
        if network not in ["lan", "guest"]:
            raise ValueError("Network must be 'lan' or 'guest'")

        # Build service name
        service = f"NetMaster.LAN.default.Bridge.{network}"

        # Build parameters (only include non-None values)
        parameters: Dict[str, Any] = {}

        if gateway_ip is not None:
            parameters["Address"] = gateway_ip
        if subnet_mask is not None:
            parameters["PrefixLength"] = subnet_mask
        if dhcp_enabled is not None:
            parameters["DHCPEnable"] = dhcp_enabled
        if dhcp_min_ip is not None:
            parameters["DHCPMinAddress"] = dhcp_min_ip
        if dhcp_max_ip is not None:
            parameters["DHCPMaxAddress"] = dhcp_max_ip
        if lease_time_seconds is not None:
            parameters["LeaseTime"] = str(lease_time_seconds)
        if dhcp_authoritative is not None:
            parameters["DHCPAuthoritative"] = dhcp_authoritative
        if dns_servers is not None:
            parameters["DNSServers"] = dns_servers

        if not parameters:
            raise ValueError("At least one parameter must be provided")

        result = self._make_api_call(
            service=service, method="setIPv4", parameters=parameters
        )

        # The API returns null for success, so we check if no error occurred
        return self._succeeded(result)

    def set_home_dhcp_config(
        self,
        gateway_ip: Optional[str] = None,
        subnet_mask: Optional[int] = None,
        dhcp_enabled: Optional[bool] = None,
        dhcp_min_ip: Optional[str] = None,
        dhcp_max_ip: Optional[str] = None,
        lease_time_seconds: Optional[int] = None,
        dhcp_authoritative: Optional[bool] = None,
        dns_servers: Optional[str] = None,
    ) -> bool:
        """
        Configure DHCP server settings for the home network.

        Args:
            gateway_ip: Gateway IP address (default: "192.168.2.254")
            subnet_mask: Subnet prefix length (default: 24)
            dhcp_enabled: Enable/disable DHCP server (default: True)
            dhcp_min_ip: Minimum IP for DHCP pool (default: "192.168.2.100")
            dhcp_max_ip: Maximum IP for DHCP pool (default: "192.168.2.200")
            lease_time_seconds: DHCP lease time in seconds (default: 14400)
            dhcp_authoritative: Whether DHCP server is authoritative (default: True)
            dns_servers: DNS servers comma-separated (default: "9.9.9.9,149.112.112.112")

        Returns:
            True if configuration was successful

        Example:
            # Standard home network setup
            api.set_home_dhcp_config(
                gateway_ip="192.168.2.254",
                subnet_mask=24,
                dhcp_enabled=True,
                dhcp_min_ip="192.168.2.100",
                dhcp_max_ip="192.168.2.200",
                lease_time_seconds=14400,
                dns_servers="9.9.9.9,149.112.112.112"
            )
        """
        return self.set_dhcp_server_config(
            network="lan",
            gateway_ip=gateway_ip,
            subnet_mask=subnet_mask,
            dhcp_enabled=dhcp_enabled,
            dhcp_min_ip=dhcp_min_ip,
            dhcp_max_ip=dhcp_max_ip,
            lease_time_seconds=lease_time_seconds,
            dhcp_authoritative=dhcp_authoritative,
            dns_servers=dns_servers,
        )

    def set_guest_dhcp_config(
        self,
        gateway_ip: Optional[str] = None,
        subnet_mask: Optional[int] = None,
        dhcp_enabled: Optional[bool] = None,
        dhcp_min_ip: Optional[str] = None,
        dhcp_max_ip: Optional[str] = None,
        lease_time_seconds: Optional[int] = None,
        dns_servers: Optional[str] = None,
    ) -> bool:
        """
        Configure DHCP server settings for the guest network.

        Args:
            gateway_ip: Gateway IP address (default: "192.168.3.254")
            subnet_mask: Subnet prefix length (default: 24)
            dhcp_enabled: Enable/disable DHCP server (default: True)
            dhcp_min_ip: Minimum IP for DHCP pool (default: "192.168.3.1")
            dhcp_max_ip: Maximum IP for DHCP pool (default: "192.168.3.32")
            lease_time_seconds: DHCP lease time in seconds (default: 14400)
            dns_servers: DNS servers comma-separated (default: "9.9.9.9,149.112.112.112")

        Returns:
            True if configuration was successful

        Example:
            # Guest network with limited IP range
            api.set_guest_dhcp_config(
                gateway_ip="192.168.3.254",
                dhcp_min_ip="192.168.3.1",
                dhcp_max_ip="192.168.3.32",
                lease_time_seconds=3600,  # 1 hour for guests
                dns_servers="9.9.9.9,149.112.112.112"
            )
        """
        return self.set_dhcp_server_config(
            network="guest",
            gateway_ip=gateway_ip,
            subnet_mask=subnet_mask,
            dhcp_enabled=dhcp_enabled,
            dhcp_min_ip=dhcp_min_ip,
            dhcp_max_ip=dhcp_max_ip,
            lease_time_seconds=lease_time_seconds,
            dhcp_authoritative=None,  # Guest network doesn't use authoritative
            dns_servers=dns_servers,
        )

    def configure_network_isolation(
        self,
        home_subnet: str = "192.168.2.0/24",
        guest_subnet: str = "192.168.3.0/24",
        home_dhcp_range: tuple = ("192.168.2.100", "192.168.2.200"),
        guest_dhcp_range: tuple = ("192.168.3.1", "192.168.3.32"),
        dns_servers: str = "9.9.9.9,149.112.112.112",
    ) -> Dict[str, bool]:
        """
        Configure network isolation between home and guest networks.

        This sets up proper IP ranges and DHCP pools to keep networks separated.

        Args:
            home_subnet: Home network subnet in CIDR notation
            guest_subnet: Guest network subnet in CIDR notation
            home_dhcp_range: Tuple of (min_ip, max_ip) for home DHCP
            guest_dhcp_range: Tuple of (min_ip, max_ip) for guest DHCP
            dns_servers: DNS servers for both networks

        Returns:
            Dictionary with configuration results for home and guest networks

        Example:
            # Set up isolated networks
            result = api.configure_network_isolation(
                home_subnet="192.168.2.0/24",
                guest_subnet="192.168.3.0/24",
                home_dhcp_range=("192.168.2.100", "192.168.2.200"),
                guest_dhcp_range=("192.168.3.1", "192.168.3.50")
            )
        """
        results: Dict[str, Any] = {}

        try:
            # Parse subnets
            home_net = ipaddress.IPv4Network(home_subnet, strict=False)
            guest_net = ipaddress.IPv4Network(guest_subnet, strict=False)

            # Configure home network
            home_gateway = str(list(home_net.hosts())[-1])  # Last IP as gateway
            results["home"] = self.set_home_dhcp_config(
                gateway_ip=home_gateway,
                subnet_mask=home_net.prefixlen,
                dhcp_enabled=True,
                dhcp_min_ip=home_dhcp_range[0],
                dhcp_max_ip=home_dhcp_range[1],
                lease_time_seconds=14400,
                dhcp_authoritative=True,
                dns_servers=dns_servers,
            )

            # Configure guest network
            guest_gateway = str(list(guest_net.hosts())[-1])  # Last IP as gateway
            results["guest"] = self.set_guest_dhcp_config(
                gateway_ip=guest_gateway,
                subnet_mask=guest_net.prefixlen,
                dhcp_enabled=True,
                dhcp_min_ip=guest_dhcp_range[0],
                dhcp_max_ip=guest_dhcp_range[1],
                lease_time_seconds=14400,
                dns_servers=dns_servers,
            )

        except (ValueError, APIError) as e:
            # Invalid subnet, or the router rejected a step. Connection and
            # authentication problems are raised to the caller.
            results["error"] = str(e)
            results.setdefault("home", False)
            results.setdefault("guest", False)

        return results

    def get_dhcp_leases(self, pool_id: str = "default") -> List[Dict[str, Any]]:
        """
        Get DHCP leases for a specific pool.

        Args:
            pool_id: DHCP pool ID - "default" or "guest" (default: "default")

        Returns:
            List of DHCP lease dictionaries with fields:
            - ClientID: DHCP client identifier
            - IPAddress: Assigned IP address
            - MACAddress: Device MAC address
            - FriendlyName: Device name/hostname
            - Active: Whether lease is currently active (True/False)
            - Reserved: Whether IP is reserved for this device (True/False)
            - LeaseTime: Total lease duration in seconds
            - LeaseTimeRemaining: Remaining lease time in seconds (-1 = permanent)
            - Gateway: Gateway configuration
            - Flags: DHCP flags
            - And other DHCP lease fields

        Raises:
            ValueError: If pool_id is not "default" or "guest"
        """
        validate_pool(pool_id)

        response = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}", method="getLeases", parameters={}
        )

        leases = []

        # Extract DHCP leases from response
        if isinstance(response, dict) and "status" in response:
            pool_data = self._status_dict(response).get(pool_id)
            if not isinstance(pool_data, dict):
                pool_data = {}
            for lease_data in pool_data.values():
                if isinstance(lease_data, dict):
                    # Add pool ID for reference
                    lease_data["PoolID"] = pool_id
                    leases.append(lease_data)

        return leases

    def get_default_dhcp_leases(self) -> List[Dict[str, Any]]:
        """
        Get DHCP leases for the default network.

        Returns:
            List of DHCP lease dictionaries for default network
        """
        return self.get_dhcp_leases("default")

    def get_guest_dhcp_leases(self) -> List[Dict[str, Any]]:
        """
        Get DHCP leases for the guest network.

        Returns:
            List of DHCP lease dictionaries for guest network
        """
        return self.get_dhcp_leases("guest")

    def get_all_dhcp_leases(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all DHCP leases (both default and guest networks).

        Returns:
            Dictionary with keys:
            - 'default': List of default network DHCP leases
            - 'guest': List of guest network DHCP leases
        """
        return {
            "default": self.get_default_dhcp_leases(),
            "guest": self.get_guest_dhcp_leases(),
        }

    def get_active_dhcp_leases(self, pool_id: str = "default") -> List[Dict[str, Any]]:
        """
        Get only active DHCP leases for a specific pool.

        Args:
            pool_id: DHCP pool ID - "default" or "guest" (default: "default")

        Returns:
            List of active DHCP lease dictionaries
        """
        all_leases = self.get_dhcp_leases(pool_id)
        return [lease for lease in all_leases if lease.get("Active", False)]

    def get_dhcp_static_leases(self, pool_id: str = "default") -> List[Dict[str, Any]]:
        """
        Get DHCP static lease reservations for a specific pool.

        Args:
            pool_id: DHCP pool ID - "default" or "guest" (default: "default")

        Returns:
            List of static lease dictionaries with fields:
            - IPAddress: Reserved IP address
            - MACAddress: Device MAC address
            - LeasePath: Internal lease path identifier

        Raises:
            ValueError: If pool_id is not "default" or "guest"
        """
        validate_pool(pool_id)

        response = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="getStaticLeases",
            parameters=pool_id,
        )

        static_leases = self._status_list(response)

        # Add pool ID for reference
        for lease in static_leases:
            lease["PoolID"] = pool_id

        return static_leases

    def get_default_dhcp_static_leases(self) -> List[Dict[str, Any]]:
        """
        Get DHCP static lease reservations for the default network.

        Returns:
            List of static lease dictionaries for default network
        """
        return self.get_dhcp_static_leases("default")

    def get_guest_dhcp_static_leases(self) -> List[Dict[str, Any]]:
        """
        Get DHCP static lease reservations for the guest network.

        Returns:
            List of static lease dictionaries for guest network
        """
        return self.get_dhcp_static_leases("guest")

    def get_all_dhcp_static_leases(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get static DHCP leases (IP reservations) for all pools.

        Returns:
            Dictionary with 'default' and 'guest' static lease lists
        """
        return {
            "default": self.get_default_dhcp_static_leases(),
            "guest": self.get_guest_dhcp_static_leases(),
        }

    def add_static_lease(
        self, mac_address: str, ip_address: str, pool_id: str = "default"
    ) -> bool:
        """
        Add a static DHCP lease (IP reservation) for a device.

        This ensures a device with the specified MAC address will always
        receive the same IP address from the DHCP server.

        Args:
            mac_address: MAC address of the device (e.g., "50:DE:06:9A:A6:98")
            ip_address: IP address to reserve (e.g., "192.168.2.118")
            pool_id: DHCP pool ID ("default" for home network, "guest" for guest network)

        Returns:
            True if static lease was successfully added

        Raises:
            ValueError: If MAC address or IP address format is invalid

        Example:
            # Reserve IP for a printer
            success = api.add_static_lease("50:DE:06:9A:A6:98", "192.168.2.118")

            # Reserve IP for a server in guest network
            success = api.add_static_lease("00:17:88:4A:40:B4", "192.168.3.10", "guest")
        """
        validate_mac(mac_address)
        validate_ipv4(ip_address)

        result = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="addStaticLease",
            parameters={"MACAddress": mac_address, "IPAddress": ip_address},
        )

        # API returns null on success
        return self._succeeded(result)

    def delete_static_lease(self, mac_address: str, pool_id: str = "default") -> bool:
        """
        Delete a static DHCP lease (IP reservation) for a device.

        This removes the IP reservation, allowing the device to receive
        any available IP address from the DHCP pool.

        Args:
            mac_address: MAC address of the device (e.g., "50:DE:06:9A:A6:98")
            pool_id: DHCP pool ID ("default" for home network, "guest" for guest network)

        Returns:
            True if static lease was successfully deleted

        Raises:
            ValueError: If MAC address format is invalid

        Example:
            # Remove IP reservation for a device
            success = api.delete_static_lease("50:DE:06:9A:A6:98")
        """
        validate_mac(mac_address)

        result = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="deleteStaticLease",
            parameters={"MACAddress": mac_address},
        )

        # API returns null on success
        return self._succeeded(result)

    def set_static_lease(
        self, mac_address: str, ip_address: str, pool_id: str = "default"
    ) -> bool:
        """
        Set/update a static DHCP lease (IP reservation) for a device.

        This modifies an existing IP reservation or creates a new one if it doesn't exist.

        Args:
            mac_address: MAC address of the device (e.g., "00:17:88:4A:40:B4")
            ip_address: IP address to reserve (e.g., "192.168.2.124")
            pool_id: DHCP pool ID ("default" for home network, "guest" for guest network)

        Returns:
            True if static lease was successfully set/updated

        Raises:
            ValueError: If MAC address or IP address format is invalid

        Example:
            # Update IP reservation for a device
            success = api.set_static_lease("00:17:88:4A:40:B4", "192.168.2.124")
        """
        validate_mac(mac_address)
        validate_ipv4(ip_address)

        result = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="setStaticLease",
            parameters={"MACAddress": mac_address, "IPAddress": ip_address},
        )

        # API returns null on success
        return self._succeeded(result)

    def manage_device_ip_reservation(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        action: str = "add",
        pool_id: str = "default",
    ) -> bool:
        """
        Comprehensive IP reservation management for a device.

        Args:
            mac_address: MAC address of the device
            ip_address: IP address to reserve (required for add/set actions)
            action: Action to perform ("add", "delete", "set", "update")
            pool_id: DHCP pool ID ("default" or "guest")

        Returns:
            True if action was successful

        Example:
            # Add reservation
            api.manage_device_ip_reservation("AA:BB:CC:DD:EE:FF", "192.168.2.100", "add")

            # Update reservation
            api.manage_device_ip_reservation("AA:BB:CC:DD:EE:FF", "192.168.2.101", "set")

            # Remove reservation
            api.manage_device_ip_reservation("AA:BB:CC:DD:EE:FF", action="delete")
        """
        if action.lower() in ["add"]:
            if not ip_address:
                raise ValueError("IP address required for add action")
            return self.add_static_lease(mac_address, ip_address, pool_id)

        elif action.lower() in ["delete", "remove"]:
            return self.delete_static_lease(mac_address, pool_id)

        elif action.lower() in ["set", "update", "modify"]:
            if not ip_address:
                raise ValueError("IP address required for set/update action")
            return self.set_static_lease(mac_address, ip_address, pool_id)

        else:
            raise ValueError("Invalid action. Use 'add', 'delete', 'set', or 'update'")

    def reserve_device_ip(
        self,
        device_identifier: str,
        ip_address: str,
        pool_id: str = "default",
        auto_detect_mac: bool = True,
    ) -> bool:
        """
        Reserve an IP address for a device (with smart device detection).

        Args:
            device_identifier: MAC address or device name
            ip_address: IP address to reserve
            pool_id: DHCP pool ID ("default" or "guest")
            auto_detect_mac: If True, try to find MAC address from device name

        Returns:
            True if reservation was successful

        Example:
            # Reserve by MAC address
            api.reserve_device_ip("AA:BB:CC:DD:EE:FF", "192.168.2.100")

            # Reserve by device name (auto-detect MAC)
            api.reserve_device_ip("My Printer", "192.168.2.100")
        """
        mac_address = device_identifier

        # Look the device up by name unless a MAC address was given
        if auto_detect_mac and ":" not in device_identifier:
            devices = self.list_managed_devices()
            matching_devices = [
                d
                for d in devices
                if d.get("name", "").lower() == device_identifier.lower()
            ]

            if not matching_devices:
                raise ValueError(
                    f"Could not find MAC address for device '{device_identifier}'"
                )
            mac_address = matching_devices[0]["mac_address"]

        return self.add_static_lease(mac_address, ip_address, pool_id)

    def get_device_ip_reservation(
        self, mac_address: str, pool_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Get IP reservation information for a specific device.

        Args:
            mac_address: MAC address of the device
            pool_id: DHCP pool ID ("default" or "guest")

        Returns:
            Dictionary with reservation information or empty dict if not found

        Example:
            reservation = api.get_device_ip_reservation("AA:BB:CC:DD:EE:FF")
            if reservation:
                print(f"Reserved IP: {reservation['ip_address']}")
        """
        for lease in self.get_dhcp_static_leases(pool_id):
            if _lease_mac(lease).lower() == mac_address.lower():
                return _with_aliases(lease)

        return {}

    def list_ip_reservations(
        self, pool_id: str = "default", include_device_info: bool = True
    ) -> List[Dict[str, Any]]:
        """
        List all IP reservations with enhanced device information.

        Args:
            pool_id: DHCP pool ID ("default" or "guest")
            include_device_info: Include device names and types from device list

        Returns:
            List of IP reservations with device information

        Example:
            reservations = api.list_ip_reservations()
            for res in reservations:
                print(f"{res['device_name']}: {res['ip_address']} ({res['mac_address']})")
        """
        static_leases = [
            _with_aliases(lease) for lease in self.get_dhcp_static_leases(pool_id)
        ]

        if not include_device_info:
            return static_leases

        # Device information is a nice-to-have: carry on without it if the router
        # refuses the device calls.
        try:
            devices = self.list_managed_devices()
        except APIError:
            devices = []
        device_lookup = {d["mac_address"].lower(): d for d in devices}

        enhanced_leases = []
        for lease in static_leases:
            device = device_lookup.get(lease["mac_address"].lower())

            if device:
                lease.update(
                    {
                        "device_name": device.get("name", "Unknown"),
                        "device_type": device.get("device_type", "Unknown"),
                        "active": device.get("active", False),
                        "last_seen": device.get("last_seen", "Unknown"),
                    }
                )
            else:
                lease.update(
                    {
                        "device_name": "Unknown Device",
                        "device_type": "Unknown",
                        "active": False,
                        "last_seen": "Unknown",
                    }
                )

            enhanced_leases.append(lease)

        return enhanced_leases

    def suggest_available_ips(
        self, pool_id: str = "default", count: int = 5
    ) -> List[str]:
        """
        Suggest available IP addresses for new reservations.

        Args:
            pool_id: DHCP pool ID ("default" or "guest")
            count: Number of IP suggestions to return

        Returns:
            List of suggested available IP addresses

        Example:
            available_ips = api.suggest_available_ips()
            print(f"Available IPs: {available_ips}")
        """
        validate_pool(pool_id)
        min_ip, max_ip = self._dhcp_range(pool_id)

        # Reserved addresses and addresses that are in use right now
        used_ips = {_lease_ip(lease) for lease in self.get_dhcp_static_leases(pool_id)}
        used_ips.update(
            _lease_ip(lease)
            for lease in self.get_dhcp_leases(pool_id)
            if lease.get("Active", False)
        )

        available_ips: List[str] = []
        current_ip = min_ip

        while current_ip <= max_ip and len(available_ips) < count:
            if str(current_ip) not in used_ips:
                available_ips.append(str(current_ip))
            current_ip += 1

        return available_ips

    def cleanup_invalid_reservations(self, pool_id: str = "default") -> Dict[str, Any]:
        """
        Find invalid or conflicting IP reservations.

        Nothing is removed: the result lists what to fix.

        Args:
            pool_id: DHCP pool ID ("default" or "guest")

        Returns:
            Dictionary with cleanup results

        Example:
            result = api.cleanup_invalid_reservations()
            print(f"Found {result['total_issues']} problems with reservations")
        """
        validate_pool(pool_id)

        try:
            min_ip, max_ip = self._dhcp_range(pool_id)
            static_leases = self.get_dhcp_static_leases(pool_id)
        except APIError as e:
            return {
                "error": str(e),
                "invalid_range": [],
                "duplicate_ips": {},
                "total_issues": 0,
                "recommendations": ["Error during validation - check manually"],
            }

        invalid_leases = []
        leases_by_ip: Dict[str, List[Dict[str, Any]]] = {}

        for lease in static_leases:
            ip_str = _lease_ip(lease)

            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
            except ValueError:
                invalid_leases.append({"lease": lease, "reason": "Invalid IP format"})
                continue

            if not (min_ip <= ip_obj <= max_ip):
                invalid_leases.append(
                    {"lease": lease, "reason": "IP outside DHCP range"}
                )
                continue

            leases_by_ip.setdefault(ip_str, []).append(lease)

        # More than one lease per IP is a conflict
        duplicate_conflicts = {
            ip: leases for ip, leases in leases_by_ip.items() if len(leases) > 1
        }

        recommendations = []
        if invalid_leases:
            recommendations.append("Remove IP reservations outside DHCP range")
        if duplicate_conflicts:
            recommendations.append("Resolve duplicate IP assignments")

        return {
            "invalid_range": invalid_leases,
            "duplicate_ips": duplicate_conflicts,
            "total_issues": len(invalid_leases) + len(duplicate_conflicts),
            "recommendations": recommendations,
        }

    def _dhcp_range(
        self, pool_id: str
    ) -> Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
        """First and last address of a DHCP pool, as configured on the router."""
        dhcp_config = self.get_dhcp_server(pool_id)
        min_ip = dhcp_config.get("MinAddress")
        max_ip = dhcp_config.get("MaxAddress")
        if not min_ip or not max_ip:
            raise APIError(
                f"DHCP range of pool '{pool_id}' not found in router response"
            )
        try:
            return ipaddress.IPv4Address(min_ip), ipaddress.IPv4Address(max_ip)
        except ValueError as e:
            raise APIError(f"Invalid DHCP range for pool '{pool_id}': {e}") from e
