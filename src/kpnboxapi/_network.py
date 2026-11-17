"""WAN, LAN, IPv6, DNS, DynDNS, ethernet ports and interface statistics."""

from typing import Any, Dict, List, Optional

from ._base import KPNBoxBase
from .exceptions import APIError


class NetworkMixin(KPNBoxBase):
    """WAN, LAN, IPv6, DNS, DynDNS, ethernet ports and interface statistics."""

    def get_public_ipv6(self) -> str:
        """
        Get the public IPv6 address of the KPN Box modem.

        Returns:
            Public IPv6 address as string (e.g., "2a02:a46f:ff52:0:4e22:f3ff:fecb:61b0")
        """
        response = self._make_api_call(
            service="NeMo.Intf.data",
            method="luckyAddrAddress",
            parameters={"flag": "ipv6 && global && @gua", "traverse": "down"},
        )

        return self._status_str(response)

    def get_dyndns_hosts(self) -> List[Dict[str, Any]]:
        """
        Get Dynamic DNS host configurations.

        Returns:
            List of DynDNS host dictionaries with fields:
            - service: DynDNS provider service (e.g., "No-IP")
            - hostname: Dynamic DNS hostname (e.g., "example.ddns.net")
            - username: DynDNS account username
            - password: DynDNS account password
            - last_update: Last update timestamp (ISO format)
            - status: Current status (e.g., "UPDATED", "ERROR")
            - enable: Whether DynDNS is enabled (True/False)
        """
        response = self._make_api_call(
            service="DynDNS", method="getHosts", parameters={}
        )

        hosts = []

        # Extract DynDNS hosts from response
        if isinstance(response, dict) and "status" in response:
            status_data = response["status"]
            if isinstance(status_data, list):
                hosts = [host for host in status_data if isinstance(host, dict)]
            elif isinstance(status_data, dict):
                # Single host case
                hosts = [status_data]

        return hosts

    def add_dyndns_host(
        self, service: str, username: str, hostname: str, password: str
    ) -> bool:
        """
        Add a new Dynamic DNS host configuration.

        Args:
            service: DynDNS provider service (e.g., "dyndns", "noip", "freedns")
            username: DynDNS account username
            hostname: Dynamic DNS hostname (e.g., "yourdomain.ddns.net")
            password: DynDNS account password

        Returns:
            True if host was successfully added

        Raises:
            ValueError: If any required parameter is empty
            APIError: If the DynDNS service configuration is invalid

        Example:
            # Add a DynDNS host
            success = api.add_dyndns_host(
                service="dyndns",
                username="myuser",
                hostname="myhome.ddns.net",
                password="mypassword"
            )
        """
        # Validate required parameters
        if not service or not service.strip():
            raise ValueError("Service parameter cannot be empty")
        if not username or not username.strip():
            raise ValueError("Username parameter cannot be empty")
        if not hostname or not hostname.strip():
            raise ValueError("Hostname parameter cannot be empty")
        if not password or not password.strip():
            raise ValueError("Password parameter cannot be empty")

        result = self._make_api_call(
            service="DynDNS",
            method="addHost",
            parameters={
                "service": service.strip(),
                "username": username.strip(),
                "hostname": hostname.strip(),
                "password": password.strip(),
            },
        )

        # Check for API errors in response
        if isinstance(result, dict):
            if result.get("status") is False and "errors" in result:
                errors = result["errors"]
                if errors and len(errors) > 0:
                    error_desc = errors[0].get("description", "Unknown error")
                    error_info = errors[0].get("info", "")
                    raise APIError(
                        f"DynDNS configuration failed: {error_desc} ({error_info})"
                    )

            return self._is_true(result)

        return False

    def delete_dyndns_host(self, hostname: str) -> bool:
        """
        Delete a Dynamic DNS host configuration.

        Args:
            hostname: Dynamic DNS hostname to delete (e.g., "yourdomain.ddns.net")

        Returns:
            True if host was successfully deleted

        Raises:
            ValueError: If hostname parameter is empty

        Example:
            # Delete a DynDNS host
            success = api.delete_dyndns_host("myhome.ddns.net")
        """
        # Validate required parameter
        if not hostname or not hostname.strip():
            raise ValueError("Hostname parameter cannot be empty")

        result = self._make_api_call(
            service="DynDNS",
            method="delHost",
            parameters={"hostname": hostname.strip()},
        )

        return self._is_true(result)

    def update_dyndns_host(
        self,
        hostname: str,
        service: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> bool:
        """
        Update an existing Dynamic DNS host configuration.

        This method deletes the existing host and adds it back with new configuration.

        Args:
            hostname: Dynamic DNS hostname to update (e.g., "yourdomain.ddns.net")
            service: New DynDNS provider service (if changing)
            username: New DynDNS account username (if changing)
            password: New DynDNS account password (if changing)

        Returns:
            True if host was successfully updated

        Raises:
            ValueError: If hostname is empty or no update parameters provided

        Example:
            # Update password for existing DynDNS host
            success = api.update_dyndns_host(
                hostname="myhome.ddns.net",
                password="newpassword"
            )
        """
        # Validate required parameter
        if not hostname or not hostname.strip():
            raise ValueError("Hostname parameter cannot be empty")

        # Check if any update parameters are provided
        if service is None and username is None and password is None:
            raise ValueError(
                "At least one parameter (service, username, or password) must be provided for update"
            )

        # Get current host configuration to fill in missing values
        current_hosts = self.get_dyndns_hosts()
        current_host = None

        for host in current_hosts:
            if host.get("hostname", "").lower() == hostname.strip().lower():
                current_host = host
                break

        if not current_host:
            raise ValueError(f"DynDNS host '{hostname}' not found")

        # Use provided values or fall back to current values
        update_service = service.strip() if service else current_host.get("service", "")
        update_username = (
            username.strip() if username else current_host.get("username", "")
        )
        update_password = (
            password.strip() if password else current_host.get("password", "")
        )

        # Validate that we have all required values
        if not update_service:
            raise ValueError(
                "Service value not found in current configuration and not provided"
            )
        if not update_username:
            raise ValueError(
                "Username value not found in current configuration and not provided"
            )
        if not update_password:
            raise ValueError(
                "Password value not found in current configuration and not provided"
            )

        # Delete the existing host
        delete_success = self.delete_dyndns_host(hostname.strip())
        if not delete_success:
            return False

        # Add the host back with updated configuration
        return self.add_dyndns_host(
            update_service, update_username, hostname.strip(), update_password
        )

    def get_dyndns_status(self, hostname: Optional[str] = None) -> Dict[str, Any]:
        """
        Get Dynamic DNS status for a specific hostname or all hosts.

        Args:
            hostname: Specific hostname to check (optional, returns all if not specified)

        Returns:
            Dictionary with DynDNS status information or single host if hostname specified

        Example:
            # Get status for all DynDNS hosts
            all_status = api.get_dyndns_status()

            # Get status for specific host
            host_status = api.get_dyndns_status("myhome.ddns.net")
        """
        hosts = self.get_dyndns_hosts()

        if hostname:
            # Return specific host
            for host in hosts:
                if host.get("hostname", "").lower() == hostname.strip().lower():
                    return host
            return {}

        # Return all hosts as a summary
        return {
            "total_hosts": len(hosts),
            "hosts": hosts,
            "active_hosts": [h for h in hosts if h.get("enable", False)],
            "last_updated": max([h.get("last_update", "") for h in hosts] or [""]),
        }

    def manage_dyndns_service(
        self,
        action: str,
        hostname: str,
        service: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> bool:
        """
        Comprehensive DynDNS management method.

        Args:
            action: Action to perform ("add", "delete", "update")
            hostname: Dynamic DNS hostname
            service: DynDNS provider service (required for add)
            username: DynDNS account username (required for add)
            password: DynDNS account password (required for add)

        Returns:
            True if action was successful

        Example:
            # Add new host
            api.manage_dyndns_service("add", "test.ddns.net", "dyndns", "user", "pass")

            # Update password
            api.manage_dyndns_service("update", "test.ddns.net", password="newpass")

            # Delete host
            api.manage_dyndns_service("delete", "test.ddns.net")
        """
        action = action.lower().strip()

        if action == "add":
            if not service or not username or not password:
                raise ValueError(
                    "Service, username, and password are required for add action"
                )
            return self.add_dyndns_host(service, username, hostname, password)

        elif action == "delete":
            return self.delete_dyndns_host(hostname)

        elif action in ["update", "modify"]:
            return self.update_dyndns_host(hostname, service, username, password)

        else:
            raise ValueError("Invalid action. Use 'add', 'delete', or 'update'")

    def get_network_stats(self, interface: str = "ETH0") -> Dict[str, Any]:
        """
        Get network device statistics for a specific interface.

        Args:
            interface: Interface name - "ETH0", "ETH1", "ETH2", "ETH3", "eth4", or "ppp_vdata" (default: "ETH0")
                      - ETH0-ETH3: Individual Ethernet ports
                      - eth4: Total WAN statistics (all WAN traffic combined)
                      - ppp_vdata: PPP connection statistics

        Returns:
            Dictionary with network statistics including:
            - RxPackets: Received packets count
            - TxPackets: Transmitted packets count
            - RxBytes: Received bytes count
            - TxBytes: Transmitted bytes count
            - RxErrors: Received errors count
            - TxErrors: Transmitted errors count
            - RxDropped: Received dropped packets count
            - TxDropped: Transmitted dropped packets count
            - Multicast: Multicast packets count
            - Collisions: Network collisions count
            - Various detailed error statistics (CRC, Frame, FIFO, etc.)

        Raises:
            ValueError: If interface is not one of the supported interfaces
        """
        valid_interfaces = ["ETH0", "ETH1", "ETH2", "ETH3", "eth4", "ppp_vdata"]
        if interface not in valid_interfaces:
            raise ValueError(f"interface must be one of {valid_interfaces}")

        response = self._make_api_call(
            service=f"NeMo.Intf.{interface}", method="getNetDevStats", parameters={}
        )

        stats = self._status_dict(response)
        if not stats:
            return {}

        # Add interface name for reference
        stats["Interface"] = interface
        return stats

    def get_wan_total_stats(self) -> Dict[str, Any]:
        """
        Get total WAN network statistics (all WAN traffic combined).

        Returns:
            Dictionary with total WAN network statistics
        """
        return self.get_network_stats("eth4")

    def get_ppp_stats(self) -> Dict[str, Any]:
        """
        Get PPP connection network statistics.

        Returns:
            Dictionary with PPP connection network statistics
        """
        return self.get_network_stats("ppp_vdata")

    def get_all_network_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get network device statistics for all interfaces (ETH0-ETH3, WAN total, PPP).

        Returns:
            Dictionary with keys for all interfaces containing their respective statistics.
            Interfaces that are not available will have empty dictionaries.
        """
        all_stats = {}

        # Ethernet ports, WAN total and PPP
        for interface in ["ETH0", "ETH1", "ETH2", "ETH3", "eth4", "ppp_vdata"]:
            try:
                stats = self.get_network_stats(interface)
            except APIError:
                stats = {}

            # Interface might not be available on this box
            all_stats[interface] = stats or {"Interface": interface, "Available": False}

        return all_stats

    def set_interface_duplex(
        self, interface: str = "eth4", duplex_mode: str = "Auto"
    ) -> bool:
        """
        Set network interface duplex mode.

        Args:
            interface: Interface name (default: "eth4" for WAN)
            duplex_mode: Duplex mode - "Auto", "Half", or "Full" (default: "Auto")

        Returns:
            True if successful
        """
        if duplex_mode not in ["Auto", "Half", "Full"]:
            raise ValueError("duplex_mode must be 'Auto', 'Half', or 'Full'")

        result = self._make_api_call(
            service=f"NeMo.Intf.{interface}",
            method="set",
            parameters={"DuplexModeEnabled": duplex_mode},
        )

        return self._is_true(result)

    def set_interface_speed(self, interface: str = "eth4", max_speed: int = -1) -> bool:
        """
        Set network interface maximum link speed.

        Args:
            interface: Interface name (default: "eth4" for WAN)
            max_speed: Maximum speed in Mbps, or -1 for Auto (default: -1)

        Returns:
            True if successful
        """
        result = self._make_api_call(
            service=f"NeMo.Intf.{interface}",
            method="set",
            parameters={"MaxBitRateEnabled": max_speed},
        )

        return self._is_true(result)

    def set_port4_guest_network(self, enabled: bool = True) -> bool:
        """
        Enable or disable guest network on Ethernet port 4.

        Args:
            enabled: Whether to enable guest network on port 4 (default: True)
                    When True: Port 4 connects to guest network
                    When False: Port 4 connects to home LAN network

        Returns:
            True if both API calls were successful

        Note:
            Port 4 corresponds to ETH3 interface in the KPN Box.
            This function makes 2 API calls to remove and add the interface
            to the appropriate bridge (lan or guest).
        """
        success_count = 0

        if enabled:
            # Enable guest network on port 4
            # 1. Remove ETH3 from LAN bridge
            result1 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan",
                method="removeIntf",
                parameters={"Intf": "ETH3"},
            )
            if self._succeeded(result1):  # status null indicates success
                success_count += 1

            # 2. Add ETH3 to guest bridge
            result2 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.guest",
                method="addIntf",
                parameters={"Intf": "ETH3"},
            )
            if self._succeeded(result2):  # status null indicates success
                success_count += 1
        else:
            # Disable guest network on port 4 (return to LAN)
            # 1. Remove ETH3 from guest bridge
            result1 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.guest",
                method="removeIntf",
                parameters={"Intf": "ETH3"},
            )
            if self._succeeded(result1):  # status null indicates success
                success_count += 1

            # 2. Add ETH3 to LAN bridge
            result2 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan",
                method="addIntf",
                parameters={"Intf": "ETH3"},
            )
            if self._succeeded(result2):  # status null indicates success
                success_count += 1

        return success_count == 2

    def enable_port4_guest_network(self) -> bool:
        """
        Enable guest network on Ethernet port 4.

        Returns:
            True if successful

        Note: Convenience method that calls set_port4_guest_network(True).
        """
        return self.set_port4_guest_network(True)

    def disable_port4_guest_network(self) -> bool:
        """
        Disable guest network on Ethernet port 4 (return to home LAN).

        Returns:
            True if successful

        Note: Convenience method that calls set_port4_guest_network(False).
        """
        return self.set_port4_guest_network(False)

    def configure_ethernet_port(
        self, port: int = 4, guest_network: bool = False
    ) -> bool:
        """
        Configure Ethernet port network assignment.

        Args:
            port: Ethernet port number (currently only port 4 is supported)
            guest_network: Whether to assign port to guest network (default: False)

        Returns:
            True if successful

        Raises:
            ValueError: If port number is not supported

        Note: Currently only port 4 (ETH3) configuration is supported.
        """
        if port != 4:
            raise ValueError("Only port 4 configuration is currently supported")

        return self.set_port4_guest_network(guest_network)

    def set_stp_enabled(self, enabled: bool = True) -> bool:
        """
        Enable or disable STP (Spanning Tree Protocol) on the bridge.

        Args:
            enabled: Whether to enable STP (default: True)

        Returns:
            True if successful

        Note:
            STP helps prevent network loops in bridged networks.
            Disabling STP can improve performance but may cause loops
            if multiple network paths exist.
        """
        result = self._make_api_call(
            service="NeMo.Intf.bridge", method="set", parameters={"STPEnable": enabled}
        )

        return self._is_true(result)

    def enable_stp(self) -> bool:
        """
        Enable STP (Spanning Tree Protocol).

        Returns:
            True if successful

        Note: Convenience method that calls set_stp_enabled(True).
        """
        return self.set_stp_enabled(True)

    def disable_stp(self) -> bool:
        """
        Disable STP (Spanning Tree Protocol).

        Returns:
            True if successful

        Note: Convenience method that calls set_stp_enabled(False).
        """
        return self.set_stp_enabled(False)

    def get_wan_status(self) -> Dict[str, Any]:
        """
        Get WAN connection status and information.

        Returns:
            Dictionary with WAN connection information including:
            - LinkType: Connection link type (e.g., "ethernet")
            - LinkState: Physical link state (e.g., "up", "down")
            - MACAddress: WAN interface MAC address
            - Protocol: Connection protocol (e.g., "ppp")
            - ConnectionState: Connection state (e.g., "Connected", "Disconnected")
            - LastConnectionError: Last connection error (if any)
            - IPAddress: Current public IPv4 address
            - RemoteGateway: ISP gateway IP address
            - DNSServers: DNS server addresses (comma-separated)
            - IPv6Address: Current public IPv6 address
            - IPv6DelegatedPrefix: IPv6 prefix delegated by ISP
        """
        response = self._make_api_call(
            service="NMC", method="getWANStatus", parameters={}
        )

        return self._data_dict(response) or self._status_dict(response)

    def get_ppp_info(self) -> Dict[str, Any]:
        """
        Get detailed PPP connection information.

        Returns:
            Dictionary with PPP connection details including:
            - Username: PPP authentication username
            - Password: PPP authentication password
            - ConnectionStatus: Current connection status
            - LastConnectionError: Last connection error code
            - MaxMRUSize: Maximum Receive Unit size
            - PPPoESessionID: PPPoE session identifier
            - PPPoEACName: PPPoE Access Concentrator name
            - PPPoEServiceName: PPPoE service name
            - RemoteIPAddress: Remote PPP endpoint IP
            - LocalIPAddress: Local PPP endpoint IP
            - LastChangeTime: Time since last status change
            - LastChange: Last change timestamp
            - DNSServers: DNS servers from PPP negotiation
            - TransportType: Transport protocol (e.g., "PPPoE")
            - LCPEcho: LCP echo interval
            - LCPEchoRetry: LCP echo retry count
            - IPCPEnable: Whether IPCP is enabled
            - IPv6CPEnable: Whether IPv6CP is enabled
            - IPv6CPLocalInterfaceIdentifier: Local IPv6 interface ID
            - IPv6CPRemoteInterfaceIdentifier: Remote IPv6 interface ID
            - ConnectionTrigger: Connection trigger mode
            - IdleDisconnectTime: Idle disconnect timeout
        """
        response = self._make_api_call(
            service="NeMo.Intf.data", method="getMIBs", parameters={"mibs": "ppp"}
        )

        # Extract PPP information from response
        if isinstance(response, dict) and "status" in response:
            ppp_data = self._status_dict(response).get("ppp")
            if not isinstance(ppp_data, dict):
                ppp_data = {}
            for ppp_interface, ppp_config in ppp_data.items():
                if isinstance(ppp_config, dict):
                    # Add interface name for reference
                    ppp_config["Interface"] = ppp_interface
                    return ppp_config

        return {}

    def get_connection_info(self) -> Dict[str, Any]:
        """
        Get comprehensive internet connection information (WAN + PPP).

        Returns:
            Dictionary with keys:
            - 'wan_status': WAN connection status
            - 'ppp_info': Detailed PPP connection information
        """
        return {"wan_status": self.get_wan_status(), "ppp_info": self.get_ppp_info()}

    def get_wwan_status(self) -> Dict[str, Any]:
        """
        Get WWAN (mobile internet backup) interface status and configuration.

        Returns:
            Dictionary with WWAN interface information including:
            - Name: Interface name ("wwan")
            - Enable: Whether WWAN interface is enabled
            - Status: Current status (True/False)
            - Flags: Interface flags
            - Alias: Interface alias (e.g., "cpe-wwan")
            - APN: Access Point Name (e.g., "basicinternet")
            - PINCode: SIM PIN code (if configured)
            - Username: Authentication username
            - Password: Authentication password
            - AuthenticationMethod: Auth method (e.g., "chap")
            - DNSServers: DNS servers for mobile connection
            - IPRouter: Gateway IP address
            - LocalIPAddress: Assigned local IP address
            - ConnectionStatus: Connection status (e.g., "NotPresent", "Connected")
            - ConnectionError: Last connection error
            - ConnectionErrorSource: Source of connection error
            - AutoConnection: Whether auto-connection is enabled
            - SignalStrength: Signal strength (0-100)
            - Technology: Mobile technology (e.g., "4G", "5G", "none")
            - Manufacturer: Modem manufacturer
            - Model: Modem model
            - IMEI: Device IMEI number
            - PinType: PIN type required
            - PinRetryCount: Remaining PIN retry attempts
            - PukRetryCount: Remaining PUK retry attempts
            - IMSI: SIM IMSI number
            - ICCID: SIM card identifier
            - MSISDN: Mobile number
            - LastChange: Last change timestamp
            - LastChangeTime: Last change time
            - TechnologyPreference: Preferred technology
            - NATEnabled: Whether NAT is enabled
            - MTU: Maximum Transmission Unit
            - IPv4Forwarding: Whether IPv4 forwarding is enabled
            - IPv6Disable: Whether IPv6 is disabled
            - And other network interface settings
        """
        response = self._make_api_call(
            service="NeMo.Intf.wwan", method="get", parameters={}
        )

        return self._status_dict(response)

    def is_connected(self) -> bool:
        """
        Check if the internet connection is active.

        Returns:
            True if connected to the internet, False otherwise
        """
        wan_status = self.get_wan_status()
        return wan_status.get("ConnectionState") == "Connected"

    def get_lan_ipv4_config(self) -> Dict[str, Any]:
        """
        Get LAN IPv4 network configuration.

        Returns:
            Dictionary with LAN IPv4 configuration including:
            - Address: LAN IPv4 address (e.g., "192.168.2.254")
            - PrefixLength: Network prefix length (e.g., 24)
            - DHCPEnable: Whether DHCP server is enabled
            - DHCPAuthoritative: Whether DHCP server is authoritative
            - DHCPMinAddress: DHCP range start address
            - DHCPMaxAddress: DHCP range end address
            - LeaseTime: DHCP lease time in seconds
            - DNSServers: DNS server addresses (comma-separated)
            - NTPServers: NTP server addresses (comma-separated)
            - DomainSearchList: Domain search list
            - Enable: Whether IPv4 is enabled
            - AllowPublic: Whether public access is allowed
            - NATEnable: Whether NAT is enabled
        """
        response = self._make_api_call(
            service="NetMaster.LAN.default.Bridge.lan", method="getIPv4", parameters={}
        )

        return self._data_dict(response) or self._status_dict(response)

    def get_lan_ipv6_config(self) -> Dict[str, Any]:
        """
        Get LAN IPv6 network configuration.

        Returns:
            Dictionary with LAN IPv6 configuration including:
            - Address: LAN IPv6 address
            - PrefixLength: Network prefix length
            - Intf: Interface name (e.g., "data")
            - SubnetOffset: Subnet offset value
            - DHCPEnable: Whether DHCPv6 server is enabled
            - DHCPIAPDEnable: Whether DHCPv6 Identity Association for Prefix Delegation is enabled
            - DHCPIANAEnable: Whether DHCPv6 Identity Association for Non-temporary Addresses is enabled
            - DNSServers: IPv6 DNS server addresses (comma-separated)
            - NTPServers: IPv6 NTP server addresses (comma-separated)
            - Enable: Whether IPv6 is enabled
        """
        response = self._make_api_call(
            service="NetMaster.LAN.default.Bridge.lan",
            method="getIPv6Configuration",
            parameters={"Name": "lan"},
        )

        return self._data_dict(response) or self._status_dict(response)

    def get_lan_config(self) -> Dict[str, Any]:
        """
        Get comprehensive LAN network configuration (both IPv4 and IPv6).

        Returns:
            Dictionary with keys:
            - 'ipv4': LAN IPv4 configuration
            - 'ipv6': LAN IPv6 configuration
        """
        return {"ipv4": self.get_lan_ipv4_config(), "ipv6": self.get_lan_ipv6_config()}

    def get_dns_servers(self) -> Dict[str, str]:
        """
        Get DNS server configuration for both IPv4 and IPv6.

        Returns:
            Dictionary with keys:
            - 'ipv4': IPv4 DNS servers (comma-separated)
            - 'ipv6': IPv6 DNS servers (comma-separated)
        """
        lan_config = self.get_lan_config()

        return {
            "ipv4": lan_config["ipv4"].get("DNSServers", ""),
            "ipv6": lan_config["ipv6"].get("DNSServers", ""),
        }

    def set_lan_ipv4_config(
        self,
        network: str = "lan",
        dns_servers: Optional[str] = None,
        address: Optional[str] = None,
        dhcp_enabled: Optional[bool] = None,
        dhcp_min_address: Optional[str] = None,
        dhcp_max_address: Optional[str] = None,
        prefix_length: Optional[int] = None,
    ) -> bool:
        """
        Configure LAN IPv4 settings including DNS servers and DHCP.

        Args:
            network: Network to configure - "lan" (default) or "guest"
            dns_servers: DNS servers (comma-separated, e.g., "9.9.9.9,149.112.112.112")
            address: LAN gateway IP address (e.g., "192.168.2.254")
            dhcp_enabled: Whether to enable DHCP server
            dhcp_min_address: DHCP range start (e.g., "192.168.2.100")
            dhcp_max_address: DHCP range end (e.g., "192.168.2.200")
            prefix_length: Network prefix length (e.g., 24 for /24)

        Returns:
            True if successful (returns {"status": null} on success)
        """
        if network not in ["lan", "guest"]:
            raise ValueError("network must be 'lan' or 'guest'")

        # Get current configuration first
        if network == "lan":
            current_config = self.get_lan_ipv4_config()
        else:
            # For guest network, we'll use sensible defaults
            current_config = {
                "Address": "192.168.3.254",
                "DHCPEnable": True,
                "DHCPMinAddress": "192.168.3.1",
                "DHCPMaxAddress": "192.168.3.32",
                "PrefixLength": 24,
            }

        # Build parameters with current values as defaults
        parameters = {
            "DNSServers": dns_servers or current_config.get("DNSServers", ""),
            "Address": address or current_config.get("Address", ""),
            "DHCPEnable": dhcp_enabled
            if dhcp_enabled is not None
            else current_config.get("DHCPEnable", True),
            "DHCPMinAddress": dhcp_min_address
            or current_config.get("DHCPMinAddress", ""),
            "DHCPMaxAddress": dhcp_max_address
            or current_config.get("DHCPMaxAddress", ""),
            "PrefixLength": prefix_length
            if prefix_length is not None
            else current_config.get("PrefixLength", 24),
        }

        result = self._make_api_call(
            service=f"NetMaster.LAN.default.Bridge.{network}",
            method="setIPv4",
            parameters=parameters,
        )

        # For these DNS/LAN config calls, success returns {"status": null}
        return self._succeeded(result)

    def set_lan_ipv6_config(
        self, network: str = "lan", dns_servers: Optional[str] = None
    ) -> bool:
        """
        Configure LAN IPv6 DNS servers.

        Args:
            network: Network to configure - "lan" (default) or "guest"
            dns_servers: IPv6 DNS servers (comma-separated, e.g., "2620:fe::fe,2620:fe::9")

        Returns:
            True if successful (returns {"status": null} on success)
        """
        if network not in ["lan", "guest"]:
            raise ValueError("network must be 'lan' or 'guest'")

        if dns_servers is None:
            raise ValueError("dns_servers parameter is required")

        parameters = {"DNSServers": dns_servers, "Name": network}

        result = self._make_api_call(
            service=f"NetMaster.LAN.default.Bridge.{network}",
            method="setIPv6Configuration",
            parameters=parameters,
        )

        # For these DNS/LAN config calls, success returns {"status": null}
        return self._succeeded(result)

    def set_dns_servers(
        self,
        ipv4_dns: Optional[str] = None,
        ipv6_dns: Optional[str] = None,
        network: str = "lan",
    ) -> Dict[str, bool]:
        """
        Set DNS servers for both IPv4 and IPv6 on specified network.

        Args:
            ipv4_dns: IPv4 DNS servers (comma-separated, e.g., "9.9.9.9,149.112.112.112")
            ipv6_dns: IPv6 DNS servers (comma-separated, e.g., "2620:fe::fe,2620:fe::9")
            network: Network to configure - "lan" (default) or "guest"

        Returns:
            Dictionary with 'ipv4' and 'ipv6' keys indicating success for each
        """
        results = {}

        if ipv4_dns is not None:
            results["ipv4"] = self.set_lan_ipv4_config(
                network=network, dns_servers=ipv4_dns
            )

        if ipv6_dns is not None:
            results["ipv6"] = self.set_lan_ipv6_config(
                network=network, dns_servers=ipv6_dns
            )

        return results

    def get_netmaster_config(self) -> Dict[str, Any]:
        """
        Get NetMaster network configuration settings.

        Returns:
            Dictionary with network master configuration including:
            - EnableInterfaces: Whether interfaces are enabled
            - EnableIPv6: Whether IPv6 is globally enabled
            - IPv6PrefixMode: IPv6 prefix mode (e.g., "RA" for Router Advertisement)
            - DisablePhysicalInterfaces: Whether physical interfaces are disabled
            - WANMode: WAN connection mode (e.g., "Ethernet_PPP")
        """
        response = self._make_api_call(service="NetMaster", method="get", parameters={})

        return self._status_dict(response)

    def set_ipv6_enabled(
        self, enabled: bool = True, prefix_mode: str = "DHCPv6"
    ) -> bool:
        """
        Enable or disable IPv6 globally on the router.

        Args:
            enabled: Whether to enable IPv6 (default: True)
            prefix_mode: IPv6 prefix mode when enabling - "DHCPv6" or "RA" (default: "DHCPv6")

        Returns:
            True if successful
        """
        if prefix_mode not in ["DHCPv6", "RA"]:
            raise ValueError("prefix_mode must be 'DHCPv6' or 'RA'")

        result = self._make_api_call(
            service="NetMaster",
            method="set",
            parameters={
                "EnableIPv6": 1 if enabled else 0,
                "IPv6PrefixMode": prefix_mode,
            },
        )

        return self._is_true(result)

    def set_ipv6_prefix_delegation(self, mode: str = "off") -> bool:
        """
        Configure IPv6 prefix delegation settings.

        Args:
            mode: IPv6 prefix delegation mode - "off", "on", or "on_with_dhcpv6" (default: "off")

        Returns:
            True if all configuration calls were successful

        Raises:
            ValueError: If mode is not valid
        """
        if mode not in ["off", "on", "on_with_dhcpv6"]:
            raise ValueError("mode must be 'off', 'on', or 'on_with_dhcpv6'")

        success_count = 0
        total_calls = 0

        if mode == "off":
            # Off: Disable prefix delegation
            # 1. Disable IAPD on LAN interface
            result1 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan",
                method="setIPv6Configuration",
                parameters={"Name": "lan", "DHCPIAPDEnable": 0},
            )
            total_calls += 1
            if self._succeeded(result1):  # status null indicates success
                success_count += 1

            # 2. Set IPv6 prefix mode to DHCPv6
            result2 = self._make_api_call(
                service="NetMaster",
                method="set",
                parameters={"EnableIPv6": 1, "IPv6PrefixMode": "DHCPv6"},
            )
            total_calls += 1
            if self._is_true(result2):
                success_count += 1

        elif mode == "on_with_dhcpv6":
            # On with DHCPv6: Enable with RAandDHCPv6 mode (4 requests)
            # 1. Enable IAPD on LAN interface
            result1 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan",
                method="setIPv6Configuration",
                parameters={"Name": "lan", "DHCPIAPDEnable": 1},
            )
            total_calls += 1
            if self._succeeded(result1):  # status null indicates success
                success_count += 1

            # 2. Set prefix length for lan DHCPv6
            result2 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan.IPv6.lan.DHCPv6",
                method="set",
                parameters={"IAPDPrefixLength": 56},
            )
            total_calls += 1
            if self._is_true(result2):
                success_count += 1

            # 3. Set prefix length for guest DHCPv6
            result3 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.guest.IPv6.guest.DHCPv6",
                method="set",
                parameters={"IAPDPrefixLength": 56},
            )
            total_calls += 1
            if self._is_true(result3):
                success_count += 1

            # 4. Set IPv6 prefix mode to RAandDHCPv6
            result4 = self._make_api_call(
                service="NetMaster",
                method="set",
                parameters={"EnableIPv6": 1, "IPv6PrefixMode": "RAandDHCPv6"},
            )
            total_calls += 1
            if self._is_true(result4):
                success_count += 1

        elif mode == "on":
            # On: Enable with RA mode (4 requests)
            # 1. Set prefix length for lan DHCPv6
            result1 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan.IPv6.lan.DHCPv6",
                method="set",
                parameters={"IAPDPrefixLength": 56},
            )
            total_calls += 1
            if self._is_true(result1):
                success_count += 1

            # 2. Enable IAPD on LAN interface
            result2 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan",
                method="setIPv6Configuration",
                parameters={"Name": "lan", "DHCPIAPDEnable": 1},
            )
            total_calls += 1
            if self._succeeded(result2):  # status null indicates success
                success_count += 1

            # 3. Set prefix length for guest DHCPv6
            result3 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.guest.IPv6.guest.DHCPv6",
                method="set",
                parameters={"IAPDPrefixLength": 56},
            )
            total_calls += 1
            if self._is_true(result3):
                success_count += 1

            # 4. Set IPv6 prefix mode to RA
            result4 = self._make_api_call(
                service="NetMaster",
                method="set",
                parameters={"EnableIPv6": 1, "IPv6PrefixMode": "RA"},
            )
            total_calls += 1
            if self._is_true(result4):
                success_count += 1

        return success_count == total_calls

    def disable_ipv6_prefix_delegation(self) -> bool:
        """
        Disable IPv6 prefix delegation.

        Returns:
            True if successful
        """
        return self.set_ipv6_prefix_delegation("off")

    def enable_ipv6_prefix_delegation(self, use_dhcpv6: bool = False) -> bool:
        """
        Enable IPv6 prefix delegation.

        Args:
            use_dhcpv6: Whether to enable with DHCPv6 mode (True) or RA mode (False, default)

        Returns:
            True if successful
        """
        mode = "on_with_dhcpv6" if use_dhcpv6 else "on"
        return self.set_ipv6_prefix_delegation(mode)

    def configure_ipv6_prefix_delegation(
        self, enabled: bool = True, use_dhcpv6: bool = False, prefix_length: int = 56
    ) -> bool:
        """
        Comprehensive IPv6 prefix delegation configuration.

        Args:
            enabled: Whether to enable prefix delegation (default: True)
            use_dhcpv6: Whether to enable DHCPv6 mode when enabling (default: False = RA mode)
            prefix_length: Prefix length for delegation (default: 56)

        Returns:
            True if successful
        """
        if not enabled:
            return self.disable_ipv6_prefix_delegation()

        # For now, we only support prefix length 56 as per the API examples
        if prefix_length != 56:
            raise ValueError("Only prefix length 56 is currently supported")

        mode = "on_with_dhcpv6" if use_dhcpv6 else "on"
        return self.set_ipv6_prefix_delegation(mode)

    def get_dhcpv6_client_status(self) -> Dict[str, Any]:
        """
        Get DHCPv6 client status (router acting as DHCPv6 client to ISP).

        Returns:
            Dictionary with DHCPv6 client information including:
            - Name: Interface name (e.g., "dhcpv6_pdata")
            - Enable: Whether DHCPv6 client is enabled
            - Status: Current status (True/False)
            - Flags: Status flags (e.g., "dhcpv6 enabled up")
            - Alias: Interface alias
            - DHCPStatus: DHCP status (e.g., "Bound", "Requesting")
            - LastConnectionError: Last connection error (e.g., "RenewTimeout")
            - Uptime: Client uptime in seconds
            - DSCPMark: DSCP marking value
            - DUID: DHCP Unique Identifier
            - RequestAddresses: Whether requesting individual addresses
            - RequestPrefixes: Whether requesting prefix delegation
            - RapidCommit: Whether using rapid commit
            - IAID: Identity Association Identifier
            - SuggestedT1: Suggested renewal time (-1 = not set)
            - SuggestedT2: Suggested rebind time (-1 = not set)
            - SupportedOptions: Supported DHCP options
            - RequestedOptions: Requested DHCP options (comma-separated)
            - Reason: Status reason
            - Renew: Whether currently renewing
            - ResetOnPhysDownTimeout: Reset timeout on physical down
            - CheckAuthentication: Whether checking authentication
            - AuthenticationInfo: Authentication information
            - RetryOnFailedAuth: Whether retrying on failed authentication
        """
        response = self._make_api_call(
            service="NeMo.Intf.dhcpv6_pdata", method="get", parameters={}
        )

        return self._status_dict(response)

    def get_iptv_ip(self) -> str:
        """
        Get the IP address of the IPTV interface.

        Returns:
            IPTV interface IP address as string (e.g., "10.233.241.178")
        """
        response = self._make_api_call(
            service="NeMo.Intf.iptv",
            method="luckyAddrAddress",
            parameters={"flag": "ipv4", "traverse": "down"},
        )

        return self._status_str(response)
