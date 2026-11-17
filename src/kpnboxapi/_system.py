"""Router info, time, diagnostics, telephony and system maintenance."""

from typing import Any, Dict, List, Optional

from ._base import KPNBoxBase


class SystemMixin(KPNBoxBase):
    """Router info, time, diagnostics, telephony and system maintenance."""

    def get_device_info(self) -> Dict[str, Any]:
        """
        Get information about the KPN Box modem itself.

        Returns:
            Dictionary with modem information including:
            - Manufacturer: Modem manufacturer
            - ModelName: Modem model
            - SerialNumber: Modem serial number
            - SoftwareVersion: Current firmware version
            - HardwareVersion: Hardware version
            - UpTime: Modem uptime in seconds
            - ExternalIPAddress: External/WAN IP address
            - DeviceStatus: Current device status
            - BaseMAC: Modem base MAC address
            - And other modem details
        """
        response = self._make_api_call(
            service="DeviceInfo", method="get", parameters=""
        )

        if isinstance(response, dict) and "status" not in response:
            return response
        return self._status_dict(response)

    def format_bytes(self, bytes_count: int) -> str:
        """
        Helper method to format byte counts in human-readable format.

        Args:
            bytes_count: Number of bytes

        Returns:
            Formatted string (e.g., "1.2 GB", "45.6 MB")
        """
        size = float(bytes_count)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def get_hgw_device_info(self) -> Dict[str, Any]:
        """
        Get detailed Home Gateway (HGW) device information.

        Returns:
            Dictionary with comprehensive HGW device information including:
            - Key: Device key (MAC address)
            - DiscoverySource: How device was discovered (e.g., "selfhgw")
            - Name: Device name
            - DeviceType: Device type ("SAH HGW")
            - Active: Whether device is active
            - Tags: Device tags (space-separated)
            - FirstSeen: First discovery timestamp
            - LastConnection: Last connection timestamp
            - LastChanged: Last change timestamp
            - Master: Master device identifier
            - Location: Device location
            - Owner: Device owner
            - Manufacturer: Device manufacturer (e.g., "Arcadyan")
            - ModelName: Device model (e.g., "BoxV14")
            - Description: Device description
            - SerialNumber: Device serial number
            - ProductClass: Product class
            - HardwareVersion: Hardware version
            - SoftwareVersion: Software/firmware version
            - BootLoaderVersion: Bootloader version
            - FirewallLevel: Current firewall level
            - LinkType: Link type (e.g., "ethernet")
            - LinkState: Link state (e.g., "up", "down")
            - ConnectionProtocol: Connection protocol (e.g., "ppp")
            - ConnectionState: Connection state (e.g., "Connected")
            - LastConnectionError: Last connection error
            - ConnectionIPv4Address: Current public IPv4 address
            - ConnectionIPv6Address: Current public IPv6 address
            - RemoteGateway: ISP gateway address
            - DNSServers: DNS servers (comma-separated)
            - Internet: Whether internet is available
            - IPTV: Whether IPTV service is available
            - Telephony: Whether telephony service is available
            - IPAddress: Local IP address
            - IPAddressSource: IP address source (e.g., "Static")
            - Index: Device index
            - Actions: Available device actions
            - Alternative: Alternative device identifiers
            - Locations: Device locations
            - Groups: Device groups
            - SSW: SSW (Smart Service Wrapper) information
            - IPv4Address: List of IPv4 addresses
            - IPv6Address: List of IPv6 addresses with details
            - Names: List of device names from different sources
            - DeviceTypes: List of device types from different sources
        """
        response = self._make_api_call(
            service="Devices.Device.HGW", method="get", parameters={}
        )

        return self._status_dict(response)

    def get_router_time(self) -> str:
        """
        Get the current time from the router.

        Returns:
            Current time as string (e.g., "Wed, 04 Jun 2025 19:50:34 GMT+0200")
        """
        response = self._make_api_call(service="Time", method="getTime", parameters="")

        # The time is in data.time; older firmware answers with a status string
        time = self._data_dict(response).get("time")
        if isinstance(time, str) and time:
            return time
        return self._status_str(response)

    def get_ntp_servers(self) -> Dict[str, str]:
        """
        Get configured NTP (Network Time Protocol) servers.

        Returns:
            Dictionary with NTP servers where keys are server numbers and values are server addresses.
            Example: {"1": "time.kpn.net", "2": "0.nl.pool.ntp.org", ...}
        """
        response = self._make_api_call(
            service="Time", method="getNTPServers", parameters=""
        )

        servers = self._data_dict(response).get("servers")
        return servers if isinstance(servers, dict) else {}

    def get_ntp_servers_list(self) -> List[str]:
        """
        Get configured NTP servers as a list.

        Returns:
            List of NTP server addresses (e.g., ["time.kpn.net", "0.nl.pool.ntp.org", ...])
        """
        ntp_servers = self.get_ntp_servers()
        return list(ntp_servers.values())

    def get_time_config(self) -> Dict[str, Any]:
        """
        Get comprehensive time configuration including current time and NTP servers.

        Returns:
            Dictionary with keys:
            - 'current_time': Current router time
            - 'ntp_servers': Dictionary of NTP servers
            - 'ntp_servers_list': List of NTP server addresses
        """
        return {
            "current_time": self.get_router_time(),
            "ntp_servers": self.get_ntp_servers(),
            "ntp_servers_list": self.get_ntp_servers_list(),
        }

    def run_download_speedtest(self) -> Dict[str, Any]:
        """
        Run a download speed test using KPN's speed test service.

        Note: This test takes several seconds to complete and will consume bandwidth.

        Returns:
            Dictionary with download speed test results including:
            - RetrievedStartTS: Test start timestamp (ISO format)
            - RetrievedTS: Test end timestamp (ISO format)
            - testserver: Speed test server used (e.g., "speedtests.kpn.com")
            - interface: Network interface used (e.g., "data")
            - latency: Network latency in milliseconds
            - suite: Test suite used (e.g., "BCMSpeedSvc")
            - duration: Test duration in milliseconds
            - rxbytes: Total bytes received during test
            - throughput: Download throughput in bits per second
        """
        response = self._make_api_call(
            service="SpeedTest.Diagnostics.Download",
            method="runDiagnostics",
            parameters="",
        )

        return self._status_dict(response)

    def run_upload_speedtest(self) -> Dict[str, Any]:
        """
        Run an upload speed test using KPN's speed test service.

        Note: This test takes several seconds to complete and will consume bandwidth.

        Returns:
            Dictionary with upload speed test results including:
            - RetrievedStartTS: Test start timestamp (ISO format)
            - RetrievedTS: Test end timestamp (ISO format)
            - testserver: Speed test server used (e.g., "speedtests.kpn.com")
            - interface: Network interface used (e.g., "data")
            - latency: Network latency in milliseconds
            - suite: Test suite used (e.g., "BCMSpeedSvc")
            - duration: Test duration in milliseconds
            - rxbytes: Total bytes sent during test
            - throughput: Upload throughput in bits per second
        """
        response = self._make_api_call(
            service="SpeedTest.Diagnostics.Upload",
            method="runDiagnostics",
            parameters="",
        )

        return self._status_dict(response)

    def run_full_speedtest(self) -> Dict[str, Any]:
        """
        Run both download and upload speed tests sequentially.

        Note: This test takes 10+ seconds to complete and will consume significant bandwidth.

        Returns:
            Dictionary with keys:
            - 'download': Download speed test results
            - 'upload': Upload speed test results
        """
        return {
            "download": self.run_download_speedtest(),
            "upload": self.run_upload_speedtest(),
        }

    def format_speed(self, kilobits_per_second: int) -> str:
        """
        Helper method to format speed in human-readable format.

        Args:
            kilobits_per_second: Speed in kilobits per second (as returned by KPN Box API)

        Returns:
            Formatted speed string (e.g., "100.5 Mbps", "1.2 Gbps")
        """
        # Convert from kilobits per second to more readable units
        if kilobits_per_second >= 1_000_000:  # Gbps
            return f"{kilobits_per_second / 1_000_000:.1f} Gbps"
        elif kilobits_per_second >= 1_000:  # Mbps
            return f"{kilobits_per_second / 1_000:.1f} Mbps"
        else:
            return f"{kilobits_per_second} Kbps"

    def run_traceroute(self, host: str, ip_version: str = "IPv4") -> Dict[str, Any]:
        """
        Run a traceroute diagnostic to a target host.

        Args:
            host: Target hostname or IP address (e.g., "www.google.com", "8.8.8.8")
            ip_version: IP version to use - "IPv4", "IPv6", or "Any" (default: "IPv4")

        Returns:
            Dictionary with traceroute results including:
            - DiagnosticState: Test state ("Complete", "Error", "InProgress")
            - Interface: Network interface used
            - ProtocolVersion: IP version used ("IPv4" or "IPv6")
            - Host: Target hostname or IP
            - NumberOfTries: Number of attempts per hop (default: 3)
            - Timeout: Timeout per hop in milliseconds (default: 5000)
            - DataBlockSize: Packet size in bytes
            - DSCP: DSCP marking value
            - MaxHopCount: Maximum number of hops (default: 30)
            - IPAddressUsed: Resolved IP address of target
            - ResponseTime: Total test duration in milliseconds
            - RouteHopsNumberOfEntries: Number of hops in route
            - RouteHops: Dictionary of hop information with keys:
              - Host: Reverse DNS hostname (may be empty)
              - HostAddress: IP address of hop router
              - ErrorCode: Error code (0=success, 11=TTL exceeded, 4294967295=no response)
              - RTTimes: Round-trip times in milliseconds (comma-separated, e.g., "18,2,2")

        Raises:
            ValueError: If ip_version is not "IPv4", "IPv6", or "Any"
        """
        if ip_version not in ["IPv4", "IPv6", "Any"]:
            raise ValueError("ip_version must be 'IPv4', 'IPv6', or 'Any'")

        response = self._make_api_call(
            service="Traceroute",
            method="start_diagnostic",
            parameters={"host": host, "ipversion": ip_version},
        )

        return self._status_dict(response)

    def run_ping(self, host: str, protocol_version: str = "Any") -> Dict[str, Any]:
        """
        Run a ping diagnostic to a target host.

        Args:
            host: Target hostname or IP address (e.g., "www.google.com", "8.8.8.8")
            protocol_version: Protocol version - "Any", "IPv4", or "IPv6" (default: "Any")

        Returns:
            Dictionary with ping results including:
            - DiagnosticsState: Test state ("Success", "Error", "InProgress")
            - ipHost: Resolved IP address of target
            - packetsSuccess: Number of successful ping packets
            - packetsFailed: Number of failed ping packets
            - packetSize: Size of ping packets in bytes
            - averageResponseTime: Average response time in milliseconds
            - minimumResponseTime: Minimum response time in milliseconds
            - maximumResponseTime: Maximum response time in milliseconds

        Raises:
            ValueError: If protocol_version is not "Any", "IPv4", or "IPv6"
        """
        if protocol_version not in ["Any", "IPv4", "IPv6"]:
            raise ValueError("protocol_version must be 'Any', 'IPv4', or 'IPv6'")

        response = self._make_api_call(
            service="IPPingDiagnostics",
            method="execDiagnostic",
            parameters={"ipHost": host, "ProtocolVersion": protocol_version},
        )

        return self._status_dict(response)

    def get_voice_profiles(self) -> Dict[str, Any]:
        """
        Get voice service profiles configuration.

        Returns:
            Dictionary with voice profiles including:
            - SIP-Trunk1-4: SIP trunk profiles
            - ATA: Analog Telephone Adapter profile
            - SIP-Extensions: SIP extensions profile
            Each profile contains Name and other configuration details
        """
        response = self._make_api_call(
            service="VoiceService.VoiceApplication.VoiceProfile",
            method="get",
            parameters={},
        )

        return self._status_dict(response)

    def get_voice_trunks(self) -> List[Dict[str, Any]]:
        """
        Get SIP trunk configurations for telephone service.

        Returns:
            List of SIP trunk dictionaries with fields:
            - name: Trunk name (e.g., "SIP-Trunk1")
            - trunkName: Trunk identifier
            - signalingProtocol: Protocol used ("SIP")
            - enable: Whether trunk is enabled ("Enabled"/"Disabled")
            - dtmfMethod: DTMF method (e.g., "RFC2833")
            - trunk_lines: List of trunk lines with details:
              - name: Line name (e.g., "LINE11")
              - enable: Line enable status
              - status: Line status
              - directoryNumber: Phone number
              - uri: SIP URI
              - authUserName: Authentication username
              - friendlyName: Display name
            - sip: SIP configuration:
              - proxyServer: SIP proxy server
              - proxyServerPort: Proxy port (default: 5060)
              - registrarServer: SIP registrar server
              - userAgentDomain: User agent domain
              - sessionExpire: Session expiration time
            - rtp: RTP configuration:
              - localPortMin: Minimum local port
              - localPortMax: Maximum local port
        """
        response = self._make_api_call(
            service="VoiceService.VoiceApplication", method="listTrunks", parameters={}
        )

        return self._status_list(response)

    def get_voice_groups(self) -> List[Dict[str, Any]]:
        """
        Get voice groups configuration.

        Returns:
            List of voice group dictionaries with fields:
            - group_id: Group identifier (e.g., "Group1")
            - ep_names: List of endpoint names in the group
        """
        response = self._make_api_call(
            service="VoiceService.VoiceApplication", method="listGroups", parameters={}
        )

        return self._status_list(response)

    def get_voice_handsets(self) -> List[Dict[str, Any]]:
        """
        Get voice handsets/endpoints configuration.

        Returns:
            List of handset dictionaries with fields:
            - line: Line identifier (e.g., "FXS1", "Account1")
            - name: Handset name
            - enable: Whether handset is enabled ("Enabled"/"Disabled")
            - status: Current status ("Up"/"Down"/"Disabled")
            - directoryNumber: Phone number or extension
            - endpointType: Type of endpoint ("FXS", "SIP")
            - dtmfMethod: DTMF method ("Inherit" or specific)
            - outgoingTrunkLine: Associated trunk line
            - outgoingSubscriberNumberId: Subscriber number ID
            - callWaitingEnable: Whether call waiting is enabled
            - sipExtensionIPAddress: SIP extension IP (for SIP endpoints)
            - authUserName: Authentication username (for SIP endpoints)
        """
        response = self._make_api_call(
            service="VoiceService.VoiceApplication",
            method="listHandsets",
            parameters={},
        )

        return self._status_list(response)

    def ring_test_phone(self) -> bool:
        """
        Ring the phone for testing purposes.

        Returns:
            True if ring test command was sent successfully
        """
        response = self._make_api_call(
            service="VoiceService.VoiceApplication", method="ring", parameters={}
        )

        # For this function, success returns {"status": null}
        return self._succeeded(response)

    def set_ntp_servers(self, servers: Dict[str, str]) -> bool:
        """
        Configure NTP (Network Time Protocol) servers.

        Args:
            servers: Dictionary mapping server numbers to server addresses
                    Example: {
                        "1": "time.kpn.net",
                        "2": "0.nl.pool.ntp.org",
                        "3": "1.nl.pool.ntp.org",
                        "4": "2.nl.pool.ntp.org",
                        "5": "3.nl.pool.ntp.org"
                    }

        Returns:
            True if successful

        Note:
            - Server numbers should be strings ("1", "2", etc.)
            - You can configure up to 5 NTP servers
            - Common NTP servers: time.kpn.net, pool.ntp.org servers
        """
        if not servers or not isinstance(servers, dict):
            raise ValueError("servers must be a non-empty dictionary")

        result = self._make_api_call(
            service="Time", method="setNTPServers", parameters={"servers": servers}
        )

        # The router answers with a null status, so success means "no errors reported"
        return not self._has_errors(result)

    def change_password(
        self, new_password: str, old_password: str, username: str = "admin"
    ) -> bool:
        """
        Change the login password for a user account.

        Args:
            new_password: The new password to set
            old_password: The current password for authentication
            username: Username to change password for (default: "admin")

        Returns:
            True if password change was successful

        Raises:
            ValueError: If required parameters are missing

        Note:
            - New password should be strong (recommended: 8+ chars with mixed case, numbers, symbols)
            - You must provide the correct current password
            - After changing password, you'll need to login again with the new password
        """
        if not new_password:
            raise ValueError("new_password is required")
        if not old_password:
            raise ValueError("old_password is required")
        if not username:
            raise ValueError("username is required")

        result = self._make_api_call(
            service="UserManagement",
            method="changePasswordSec",
            parameters={
                "name": username,
                "password": new_password,
                "old_password": old_password,
            },
        )

        changed = self._is_true(result)
        if changed and username == self._username:
            # Keep automatic re-login working with the new password
            self._password = new_password
        return changed

    def reboot_system(self, reason: str = "API reboot") -> bool:
        """
        Reboot the KPN Box system.

        Args:
            reason: Reason for the reboot (default: "API reboot")

        Returns:
            True if reboot command was sent successfully

        Warning:
            This will reboot the entire KPN Box router. All network connections
            will be temporarily lost during the reboot process (typically 2-3 minutes).
        """
        result = self._make_api_call(
            service="NMC", method="reboot", parameters={"reason": reason}
        )

        # The router does not confirm these commands; success means "accepted without errors"
        return not self._has_errors(result)

    def factory_reset_system(self, reason: str = "API reset") -> bool:
        """
        Perform a factory reset of the entire KPN Box system.

        Args:
            reason: Reason for the factory reset (default: "API reset")

        Returns:
            True if factory reset command was sent successfully

        Warning:
            This will completely reset the KPN Box to factory defaults!
            ALL settings will be lost including:
            - WiFi passwords and network names
            - Port forwarding rules
            - Device schedules and restrictions
            - DHCP reservations
            - All custom configurations
            Use with extreme caution!
        """
        result = self._make_api_call(
            service="NMC", method="reset", parameters={"reason": reason}
        )

        # The router does not confirm these commands; success means "accepted without errors"
        return not self._has_errors(result)

    def factory_reset_wifi(self) -> bool:
        """
        Perform a factory reset of WiFi settings only.

        Returns:
            True if WiFi factory reset command was sent successfully

        Warning:
            This will reset ALL WiFi settings to factory defaults including:
            - WiFi network names (SSIDs)
            - WiFi passwords
            - WiFi security settings
            - Guest network configuration
            - WiFi scheduling settings
            You will need to reconfigure WiFi after this operation!
        """
        result = self._make_api_call(
            service="NMC.Wifi", method="wififactoryReset", parameters={}
        )

        # The router does not confirm these commands; success means "accepted without errors"
        return not self._has_errors(result)

    def restart_home_network(self, reason: str = "API reboot") -> bool:
        """
        Restart the home network group function.

        Args:
            reason: Reason for the restart (default: "API reboot")

        Returns:
            True if restart command was sent successfully

        Note:
            This restarts network services without a full system reboot.
            May cause temporary network disruption.
        """
        result = self._make_api_call(
            service="NMC.GroupFunction", method="reboot", parameters={"reason": reason}
        )

        # The router does not confirm these commands; success means "accepted without errors"
        return not self._has_errors(result)

    def factory_reset_home_network(self, reason: str = "API reset") -> bool:
        """
        Perform a factory reset of home network settings.

        Args:
            reason: Reason for the factory reset (default: "API reset")

        Returns:
            True if factory reset command was sent successfully

        Warning:
            This will reset home network settings to factory defaults including:
            - Network configuration
            - DHCP settings
            - Port forwarding rules
            - Device schedules and restrictions
            - Network security settings
            Use with caution!
        """
        result = self._make_api_call(
            service="NMC.GroupFunction",
            method="factoryReset",
            parameters={"reason": reason},
        )

        # The router does not confirm these commands; success means "accepted without errors"
        return not self._has_errors(result)

    def get_system_stats(self, device_mac: Optional[str] = None) -> Dict[str, Any]:
        """
        Get system CPU and RAM statistics from the KPN Box router.

        Args:
            device_mac: MAC address of the device to monitor (default: auto-detect router MAC)

        Returns:
            Dictionary containing system statistics:
            - timestamp: ISO timestamp of the data
            - uptime_seconds: System uptime in seconds
            - uptime_formatted: Human-readable uptime
            - load_average: Dict with 1min, 5min, 15min load averages (normalized 0-100%)
            - memory: Dict with RAM statistics in bytes and percentages
            - swap: Dict with swap statistics
            - processes: Number of running processes

        Note:
            If device_mac is not provided, attempts to auto-detect the router's MAC address.
            Load averages are normalized from raw values to percentages (0-100).
        """
        # If no MAC provided, use the router's own MAC address
        if not device_mac:
            device_mac = self.get_hgw_device_info().get("Key", "")
            if not device_mac:
                raise ValueError(
                    "Could not auto-detect router MAC address. Please provide device_mac parameter."
                )

        # Clean MAC address format
        device_mac = device_mac.replace("-", ":").upper()

        result = self._make_api_call(
            service="eventmanager",
            method="get_events",
            parameters={
                "events": [
                    {"service": f"Devices.Device.{device_mac}", "event": "cpu"},
                    {
                        "service": f"Devices.Device.{device_mac}",
                        "event": "sysinfo",
                        "data": {"types": "sysinfo"},
                    },
                    {
                        "service": "Devices.Device.LAN",
                        "event": "network",
                        "data": {"types": "network"},
                    },
                ],
                "channelid": 0,
            },
        )

        events = self._status_dict(result).get("events")
        if not isinstance(events, list):
            return {}

        # Find the sysinfo event
        sysinfo_data = None
        for event in events:
            event_object = (
                (event.get("data") or {}).get("object")
                if isinstance(event, dict)
                else None
            )
            if (
                isinstance(event_object, dict)
                and event_object.get("reason") == "sysinfo"
            ):
                sysinfo_data = (event_object.get("attributes") or {}).get(device_mac)
                break

        if not isinstance(sysinfo_data, dict):
            return {}

        # Parse and format the data
        total_ram = sysinfo_data.get("totalram", 0)
        free_ram = sysinfo_data.get("freeram", 0)
        used_ram = total_ram - free_ram

        # Format uptime
        uptime_seconds = sysinfo_data.get("uptime", 0)
        days = uptime_seconds // 86400
        hours = (uptime_seconds % 86400) // 3600
        minutes = (uptime_seconds % 3600) // 60
        uptime_formatted = f"{days}d {hours}h {minutes}m"

        # Normalize load averages (divide by 1000 to get percentage-like values)
        load_1min = sysinfo_data.get("loadaverage_1min", 0) / 1000
        load_5min = sysinfo_data.get("loadaverage_5min", 0) / 1000
        load_15min = sysinfo_data.get("loadaverage_15min", 0) / 1000

        return {
            "timestamp": sysinfo_data.get("Timestamp", ""),
            "uptime_seconds": uptime_seconds,
            "uptime_formatted": uptime_formatted,
            "load_average": {
                "1min": round(load_1min, 1),
                "5min": round(load_5min, 1),
                "15min": round(load_15min, 1),
            },
            "memory": {
                "total_bytes": total_ram,
                "used_bytes": used_ram,
                "free_bytes": free_ram,
                "shared_bytes": sysinfo_data.get("sharedram", 0),
                "buffer_bytes": sysinfo_data.get("bufferram", 0),
                "cached_bytes": sysinfo_data.get("cachedram", 0),
                "used_percentage": round((used_ram / total_ram * 100), 1)
                if total_ram > 0
                else 0,
                "free_percentage": round((free_ram / total_ram * 100), 1)
                if total_ram > 0
                else 0,
            },
            "swap": {
                "total_bytes": sysinfo_data.get("totalswap", 0),
                "free_bytes": sysinfo_data.get("freeswap", 0),
            },
            "processes": sysinfo_data.get("procs", 0),
            "device_mac": device_mac,
        }

    def format_memory_size(self, bytes_value: int) -> str:
        """
        Format memory size from bytes to human-readable format.

        Args:
            bytes_value: Memory size in bytes

        Returns:
            Human-readable string (e.g., "1.5 GB", "512 MB")
        """
        if bytes_value == 0:
            return "0 B"

        units = ["B", "KB", "MB", "GB", "TB"]
        unit_index = 0
        size = float(bytes_value)

        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        return f"{size:.1f} {units[unit_index]}"
