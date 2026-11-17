"""Firewall: levels, custom rules, port forwarding, IPv6 pinholes, DMZ and UPnP."""

from typing import Any, Dict, List, Optional, Union

from ._base import KPNBoxBase
from ._utils import (
    validate_protocol,
)
from .exceptions import APIError


def _rule_id(result: Any, default: str) -> str:
    """The rule ID the router reports for a saved rule, or "" if it refused.

    ``default`` is used when the router accepts the rule without echoing an ID.
    """
    if not isinstance(result, dict):
        return default
    if result.get("errors") or result.get("status") is False:
        return ""

    status = result.get("status")
    if isinstance(status, str) and status:
        return status

    data = result.get("data")
    rule = data.get("rule") if isinstance(data, dict) else None
    if isinstance(rule, dict) and isinstance(rule.get("Id"), str):
        return rule["Id"]
    return default


class FirewallMixin(KPNBoxBase):
    """Firewall: levels, custom rules, port forwarding, IPv6 pinholes, DMZ and UPnP."""

    def get_port_forwarding(self, origin: str = "webui") -> List[Dict[str, Any]]:
        """
        Get firewall port forwarding rules.

        Args:
            origin: Rule origin filter - "webui", "upnp", or other origin (default: "webui")

        Returns:
            List of port forwarding rule dictionaries with fields:
            - Id: Rule identifier
            - Origin: Rule origin (e.g., "webui", "upnp")
            - Description: Human-readable description
            - Status: Current status ("Enabled" or "Disabled")
            - Enable: Whether rule is enabled (True/False)
            - SourceInterface: Source interface (e.g., "data")
            - Protocol: Protocol numbers (6=TCP, 17=UDP, comma-separated)
            - ExternalPort: External port number
            - InternalPort: Internal port number
            - DestinationIPAddress: Target internal IP address
            - DestinationMACAddress: Target MAC address (if specified)
            - LeaseDuration: Rule lease duration in seconds
            - HairpinNAT: Whether hairpin NAT is enabled
            - SymmetricSNAT: Whether symmetric SNAT is enabled
            - UPnPV1Compat: Whether UPnP v1 compatibility is enabled
        """
        response = self._make_api_call(
            service="Firewall",
            method="getPortForwarding",
            parameters={"origin": origin},
        )

        rules = []

        # Extract port forwarding rules from response
        if isinstance(response, dict) and "status" in response:
            status_data = self._status_dict(response)
            for rule_data in status_data.values():
                if isinstance(rule_data, dict):
                    rules.append(rule_data)

        return rules

    def get_all_port_forwarding(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all port forwarding rules from different origins.

        Returns:
            Dictionary with keys for different origins (e.g., 'webui', 'upnp')
            containing their respective port forwarding rules.
        """
        all_rules = {}

        # Try common origins
        for origin in ["webui", "upnp"]:
            try:
                rules = self.get_port_forwarding(origin)
            except APIError:
                # Origin might not be supported
                continue
            if rules:  # Only include origins that have rules
                all_rules[origin] = rules

        return all_rules

    def get_active_port_forwarding(self, origin: str = "webui") -> List[Dict[str, Any]]:
        """
        Get only enabled port forwarding rules.

        Args:
            origin: Rule origin filter - "webui", "upnp", or other origin (default: "webui")

        Returns:
            List of enabled port forwarding rule dictionaries
        """
        all_rules = self.get_port_forwarding(origin)
        return [rule for rule in all_rules if rule.get("Enable", False)]

    def format_protocol(self, protocol_str: str) -> str:
        """
        Helper method to format protocol numbers into readable names.

        Args:
            protocol_str: Protocol string (e.g., "6,17" or "6")

        Returns:
            Formatted protocol string (e.g., "TCP,UDP" or "TCP")
        """
        protocol_map = {"6": "TCP", "17": "UDP"}

        if not protocol_str:
            return "Unknown"

        protocols = []
        for proto_num in protocol_str.split(","):
            proto_num = proto_num.strip()
            protocols.append(protocol_map.get(proto_num, f"Protocol-{proto_num}"))

        return ",".join(protocols)

    def get_ipv6_pinholes(self) -> List[Dict[str, Any]]:
        """
        Get IPv6 pinhole (port forwarding) rules.

        Returns:
            List of IPv6 pinhole rule dictionaries with fields:
            - Id: Rule identifier
            - Origin: Rule origin (e.g., "webui", "upnp")
            - Description: Human-readable description
            - Status: Current status ("Enabled" or "Disabled")
            - Enable: Whether rule is enabled (True/False)
            - SourceInterface: Source interface (e.g., "data")
            - Protocol: Protocol numbers (6=TCP, 17=UDP, comma-separated)
            - IPVersion: IP version (should be 6 for IPv6)
            - SourcePort: Source port filter (if specified)
            - DestinationPort: Destination port or port range
            - SourcePrefix: Source IP prefix filter (if specified)
            - DestinationIPAddress: Target IPv6 address
            - DestinationMACAddress: Target MAC address (if specified)
        """
        response = self._make_api_call(
            service="Firewall", method="getPinhole", parameters={}
        )

        rules = []

        # Extract IPv6 pinhole rules from response
        if isinstance(response, dict) and "status" in response:
            status_data = self._status_dict(response)
            for rule_data in status_data.values():
                if isinstance(rule_data, dict):
                    rules.append(rule_data)

        return rules

    def get_active_ipv6_pinholes(self) -> List[Dict[str, Any]]:
        """
        Get only enabled IPv6 pinhole rules.

        Returns:
            List of enabled IPv6 pinhole rule dictionaries
        """
        all_rules = self.get_ipv6_pinholes()
        return [rule for rule in all_rules if rule.get("Enable", False)]

    def get_all_firewall_rules(self) -> Dict[str, Any]:
        """
        Get all firewall rules (both IPv4 port forwarding and IPv6 pinholes).

        Returns:
            Dictionary with keys:
            - 'port_forwarding': IPv4 port forwarding rules
            - 'ipv6_pinholes': IPv6 pinhole rules
        """
        return {
            "port_forwarding": self.get_all_port_forwarding(),
            "ipv6_pinholes": self.get_ipv6_pinholes(),
        }

    def get_firewall_level(self) -> str:
        """
        Get the current firewall security level.

        Returns:
            Firewall level as string (e.g., "Low", "Medium", "High")
        """
        response = self._make_api_call(
            service="Firewall", method="getFirewallLevel", parameters={}
        )

        return self._status_str(response, default="Unknown")

    def get_ping_response_settings(
        self, source_interface: str = "data"
    ) -> Dict[str, Any]:
        """
        Get ping response settings for a specific interface.

        Args:
            source_interface: Source interface to check (default: "data")

        Returns:
            Dictionary with ping response settings including:
            - enableIPv4: Whether responding to IPv4 pings is enabled
            - enableIPv6: Whether responding to IPv6 pings is enabled
        """
        response = self._make_api_call(
            service="Firewall",
            method="getRespondToPing",
            parameters={"sourceInterface": source_interface},
        )

        return self._status_dict(response)

    def get_firewall_config(self) -> Dict[str, Any]:
        """
        Get comprehensive firewall configuration.

        Returns:
            Dictionary with firewall configuration including:
            - Status: Firewall status ("Enabled" or "Disabled")
            - AdvancedLevel: Advanced firewall level for IPv4
            - AdvancedIPv6Level: Advanced firewall level for IPv6
            - ExcludedOriginsPCP: Excluded origins for PCP
            - UpnpPortForwardingStatus: Current UPnP port forwarding status
            - UpnpPortForwardingEnable: Whether UPnP port forwarding is enabled
            - ChainNumberOfEntries: Number of firewall chain entries
            - ProtocolForwardingNumberOfEntries: Number of protocol forwarding entries
            - PinholeNumberOfEntries: Number of pinhole entries
            - ListNumberOfEntries: Number of list entries
        """
        response = self._make_api_call(service="Firewall", method="get", parameters={})

        return self._status_dict(response)

    def get_dmz_config(self) -> Dict[str, Any]:
        """
        Get DMZ (Demilitarized Zone) configuration.

        Returns:
            Dictionary with DMZ configuration including:
            - SourceInterface: Source interface (e.g., "data")
            - DestinationIPAddress: IP address of DMZ host
            - SourcePrefix: Source prefix filter
            - Status: DMZ status ("Enabled" or "Disabled")
            - Enable: Whether DMZ is enabled
        """
        response = self._make_api_call(
            service="Firewall", method="getDMZ", parameters={}
        )

        # Extract DMZ configuration from response
        if isinstance(response, dict) and "status" in response:
            # Extract the first DMZ rule (usually webui)
            status_data = self._status_dict(response)
            for origin, dmz_config in status_data.items():
                if isinstance(dmz_config, dict):
                    # Add origin for reference
                    dmz_config["Origin"] = origin
                    return dmz_config

        return {}

    def set_ping_response(
        self,
        source_interface: str = "data",
        enable_ipv4: bool = True,
        enable_ipv6: bool = True,
    ) -> bool:
        """
        Configure ping response settings for router.

        Args:
            source_interface: Source interface to configure (default: "data")
            enable_ipv4: Whether to respond to IPv4 pings (default: True)
            enable_ipv6: Whether to respond to IPv6 pings (default: True)

        Returns:
            True if successful

        Note:
            When disabled, the router will not respond to ping requests from
            the internet, improving security but making connectivity testing harder.
        """
        result = self._make_api_call(
            service="Firewall",
            method="setRespondToPing",
            parameters={
                "sourceInterface": source_interface,
                "service_enable": {
                    "enableIPv4": enable_ipv4,
                    "enableIPv6": enable_ipv6,
                },
            },
        )

        return self._is_true(result)

    def enable_ping_response(self, ipv4: bool = True, ipv6: bool = True) -> bool:
        """
        Enable ping response for IPv4 and/or IPv6.

        Args:
            ipv4: Enable IPv4 ping response (default: True)
            ipv6: Enable IPv6 ping response (default: True)

        Returns:
            True if successful

        Note: Convenience method that calls set_ping_response(enable_ipv4=ipv4, enable_ipv6=ipv6).
        """
        return self.set_ping_response(enable_ipv4=ipv4, enable_ipv6=ipv6)

    def disable_ping_response(self) -> bool:
        """
        Disable ping response for both IPv4 and IPv6.

        Returns:
            True if successful

        Note: Convenience method that calls set_ping_response(enable_ipv4=False, enable_ipv6=False).
        """
        return self.set_ping_response(enable_ipv4=False, enable_ipv6=False)

    def set_firewall_level(
        self, level: str = "Medium", ipv6_level: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Set firewall security level for IPv4 and optionally IPv6.

        Args:
            level: Firewall level - "Low", "Medium", "High", or "Custom" (default: "Medium")
            ipv6_level: IPv6 firewall level - if None, uses same as IPv4 level (default: None)

        Returns:
            Dictionary with 'ipv4' and 'ipv6' keys indicating success for each

        Raises:
            ValueError: If level is not valid

        Note:
            - Low: Minimal protection, allows most traffic
            - Medium: Balanced protection and functionality
            - High: Maximum protection, blocks more traffic
            - Custom: Allows custom firewall rules (required for setCustomRule)
        """
        valid_levels = ["Low", "Medium", "High", "Custom"]
        if level not in valid_levels:
            raise ValueError(f"level must be one of: {', '.join(valid_levels)}")

        if ipv6_level is None:
            ipv6_level = level
        elif ipv6_level not in valid_levels:
            raise ValueError(f"ipv6_level must be one of: {', '.join(valid_levels)}")

        results = {}

        # Set IPv4 firewall level
        result_ipv4 = self._make_api_call(
            service="Firewall", method="setFirewallLevel", parameters={"level": level}
        )
        results["ipv4"] = self._is_true(result_ipv4)

        # Set IPv6 firewall level
        result_ipv6 = self._make_api_call(
            service="Firewall",
            method="setFirewallIPv6Level",
            parameters={"level": ipv6_level},
        )
        results["ipv6"] = self._is_true(result_ipv6)

        return results

    def set_firewall_level_ipv4(self, level: str = "Medium") -> bool:
        """
        Set IPv4 firewall security level.

        Args:
            level: Firewall level - "Low", "Medium", "High", or "Custom" (default: "Medium")

        Returns:
            True if successful

        Raises:
            ValueError: If level is not valid
        """
        valid_levels = ["Low", "Medium", "High", "Custom"]
        if level not in valid_levels:
            raise ValueError(f"level must be one of: {', '.join(valid_levels)}")

        result = self._make_api_call(
            service="Firewall", method="setFirewallLevel", parameters={"level": level}
        )

        return self._is_true(result)

    def set_firewall_level_ipv6(self, level: str = "Medium") -> bool:
        """
        Set IPv6 firewall security level.

        Args:
            level: Firewall level - "Low", "Medium", "High", or "Custom" (default: "Medium")

        Returns:
            True if successful

        Raises:
            ValueError: If level is not valid
        """
        valid_levels = ["Low", "Medium", "High", "Custom"]
        if level not in valid_levels:
            raise ValueError(f"level must be one of: {', '.join(valid_levels)}")

        result = self._make_api_call(
            service="Firewall",
            method="setFirewallIPv6Level",
            parameters={"level": level},
        )

        return self._is_true(result)

    def enable_custom_firewall(self) -> Dict[str, bool]:
        """
        Enable custom firewall mode for both IPv4 and IPv6.

        Returns:
            Dictionary with 'ipv4' and 'ipv6' keys indicating success for each

        Note:
            This is required before using custom firewall rule methods.
            Sets both IPv4 and IPv6 firewall levels to "Custom".
        """
        return self.set_firewall_level("Custom", "Custom")

    def get_custom_firewall_rules(self) -> List[Dict[str, Any]]:
        """
        Get all custom firewall rules.

        Returns:
            List of custom firewall rule dictionaries with fields:
            - Id: Rule identifier (e.g., "ssh", "http", "myshit")
            - Target: Rule action ("Accept" or "Drop")
            - Status: Rule status ("Enabled" or "Disabled")
            - Class: Rule class (e.g., "Forward")
            - IPVersion: IP version (4 or 6)
            - Protocol: Protocol number (6=TCP, 17=UDP, comma-separated)
            - DestinationPort: Destination port or port range (e.g., "22", "6660-6669")
            - SourcePort: Source port filter
            - DestinationPrefix: Destination IP prefix filter
            - SourcePrefix: Source IP prefix filter
            - DestinationMACAddress: Destination MAC address filter
            - SourceMACAddress: Source MAC address filter
            - TargetChain: Target firewall chain
            - Description: Rule description
            - Enable: Whether rule is enabled

        Note:
            This method requires Custom firewall level to be enabled.
        """
        response = self._make_api_call(
            service="Firewall", method="getCustomRule", parameters={}
        )

        rules = []

        # Extract custom rules from response
        if isinstance(response, dict) and "status" in response:
            status_data = self._status_dict(response)
            for rule_data in status_data.values():
                if isinstance(rule_data, dict):
                    rules.append(rule_data)

        return rules

    def add_custom_firewall_rule(
        self,
        rule_id: str,
        action: str = "Accept",
        protocol: str = "6",
        destination_port: str = "",
        source_port: str = "",
        destination_prefix: str = "",
        source_prefix: str = "",
        ip_version: int = 4,
        chain: Optional[str] = None,
        enabled: bool = True,
    ) -> str:
        """
        Add or update a custom firewall rule.

        Args:
            rule_id: Unique identifier for the rule (e.g., "ssh", "myapp")
            action: Rule action - "Accept" or "Drop" (default: "Accept")
            protocol: Protocol number - "6" (TCP), "17" (UDP), or "6,17" (default: "6")
            destination_port: Destination port or range (e.g., "22", "8080", "6660-6669")
            source_port: Source port filter (default: "")
            destination_prefix: Destination IP address/prefix (e.g., "192.168.2.100")
            source_prefix: Source IP address/prefix filter (default: "")
            ip_version: IP version - 4 or 6 (default: 4)
            chain: Firewall chain - auto-determined if None (default: None)
            enabled: Whether to enable the rule (default: True)

        Returns:
            Rule ID if successful, empty string if failed

        Raises:
            ValueError: If parameters are invalid

        Note:
            - Requires Custom firewall level to be enabled
            - Chain is auto-determined: "Custom" for IPv4, "Custom_V6Out" for IPv6
            - Protocol numbers: 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6
            - Port ranges: "80", "80-90", "80,443,8080"

        Examples:
            # Allow SSH access from specific IP
            api.add_custom_firewall_rule("ssh_admin", "Accept", "6", "22",
                                       destination_prefix="192.168.2.100")

            # Block IRC ports (IPv6)
            api.add_custom_firewall_rule("block_irc", "Drop", "6", "6660-6669",
                                       ip_version=6)

            # Allow custom application
            api.add_custom_firewall_rule("myapp", "Accept", "6,17", "8080")
        """
        if action not in ["Accept", "Drop"]:
            raise ValueError("action must be 'Accept' or 'Drop'")

        if ip_version not in [4, 6]:
            raise ValueError("ip_version must be 4 or 6")

        # Auto-determine chain if not specified
        if chain is None:
            chain = "Custom_V6Out" if ip_version == 6 else "Custom"

        result = self._make_api_call(
            service="Firewall",
            method="setCustomRule",
            parameters={
                "id": rule_id,
                "chain": chain,
                "action": action,
                "destinationPort": destination_port,
                "sourcePort": source_port,
                "destinationPrefix": destination_prefix,
                "sourcePrefix": source_prefix,
                "protocol": protocol,
                "ipversion": ip_version,
                "enable": enabled,
            },
        )

        # Rule ID if successful, empty string if failed
        return self._status_str(result)

    def delete_custom_firewall_rule(
        self, rule_id: str, ip_version: int = 4, chain: Optional[str] = None
    ) -> bool:
        """
        Delete a custom firewall rule.

        Args:
            rule_id: Rule identifier to delete
            ip_version: IP version of the rule - 4 or 6 (default: 4)
            chain: Firewall chain - auto-determined if None (default: None)

        Returns:
            True if successful

        Raises:
            ValueError: If ip_version is invalid

        Note:
            Chain is auto-determined: "Custom" for IPv4, "Custom_V6Out" for IPv6
        """
        if ip_version not in [4, 6]:
            raise ValueError("ip_version must be 4 or 6")

        # Auto-determine chain if not specified
        if chain is None:
            chain = "Custom_V6Out" if ip_version == 6 else "Custom"

        result = self._make_api_call(
            service="Firewall",
            method="deleteCustomRule",
            parameters={"id": rule_id, "chain": chain},
        )

        return self._is_true(result)

    def update_custom_firewall_rule(self, rule_id: str, **kwargs: Any) -> str:
        """
        Update an existing custom firewall rule.

        Args:
            rule_id: Rule identifier to update
            **kwargs: Rule parameters to update (same as add_custom_firewall_rule)

        Returns:
            Rule ID if successful, empty string if failed

        Note:
            This is equivalent to calling add_custom_firewall_rule with the same rule_id.
            Only specified parameters will be updated.
        """
        return self.add_custom_firewall_rule(rule_id, **kwargs)

    def manage_custom_firewall_rule(
        self, action: str, rule_id: str, **kwargs: Any
    ) -> Union[str, bool]:
        """
        Manage custom firewall rules with a unified interface.

        Args:
            action: Action to perform - "add", "update", "delete", "enable", "disable"
            rule_id: Rule identifier
            **kwargs: Rule parameters (for add/update actions)

        Returns:
            For add/update: Rule ID if successful, empty string if failed
            For delete/enable/disable: True if successful, False if failed

        Raises:
            ValueError: If action is not valid

        Examples:
            # Add rule
            api.manage_custom_firewall_rule("add", "ssh", action="Accept",
                                          protocol="6", destination_port="22")

            # Enable rule
            api.manage_custom_firewall_rule("enable", "ssh")

            # Update rule
            api.manage_custom_firewall_rule("update", "ssh", destination_port="2222")

            # Delete rule
            api.manage_custom_firewall_rule("delete", "ssh")
        """
        if action == "add":
            return self.add_custom_firewall_rule(rule_id, **kwargs)

        elif action == "update":
            return self.update_custom_firewall_rule(rule_id, **kwargs)

        elif action == "delete":
            ip_version = kwargs.get("ip_version", 4)
            chain = kwargs.get("chain")
            return self.delete_custom_firewall_rule(rule_id, ip_version, chain)

        elif action == "enable":
            # Get current rule and enable it
            rules = self.get_custom_firewall_rules()
            current_rule = next((r for r in rules if r.get("Id") == rule_id), None)
            if current_rule:
                # Update with enabled=True
                return (
                    self.add_custom_firewall_rule(
                        rule_id=rule_id,
                        action=current_rule.get("Target", "Accept"),
                        protocol=current_rule.get("Protocol", "6"),
                        destination_port=current_rule.get("DestinationPort", ""),
                        source_port=current_rule.get("SourcePort", ""),
                        destination_prefix=current_rule.get("DestinationPrefix", ""),
                        source_prefix=current_rule.get("SourcePrefix", ""),
                        ip_version=current_rule.get("IPVersion", 4),
                        enabled=True,
                    )
                    != ""
                )
            return False

        elif action == "disable":
            # Get current rule and disable it
            rules = self.get_custom_firewall_rules()
            current_rule = next((r for r in rules if r.get("Id") == rule_id), None)
            if current_rule:
                # Update with enabled=False
                return (
                    self.add_custom_firewall_rule(
                        rule_id=rule_id,
                        action=current_rule.get("Target", "Accept"),
                        protocol=current_rule.get("Protocol", "6"),
                        destination_port=current_rule.get("DestinationPort", ""),
                        source_port=current_rule.get("SourcePort", ""),
                        destination_prefix=current_rule.get("DestinationPrefix", ""),
                        source_prefix=current_rule.get("SourcePrefix", ""),
                        ip_version=current_rule.get("IPVersion", 4),
                        enabled=False,
                    )
                    != ""
                )
            return False

        else:
            raise ValueError(
                "action must be 'add', 'update', 'delete', 'enable', or 'disable'"
            )

    def add_port_forwarding_rule(
        self,
        rule_id: str,
        internal_port: str,
        external_port: str,
        destination_ip: str,
        protocol: str = "6",
        description: str = "",
        enabled: bool = True,
        source_interface: str = "data",
        origin: str = "webui",
    ) -> str:
        """
        Add a new IPv4 port forwarding rule.

        Args:
            rule_id: Unique identifier for the rule (e.g., "SSH", "WebServer")
            internal_port: Internal port number or range (e.g., "22", "8080-8090")
            external_port: External port number or range (e.g., "22", "8080-8090")
            destination_ip: Internal IP address to forward to (e.g., "192.168.2.100")
            protocol: Protocol type - "6" (TCP), "17" (UDP), or "6,17" (both) (default: "6")
            description: Human-readable description (default: empty)
            enabled: Whether rule should be enabled (default: True)
            source_interface: Source interface (default: "data")
            origin: Rule origin (default: "webui")

        Returns:
            Full rule ID created by the router (e.g., "webui_SSH")

        Raises:
            ValueError: If required parameters are invalid

        Note:
            - Protocol 6 = TCP, 17 = UDP
            - Port ranges use format "start-end" (e.g., "8080-8090")
            - Individual ports use single numbers (e.g., "22")
        """
        # Validate required parameters
        if not rule_id or not rule_id.strip():
            raise ValueError("rule_id cannot be empty")
        if not internal_port or not external_port:
            raise ValueError("internal_port and external_port are required")
        if not destination_ip:
            raise ValueError("destination_ip is required")

        # Validate protocol
        validate_protocol(protocol)

        # Clean rule ID
        clean_rule_id = rule_id.strip()

        result = self._make_api_call(
            service="Firewall",
            method="setPortForwarding",
            parameters={
                "id": clean_rule_id,
                "internalPort": str(internal_port),
                "externalPort": str(external_port),
                "destinationIPAddress": destination_ip,
                "enable": enabled,
                "persistent": True,
                "protocol": protocol,
                "description": description,
                "sourceInterface": source_interface,
                "origin": origin,
                "destinationMACAddress": "",
                "sourcePrefix": "",
            },
        )

        return _rule_id(result, default=clean_rule_id)

    def update_port_forwarding_rule(
        self,
        rule_id: str,
        internal_port: Optional[str] = None,
        external_port: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = None,
        source_interface: str = "data",
        origin: str = "webui",
    ) -> str:
        """
        Update an existing IPv4 port forwarding rule.

        Args:
            rule_id: Full rule ID (e.g., "webui_SSH") or simple ID (e.g., "SSH")
            internal_port: Internal port number or range (optional)
            external_port: External port number or range (optional)
            destination_ip: Internal IP address to forward to (optional)
            protocol: Protocol type - "6" (TCP), "17" (UDP), or "6,17" (both) (optional)
            description: Human-readable description (optional)
            enabled: Whether rule should be enabled (optional)
            source_interface: Source interface (default: "data")
            origin: Rule origin (default: "webui")

        Returns:
            Full rule ID

        Raises:
            ValueError: If rule_id is invalid or protocol is invalid

        Note:
            Only specified parameters will be updated. Others remain unchanged.
        """
        if not rule_id or not rule_id.strip():
            raise ValueError("rule_id cannot be empty")

        # Validate protocol if provided
        if protocol is not None:
            validate_protocol(protocol)

        # Get current rule to fill in missing parameters
        existing_rules = self.get_port_forwarding(origin)
        current_rule = None

        for rule in existing_rules:
            if rule.get("Id") == rule_id or rule.get("Id") == f"{origin}_{rule_id}":
                current_rule = rule
                break

        if not current_rule:
            raise ValueError(f"Port forwarding rule '{rule_id}' not found")

        # Use current values for unspecified parameters
        update_params = {
            "id": current_rule["Id"],
            "internalPort": str(internal_port)
            if internal_port is not None
            else current_rule["InternalPort"],
            "externalPort": str(external_port)
            if external_port is not None
            else current_rule["ExternalPort"],
            "destinationIPAddress": destination_ip
            if destination_ip is not None
            else current_rule["DestinationIPAddress"],
            "enable": enabled if enabled is not None else current_rule["Enable"],
            "persistent": True,
            "protocol": protocol if protocol is not None else current_rule["Protocol"],
            "description": description
            if description is not None
            else current_rule["Description"],
            "sourceInterface": source_interface,
            "origin": origin,
            "destinationMACAddress": current_rule.get("DestinationMACAddress", ""),
            "sourcePrefix": current_rule.get("SourcePrefix", ""),
        }

        result = self._make_api_call(
            service="Firewall", method="setPortForwarding", parameters=update_params
        )

        return _rule_id(result, default=rule_id)

    def delete_port_forwarding_rule(
        self, rule_id: str, destination_ip: Optional[str] = None, origin: str = "webui"
    ) -> bool:
        """
        Delete an IPv4 port forwarding rule.

        Args:
            rule_id: Full rule ID (e.g., "webui_SSH") or simple ID (e.g., "SSH")
            destination_ip: Destination IP address (optional, for verification)
            origin: Rule origin (default: "webui")

        Returns:
            True if successful

        Raises:
            ValueError: If rule_id is invalid
        """
        if not rule_id or not rule_id.strip():
            raise ValueError("rule_id cannot be empty")

        # Ensure we have the full rule ID
        full_rule_id = (
            rule_id if rule_id.startswith(f"{origin}_") else f"{origin}_{rule_id}"
        )

        # If destination_ip not provided, try to get it from existing rule
        if destination_ip is None:
            existing_rules = self.get_port_forwarding(origin)
            for rule in existing_rules:
                if rule.get("Id") == full_rule_id:
                    destination_ip = rule.get("DestinationIPAddress")
                    break

        if not destination_ip:
            raise ValueError(
                f"destination_ip is required or rule '{rule_id}' not found"
            )

        result = self._make_api_call(
            service="Firewall",
            method="deletePortForwarding",
            parameters={
                "id": full_rule_id,
                "origin": origin,
                "destinationIPAddress": destination_ip,
            },
        )

        return self._is_true(result)

    def enable_port_forwarding_rule(self, rule_id: str, origin: str = "webui") -> bool:
        """
        Enable an existing IPv4 port forwarding rule.

        Args:
            rule_id: Full rule ID (e.g., "webui_SSH") or simple ID (e.g., "SSH")
            origin: Rule origin (default: "webui")

        Returns:
            True if successful
        """
        try:
            return bool(
                self.update_port_forwarding_rule(rule_id, enabled=True, origin=origin)
            )
        except (ValueError, KeyError):
            # Rule not found, or the router returned it without the expected fields
            return False

    def disable_port_forwarding_rule(self, rule_id: str, origin: str = "webui") -> bool:
        """
        Disable an existing IPv4 port forwarding rule.

        Args:
            rule_id: Full rule ID (e.g., "webui_SSH") or simple ID (e.g., "SSH")
            origin: Rule origin (default: "webui")

        Returns:
            True if successful
        """
        try:
            return bool(
                self.update_port_forwarding_rule(rule_id, enabled=False, origin=origin)
            )
        except (ValueError, KeyError):
            # Rule not found, or the router returned it without the expected fields
            return False

    def add_ipv6_pinhole(
        self,
        destination_ip: str,
        destination_port: str,
        protocol: str = "6",
        description: str = "",
        enabled: bool = True,
        source_interface: str = "data",
        source_port: str = "",
        origin: str = "webui",
    ) -> str:
        """
        Add a new IPv6 pinhole (firewall rule).

        Args:
            destination_ip: IPv6 address to allow access to (e.g., "2a02:a46f:ff52:0:f5a6:3bb7:c600:efc0")
            destination_port: Destination port number or range (e.g., "22", "8080-8090")
            protocol: Protocol type - "6" (TCP), "17" (UDP), or "6,17" (both) (default: "6")
            description: Human-readable description (default: empty)
            enabled: Whether rule should be enabled (default: True)
            source_interface: Source interface (default: "data")
            source_port: Source port filter (default: empty = any)
            origin: Rule origin (default: "webui")

        Returns:
            Full rule ID created by the router (e.g., "webui_1")

        Raises:
            ValueError: If required parameters are invalid

        Note:
            - Protocol 6 = TCP, 17 = UDP
            - Port ranges use format "start-end" (e.g., "8080-8090")
            - IPv6 pinholes don't use external/internal port mapping like IPv4 port forwarding
        """
        # Validate required parameters
        if not destination_ip:
            raise ValueError("destination_ip is required")
        if not destination_port:
            raise ValueError("destination_port is required")

        # Validate protocol
        validate_protocol(protocol)

        result = self._make_api_call(
            service="Firewall",
            method="setPinhole",
            parameters={
                "origin": origin,
                "sourceInterface": source_interface,
                "sourcePort": source_port,
                "destinationPort": str(destination_port),
                "destinationIPAddress": destination_ip,
                "protocol": protocol,
                "ipversion": 6,
                "enable": enabled,
                "description": description,
                "persistent": True,
            },
        )

        return _rule_id(result, default="")

    def update_ipv6_pinhole(
        self,
        rule_id: str,
        destination_ip: Optional[str] = None,
        destination_port: Optional[str] = None,
        protocol: Optional[str] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = None,
        source_interface: str = "data",
        source_port: Optional[str] = None,
        origin: str = "webui",
    ) -> str:
        """
        Update an existing IPv6 pinhole rule.

        Args:
            rule_id: Full rule ID (e.g., "webui_1")
            destination_ip: IPv6 address to allow access to (optional)
            destination_port: Destination port number or range (optional)
            protocol: Protocol type - "6" (TCP), "17" (UDP), or "6,17" (both) (optional)
            description: Human-readable description (optional)
            enabled: Whether rule should be enabled (optional)
            source_interface: Source interface (default: "data")
            source_port: Source port filter (optional)
            origin: Rule origin (default: "webui")

        Returns:
            Full rule ID

        Raises:
            ValueError: If rule_id is invalid or protocol is invalid
        """
        if not rule_id or not rule_id.strip():
            raise ValueError("rule_id cannot be empty")

        # Validate protocol if provided
        if protocol is not None:
            validate_protocol(protocol)

        # Get current rule to fill in missing parameters
        existing_rules = self.get_ipv6_pinholes()
        current_rule = None

        for rule in existing_rules:
            if rule.get("Id") == rule_id:
                current_rule = rule
                break

        if not current_rule:
            raise ValueError(f"IPv6 pinhole rule '{rule_id}' not found")

        # Use current values for unspecified parameters
        update_params = {
            "id": rule_id,
            "enable": enabled if enabled is not None else current_rule["Enable"],
            "description": description
            if description is not None
            else current_rule["Description"],
            "origin": origin,
            "sourceInterface": source_interface,
            "sourcePort": source_port
            if source_port is not None
            else current_rule.get("SourcePort", ""),
            "destinationPort": str(destination_port)
            if destination_port is not None
            else current_rule["DestinationPort"],
            "destinationIPAddress": destination_ip
            if destination_ip is not None
            else current_rule["DestinationIPAddress"],
            "protocol": protocol if protocol is not None else current_rule["Protocol"],
            "ipversion": 6,
            "persistent": True,
        }

        result = self._make_api_call(
            service="Firewall", method="setPinhole", parameters=update_params
        )

        return _rule_id(result, default=rule_id)

    def delete_ipv6_pinhole(self, rule_id: str, origin: str = "webui") -> bool:
        """
        Delete an IPv6 pinhole rule.

        Args:
            rule_id: Full rule ID (e.g., "webui_1")
            origin: Rule origin (default: "webui")

        Returns:
            True if successful

        Raises:
            ValueError: If rule_id is invalid
        """
        if not rule_id or not rule_id.strip():
            raise ValueError("rule_id cannot be empty")

        result = self._make_api_call(
            service="Firewall",
            method="deletePinhole",
            parameters={"id": rule_id, "origin": origin},
        )

        return self._is_true(result)

    def enable_ipv6_pinhole(self, rule_id: str, origin: str = "webui") -> bool:
        """
        Enable an existing IPv6 pinhole rule.

        Args:
            rule_id: Full rule ID (e.g., "webui_1")
            origin: Rule origin (default: "webui")

        Returns:
            True if successful
        """
        try:
            return bool(self.update_ipv6_pinhole(rule_id, enabled=True, origin=origin))
        except (ValueError, KeyError):
            # Rule not found, or the router returned it without the expected fields
            return False

    def disable_ipv6_pinhole(self, rule_id: str, origin: str = "webui") -> bool:
        """
        Disable an existing IPv6 pinhole rule.

        Args:
            rule_id: Full rule ID (e.g., "webui_1")
            origin: Rule origin (default: "webui")

        Returns:
            True if successful
        """
        try:
            return bool(self.update_ipv6_pinhole(rule_id, enabled=False, origin=origin))
        except (ValueError, KeyError):
            # Rule not found, or the router returned it without the expected fields
            return False

    def manage_port_forwarding(
        self, action: str, rule_id: Optional[str] = None, **kwargs: Any
    ) -> Union[str, bool, List[Dict[str, Any]], Dict[str, Any], None]:
        """
        Unified port forwarding management for both IPv4 and IPv6.

        Args:
            action: Action to perform - "add", "update", "delete", "enable", "disable", "list", "get"
            rule_id: Rule identifier (required for most actions except "list")
            **kwargs: Additional parameters based on action and IP version:

                     Common parameters:
                     - ip_version: 4 or 6 (default: 4)
                     - origin: Rule origin (default: "webui")

                     For IPv4 port forwarding (ip_version=4):
                     - internal_port: Internal port number or range
                     - external_port: External port number or range
                     - destination_ip: Internal IP address to forward to
                     - protocol: "6" (TCP), "17" (UDP), or "6,17" (both)
                     - description: Human-readable description
                     - enabled: Whether rule should be enabled

                     For IPv6 pinholes (ip_version=6):
                     - destination_ip: IPv6 address to allow access to
                     - destination_port: Destination port number or range
                     - protocol: "6" (TCP), "17" (UDP), or "6,17" (both)
                     - description: Human-readable description
                     - enabled: Whether rule should be enabled
                     - source_port: Source port filter (optional)

        Returns:
            - For "add": Rule ID (str)
            - For "update": Rule ID (str)
            - For "delete", "enable", "disable": Success status (bool)
            - For "list": List of rules (List[Dict])
            - For "get": Single rule details (Dict) or None

        Raises:
            ValueError: If action is invalid or required parameters are missing

        Examples:
            # Add IPv4 port forwarding rule
            api.manage_port_forwarding("add", "SSH",
                internal_port="22", external_port="22",
                destination_ip="192.168.2.100", protocol="6")

            # Add IPv6 pinhole
            api.manage_port_forwarding("add", ip_version=6,
                destination_ip="2a02:a46f:ff52:0:f5a6:3bb7:c600:efc0",
                destination_port="22", protocol="6", description="SSH")

            # List all IPv4 rules
            rules = api.manage_port_forwarding("list")

            # Enable a rule
            api.manage_port_forwarding("enable", "webui_SSH")
        """
        ip_version = kwargs.get("ip_version", 4)
        origin = kwargs.get("origin", "webui")

        if action == "list":
            if ip_version == 6:
                return self.get_ipv6_pinholes()
            else:
                return self.get_port_forwarding(origin)

        elif action == "get":
            if not rule_id:
                raise ValueError("rule_id is required for 'get' action")

            if ip_version == 6:
                rules = self.get_ipv6_pinholes()
            else:
                rules = self.get_port_forwarding(origin)

            # Find specific rule
            for rule in rules:
                if rule.get("Id") == rule_id or rule.get("Id") == f"{origin}_{rule_id}":
                    return rule
            return None

        elif action == "add":
            if ip_version == 6:
                destination_ip = kwargs.get("destination_ip")
                destination_port = kwargs.get("destination_port")
                if not destination_ip or not destination_port:
                    raise ValueError(
                        "destination_ip and destination_port are required for IPv6 pinholes"
                    )

                return self.add_ipv6_pinhole(
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    protocol=kwargs.get("protocol", "6"),
                    description=kwargs.get("description", ""),
                    enabled=kwargs.get("enabled", True),
                    source_port=kwargs.get("source_port", ""),
                    origin=origin,
                )
            else:
                if not rule_id:
                    raise ValueError("rule_id is required for IPv4 port forwarding")

                internal_port = kwargs.get("internal_port")
                external_port = kwargs.get("external_port")
                destination_ip = kwargs.get("destination_ip")
                if not internal_port or not external_port or not destination_ip:
                    raise ValueError(
                        "internal_port, external_port, and destination_ip are required for IPv4 port forwarding"
                    )

                return self.add_port_forwarding_rule(
                    rule_id=rule_id,
                    internal_port=internal_port,
                    external_port=external_port,
                    destination_ip=destination_ip,
                    protocol=kwargs.get("protocol", "6"),
                    description=kwargs.get("description", ""),
                    enabled=kwargs.get("enabled", True),
                    origin=origin,
                )

        elif action == "update":
            if not rule_id:
                raise ValueError("rule_id is required for 'update' action")

            if ip_version == 6:
                return self.update_ipv6_pinhole(
                    rule_id=rule_id,
                    destination_ip=kwargs.get("destination_ip"),
                    destination_port=kwargs.get("destination_port"),
                    protocol=kwargs.get("protocol"),
                    description=kwargs.get("description"),
                    enabled=kwargs.get("enabled"),
                    source_port=kwargs.get("source_port"),
                    origin=origin,
                )
            else:
                return self.update_port_forwarding_rule(
                    rule_id=rule_id,
                    internal_port=kwargs.get("internal_port"),
                    external_port=kwargs.get("external_port"),
                    destination_ip=kwargs.get("destination_ip"),
                    protocol=kwargs.get("protocol"),
                    description=kwargs.get("description"),
                    enabled=kwargs.get("enabled"),
                    origin=origin,
                )

        elif action == "delete":
            if not rule_id:
                raise ValueError("rule_id is required for 'delete' action")

            if ip_version == 6:
                return self.delete_ipv6_pinhole(rule_id, origin)
            else:
                destination_ip = kwargs.get("destination_ip")
                return self.delete_port_forwarding_rule(rule_id, destination_ip, origin)

        elif action == "enable":
            if not rule_id:
                raise ValueError("rule_id is required for 'enable' action")

            if ip_version == 6:
                return self.enable_ipv6_pinhole(rule_id, origin)
            else:
                return self.enable_port_forwarding_rule(rule_id, origin)

        elif action == "disable":
            if not rule_id:
                raise ValueError("rule_id is required for 'disable' action")

            if ip_version == 6:
                return self.disable_ipv6_pinhole(rule_id, origin)
            else:
                return self.disable_port_forwarding_rule(rule_id, origin)

        else:
            raise ValueError(
                "action must be one of: add, update, delete, enable, disable, list, get"
            )

    def set_upnp_enabled(self, enabled: bool = True) -> bool:
        """
        Enable or disable UPnP port forwarding.

        Args:
            enabled: Whether to enable UPnP port forwarding (default: True)

        Returns:
            True if successful

        Note:
            When enabled, devices on the network can automatically open ports
            through UPnP protocol. This can be convenient but may reduce security.
        """
        result = self._make_api_call(
            service="Firewall",
            method="set",
            parameters={"UpnpPortForwardingEnable": enabled},
        )

        return self._is_true(result)

    def set_dmz_host(
        self,
        destination_ip: str,
        enabled: bool = True,
        dmz_id: str = "webui",
        source_interface: str = "data",
    ) -> str:
        """
        Set up a DMZ (Demilitarized Zone) host.

        Args:
            destination_ip: IP address of the DMZ host (e.g., "192.168.2.108")
            enabled: Whether to enable the DMZ (default: True)
            dmz_id: DMZ configuration ID (default: "webui")
            source_interface: Source interface (default: "data")

        Returns:
            DMZ ID if successful, empty string if failed

        Note:
            DMZ forwards all incoming traffic to the specified host.
            This effectively puts the host outside the firewall protection.
            Only one DMZ host can be active at a time.
        """
        if not destination_ip:
            raise ValueError("destination_ip is required")

        result = self._make_api_call(
            service="Firewall",
            method="setDMZ",
            parameters={
                "id": dmz_id,
                "sourceInterface": source_interface,
                "destinationIPAddress": destination_ip,
                "enable": enabled,
            },
        )

        status = result.get("status") if isinstance(result, dict) else None
        return status if isinstance(status, str) else ""

    def delete_dmz_host(self, dmz_id: str = "webui") -> bool:
        """
        Delete DMZ host configuration.

        Args:
            dmz_id: DMZ configuration ID to delete (default: "webui")

        Returns:
            True if successful
        """
        result = self._make_api_call(
            service="Firewall", method="deleteDMZ", parameters={"id": dmz_id}
        )

        return self._is_true(result)
