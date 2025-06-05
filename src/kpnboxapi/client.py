"""Main KPNBoxAPI client class."""

import json
from typing import Dict, Any, Optional, List, Union
import requests

from .exceptions import AuthenticationError, ConnectionError, APIError


class KPNBoxAPI:
    """Client for interacting with KPN Box routers (tested with Box 14)."""
    
    def __init__(self, host: str = "192.168.2.254", timeout: int = 30):
        """
        Initialize the KPN Box API client.
        
        Args:
            host: IP address of the KPN Box (default: 192.168.2.254)
            timeout: Request timeout in seconds (default: 30)
        """
        self.host = host
        self.base_url = f"http://{host}"
        self.timeout = timeout
        self.session = requests.Session()
        self.context_id: Optional[str] = None
        self._username: Optional[str] = None
        self._password: Optional[str] = None
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Origin': self.base_url,
            'Referer': f"{self.base_url}/",
            'Connection': 'keep-alive',
        })
    
    def login(self, username: str = "admin", password: str = "") -> bool:
        """
        Authenticate with the KPN Box.
        
        Args:
            username: Username (default: "admin")
            password: Password
            
        Returns:
            True if authentication successful
            
        Raises:
            AuthenticationError: If authentication fails
            ConnectionError: If unable to connect
        """
        url = f"{self.base_url}/ws/NeMo/Intf/lan:getMIBs"

        login_data = {
            "service": "sah.Device.Information",
            "method": "createContext",
            "parameters": {
                "applicationName": "webui",
                "username": username,
                "password": password
            }
        }
        
        headers = {
            'Content-Type': 'application/x-sah-ws-4-call+js; charset=utf-8',
            'Authorization': 'X-Sah-Login',
            'Content-Length': str(len(json.dumps(login_data))),
        }
        
        try:
            response = self.session.post(url, json=login_data, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') != 0:
                raise AuthenticationError(f"Login failed with status: {data.get('status')}")
            
            # Extract context ID
            context_data = data.get('data', {})
            self.context_id = context_data.get('contextID')
            
            if not self.context_id:
                raise AuthenticationError("No context ID received from login response")
            
            # Update session headers for authenticated requests
            self.session.headers.update({
                'Content-Type': 'application/x-sah-ws-4-call+json; charset=utf-8',
                'Authorization': f'X-Sah {self.context_id}',
                'X-Context': self.context_id,
            })
            
            # Store credentials for auto-retry
            self._username = username
            self._password = password
            
            return True
            
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to connect to KPN Box: {e}")
        except json.JSONDecodeError as e:
            raise AuthenticationError(f"Invalid response format: {e}")
    
    def _make_api_call(self, service: str, method: str, parameters: Dict[str, Any] = None, _retry: bool = True) -> Any:
        """Make an authenticated API call to the KPN Box with automatic session recovery."""
        if not self.context_id:
            raise AuthenticationError("Not authenticated. Please call login() first.")
        
        url = f"{self.base_url}/ws/NeMo/Intf/lan:getMIBs"
        
        data = {
            "service": service,
            "method": method,
            "parameters": parameters or {}
        }
        
        try:
            response = self.session.post(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            result = response.json()
            
            # Check for permission denied error (session expired)
            if (isinstance(result, dict) and 
                'errors' in result and 
                isinstance(result['errors'], list) and 
                len(result['errors']) > 0 and 
                result['errors'][0].get('error') == 13):
                
                # Session expired - try to re-login automatically
                if _retry and self._username is not None and self._password is not None:
                    try:
                        # Clear current session
                        self.context_id = None
                        self.session.cookies.clear()
                        self.session.headers.pop('Authorization', None)
                        self.session.headers.pop('X-Context', None)
                        
                        # Re-login with stored credentials
                        self.login(self._username, self._password)
                        
                        # Retry the API call (with _retry=False to prevent infinite loop)
                        return self._make_api_call(service, method, parameters, _retry=False)
                        
                    except Exception:
                        # If re-login fails, raise the original permission error
                        raise APIError(f"Session expired and re-login failed. Permission denied for {service}")
                else:
                    raise APIError(f"Session expired. Permission denied for {service}")
            
            return result
            
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to make API call: {e}")
        except json.JSONDecodeError as e:
            raise APIError(f"Invalid response format: {e}")
    
    def get_connected_devices(self) -> Any:
        """
        Get raw device data from the KPN Box.
        
        Returns:
            Raw device data from the API
        """
        return self._make_api_call(
            service="Devices.Device.lan",
            method="topology",
            parameters={
                "expression": "not logical",
                "flags": "no_recurse|no_actions"
            }
        )
    
    def get_devices(self, filter: str = 'all') -> List[Dict[str, Any]]:
        """
        Get connected devices with optional filtering.
        
        Args:
            filter: Device filter - 'all', 'active', or 'inactive' (default: 'all')
        
        Returns:
            List of device dictionaries with fields:
            - Name: Device name
            - PhysAddress: MAC address  
            - IPAddress: IP address
            - Active: Connection status (True/False)
            - DeviceType: Type of device
            - Layer2Interface: Network interface
            - FirstSeen: First connection timestamp
            - LastConnection: Last connection timestamp
            - Plus many other fields from the raw API
            
        Raises:
            ValueError: If filter parameter is invalid
        """
        if filter not in ['all', 'active', 'inactive']:
            raise ValueError("Filter must be 'all', 'active', or 'inactive'")
            
        raw_data = self.get_connected_devices()
        devices = []
        
        def extract_devices(data):
            if isinstance(data, list):
                for item in data:
                    extract_devices(item)
            elif isinstance(data, dict):
                # Filter actual devices (not network interfaces)
                if (data.get('PhysAddress') and 
                    not data.get('Name', '').startswith('ETH') and 
                    not data.get('Name', '').startswith('vap') and
                    data.get('Name') != 'lan'):
                    
                    is_active = data.get('Active', False)
                    if filter == 'all' or (filter == 'active' and is_active) or (filter == 'inactive' and not is_active):
                        devices.append(data)
                
                if 'Children' in data:
                    extract_devices(data['Children'])
        
        # Handle response format
        if isinstance(raw_data, dict) and 'status' in raw_data:
            extract_devices(raw_data['status'])
        else:
            extract_devices(raw_data)
        
        return devices
    
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
            service="DeviceInfo",
            method="get",
            parameters=""
        )
        
        # Handle response format
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        return response
    
    def get_public_ipv6(self) -> str:
        """
        Get the public IPv6 address of the KPN Box modem.
        
        Returns:
            Public IPv6 address as string (e.g., "2a02:a46f:ff52:0:4e22:f3ff:fecb:61b0")
        """
        response = self._make_api_call(
            service="NeMo.Intf.data",
            method="luckyAddrAddress",
            parameters={
                "flag": "ipv6 && global && @gua",
                "traverse": "down"
            }
        )
        
        # Handle response format
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        return response
    
    def get_wifi_networks(self) -> List[Dict[str, Any]]:
        """
        Get WiFi network configurations (regular networks, not guest).
        
        Returns:
            List of WiFi network dictionaries with fields:
            - SSID: Network name
            - VAPStatus: Status ("Up" or "Down")
            - BSSID: MAC address of the access point
            - MACAddress: MAC address
            - Security: Security configuration including:
              - ModeEnabled: Security mode (e.g., "WPA2-Personal")
              - KeyPassPhrase: WiFi password
            - MaxAssociatedDevices: Maximum number of devices
            - AssociatedDeviceNumberOfEntries: Current connected devices
            - EssIdentifier: Network identifier ("Primary", "Secondary")
            - BridgeInterface: Network bridge interface
            - And many other WiFi configuration fields
        """
        response = self._make_api_call(
            service="NeMo.Intf.lan",
            method="getMIBs",
            parameters={
                "mibs": "wlanvap",
                "flag": "!backhaul"
            }
        )
        
        networks = []
        
        # Extract WiFi networks from response
        if isinstance(response, dict) and 'status' in response:
            wlanvap_data = response['status'].get('wlanvap', {})
            for vap_name, vap_config in wlanvap_data.items():
                if isinstance(vap_config, dict):
                    # Add the VAP name to the config for reference
                    vap_config['VAPName'] = vap_name
                    networks.append(vap_config)
        
        return networks
    
    def get_guest_wifi_networks(self) -> List[Dict[str, Any]]:
        """
        Get guest WiFi network configurations.
        
        Returns:
            List of guest WiFi network dictionaries with same structure as get_wifi_networks()
            but for guest networks which typically have:
            - EssIdentifier: "Guest"
            - BridgeInterface: "brguest"
            - More restrictive settings
        """
        response = self._make_api_call(
            service="NeMo.Intf.brguest",
            method="getMIBs",
            parameters={
                "mibs": "wlanvap",
                "flag": "!backhaul",
                "traverse": "one level down"
            }
        )
        
        networks = []
        
        # Extract guest WiFi networks from response
        if isinstance(response, dict) and 'status' in response:
            wlanvap_data = response['status'].get('wlanvap', {})
            for vap_name, vap_config in wlanvap_data.items():
                if isinstance(vap_config, dict):
                    # Add the VAP name to the config for reference
                    vap_config['VAPName'] = vap_name
                    networks.append(vap_config)
        
        return networks
    
    def get_all_wifi_networks(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all WiFi networks (both regular and guest).
        
        Returns:
            Dictionary with keys:
            - 'regular': List of regular WiFi networks
            - 'guest': List of guest WiFi networks
        """
        return {
            'regular': self.get_wifi_networks(),
            'guest': self.get_guest_wifi_networks()
        }
    
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
        if pool_id not in ["default", "guest"]:
            raise ValueError("pool_id must be 'default' or 'guest'")
        
        response = self._make_api_call(
            service="DHCPv4.Server",
            method="getDHCPServerPool",
            parameters={"id": pool_id}
        )
        
        # Extract DHCP configuration from response
        if isinstance(response, dict) and 'status' in response:
            dhcp_data = response['status'].get(pool_id, {})
            # Add pool ID for reference
            dhcp_data['PoolID'] = pool_id
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
            'default': self.get_default_dhcp_server(),
            'guest': self.get_guest_dhcp_server()
        }

    def set_dhcp_server_config(self, 
                              network: str = "lan",
                              gateway_ip: str = None,
                              subnet_mask: int = None, 
                              dhcp_enabled: bool = None,
                              dhcp_min_ip: str = None,
                              dhcp_max_ip: str = None,
                              lease_time_seconds: int = None,
                              dhcp_authoritative: bool = None,
                              dns_servers: str = None) -> bool:
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
        parameters = {}
        
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
            service=service,
            method="setIPv4",
            parameters=parameters
        )
        
        # The API returns null for success, so we check if no error occurred
        return result is None or result.get('status') != False

    def set_home_dhcp_config(self,
                            gateway_ip: str = None,
                            subnet_mask: int = None,
                            dhcp_enabled: bool = None,
                            dhcp_min_ip: str = None,
                            dhcp_max_ip: str = None,
                            lease_time_seconds: int = None,
                            dhcp_authoritative: bool = None,
                            dns_servers: str = None) -> bool:
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
            dns_servers=dns_servers
        )

    def set_guest_dhcp_config(self,
                             gateway_ip: str = None,
                             subnet_mask: int = None,
                             dhcp_enabled: bool = None,
                             dhcp_min_ip: str = None,
                             dhcp_max_ip: str = None,
                             lease_time_seconds: int = None,
                             dns_servers: str = None) -> bool:
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
            dns_servers=dns_servers
        )

    def configure_network_isolation(self,
                                   home_subnet: str = "192.168.2.0/24",
                                   guest_subnet: str = "192.168.3.0/24",
                                   home_dhcp_range: tuple = ("192.168.2.100", "192.168.2.200"),
                                   guest_dhcp_range: tuple = ("192.168.3.1", "192.168.3.32"),
                                   dns_servers: str = "9.9.9.9,149.112.112.112") -> Dict[str, bool]:
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
        import ipaddress
        
        results = {}
        
        try:
            # Parse subnets
            home_net = ipaddress.IPv4Network(home_subnet, strict=False)
            guest_net = ipaddress.IPv4Network(guest_subnet, strict=False)
            
            # Configure home network
            home_gateway = str(list(home_net.hosts())[-1])  # Last IP as gateway
            results['home'] = self.set_home_dhcp_config(
                gateway_ip=home_gateway,
                subnet_mask=home_net.prefixlen,
                dhcp_enabled=True,
                dhcp_min_ip=home_dhcp_range[0],
                dhcp_max_ip=home_dhcp_range[1],
                lease_time_seconds=14400,
                dhcp_authoritative=True,
                dns_servers=dns_servers
            )
            
            # Configure guest network
            guest_gateway = str(list(guest_net.hosts())[-1])  # Last IP as gateway
            results['guest'] = self.set_guest_dhcp_config(
                gateway_ip=guest_gateway,
                subnet_mask=guest_net.prefixlen,
                dhcp_enabled=True,
                dhcp_min_ip=guest_dhcp_range[0],
                dhcp_max_ip=guest_dhcp_range[1],
                lease_time_seconds=14400,
                dns_servers=dns_servers
            )
            
        except Exception as e:
            results['error'] = str(e)
            results['home'] = False
            results['guest'] = False
        
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
        if pool_id not in ["default", "guest"]:
            raise ValueError("pool_id must be 'default' or 'guest'")
        
        response = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="getLeases",
            parameters={}
        )
        
        leases = []
        
        # Extract DHCP leases from response
        if isinstance(response, dict) and 'status' in response:
            pool_data = response['status'].get(pool_id, {})
            for client_id, lease_data in pool_data.items():
                if isinstance(lease_data, dict):
                    # Add client ID and pool ID for reference
                    lease_data['PoolID'] = pool_id
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
            'default': self.get_default_dhcp_leases(),
            'guest': self.get_guest_dhcp_leases()
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
        return [lease for lease in all_leases if lease.get('Active', False)]
    
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
            service="DynDNS",
            method="getHosts",
            parameters={}
        )
        
        hosts = []
        
        # Extract DynDNS hosts from response
        if isinstance(response, dict) and 'status' in response:
            status_data = response['status']
            if isinstance(status_data, list):
                hosts = status_data
            elif isinstance(status_data, dict):
                # Single host case
                hosts = [status_data]
        
        return hosts
    
    def add_dyndns_host(self, service: str, username: str, hostname: str, password: str) -> bool:
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
                "password": password.strip()
            }
        )
        
        # Check for API errors in response
        if isinstance(result, dict):
            if result.get('status') == False and 'errors' in result:
                errors = result['errors']
                if errors and len(errors) > 0:
                    error_desc = errors[0].get('description', 'Unknown error')
                    error_info = errors[0].get('info', '')
                    raise APIError(f"DynDNS configuration failed: {error_desc} ({error_info})")
            
            return result.get('status', False) == True
        
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
            parameters={"hostname": hostname.strip()}
        )
        
        return result.get('status', False) == True
    
    def update_dyndns_host(self, hostname: str, service: str = None, username: str = None, password: str = None) -> bool:
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
            raise ValueError("At least one parameter (service, username, or password) must be provided for update")
        
        # Get current host configuration to fill in missing values
        current_hosts = self.get_dyndns_hosts()
        current_host = None
        
        for host in current_hosts:
            if host.get('hostname', '').lower() == hostname.strip().lower():
                current_host = host
                break
        
        if not current_host:
            raise ValueError(f"DynDNS host '{hostname}' not found")
        
        # Use provided values or fall back to current values
        update_service = service.strip() if service else current_host.get('service', '')
        update_username = username.strip() if username else current_host.get('username', '')
        update_password = password.strip() if password else current_host.get('password', '')
        
        # Validate that we have all required values
        if not update_service:
            raise ValueError("Service value not found in current configuration and not provided")
        if not update_username:
            raise ValueError("Username value not found in current configuration and not provided")
        if not update_password:
            raise ValueError("Password value not found in current configuration and not provided")
        
        # Delete the existing host
        delete_success = self.delete_dyndns_host(hostname.strip())
        if not delete_success:
            return False
        
        # Add the host back with updated configuration
        return self.add_dyndns_host(update_service, update_username, hostname.strip(), update_password)
    
    def get_dyndns_status(self, hostname: str = None) -> Dict[str, Any]:
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
                if host.get('hostname', '').lower() == hostname.strip().lower():
                    return host
            return {}
        
        # Return all hosts as a summary
        return {
            'total_hosts': len(hosts),
            'hosts': hosts,
            'active_hosts': [h for h in hosts if h.get('enable', False)],
            'last_updated': max([h.get('last_update', '') for h in hosts] or [''])
        }
    
    def manage_dyndns_service(self, action: str, hostname: str, service: str = None, 
                             username: str = None, password: str = None) -> bool:
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
            if not all([service, username, password]):
                raise ValueError("Service, username, and password are required for add action")
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
            service=f"NeMo.Intf.{interface}",
            method="getNetDevStats",
            parameters={}
        )
        
        # Extract network statistics from response
        if isinstance(response, dict) and 'status' in response:
            stats = response['status']
            # Add interface name for reference
            stats['Interface'] = interface
            return stats
        
        return {}
    
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
        
        # Ethernet ports
        for interface in ["ETH0", "ETH1", "ETH2", "ETH3"]:
            try:
                all_stats[interface] = self.get_network_stats(interface)
            except Exception:
                # Interface might not be available, set empty stats
                all_stats[interface] = {'Interface': interface, 'Available': False}
        
        # WAN total and PPP
        for interface in ["eth4", "ppp_vdata"]:
            try:
                all_stats[interface] = self.get_network_stats(interface)
            except Exception:
                # Interface might not be available, set empty stats
                all_stats[interface] = {'Interface': interface, 'Available': False}
        
        return all_stats
    
    def set_interface_duplex(self, interface: str = "eth4", duplex_mode: str = "Auto") -> bool:
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
            parameters={"DuplexModeEnabled": duplex_mode}
        )
        
        return result.get('status', False) == True
    
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
            parameters={"MaxBitRateEnabled": max_speed}
        )
        
        return result.get('status', False) == True
    
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
                parameters={"Intf": "ETH3"}
            )
            if result1.get('status') is None:  # status null indicates success
                success_count += 1
            
            # 2. Add ETH3 to guest bridge
            result2 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.guest",
                method="addIntf",
                parameters={"Intf": "ETH3"}
            )
            if result2.get('status') is None:  # status null indicates success
                success_count += 1
        else:
            # Disable guest network on port 4 (return to LAN)
            # 1. Remove ETH3 from guest bridge
            result1 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.guest",
                method="removeIntf",
                parameters={"Intf": "ETH3"}
            )
            if result1.get('status') is None:  # status null indicates success
                success_count += 1
            
            # 2. Add ETH3 to LAN bridge
            result2 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan",
                method="addIntf",
                parameters={"Intf": "ETH3"}
            )
            if result2.get('status') is None:  # status null indicates success
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
    
    def configure_ethernet_port(self, port: int = 4, guest_network: bool = False) -> bool:
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
            service="NeMo.Intf.bridge",
            method="set",
            parameters={"STPEnable": enabled}
        )
        
        return result.get('status', False) == True
    
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
    
    def format_bytes(self, bytes_count: int) -> str:
        """
        Helper method to format byte counts in human-readable format.
        
        Args:
            bytes_count: Number of bytes
            
        Returns:
            Formatted string (e.g., "1.2 GB", "45.6 MB")
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    
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
            parameters={"origin": origin}
        )
        
        rules = []
        
        # Extract port forwarding rules from response
        if isinstance(response, dict) and 'status' in response:
            status_data = response['status']
            for rule_id, rule_data in status_data.items():
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
                if rules:  # Only include origins that have rules
                    all_rules[origin] = rules
            except Exception:
                # Origin might not be supported or have no rules
                continue
        
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
        return [rule for rule in all_rules if rule.get('Enable', False)]
    
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
        for proto_num in protocol_str.split(','):
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
            service="Firewall",
            method="getPinhole",
            parameters={}
        )
        
        rules = []
        
        # Extract IPv6 pinhole rules from response
        if isinstance(response, dict) and 'status' in response:
            status_data = response['status']
            for rule_id, rule_data in status_data.items():
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
        return [rule for rule in all_rules if rule.get('Enable', False)]
    
    def get_all_firewall_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all firewall rules (both IPv4 port forwarding and IPv6 pinholes).
        
        Returns:
            Dictionary with keys:
            - 'port_forwarding': IPv4 port forwarding rules
            - 'ipv6_pinholes': IPv6 pinhole rules
        """
        return {
            'port_forwarding': self.get_all_port_forwarding(),
            'ipv6_pinholes': self.get_ipv6_pinholes()
        }
    
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
            service="NMC",
            method="getWANStatus",
            parameters={}
        )
        
        # Extract WAN status from response
        if isinstance(response, dict) and 'data' in response:
            return response['data']
        elif isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
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
            service="NeMo.Intf.data",
            method="getMIBs",
            parameters={"mibs": "ppp"}
        )
        
        # Extract PPP information from response
        if isinstance(response, dict) and 'status' in response:
            ppp_data = response['status'].get('ppp', {})
            for ppp_interface, ppp_config in ppp_data.items():
                if isinstance(ppp_config, dict):
                    # Add interface name for reference
                    ppp_config['Interface'] = ppp_interface
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
        return {
            'wan_status': self.get_wan_status(),
            'ppp_info': self.get_ppp_info()
        }
    
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
            service="NeMo.Intf.wwan",
            method="get",
            parameters={}
        )
        
        # Extract WWAN status from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
    def is_connected(self) -> bool:
        """
        Check if the internet connection is active.
        
        Returns:
            True if connected to the internet, False otherwise
        """
        wan_status = self.get_wan_status()
        return wan_status.get('ConnectionState') == 'Connected'
    
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
            service="NetMaster.LAN.default.Bridge.lan",
            method="getIPv4",
            parameters={}
        )
        
        # Extract IPv4 configuration from response
        if isinstance(response, dict) and 'data' in response:
            return response['data']
        elif isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
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
            parameters={"Name": "lan"}
        )
        
        # Extract IPv6 configuration from response
        if isinstance(response, dict) and 'data' in response:
            return response['data']
        elif isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
    def get_lan_config(self) -> Dict[str, Any]:
        """
        Get comprehensive LAN network configuration (both IPv4 and IPv6).
        
        Returns:
            Dictionary with keys:
            - 'ipv4': LAN IPv4 configuration
            - 'ipv6': LAN IPv6 configuration
        """
        return {
            'ipv4': self.get_lan_ipv4_config(),
            'ipv6': self.get_lan_ipv6_config()
        }
    
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
            'ipv4': lan_config['ipv4'].get('DNSServers', ''),
            'ipv6': lan_config['ipv6'].get('DNSServers', '')
        }
    
    def set_lan_ipv4_config(self, network: str = "lan", dns_servers: str = None, 
                           address: str = None, dhcp_enabled: bool = None,
                           dhcp_min_address: str = None, dhcp_max_address: str = None,
                           prefix_length: int = None) -> bool:
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
                'Address': '192.168.3.254',
                'DHCPEnable': True,
                'DHCPMinAddress': '192.168.3.1',
                'DHCPMaxAddress': '192.168.3.32',
                'PrefixLength': 24
            }
        
        # Build parameters with current values as defaults
        parameters = {
            "DNSServers": dns_servers or current_config.get('DNSServers', ''),
            "Address": address or current_config.get('Address', ''),
            "DHCPEnable": dhcp_enabled if dhcp_enabled is not None else current_config.get('DHCPEnable', True),
            "DHCPMinAddress": dhcp_min_address or current_config.get('DHCPMinAddress', ''),
            "DHCPMaxAddress": dhcp_max_address or current_config.get('DHCPMaxAddress', ''),
            "PrefixLength": prefix_length if prefix_length is not None else current_config.get('PrefixLength', 24)
        }
        
        result = self._make_api_call(
            service=f"NetMaster.LAN.default.Bridge.{network}",
            method="setIPv4",
            parameters=parameters
        )
        
        # For these DNS/LAN config calls, success returns {"status": null}
        return result.get('status') is None
    
    def set_lan_ipv6_config(self, network: str = "lan", dns_servers: str = None) -> bool:
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
        
        parameters = {
            "DNSServers": dns_servers,
            "Name": network
        }
        
        result = self._make_api_call(
            service=f"NetMaster.LAN.default.Bridge.{network}",
            method="setIPv6Configuration",
            parameters=parameters
        )
        
        # For these DNS/LAN config calls, success returns {"status": null}
        return result.get('status') is None
    
    def set_dns_servers(self, ipv4_dns: str = None, ipv6_dns: str = None, 
                       network: str = "lan") -> Dict[str, bool]:
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
            results['ipv4'] = self.set_lan_ipv4_config(network=network, dns_servers=ipv4_dns)
        
        if ipv6_dns is not None:
            results['ipv6'] = self.set_lan_ipv6_config(network=network, dns_servers=ipv6_dns)
        
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
        response = self._make_api_call(
            service="NetMaster",
            method="get",
            parameters={}
        )
        
        # Extract NetMaster configuration from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
    def set_ipv6_enabled(self, enabled: bool = True, prefix_mode: str = "DHCPv6") -> bool:
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
                "IPv6PrefixMode": prefix_mode
            }
        )
        
        return result.get('status', False) == True
    
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
                parameters={"Name": "lan", "DHCPIAPDEnable": 0}
            )
            total_calls += 1
            if result1.get('status') is None:  # status null indicates success
                success_count += 1
            
            # 2. Set IPv6 prefix mode to DHCPv6
            result2 = self._make_api_call(
                service="NetMaster",
                method="set",
                parameters={"EnableIPv6": 1, "IPv6PrefixMode": "DHCPv6"}
            )
            total_calls += 1
            if result2.get('status') == True:
                success_count += 1
        
        elif mode == "on_with_dhcpv6":
            # On with DHCPv6: Enable with RAandDHCPv6 mode (4 requests)
            # 1. Enable IAPD on LAN interface
            result1 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan",
                method="setIPv6Configuration",
                parameters={"Name": "lan", "DHCPIAPDEnable": 1}
            )
            total_calls += 1
            if result1.get('status') is None:  # status null indicates success
                success_count += 1
            
            # 2. Set prefix length for lan DHCPv6
            result2 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan.IPv6.lan.DHCPv6",
                method="set",
                parameters={"IAPDPrefixLength": 56}
            )
            total_calls += 1
            if result2.get('status') == True:
                success_count += 1
            
            # 3. Set prefix length for guest DHCPv6
            result3 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.guest.IPv6.guest.DHCPv6",
                method="set",
                parameters={"IAPDPrefixLength": 56}
            )
            total_calls += 1
            if result3.get('status') == True:
                success_count += 1
            
            # 4. Set IPv6 prefix mode to RAandDHCPv6
            result4 = self._make_api_call(
                service="NetMaster",
                method="set",
                parameters={"EnableIPv6": 1, "IPv6PrefixMode": "RAandDHCPv6"}
            )
            total_calls += 1
            if result4.get('status') == True:
                success_count += 1
        
        elif mode == "on":
            # On: Enable with RA mode (4 requests)
            # 1. Set prefix length for lan DHCPv6
            result1 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan.IPv6.lan.DHCPv6",
                method="set",
                parameters={"IAPDPrefixLength": 56}
            )
            total_calls += 1
            if result1.get('status') == True:
                success_count += 1
            
            # 2. Enable IAPD on LAN interface
            result2 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.lan",
                method="setIPv6Configuration",
                parameters={"Name": "lan", "DHCPIAPDEnable": 1}
            )
            total_calls += 1
            if result2.get('status') is None:  # status null indicates success
                success_count += 1
            
            # 3. Set prefix length for guest DHCPv6
            result3 = self._make_api_call(
                service="NetMaster.LAN.default.Bridge.guest.IPv6.guest.DHCPv6",
                method="set",
                parameters={"IAPDPrefixLength": 56}
            )
            total_calls += 1
            if result3.get('status') == True:
                success_count += 1
            
            # 4. Set IPv6 prefix mode to RA
            result4 = self._make_api_call(
                service="NetMaster",
                method="set",
                parameters={"EnableIPv6": 1, "IPv6PrefixMode": "RA"}
            )
            total_calls += 1
            if result4.get('status') == True:
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
    
    def configure_ipv6_prefix_delegation(self, enabled: bool = True, 
                                        use_dhcpv6: bool = False,
                                        prefix_length: int = 56) -> bool:
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
            service="NeMo.Intf.dhcpv6_pdata",
            method="get",
            parameters={}
        )
        
        # Extract DHCPv6 client status from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
    def get_firewall_level(self) -> str:
        """
        Get the current firewall security level.
        
        Returns:
            Firewall level as string (e.g., "Low", "Medium", "High")
        """
        response = self._make_api_call(
            service="Firewall",
            method="getFirewallLevel",
            parameters={}
        )
        
        # Extract firewall level from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return "Unknown"
    
    def get_ping_response_settings(self, source_interface: str = "data") -> Dict[str, Any]:
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
            parameters={"sourceInterface": source_interface}
        )
        
        # Extract ping response settings from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
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
        response = self._make_api_call(
            service="Firewall",
            method="get",
            parameters={}
        )
        
        # Extract firewall configuration from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
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
            service="Firewall",
            method="getDMZ",
            parameters={}
        )
        
        # Extract DMZ configuration from response
        if isinstance(response, dict) and 'status' in response:
            # Extract the first DMZ rule (usually webui)
            status_data = response['status']
            for origin, dmz_config in status_data.items():
                if isinstance(dmz_config, dict):
                    # Add origin for reference
                    dmz_config['Origin'] = origin
                    return dmz_config
        
        return {}
    
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
        if pool_id not in ["default", "guest"]:
            raise ValueError("pool_id must be 'default' or 'guest'")
        
        response = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="getStaticLeases",
            parameters=pool_id
        )
        
        static_leases = []
        
        # Extract static leases from response
        if isinstance(response, dict) and 'status' in response:
            status_data = response['status']
            if isinstance(status_data, list):
                static_leases = status_data
        
        # Add pool ID for reference
        for lease in static_leases:
            lease['PoolID'] = pool_id
        
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
            'default': self.get_default_dhcp_static_leases(),
            'guest': self.get_guest_dhcp_static_leases()
        }

    def add_static_lease(self, mac_address: str, ip_address: str, pool_id: str = "default") -> bool:
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
        # Basic validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        if not ip_address or '.' not in ip_address:
            raise ValueError("Invalid IP address format")
        
        result = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="addStaticLease",
            parameters={
                "MACAddress": mac_address,
                "IPAddress": ip_address
            }
        )
        
        # API returns null on success
        return result is None

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
        # Basic validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        result = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="deleteStaticLease",
            parameters={
                "MACAddress": mac_address
            }
        )
        
        # API returns null on success
        return result is None

    def set_static_lease(self, mac_address: str, ip_address: str, pool_id: str = "default") -> bool:
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
        # Basic validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        if not ip_address or '.' not in ip_address:
            raise ValueError("Invalid IP address format")
        
        result = self._make_api_call(
            service=f"DHCPv4.Server.Pool.{pool_id}",
            method="setStaticLease",
            parameters={
                "MACAddress": mac_address,
                "IPAddress": ip_address
            }
        )
        
        # API returns null on success
        return result is None

    def manage_device_ip_reservation(self, mac_address: str, ip_address: str = None, 
                                   action: str = "add", pool_id: str = "default") -> bool:
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
        if action.lower() in ['add']:
            if not ip_address:
                raise ValueError("IP address required for add action")
            return self.add_static_lease(mac_address, ip_address, pool_id)
        
        elif action.lower() in ['delete', 'remove']:
            return self.delete_static_lease(mac_address, pool_id)
        
        elif action.lower() in ['set', 'update', 'modify']:
            if not ip_address:
                raise ValueError("IP address required for set/update action")
            return self.set_static_lease(mac_address, ip_address, pool_id)
        
        else:
            raise ValueError("Invalid action. Use 'add', 'delete', 'set', or 'update'")

    def reserve_device_ip(self, device_identifier: str, ip_address: str, 
                         pool_id: str = "default", auto_detect_mac: bool = True) -> bool:
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
        
        # If not a MAC address format and auto-detect is enabled
        if auto_detect_mac and ':' not in device_identifier:
            # Try to find device by name
            try:
                devices = self.list_managed_devices()
                matching_devices = [d for d in devices if d.get('name', '').lower() == device_identifier.lower()]
                
                if matching_devices:
                    mac_address = matching_devices[0]['mac_address']
                else:
                    raise ValueError(f"Device '{device_identifier}' not found")
            except Exception:
                raise ValueError(f"Could not find MAC address for device '{device_identifier}'")
        
        return self.add_static_lease(mac_address, ip_address, pool_id)

    def get_device_ip_reservation(self, mac_address: str, pool_id: str = "default") -> Dict[str, Any]:
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
        static_leases = self.get_dhcp_static_leases(pool_id)
        
        for lease in static_leases:
            if lease.get('mac_address', '').lower() == mac_address.lower():
                return lease
        
        return {}

    def list_ip_reservations(self, pool_id: str = "default", include_device_info: bool = True) -> List[Dict[str, Any]]:
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
        static_leases = self.get_dhcp_static_leases(pool_id)
        
        if not include_device_info:
            return static_leases
        
        # Get device information to enhance the reservations
        try:
            devices = self.list_managed_devices()
            device_lookup = {d['mac_address'].lower(): d for d in devices}
        except Exception:
            device_lookup = {}
        
        # Enhance static lease information
        enhanced_leases = []
        for lease in static_leases:
            enhanced_lease = lease.copy()
            mac = lease.get('mac_address', '').lower()
            
            if mac in device_lookup:
                device = device_lookup[mac]
                enhanced_lease.update({
                    'device_name': device.get('name', 'Unknown'),
                    'device_type': device.get('device_type', 'Unknown'),
                    'active': device.get('active', False),
                    'last_seen': device.get('last_seen', 'Unknown')
                })
            else:
                enhanced_lease.update({
                    'device_name': 'Unknown Device',
                    'device_type': 'Unknown',
                    'active': False,
                    'last_seen': 'Unknown'
                })
            
            enhanced_leases.append(enhanced_lease)
        
        return enhanced_leases

    def suggest_available_ips(self, pool_id: str = "default", count: int = 5) -> List[str]:
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
        try:
            # Get DHCP server config to find the pool range
            if pool_id == "default":
                dhcp_config = self.get_default_dhcp_server()
            else:
                dhcp_config = self.get_guest_dhcp_server()
            
            min_ip = dhcp_config.get('dhcp_min_address', '192.168.2.100')
            max_ip = dhcp_config.get('dhcp_max_address', '192.168.2.200')
            
            # Get existing reservations and active leases
            static_leases = self.get_dhcp_static_leases(pool_id)
            active_leases = self.get_dhcp_leases(pool_id)
            
            # Create set of used IPs
            used_ips = set()
            
            # Add static lease IPs
            for lease in static_leases:
                used_ips.add(lease.get('ip_address', ''))
            
            # Add active lease IPs
            for lease in active_leases:
                if lease.get('active', False):
                    used_ips.add(lease.get('ip_address', ''))
            
            # Generate IP range
            import ipaddress
            min_ip_obj = ipaddress.IPv4Address(min_ip)
            max_ip_obj = ipaddress.IPv4Address(max_ip)
            
            available_ips = []
            current_ip = min_ip_obj
            
            while current_ip <= max_ip_obj and len(available_ips) < count:
                ip_str = str(current_ip)
                if ip_str not in used_ips:
                    available_ips.append(ip_str)
                current_ip += 1
            
            return available_ips
            
        except Exception:
            # Fallback to simple suggestions
            base_ip = "192.168.2." if pool_id == "default" else "192.168.3."
            return [f"{base_ip}{i}" for i in range(100, 100 + count)]

    def cleanup_invalid_reservations(self, pool_id: str = "default") -> Dict[str, Any]:
        """
        Clean up invalid or conflicting IP reservations.
        
        Args:
            pool_id: DHCP pool ID ("default" or "guest")
        
        Returns:
            Dictionary with cleanup results
            
        Example:
            result = api.cleanup_invalid_reservations()
            print(f"Cleaned up {result['removed_count']} invalid reservations")
        """
        try:
            # Get DHCP config to validate IP ranges
            if pool_id == "default":
                dhcp_config = self.get_default_dhcp_server()
            else:
                dhcp_config = self.get_guest_dhcp_server()
            
            min_ip = dhcp_config.get('dhcp_min_address', '192.168.2.100')
            max_ip = dhcp_config.get('dhcp_max_address', '192.168.2.200')
            
            # Get current static leases
            static_leases = self.get_dhcp_static_leases(pool_id)
            
            import ipaddress
            min_ip_obj = ipaddress.IPv4Address(min_ip)
            max_ip_obj = ipaddress.IPv4Address(max_ip)
            
            invalid_leases = []
            duplicate_ips = {}
            
            # Check for invalid and duplicate IPs
            for lease in static_leases:
                ip_str = lease.get('ip_address', '')
                mac = lease.get('mac_address', '')
                
                try:
                    ip_obj = ipaddress.IPv4Address(ip_str)
                    
                    # Check if IP is outside DHCP range
                    if not (min_ip_obj <= ip_obj <= max_ip_obj):
                        invalid_leases.append({
                            'lease': lease,
                            'reason': 'IP outside DHCP range'
                        })
                        continue
                    
                    # Track duplicate IPs
                    if ip_str in duplicate_ips:
                        duplicate_ips[ip_str].append(lease)
                    else:
                        duplicate_ips[ip_str] = [lease]
                        
                except ValueError:
                    invalid_leases.append({
                        'lease': lease,
                        'reason': 'Invalid IP format'
                    })
            
            # Find actual duplicates (more than one lease per IP)
            duplicate_conflicts = {ip: leases for ip, leases in duplicate_ips.items() if len(leases) > 1}
            
            result = {
                'invalid_range': invalid_leases,
                'duplicate_ips': duplicate_conflicts,
                'total_issues': len(invalid_leases) + len(duplicate_conflicts),
                'recommendations': []
            }
            
            # Add recommendations
            if invalid_leases:
                result['recommendations'].append("Remove IP reservations outside DHCP range")
            if duplicate_conflicts:
                result['recommendations'].append("Resolve duplicate IP assignments")
            
            return result
            
        except Exception as e:
            return {
                'error': str(e),
                'invalid_range': [],
                'duplicate_ips': {},
                'total_issues': 0,
                'recommendations': ['Error during validation - check manually']
            }

    def get_device_schedules(self, schedule_type: str = "ToD") -> List[Dict[str, Any]]:
        """
        Get device access schedules (Time of Day restrictions).
        
        Args:
            schedule_type: Type of schedule to retrieve (default: "ToD")
        
        Returns:
            List of device schedule dictionaries with fields:
            - ID: Device identifier (usually MAC address)
            - name: Device name
            - enable: Whether scheduling is enabled for this device
            - base: Schedule base type (e.g., "Weekly")
            - def: Default state ("Enable" or "Disable")
            - stateMode: Current state mode ("Default", "Override")
            - override: Override setting ("Enable", "Disable", or "")
            - temporaryOverride: Whether temporary override is active
            - value: Current effective value ("Enable" or "Disable")
            - schedule: List of schedule rules
            - device: Device location ("LOCAL")
            - target: List of target devices
        """
        response = self._make_api_call(
            service="Scheduler",
            method="getCompleteSchedules",
            parameters={"type": schedule_type}
        )
        
        schedules = []
        
        # Extract schedules from response
        if isinstance(response, dict) and 'data' in response:
            data = response['data']
            if 'scheduleInfo' in data and isinstance(data['scheduleInfo'], list):
                schedules = data['scheduleInfo']
        
        return schedules
    
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
            service="Devices.Device.HGW",
            method="get",
            parameters={}
        )
        
        # Extract HGW device information from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
    def get_router_time(self) -> str:
        """
        Get the current time from the router.
        
        Returns:
            Current time as string (e.g., "Wed, 04 Jun 2025 19:50:34 GMT+0200")
        """
        response = self._make_api_call(
            service="Time",
            method="getTime",
            parameters=""
        )
        
        # Extract time from response
        if isinstance(response, dict) and 'data' in response:
            return response['data'].get('time', '')
        elif isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return ""
    
    def get_ntp_servers(self) -> Dict[str, str]:
        """
        Get configured NTP (Network Time Protocol) servers.
        
        Returns:
            Dictionary with NTP servers where keys are server numbers and values are server addresses.
            Example: {"1": "time.kpn.net", "2": "0.nl.pool.ntp.org", ...}
        """
        response = self._make_api_call(
            service="Time",
            method="getNTPServers",
            parameters=""
        )
        
        # Extract NTP servers from response
        if isinstance(response, dict) and 'data' in response:
            data = response['data']
            if 'servers' in data and isinstance(data['servers'], dict):
                return data['servers']
        
        return {}
    
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
            'current_time': self.get_router_time(),
            'ntp_servers': self.get_ntp_servers(),
            'ntp_servers_list': self.get_ntp_servers_list()
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
            parameters=""
        )
        
        # Extract speed test results from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
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
            parameters=""
        )
        
        # Extract speed test results from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
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
            'download': self.run_download_speedtest(),
            'upload': self.run_upload_speedtest()
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
            parameters={
                "host": host,
                "ipversion": ip_version
            }
        )
        
        # Extract traceroute results from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
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
            parameters={
                "ipHost": host,
                "ProtocolVersion": protocol_version
            }
        )
        
        # Extract ping results from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
    def get_iptv_ip(self) -> str:
        """
        Get the IP address of the IPTV interface.
        
        Returns:
            IPTV interface IP address as string (e.g., "10.233.241.178")
        """
        response = self._make_api_call(
            service="NeMo.Intf.iptv",
            method="luckyAddrAddress",
            parameters={
                "flag": "ipv4",
                "traverse": "down"
            }
        )
        
        # Extract IPTV IP from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return ""
    
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
            parameters={}
        )
        
        # Extract voice profiles from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}
    
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
            service="VoiceService.VoiceApplication",
            method="listTrunks",
            parameters={}
        )
        
        # Extract voice trunks from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return []
    
    def get_voice_groups(self) -> List[Dict[str, Any]]:
        """
        Get voice groups configuration.
        
        Returns:
            List of voice group dictionaries with fields:
            - group_id: Group identifier (e.g., "Group1")
            - ep_names: List of endpoint names in the group
        """
        response = self._make_api_call(
            service="VoiceService.VoiceApplication",
            method="listGroups",
            parameters={}
        )
        
        # Extract voice groups from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return []
    
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
            parameters={}
        )
        
        # Extract voice handsets from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return []
    
    def ring_test_phone(self) -> bool:
        """
        Ring the phone for testing purposes.
        
        Returns:
            True if ring test command was sent successfully
        """
        response = self._make_api_call(
            service="VoiceService.VoiceApplication",
            method="ring",
            parameters={}
        )
        
        # For this function, success returns {"status": null}
        return response.get('status') is None
    
    def set_wifi_config(self, ssid_2g: str = None, ssid_5g: str = None, 
                       password_2g: str = None, password_5g: str = None,
                       security_mode_2g: str = None, security_mode_5g: str = None,
                       mfp_config_2g: str = "", mfp_config_5g: str = "") -> bool:
        """
        Configure WiFi network settings (SSID, password, security).
        
        Args:
            ssid_2g: 2.4GHz network name/SSID
            ssid_5g: 5GHz network name/SSID  
            password_2g: 2.4GHz network password
            password_5g: 5GHz network password
            security_mode_2g: 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            security_mode_5g: 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            mfp_config_2g: 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
            mfp_config_5g: 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
        
        Returns:
            True if successful (returns {"status": null} on success)
        """
        # Get current WiFi configuration to find VAP names
        current_networks = self.get_wifi_networks()
        
        # Find 2.4G and 5G networks
        vap_2g = None
        vap_5g = None
        
        for network in current_networks:
            vap_name = network.get('VAPName', '')
            if '2g' in vap_name and 'priv' in vap_name:
                vap_2g = vap_name
            elif '5g' in vap_name and 'priv' in vap_name:
                vap_5g = vap_name
        
        if not vap_2g or not vap_5g:
            # Fallback to standard names if detection fails
            vap_2g = 'vap2g0priv'
            vap_5g = 'vap5g0priv'
        
        return self._set_wifi_config_internal(
            vap_2g=vap_2g,
            vap_5g=vap_5g,
            ssid_2g=ssid_2g,
            ssid_5g=ssid_5g,
            password_2g=password_2g,
            password_5g=password_5g,
            security_mode_2g=security_mode_2g,
            security_mode_5g=security_mode_5g,
            mfp_config_2g=mfp_config_2g,
            mfp_config_5g=mfp_config_5g,
            include_penable=False
        )
    
    def set_wifi_visibility(self, visible_2g: bool = None, visible_5g: bool = None) -> bool:
        """
        Enable or disable WiFi network visibility (SSID advertisement).
        
        Args:
            visible_2g: Whether 2.4GHz network should be visible (broadcast SSID)
            visible_5g: Whether 5GHz network should be visible (broadcast SSID)
        
        Returns:
            True if successful (returns {"status": null} on success)
        """
        # Get current WiFi configuration to find VAP names
        current_networks = self.get_wifi_networks()
        
        # Find 2.4G and 5G networks
        vap_2g = None
        vap_5g = None
        
        for network in current_networks:
            vap_name = network.get('VAPName', '')
            if '2g' in vap_name and 'priv' in vap_name:
                vap_2g = vap_name
            elif '5g' in vap_name and 'priv' in vap_name:
                vap_5g = vap_name
        
        if not vap_2g or not vap_5g:
            # Fallback to standard names if detection fails
            vap_2g = 'vap2g0priv'
            vap_5g = 'vap5g0priv'
        
        return self._set_wifi_visibility_internal(
            vap_2g=vap_2g,
            vap_5g=vap_5g,
            visible_2g=visible_2g,
            visible_5g=visible_5g
        )
    
    def set_wps_enabled(self, enabled_2g: bool = None, enabled_5g: bool = None) -> Dict[str, bool]:
        """
        Enable or disable WPS (WiFi Protected Setup) for WiFi networks.
        
        Args:
            enabled_2g: Whether to enable WPS on 2.4GHz network
            enabled_5g: Whether to enable WPS on 5GHz network
        
        Returns:
            Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band
        """
        results = {}
        
        # Get current WiFi configuration to find VAP names
        current_networks = self.get_wifi_networks()
        
        # Find 2.4G and 5G networks
        vap_2g = None
        vap_5g = None
        
        for network in current_networks:
            vap_name = network.get('VAPName', '')
            if '2g' in vap_name and 'priv' in vap_name:
                vap_2g = vap_name
            elif '5g' in vap_name and 'priv' in vap_name:
                vap_5g = vap_name
        
        if not vap_2g or not vap_5g:
            # Fallback to standard names if detection fails
            vap_2g = 'vap2g0priv'
            vap_5g = 'vap5g0priv'
        
        # Configure 2.4GHz WPS
        if enabled_2g is not None:
            result = self._make_api_call(
                service=f"NeMo.Intf.{vap_2g}.WPS",
                method="set",
                parameters={"Enable": enabled_2g}
            )
            results['band_2g'] = result.get('status', False) == True
        
        # Configure 5GHz WPS
        if enabled_5g is not None:
            result = self._make_api_call(
                service=f"NeMo.Intf.{vap_5g}.WPS",
                method="set",
                parameters={"Enable": enabled_5g}
            )
            results['band_5g'] = result.get('status', False) == True
        
        return results

    def enable_guest_network(self, enabled: bool = True) -> bool:
        """
        Enable or disable the guest WiFi network.
        
        Args:
            enabled: Whether to enable guest network (default: True)
        
        Returns:
            True if all operations successful
        """
        try:
            # Step 1: Enable/disable guest network service
            result1 = self._make_api_call(
                service="NMC.Guest",
                method="set",
                parameters={"Enable": "1" if enabled else "0"}
            )
            success1 = result1.get('status', False) == True
            
            # Step 2: Enable/disable 2.4GHz guest VAP
            result2 = self._make_api_call(
                service="NeMo.Intf.vap2g0guest",
                method="set",
                parameters={"PersistentEnable": enabled}
            )
            success2 = result2.get('status', False) == True
            
            # Step 3: Enable/disable 5GHz guest VAP  
            result3 = self._make_api_call(
                service="NeMo.Intf.vap5g0guest",
                method="set",
                parameters={"PersistentEnable": enabled}
            )
            success3 = result3.get('status', False) == True
            
            return success1 and success2 and success3
            
        except Exception:
            return False
    
    def set_guest_wifi_config(self, ssid_2g: str = None, ssid_5g: str = None,
                             password_2g: str = None, password_5g: str = None,
                             security_mode_2g: str = None, security_mode_5g: str = None,
                             mfp_config_2g: str = "", mfp_config_5g: str = "") -> bool:
        """
        Configure guest WiFi network settings (SSID, password, security).
        
        Args:
            ssid_2g: 2.4GHz guest network name/SSID
            ssid_5g: 5GHz guest network name/SSID
            password_2g: 2.4GHz guest network password
            password_5g: 5GHz guest network password
            security_mode_2g: 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            security_mode_5g: 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            mfp_config_2g: 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
            mfp_config_5g: 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
        
        Returns:
            True if successful (returns {"status": null} on success)
        """
        return self._set_wifi_config_internal(
            vap_2g="vap2g0guest",
            vap_5g="vap5g0guest",
            ssid_2g=ssid_2g,
            ssid_5g=ssid_5g,
            password_2g=password_2g,
            password_5g=password_5g,
            security_mode_2g=security_mode_2g,
            security_mode_5g=security_mode_5g,
            mfp_config_2g=mfp_config_2g,
            mfp_config_5g=mfp_config_5g,
            include_penable=True
        )
    
    def set_guest_wifi_visibility(self, visible_2g: bool = None, visible_5g: bool = None) -> bool:
        """
        Enable or disable guest WiFi network visibility (SSID advertisement).
        
        Args:
            visible_2g: Whether 2.4GHz guest network should be visible (broadcast SSID)
            visible_5g: Whether 5GHz guest network should be visible (broadcast SSID)
        
        Returns:
            True if successful (returns {"status": null} on success)
        """
        return self._set_wifi_visibility_internal(
            vap_2g="vap2g0guest",
            vap_5g="vap5g0guest",
            visible_2g=visible_2g,
            visible_5g=visible_5g
        )
    
    def set_guest_bandwidth_limit(self, limit_mbps: int = 0) -> bool:
        """
        Set bandwidth limitation for guest network.
        
        Args:
            limit_mbps: Bandwidth limit in Mbps (0 = unlimited, max 50000 = 50 Gbps)
        
        Returns:
            True if successful (returns {"status": true} on success)
        """
        if limit_mbps < 0 or limit_mbps > 50000:
            raise ValueError("Bandwidth limit must be between 0 and 50000 Mbps")
        
        result = self._make_api_call(
            service="NMC.Guest",
            method="set",
            parameters={"BandwidthLimitation": limit_mbps}
        )
        
        return result.get('status', False) == True

    def _set_wifi_config_internal(self, vap_2g: str, vap_5g: str, ssid_2g: str = None, ssid_5g: str = None,
                                 password_2g: str = None, password_5g: str = None,
                                 security_mode_2g: str = None, security_mode_5g: str = None,
                                 mfp_config_2g: str = "", mfp_config_5g: str = "",
                                 include_penable: bool = False) -> bool:
        """
        Internal method for WiFi configuration shared by regular/guest/extra networks.
        
        Args:
            vap_2g: 2.4GHz VAP name (e.g., "vap2g0priv", "vap2g0guest", "vap2g0ext")
            vap_5g: 5GHz VAP name (e.g., "vap5g0priv", "vap5g0guest", "vap5g0ext")
            include_penable: Whether to include penable section (needed for guest networks)
            ... other parameters same as public methods
        """
        # Build configuration parameters
        wlanvap_config = {}
        penable_config = {}
        
        # Configure 2.4GHz network
        if any([ssid_2g, password_2g, security_mode_2g, mfp_config_2g]):
            config_2g = {}
            
            if ssid_2g is not None:
                config_2g['SSID'] = ssid_2g
            
            if any([password_2g, security_mode_2g, mfp_config_2g]):
                security_config = {}
                if password_2g is not None:
                    security_config['KeyPassPhrase'] = password_2g
                if security_mode_2g is not None:
                    security_config['ModeEnabled'] = security_mode_2g
                if mfp_config_2g is not None:
                    security_config['MFPConfig'] = mfp_config_2g
                
                config_2g['Security'] = security_config
            
            wlanvap_config[vap_2g] = config_2g
            if include_penable:
                penable_config[vap_2g] = {"Enable": "", "PersistentEnable": "", "Status": ""}
        
        # Configure 5GHz network
        if any([ssid_5g, password_5g, security_mode_5g, mfp_config_5g]):
            config_5g = {}
            
            if ssid_5g is not None:
                config_5g['SSID'] = ssid_5g
            
            if any([password_5g, security_mode_5g, mfp_config_5g]):
                security_config = {}
                if password_5g is not None:
                    security_config['KeyPassPhrase'] = password_5g
                if security_mode_5g is not None:
                    security_config['ModeEnabled'] = security_mode_5g
                if mfp_config_5g is not None:
                    security_config['MFPConfig'] = mfp_config_5g
                
                config_5g['Security'] = security_config
            
            wlanvap_config[vap_5g] = config_5g
            if include_penable:
                penable_config[vap_5g] = {"Enable": "", "PersistentEnable": "", "Status": ""}
        
        if not wlanvap_config:
            return True
        
        # Build the complete parameters
        parameters = {"mibs": {}}
        if include_penable and penable_config:
            parameters["mibs"]["penable"] = penable_config
        if wlanvap_config:
            parameters["mibs"]["wlanvap"] = wlanvap_config
        
        result = self._make_api_call(
            service="NeMo.Intf.lan",
            method="setWLANConfig",
            parameters=parameters
        )
        
        return result.get('status') is None

    def _set_wifi_visibility_internal(self, vap_2g: str, vap_5g: str, visible_2g: bool = None, visible_5g: bool = None) -> bool:
        """
        Internal method for WiFi visibility shared by regular/guest/extra networks.
        
        Args:
            vap_2g: 2.4GHz VAP name (e.g., "vap2g0priv", "vap2g0guest", "vap2g0ext")
            vap_5g: 5GHz VAP name (e.g., "vap5g0priv", "vap5g0guest", "vap5g0ext")
            visible_2g: Whether 2.4GHz network should be visible
            visible_5g: Whether 5GHz network should be visible
        """
        if visible_2g is None and visible_5g is None:
            return True
        
        wlanvap_config = {}
        
        if visible_2g is not None:
            wlanvap_config[vap_2g] = {"SSIDAdvertisementEnabled": visible_2g}
        
        if visible_5g is not None:
            wlanvap_config[vap_5g] = {"SSIDAdvertisementEnabled": visible_5g}
        
        result = self._make_api_call(
            service="NeMo.Intf.lan",
            method="setWLANConfig",
            parameters={
                "mibs": {
                    "wlanvap": wlanvap_config
                }
            }
        )
        
        return result.get('status') is None

    def enable_extra_wifi(self, enabled_2g: bool = None, enabled_5g: bool = None) -> Dict[str, bool]:
        """
        Enable or disable extra WiFi networks.
        
        Args:
            enabled_2g: Whether to enable 2.4GHz extra network
            enabled_5g: Whether to enable 5GHz extra network
        
        Returns:
            Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band
        """
        results = {}
        
        # Enable/disable 2.4GHz extra WiFi
        if enabled_2g is not None:
            result = self._make_api_call(
                service="NeMo.Intf.vap2g0ext",
                method="set",
                parameters={"PersistentEnable": enabled_2g}
            )
            results['band_2g'] = result.get('status', False) == True
        
        # Enable/disable 5GHz extra WiFi
        if enabled_5g is not None:
            result = self._make_api_call(
                service="NeMo.Intf.vap5g0ext",
                method="set",
                parameters={"PersistentEnable": enabled_5g}
            )
            results['band_5g'] = result.get('status', False) == True
        
        return results

    def set_extra_wifi_config(self, ssid_2g: str = None, ssid_5g: str = None,
                             password_2g: str = None, password_5g: str = None,
                             security_mode_2g: str = None, security_mode_5g: str = None,
                             mfp_config_2g: str = "", mfp_config_5g: str = "") -> bool:
        """
        Configure extra WiFi network settings (SSID, password, security).
        
        Args:
            ssid_2g: 2.4GHz extra network name/SSID
            ssid_5g: 5GHz extra network name/SSID
            password_2g: 2.4GHz extra network password
            password_5g: 5GHz extra network password
            security_mode_2g: 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            security_mode_5g: 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            mfp_config_2g: 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
            mfp_config_5g: 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
        
        Returns:
            True if successful
        """
        return self._set_wifi_config_internal(
            vap_2g="vap2g0ext",
            vap_5g="vap5g0ext",
            ssid_2g=ssid_2g,
            ssid_5g=ssid_5g,
            password_2g=password_2g,
            password_5g=password_5g,
            security_mode_2g=security_mode_2g,
            security_mode_5g=security_mode_5g,
            mfp_config_2g=mfp_config_2g,
            mfp_config_5g=mfp_config_5g,
            include_penable=False
        )

    def set_extra_wifi_visibility(self, visible_2g: bool = None, visible_5g: bool = None) -> bool:
        """
        Enable or disable extra WiFi network visibility (SSID advertisement).
        
        Args:
            visible_2g: Whether 2.4GHz extra network should be visible (broadcast SSID)
            visible_5g: Whether 5GHz extra network should be visible (broadcast SSID)
        
        Returns:
            True if successful
        """
        return self._set_wifi_visibility_internal(
            vap_2g="vap2g0ext",
            vap_5g="vap5g0ext",
            visible_2g=visible_2g,
            visible_5g=visible_5g
        )

    def get_wifi_status(self) -> Dict[str, Any]:
        """
        Get overall WiFi status and configuration.
        
        Returns:
            Dictionary with WiFi status including:
            - Enable: Whether WiFi is globally enabled
            - Status: Current WiFi status
            - Various WiFi configuration fields
        """
        response = self._make_api_call(
            service="NMC.Wifi",
            method="get",
            parameters={}
        )
        
        # Extract WiFi status from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}

    def set_wifi_enabled(self, enabled: bool = True, sync_extenders: bool = True) -> bool:
        """
        Enable or disable WiFi radios completely.
        
        Args:
            enabled: Whether to enable WiFi (default: True)
            sync_extenders: Whether to keep WiFi on extenders enabled (default: True)
        
        Returns:
            True if all operations successful
        """
        success_count = 0
        total_operations = 6 if sync_extenders else 5
        
        # Enable/disable overall WiFi
        result1 = self._make_api_call(
            service="NMC.Wifi",
            method="set",
            parameters={"Enable": enabled}
        )
        if result1.get('status', False) == True:
            success_count += 1
        
        # Enable/disable 2.4GHz radio
        result2 = self._make_api_call(
            service="NeMo.Intf.rad2g0",
            method="set",
            parameters={"Enable": enabled}
        )
        if result2.get('status', False) == True:
            success_count += 1
        
        # Enable/disable 5GHz radio
        result3 = self._make_api_call(
            service="NeMo.Intf.rad5g0",
            method="set",
            parameters={"Enable": enabled}
        )
        if result3.get('status', False) == True:
            success_count += 1
        
        # Enable/disable main 2.4GHz network
        result4 = self._make_api_call(
            service="NeMo.Intf.vap2g0priv",
            method="set",
            parameters={"PersistentEnable": enabled}
        )
        if result4.get('status', False) == True:
            success_count += 1
        
        # Enable/disable main 5GHz network
        result5 = self._make_api_call(
            service="NeMo.Intf.vap5g0priv",
            method="set",
            parameters={"PersistentEnable": enabled}
        )
        if result5.get('status', False) == True:
            success_count += 1
        
        # Optionally sync with extenders
        if sync_extenders:
            result6 = self._make_api_call(
                service="SSW.Steering.MasterConfig",
                method="set",
                parameters={"SyncEnableField": True}
            )
            if result6.get('status', False) == True:
                success_count += 1
        
        return success_count == total_operations

    def set_wifi_radio_config(self, band_2g_config: Dict[str, Any] = None, 
                             band_5g_config: Dict[str, Any] = None) -> Dict[str, bool]:
        """
        Configure WiFi radio settings for 2.4GHz and/or 5GHz bands.
        
        Args:
            band_2g_config: 2.4GHz radio configuration dictionary with keys:
                - AutoChannelEnable: Whether to enable auto channel selection (bool)
                - OperatingChannelBandwidth: Channel bandwidth ("20MHz", "40MHz")
                - OperatingStandards: Supported standards (e.g., "g,n,ax")
            band_5g_config: 5GHz radio configuration dictionary with keys:
                - AutoChannelEnable: Whether to enable auto channel selection (bool)  
                - OperatingChannelBandwidth: Channel bandwidth ("20MHz", "40MHz", "80MHz", "160MHz")
                - OperatingStandards: Supported standards (e.g., "a,n,ac,ax")
        
        Returns:
            Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band
        """
        results = {}
        
        # Configure 2.4GHz radio
        if band_2g_config is not None:
            result = self._make_api_call(
                service="NeMo.Intf.rad2g0",
                method="setWLANConfig",
                parameters={
                    "mibs": {
                        "wlanradio": {
                            "rad2g0": band_2g_config
                        }
                    }
                }
            )
            results['band_2g'] = result.get('status') is None
        
        # Configure 5GHz radio
        if band_5g_config is not None:
            result = self._make_api_call(
                service="NeMo.Intf.rad5g0",
                method="setWLANConfig", 
                parameters={
                    "mibs": {
                        "wlanradio": {
                            "rad5g0": band_5g_config
                        }
                    }
                }
            )
            results['band_5g'] = result.get('status') is None
        
        return results

    def set_wifi_radio_defaults(self) -> Dict[str, bool]:
        """
        Set WiFi radio configuration to recommended defaults.
        
        Returns:
            Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band
        """
        return self.set_wifi_radio_config(
            band_2g_config={
                "AutoChannelEnable": True,
                "OperatingChannelBandwidth": "20MHz",
                "OperatingStandards": "g,n,ax"
            },
            band_5g_config={
                "AutoChannelEnable": True,
                "OperatingChannelBandwidth": "80MHz", 
                "OperatingStandards": "a,n,ac,ax"
            }
        )

    def enable_wifi_schedule(self, network_id: str = "wl0", enabled: bool = True) -> bool:
        """
        Enable or disable WiFi time scheduling.
        
        Args:
            network_id: WiFi network identifier (default: "wl0")
            enabled: Whether to enable scheduling (default: True)
        
        Returns:
            True if successful
        """
        result = self._make_api_call(
            service="Scheduler",
            method="enableSchedule",
            parameters={
                "type": "WLAN",
                "ID": network_id,
                "enable": enabled
            }
        )
        
        return result.get('status', False) == True

    def set_wifi_schedule(self, network_id: str = "wl0", 
                         disable_blocks: List[Dict[str, int]] = None,
                         enabled: bool = True) -> bool:
        """
        Set WiFi time schedule with specific disable periods.
        
        Args:
            network_id: WiFi network identifier (default: "wl0")
            disable_blocks: List of time blocks when WiFi should be disabled.
                           Each block is a dict with 'begin' and 'end' keys (seconds from Monday 00:00)
            enabled: Whether the schedule should be enabled (default: True)
        
        Returns:
            True if successful
        
        Example:
            # Disable WiFi from 10 PM to 6 AM on weekdays
            api.set_wifi_schedule(disable_blocks=[
                {"begin": 79200, "end": 108000},  # Monday 22:00-06:00+1  
                {"begin": 165600, "end": 194400}, # Tuesday 22:00-06:00+1
                # ... more days
            ])
        """
        if disable_blocks is None:
            disable_blocks = []
        
        # Convert disable blocks to schedule format
        schedule = []
        for block in disable_blocks:
            schedule.append({
                "state": "Disable",
                "begin": block["begin"],
                "end": block["end"]
            })
        
        schedule_info = {
            "base": "Weekly",
            "def": "Enable",  # Default state is enabled
            "ID": network_id,
            "schedule": schedule,
            "enable": enabled,
            "override": ""
        }
        
        result = self._make_api_call(
            service="Scheduler",
            method="addSchedule",
            parameters={
                "type": "WLAN",
                "info": schedule_info
            }
        )
        
        return result.get('status', False) == True

    def set_wifi_bedtime_schedule(self, network_id: str = "wl0",
                                 bedtime_hour: int = 22, wakeup_hour: int = 6,
                                 weekdays_only: bool = True) -> bool:
        """
        Set a simple bedtime WiFi schedule (disable during night hours).
        
        Args:
            network_id: WiFi network identifier (default: "wl0")
            bedtime_hour: Hour to disable WiFi (0-23, default: 22 = 10 PM)
            wakeup_hour: Hour to enable WiFi (0-23, default: 6 = 6 AM)
            weekdays_only: Whether to apply only on weekdays (default: True)
        
        Returns:
            True if successful
        """
        if not (0 <= bedtime_hour <= 23) or not (0 <= wakeup_hour <= 23):
            raise ValueError("Hours must be between 0 and 23")
        
        disable_blocks = []
        
        # Define which days to apply the schedule
        if weekdays_only:
            days = [0, 1, 2, 3, 4]  # Monday to Friday
        else:
            days = [0, 1, 2, 3, 4, 5, 6]  # All week
        
        for day in days:
            day_start = day * 24 * 3600  # Start of day in seconds
            
            if bedtime_hour > wakeup_hour:
                # Bedtime is before midnight, wakeup is next day
                bedtime_start = day_start + (bedtime_hour * 3600)
                bedtime_end = day_start + (24 * 3600)  # End of current day
                
                wakeup_start = (day + 1) * 24 * 3600  # Start of next day
                wakeup_end = wakeup_start + (wakeup_hour * 3600)
                
                # Add both blocks
                disable_blocks.append({"begin": bedtime_start, "end": bedtime_end})
                if day < 6:  # Don't go beyond week
                    disable_blocks.append({"begin": wakeup_start, "end": wakeup_end})
            else:
                # Both bedtime and wakeup are on same day (unusual but possible)
                bedtime_start = day_start + (bedtime_hour * 3600)
                bedtime_end = day_start + (wakeup_hour * 3600)
                disable_blocks.append({"begin": bedtime_start, "end": bedtime_end})
        
        return self.set_wifi_schedule(network_id, disable_blocks, enabled=True)

    def clear_wifi_schedule(self, network_id: str = "wl0") -> bool:
        """
        Clear WiFi schedule (remove all time restrictions).
        
        Args:
            network_id: WiFi network identifier (default: "wl0")
        
        Returns:
            True if successful
        """
        # Set empty schedule (WiFi always enabled)
        return self.set_wifi_schedule(network_id, disable_blocks=[], enabled=False)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup session data."""
        self.context_id = None
        self._username = None
        self._password = None
        self.session.cookies.clear()
        self.session.headers.pop('Authorization', None)
        self.session.headers.pop('X-Context', None)

    def get_wifi_radio_info(self, band: str = "2g") -> Dict[str, Any]:
        """
        Get detailed WiFi radio information for a specific band.
        
        Args:
            band: WiFi band - "2g" or "5g" (default: "2g")
        
        Returns:
            Dictionary with comprehensive radio information including:
            - Name: Radio name (e.g., "rad2g0", "rad5g0")
            - Enable: Whether radio is enabled
            - Status: Current radio status
            - RadioStatus: Radio operational status ("Up", "Down")
            - OperatingFrequencyBand: Current frequency band ("2.4GHz", "5GHz")
            - CurrentOperatingChannelBandwidth: Current channel bandwidth (e.g., "20MHz", "80MHz")
            - MaxChannelBandwidth: Maximum supported bandwidth (e.g., "40MHz", "160MHz")
            - SupportedStandards: Supported WiFi standards (e.g., "a,b,g,n,ax")
            - OperatingStandards: Currently enabled standards
            - Channel: Current operating channel
            - ChannelsInUse: Channels currently in use (for 80MHz/160MHz)
            - AutoChannelEnable: Whether auto channel selection is enabled
            - AutoBandwidthEnable: Whether auto bandwidth selection is enabled
            - ChannelLoad: Current channel load percentage (0-100)
            - Interference: Interference level percentage
            - Noise: Noise level in dBm
            - TransmitPower: Transmit power setting (-1 = auto)
            - MaxAssociatedDevices: Maximum allowed connected devices
            - ActiveAssociatedDevices: Currently connected devices
            - BeaconPeriod: Beacon transmission interval (milliseconds)
            - DTIMPeriod: DTIM period
            - OfdmaEnable: Whether OFDMA is enabled
            - MultiUserMIMOEnabled: Whether MU-MIMO is enabled
            - ImplicitBeamFormingEnabled: Whether implicit beamforming is enabled
            - ExplicitBeamFormingEnabled: Whether explicit beamforming is enabled
            - IEEE80211hEnabled: Whether 802.11h (DFS) is enabled
            - IEEE80211rSupported: Whether 802.11r (fast roaming) is supported
            - IEEE80211kSupported: Whether 802.11k (neighbor reports) is supported
            - RegulatoryDomain: Regulatory domain (e.g., "NL")
            - And many other detailed radio configuration fields
            
        Raises:
            ValueError: If band is not "2g" or "5g"
        """
        if band not in ["2g", "5g"]:
            raise ValueError("band must be '2g' or '5g'")
        
        radio_name = f"rad{band}0"
        
        response = self._make_api_call(
            service=f"NeMo.Intf.{radio_name}",
            method="get",
            parameters={}
        )
        
        # Extract radio information from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}

    def get_wifi_spectrum_info(self, band: str = "2g", update: bool = True) -> List[Dict[str, Any]]:
        """
        Get WiFi spectrum analysis information for a specific band.
        
        Args:
            band: WiFi band - "2g" or "5g" (default: "2g")
            update: Whether to update spectrum data before returning (default: True)
        
        Returns:
            List of channel analysis dictionaries with fields:
            - channel: Channel number (e.g., 1-13 for 2.4GHz, 36-140 for 5GHz)
            - bandwidth: Channel bandwidth in MHz (typically 20)
            - isBanned: Whether channel is banned/restricted
            - Bonus: Channel bonus score for selection
            - availability: Channel availability percentage (0-100, higher = less congested)
            - ourUsage: Our own usage on this channel (0-100)
            - noiselevel: Background noise level in dBm
            - accesspoints: Number of other access points detected on this channel
            
        Raises:
            ValueError: If band is not "2g" or "5g"
            
        Note:
            Higher availability percentages indicate less congested channels.
            Lower noise levels (more negative dBm) indicate cleaner channels.
            Fewer access points indicate less competition for the channel.
        """
        if band not in ["2g", "5g"]:
            raise ValueError("band must be '2g' or '5g'")
        
        radio_name = f"rad{band}0"
        
        response = self._make_api_call(
            service=f"NeMo.Intf.{radio_name}",
            method="getSpectrumInfo",
            parameters={"update": update}
        )
        
        # Extract spectrum information from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return []

    def get_wifi_scan_results(self, band: str = "2g") -> List[Dict[str, Any]]:
        """
        Get WiFi scan results showing all detected networks in a specific band.
        
        Args:
            band: WiFi band - "2g" or "5g" (default: "2g")
        
        Returns:
            List of detected network dictionaries with fields:
            - SSID: Network name (may be empty for hidden networks)
            - BSSID: MAC address of the access point
            - SignalNoiseRatio: Signal-to-noise ratio
            - Noise: Noise level in dBm
            - RSSI: Received Signal Strength Indicator in dBm
            - Channel: WiFi channel number
            - CentreChannel: Center channel for wide channels
            - Bandwidth: Channel bandwidth in MHz (20, 40, 80, 160)
            - SignalStrength: Signal strength in dBm (same as RSSI)
            - SecurityModeEnabled: Security mode (e.g., "WPA2-Personal", "WPA3-Personal")
            - MFPConfig: Management Frame Protection configuration
            - WPSConfigMethodsSupported: Supported WPS methods
            - EncryptionMode: Encryption type (e.g., "AES")
            - OperatingStandards: Supported WiFi standards (e.g., "a,n,ac,ax")
            - VendorIEs: Vendor-specific information elements
            
        Raises:
            ValueError: If band is not "2g" or "5g"
            
        Note:
            Hidden networks will have empty SSID but still show other information.
            Signal strength values are in dBm (higher/less negative = stronger signal).
        """
        if band not in ["2g", "5g"]:
            raise ValueError("band must be '2g' or '5g'")
        
        radio_name = f"rad{band}0"
        
        response = self._make_api_call(
            service=f"NeMo.Intf.{radio_name}",
            method="getScanResults",
            parameters={}
        )
        
        # Extract scan results from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return []

    def get_all_wifi_radio_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get WiFi radio information for both 2.4GHz and 5GHz bands.
        
        Returns:
            Dictionary with keys:
            - 'band_2g': 2.4GHz radio information
            - 'band_5g': 5GHz radio information
        """
        return {
            'band_2g': self.get_wifi_radio_info("2g"),
            'band_5g': self.get_wifi_radio_info("5g")
        }

    def get_all_wifi_spectrum_info(self, update: bool = True) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get WiFi spectrum analysis for both 2.4GHz and 5GHz bands.
        
        Args:
            update: Whether to update spectrum data before returning (default: True)
        
        Returns:
            Dictionary with keys:
            - 'band_2g': 2.4GHz spectrum analysis
            - 'band_5g': 5GHz spectrum analysis
        """
        return {
            'band_2g': self.get_wifi_spectrum_info("2g", update),
            'band_5g': self.get_wifi_spectrum_info("5g", update)
        }

    def get_all_wifi_scan_results(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get WiFi scan results for both 2.4GHz and 5GHz bands.
        
        Returns:
            Dictionary with keys:
            - 'band_2g': 2.4GHz scan results
            - 'band_5g': 5GHz scan results
        """
        return {
            'band_2g': self.get_wifi_scan_results("2g"),
            'band_5g': self.get_wifi_scan_results("5g")
        }

    def get_best_wifi_channels(self, band: str = "2g", top_n: int = 3) -> List[Dict[str, Any]]:
        """
        Get the best WiFi channels based on availability and interference.
        
        Args:
            band: WiFi band - "2g" or "5g" (default: "2g")
            top_n: Number of top channels to return (default: 3)
        
        Returns:
            List of best channel dictionaries sorted by score, with additional fields:
            - score: Calculated channel score (higher = better)
            - congestion_level: Text description of congestion ("Low", "Medium", "High")
            - recommendation: Text recommendation for this channel
            Plus all original spectrum info fields
            
        Raises:
            ValueError: If band is not "2g" or "5g"
        """
        spectrum_data = self.get_wifi_spectrum_info(band)
        
        if not spectrum_data:
            return []
        
        # Calculate scores and add analysis
        scored_channels = []
        for channel_info in spectrum_data:
            # Calculate a score based on availability, noise, and access point count
            availability = channel_info.get('availability', 0)
            noise_level = channel_info.get('noiselevel', -50)  # dBm
            access_points = channel_info.get('accesspoints', 0)
            our_usage = channel_info.get('ourUsage', 0)
            
            # Score calculation (0-100):
            # - High availability is good
            # - Low noise is good (more negative dBm)
            # - Fewer access points is good
            # - Our own usage doesn't count against the channel
            score = availability
            score += max(0, (noise_level + 100)) * 0.5  # Noise bonus (better for lower noise)
            score -= access_points * 5  # Penalty for each access point
            score = max(0, min(100, score))  # Clamp to 0-100
            
            # Determine congestion level
            if availability > 80 and access_points <= 1:
                congestion_level = "Low"
                recommendation = "Excellent choice - low congestion"
            elif availability > 60 and access_points <= 3:
                congestion_level = "Medium"
                recommendation = "Good choice - moderate usage"
            else:
                congestion_level = "High"
                recommendation = "Avoid if possible - high congestion"
            
            # Create enhanced channel info
            enhanced_info = channel_info.copy()
            enhanced_info.update({
                'score': round(score, 1),
                'congestion_level': congestion_level,
                'recommendation': recommendation
            })
            
            scored_channels.append(enhanced_info)
        
        # Sort by score (highest first) and return top N
        scored_channels.sort(key=lambda x: x['score'], reverse=True)
        return scored_channels[:top_n]

    def analyze_wifi_environment(self) -> Dict[str, Any]:
        """
        Perform comprehensive WiFi environment analysis for both bands.
        
        Returns:
            Dictionary with comprehensive WiFi analysis including:
            - summary: Overall environment summary
            - band_2g: 2.4GHz analysis with radio info, spectrum data, best channels
            - band_5g: 5GHz analysis with radio info, spectrum data, best channels
            - recommendations: List of optimization recommendations
            - total_networks: Total number of detected networks across both bands
        """
        # Get data for both bands
        radio_2g = self.get_wifi_radio_info("2g")
        radio_5g = self.get_wifi_radio_info("5g")
        spectrum_2g = self.get_wifi_spectrum_info("2g")
        spectrum_5g = self.get_wifi_spectrum_info("5g")
        scan_2g = self.get_wifi_scan_results("2g")
        scan_5g = self.get_wifi_scan_results("5g")
        best_2g = self.get_best_wifi_channels("2g", 3)
        best_5g = self.get_best_wifi_channels("5g", 3)
        
        # Count total networks
        total_networks_2g = len([n for n in scan_2g if n.get('SSID', '').strip()])
        total_networks_5g = len([n for n in scan_5g if n.get('SSID', '').strip()])
        total_networks = total_networks_2g + total_networks_5g
        
        # Analyze current channel usage
        current_channel_2g = radio_2g.get('Channel', 0)
        current_channel_5g = radio_5g.get('Channel', 0)
        
        current_2g_info = next((ch for ch in spectrum_2g if ch['channel'] == current_channel_2g), {})
        current_5g_info = next((ch for ch in spectrum_5g if ch['channel'] == current_channel_5g), {})
        
        # Generate recommendations
        recommendations = []
        
        if current_2g_info.get('availability', 100) < 50:
            best_2g_channel = best_2g[0]['channel'] if best_2g else None
            if best_2g_channel and best_2g_channel != current_channel_2g:
                recommendations.append(f"Consider switching 2.4GHz from channel {current_channel_2g} to {best_2g_channel}")
        
        if current_5g_info.get('availability', 100) < 70:
            best_5g_channel = best_5g[0]['channel'] if best_5g else None
            if best_5g_channel and best_5g_channel != current_channel_5g:
                recommendations.append(f"Consider switching 5GHz from channel {current_channel_5g} to {best_5g_channel}")
        
        if total_networks > 20:
            recommendations.append("High WiFi density detected - consider using 5GHz for better performance")
        
        if radio_2g.get('CurrentOperatingChannelBandwidth') == '40MHz':
            recommendations.append("Consider using 20MHz bandwidth on 2.4GHz to reduce interference")
        
        # Generate summary
        if total_networks < 10:
            environment = "Light"
        elif total_networks < 25:
            environment = "Moderate"
        else:
            environment = "Congested"
        
        summary = f"{environment} WiFi environment with {total_networks} networks detected"
        
        return {
            'summary': summary,
            'band_2g': {
                'radio_info': radio_2g,
                'spectrum_analysis': spectrum_2g,
                'scan_results': scan_2g,
                'best_channels': best_2g,
                'current_channel': current_channel_2g,
                'current_channel_info': current_2g_info,
                'networks_detected': total_networks_2g
            },
            'band_5g': {
                'radio_info': radio_5g,
                'spectrum_analysis': spectrum_5g,
                'scan_results': scan_5g,
                'best_channels': best_5g,
                'current_channel': current_channel_5g,
                'current_channel_info': current_5g_info,
                'networks_detected': total_networks_5g
            },
            'recommendations': recommendations,
            'total_networks': total_networks
        }
    
    def get_device_details(self, mac_address: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific connected device.
        
        Args:
            mac_address: MAC address of the device (e.g., "DC:A6:32:C2:61:E3")
        
        Returns:
            Dictionary with comprehensive device information including:
            - Key: Device MAC address identifier
            - Name: Device name/hostname
            - DeviceType: Device type (e.g., "Computer", "Smartphone", "Tablet")
            - Active: Whether device is currently connected
            - Tags: Device capability tags (e.g., "lan", "ipv4", "dhcp")
            - FirstSeen: First connection timestamp
            - LastConnection: Last connection timestamp
            - LastChanged: Last configuration change timestamp
            - IPAddress: Current IP address
            - IPAddressSource: How IP was assigned ("DHCP", "Static")
            - PhysAddress: Physical MAC address
            - Layer2Interface: Network interface (e.g., "ETH2", "WLAN")
            - Owner: Device owner (if set)
            - Location: Device location (if set)
            - Actions: Available management actions (setName, setType, etc.)
            - IPv4Address: List of IPv4 addresses with status
            - IPv6Address: List of IPv6 addresses with status
            - Security: Security scoring information
            - Priority: QoS priority configuration
            - WANAccess: WAN access control information
            - BDD: Device fingerprinting information
            - Names: Historical device names from different sources
            - DeviceTypes: Historical device types from different sources
            
        Raises:
            ValueError: If mac_address format is invalid
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        response = self._make_api_call(
            service=f"Devices.Device.{mac_address}",
            method="get",
            parameters={"flags": "full_links"}
        )
        
        # Extract device details from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}

    def get_device_schedule(self, mac_address: str) -> Dict[str, Any]:
        """
        Get Time of Day access schedule for a specific device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
        
        Returns:
            Dictionary with device schedule information including:
            - base: Schedule base type ("Weekly")
            - def: Default state ("Enable" or "Disable")
            - ID: Device identifier (MAC address)
            - schedule: List of time restriction blocks
            - enable: Whether scheduling is enabled for this device
            - override: Current override setting ("Enable", "Disable", or "")
            
            Returns False if no schedule is configured for the device.
            
        Raises:
            ValueError: If mac_address format is invalid
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        response = self._make_api_call(
            service="Scheduler",
            method="getSchedule",
            parameters={
                "type": "ToD",
                "ID": mac_address
            }
        )
        
        # Extract schedule from response
        if isinstance(response, dict) and 'status' in response:
            return response['status']
        
        return {}

    def set_device_schedule(self, mac_address: str, 
                           schedule_blocks: List[Dict[str, int]] = None,
                           enabled: bool = True,
                           default_state: str = "Enable",
                           override: str = "") -> bool:
        """
        Set Time of Day access schedule for a specific device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            schedule_blocks: List of time blocks when device should be disabled.
                           Each block is a dict with 'begin' and 'end' keys (seconds from Monday 00:00)
            enabled: Whether the schedule should be enabled (default: True)
            default_state: Default access state - "Enable" or "Disable" (default: "Enable")
            override: Override setting - "Enable", "Disable", or "" (default: "")
        
        Returns:
            True if successful
            
        Raises:
            ValueError: If mac_address format is invalid or default_state is invalid
            
        Example:
            # Block device from 8 PM to 8 AM on weekdays
            api.set_device_schedule(
                "A8:A1:59:33:F1:E4",
                schedule_blocks=[
                    {"begin": 72000, "end": 115200},   # Monday 20:00-08:00+1
                    {"begin": 158400, "end": 201600},  # Tuesday 20:00-08:00+1
                    # ... more days
                ],
                enabled=True
            )
            
            # Block device completely (always disabled)
            api.set_device_schedule(
                "A8:A1:59:33:F1:E4",
                schedule_blocks=[],
                enabled=True,
                override="Disable"
            )
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        if default_state not in ["Enable", "Disable"]:
            raise ValueError("default_state must be 'Enable' or 'Disable'")
        
        if schedule_blocks is None:
            schedule_blocks = []
        
        # Convert schedule blocks to proper format
        schedule = []
        for block in schedule_blocks:
            schedule.append({
                "state": "Disable",
                "begin": block["begin"],
                "end": block["end"]
            })
        
        schedule_info = {
            "base": "Weekly",
            "def": default_state,
            "ID": mac_address,
            "schedule": schedule,
            "enable": enabled,
            "override": override
        }
        
        result = self._make_api_call(
            service="Scheduler",
            method="addSchedule",
            parameters={
                "type": "ToD",
                "info": schedule_info
            }
        )
        
        return result.get('status', False) == True

    def remove_device_schedule(self, mac_address: str) -> bool:
        """
        Remove Time of Day access schedule for a specific device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
        
        Returns:
            True if successful
            
        Raises:
            ValueError: If mac_address format is invalid
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        result = self._make_api_call(
            service="Scheduler",
            method="removeSchedules",
            parameters={
                "type": "ToD",
                "ID": [mac_address]
            }
        )
        
        return result.get('status', False) == True

    def set_device_name(self, mac_address: str, name: str, source: str = "manual") -> bool:
        """
        Set the display name for a specific device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            name: New device name (e.g., "John's Laptop")
            source: Source of the name change (default: "manual")
        
        Returns:
            True if successful
            
        Raises:
            ValueError: If mac_address format is invalid or name is empty
        """
        # Basic validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        if not name or not name.strip():
            raise ValueError("Device name cannot be empty")
        
        result = self._make_api_call(
            service=f"Devices.Device.{mac_address}",
            method="setName",
            parameters={
                "name": name.strip(),
                "source": source
            }
        )
        
        return result.get('status', False) == True

    def set_device_type(self, mac_address: str, device_type: str, source: str = "manual") -> bool:
        """
        Set the device type/icon for a specific device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            device_type: Device type for icon selection. Common types include:
                        "Computer", "Laptop", "Tablet", "Smartphone", "Printer",
                        "Television", "MediaPlayer", "GameConsole", "SmartSpeaker",
                        "SmartWatch", "Camera", "Router", "Switch", "AccessPoint",
                        "IoTDevice", "SmartHome", "NAS", "Server", "Unknown"
            source: Source of the type change (default: "manual")
        
        Returns:
            True if successful
            
        Raises:
            ValueError: If mac_address format is invalid or device_type is empty
        """
        # Basic validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        if not device_type or not device_type.strip():
            raise ValueError("Device type cannot be empty")
        
        result = self._make_api_call(
            service=f"Devices.Device.{mac_address}",
            method="setType",
            parameters={
                "type": device_type.strip(),
                "source": source
            }
        )
        
        return result.get('status', False) == True

    def block_device_permanently(self, mac_address: str) -> bool:
        """
        Permanently block a device from accessing the internet.
        
        Args:
            mac_address: MAC address of the device to block
        
        Returns:
            True if successful
        """
        return self.set_device_schedule(
            mac_address=mac_address,
            schedule_blocks=[],
            enabled=True,
            default_state="Enable",
            override="Disable"
        )

    def unblock_device(self, mac_address: str) -> bool:
        """
        Remove all access restrictions from a device.
        
        Args:
            mac_address: MAC address of the device to unblock
        
        Returns:
            True if successful
        """
        return self.remove_device_schedule(mac_address)

    def set_device_bedtime_schedule(self, mac_address: str,
                                   bedtime_hour: int = 22, wakeup_hour: int = 7,
                                   weekdays_only: bool = True) -> bool:
        """
        Set a bedtime schedule for a device (disable during night hours).
        
        Args:
            mac_address: MAC address of the device
            bedtime_hour: Hour to disable device (0-23, default: 22 = 10 PM)
            wakeup_hour: Hour to enable device (0-23, default: 7 = 7 AM)
            weekdays_only: Whether to apply only on weekdays (default: True)
        
        Returns:
            True if successful
            
        Raises:
            ValueError: If hours are invalid
        """
        if not (0 <= bedtime_hour <= 23) or not (0 <= wakeup_hour <= 23):
            raise ValueError("Hours must be between 0 and 23")
        
        schedule_blocks = []
        
        # Define which days to apply the schedule
        if weekdays_only:
            days = [0, 1, 2, 3, 4]  # Monday to Friday
        else:
            days = [0, 1, 2, 3, 4, 5, 6]  # All week
        
        for day in days:
            day_start = day * 24 * 3600  # Start of day in seconds
            
            if bedtime_hour > wakeup_hour:
                # Bedtime is before midnight, wakeup is next day
                bedtime_start = day_start + (bedtime_hour * 3600)
                bedtime_end = day_start + (24 * 3600)  # End of current day
                
                wakeup_start = (day + 1) * 24 * 3600  # Start of next day
                wakeup_end = wakeup_start + (wakeup_hour * 3600)
                
                # Add both blocks
                schedule_blocks.append({"begin": bedtime_start, "end": bedtime_end})
                if day < 6:  # Don't go beyond week
                    schedule_blocks.append({"begin": wakeup_start, "end": wakeup_end})
            else:
                # Both bedtime and wakeup are on same day (unusual but possible)
                bedtime_start = day_start + (bedtime_hour * 3600)
                bedtime_end = day_start + (wakeup_hour * 3600)
                schedule_blocks.append({"begin": bedtime_start, "end": bedtime_end})
        
        return self.set_device_schedule(mac_address, schedule_blocks, enabled=True)

    def set_device_study_hours(self, mac_address: str,
                              study_start_hour: int = 19, study_end_hour: int = 21,
                              study_days: List[int] = None) -> bool:
        """
        Set study hours schedule for a device (disable during study time).
        
        Args:
            mac_address: MAC address of the device
            study_start_hour: Hour to start study time (0-23, default: 19 = 7 PM)
            study_end_hour: Hour to end study time (0-23, default: 21 = 9 PM)
            study_days: List of study days (0=Monday, 6=Sunday, default: weekdays)
        
        Returns:
            True if successful
        """
        if not (0 <= study_start_hour <= 23) or not (0 <= study_end_hour <= 23):
            raise ValueError("Hours must be between 0 and 23")
        
        if study_days is None:
            study_days = [0, 1, 2, 3, 4]  # Weekdays
        
        schedule_blocks = []
        
        for day in study_days:
            if day < 0 or day > 6:
                continue
                
            day_start = day * 24 * 3600
            study_start = day_start + (study_start_hour * 3600)
            study_end = day_start + (study_end_hour * 3600)
            
            if study_end > study_start:
                schedule_blocks.append({"begin": study_start, "end": study_end})
        
        return self.set_device_schedule(mac_address, schedule_blocks, enabled=True)

    def get_device_management_info(self, mac_address: str) -> Dict[str, Any]:
        """
        Get comprehensive device management information including details and schedule.
        
        Args:
            mac_address: MAC address of the device
        
        Returns:
            Dictionary with keys:
            - 'device_details': Complete device information
            - 'schedule': Current access schedule (if any)
            - 'is_scheduled': Whether device has active schedule
            - 'is_blocked': Whether device is permanently blocked
            - 'summary': Text summary of device status
        """
        device_details = self.get_device_details(mac_address)
        schedule = self.get_device_schedule(mac_address)
        
        # Determine device status
        is_scheduled = bool(schedule and schedule != False)
        is_blocked = False
        
        if is_scheduled and isinstance(schedule, dict):
            # Check if device is permanently blocked (override = "Disable")
            is_blocked = schedule.get('override') == 'Disable'
        
        # Generate summary
        device_name = device_details.get('Name', 'Unknown Device')
        device_type = device_details.get('DeviceType', 'Unknown')
        is_active = device_details.get('Active', False)
        
        if is_blocked:
            summary = f"{device_name} ({device_type}) - Permanently blocked"
        elif is_scheduled:
            summary = f"{device_name} ({device_type}) - Time restrictions active"
        elif is_active:
            summary = f"{device_name} ({device_type}) - Connected and unrestricted"
        else:
            summary = f"{device_name} ({device_type}) - Offline"
        
        return {
            'device_details': device_details,
            'schedule': schedule,
            'is_scheduled': is_scheduled,
            'is_blocked': is_blocked,
            'summary': summary
        }

    def list_managed_devices(self) -> List[Dict[str, Any]]:
        """
        Get list of all devices with their management status.
        
        Returns:
            List of device management summaries with:
            - mac_address: Device MAC address
            - name: Device name
            - device_type: Device type
            - active: Whether device is connected
            - scheduled: Whether device has time restrictions
            - blocked: Whether device is permanently blocked
            - last_seen: Last connection time
        """
        devices = self.get_devices('all')
        managed_devices = []
        
        for device in devices:
            mac_address = device.get('PhysAddress', '')
            if not mac_address:
                continue
            
            # Get schedule info
            schedule = self.get_device_schedule(mac_address)
            is_scheduled = bool(schedule and schedule != False)
            is_blocked = False
            
            if is_scheduled and isinstance(schedule, dict):
                is_blocked = schedule.get('override') == 'Disable'
            
            managed_device = {
                'mac_address': mac_address,
                'name': device.get('Name', 'Unknown Device'),
                'device_type': device.get('DeviceType', 'Unknown'),
                'active': device.get('Active', False),
                'scheduled': is_scheduled,
                'blocked': is_blocked,
                'last_seen': device.get('LastConnection', ''),
                'ip_address': device.get('IPAddress', ''),
                'interface': device.get('Layer2Interface', '')
            }
            
            managed_devices.append(managed_device)
        
        # Sort by name
        managed_devices.sort(key=lambda x: x['name'].lower())
        
        return managed_devices

    def get_common_device_types(self) -> List[str]:
        """
        Get list of common device types for use with set_device_type().
        
        Returns:
            List of common device type names
        """
        return [
            "Computer",
            "Laptop", 
            "Tablet",
            "Smartphone",
            "Printer",
            "Television",
            "MediaPlayer",
            "GameConsole",
            "SmartSpeaker",
            "SmartWatch",
            "Camera",
            "Router",
            "Switch",
            "AccessPoint",
            "IoTDevice",
            "SmartHome",
            "NAS",
            "Server",
            "Unknown"
        ]
    
    def delete_device(self, mac_address: str) -> bool:
        """
        Delete/destroy a device from the router's device list.
        
        This removes the device from the known devices list. Typically used
        for cleaning up old inactive devices that haven't been seen in a while.
        
        Args:
            mac_address: MAC address of the device to delete (e.g., "96:16:1A:D6:0F:30")
        
        Returns:
            True if device was successfully deleted
            
        Raises:
            ValueError: If mac_address format is invalid
            
        Note:
            - This only removes the device from the router's memory
            - If the device reconnects, it will reappear in the device list
            - Typically used for inactive devices to clean up the device list
            - Device schedules and restrictions are also removed
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        result = self._make_api_call(
            service="Devices",
            method="destroyDevice",
            parameters={"key": mac_address}
        )
        
        return result.get('status', False) == True

    def cleanup_inactive_devices(self, days_inactive: int = 30) -> Dict[str, Any]:
        """
        Clean up devices that haven't been seen for a specified number of days.
        
        Args:
            days_inactive: Number of days of inactivity before considering device for cleanup (default: 30)
        
        Returns:
            Dictionary with cleanup results:
            - 'candidates': List of devices eligible for cleanup
            - 'deleted': List of devices that were deleted
            - 'failed': List of devices that failed to delete
            - 'total_candidates': Number of devices eligible for cleanup
            - 'total_deleted': Number of devices successfully deleted
            
        Note:
            This function will automatically delete devices, use with caution.
        """
        from datetime import datetime, timedelta
        
        # Get all devices
        devices = self.list_managed_devices()
        
        # Calculate cutoff date
        cutoff_date = datetime.now() - timedelta(days=days_inactive)
        
        candidates = []
        deleted = []
        failed = []
        
        # Find inactive devices
        for device in devices:
            if device['active']:
                continue  # Skip active devices
            
            last_seen = device.get('last_seen', '')
            if not last_seen:
                continue  # Skip devices without last seen date
            
            try:
                # Parse last seen date (ISO format)
                if 'T' in last_seen:
                    device_date = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    # Convert to local time (rough approximation)
                    device_date = device_date.replace(tzinfo=None)
                    
                    if device_date < cutoff_date:
                        candidates.append(device)
                        
                        # Attempt to delete the device
                        try:
                            success = self.delete_device(device['mac_address'])
                            if success:
                                deleted.append(device)
                            else:
                                failed.append(device)
                        except Exception as e:
                            device['error'] = str(e)
                            failed.append(device)
            except Exception:
                continue  # Skip devices with unparseable dates
        
        return {
            'candidates': candidates,
            'deleted': deleted,
            'failed': failed,
            'total_candidates': len(candidates),
            'total_deleted': len(deleted),
            'total_failed': len(failed)
        }

    def list_inactive_devices(self, days_inactive: int = 7) -> List[Dict[str, Any]]:
        """
        List devices that haven't been seen for a specified number of days.
        
        Args:
            days_inactive: Number of days of inactivity to filter by (default: 7)
        
        Returns:
            List of inactive device dictionaries with additional fields:
            - 'days_since_seen': Number of days since last connection
            - All standard device management fields
        """
        from datetime import datetime, timedelta
        
        # Get all devices
        devices = self.list_managed_devices()
        
        # Calculate cutoff date
        cutoff_date = datetime.now() - timedelta(days=days_inactive)
        
        inactive_devices = []
        
        for device in devices:
            if device['active']:
                continue  # Skip active devices
            
            last_seen = device.get('last_seen', '')
            if not last_seen:
                device['days_since_seen'] = 'Unknown'
                inactive_devices.append(device)
                continue
            
            try:
                # Parse last seen date (ISO format)
                if 'T' in last_seen:
                    device_date = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    # Convert to local time (rough approximation)
                    device_date = device_date.replace(tzinfo=None)
                    
                    days_diff = (datetime.now() - device_date).days
                    device['days_since_seen'] = days_diff
                    
                    if device_date < cutoff_date:
                        inactive_devices.append(device)
            except Exception:
                device['days_since_seen'] = 'Parse Error'
                inactive_devices.append(device)
        
        # Sort by days since seen (most recent first)
        inactive_devices.sort(key=lambda x: x.get('days_since_seen', 999999) if isinstance(x.get('days_since_seen'), int) else 999999)
        
        return inactive_devices
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def set_ping_response(self, source_interface: str = "data", 
                         enable_ipv4: bool = True, enable_ipv6: bool = True) -> bool:
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
                    "enableIPv6": enable_ipv6
                }
            }
        )
        
        return result.get('status', False) == True
    
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
    
    def set_firewall_level(self, level: str = "Medium", ipv6_level: str = None) -> Dict[str, bool]:
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
            service="Firewall",
            method="setFirewallLevel",
            parameters={"level": level}
        )
        results['ipv4'] = result_ipv4.get('status', False) == True
        
        # Set IPv6 firewall level
        result_ipv6 = self._make_api_call(
            service="Firewall",
            method="setFirewallIPv6Level",
            parameters={"level": ipv6_level}
        )
        results['ipv6'] = result_ipv6.get('status', False) == True
        
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
            service="Firewall",
            method="setFirewallLevel",
            parameters={"level": level}
        )
        
        return result.get('status', False) == True
    
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
            parameters={"level": level}
        )
        
        return result.get('status', False) == True
    
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
            service="Firewall",
            method="getCustomRule",
            parameters={}
        )
        
        rules = []
        
        # Extract custom rules from response
        if isinstance(response, dict) and 'status' in response:
            status_data = response['status']
            for rule_id, rule_data in status_data.items():
                if isinstance(rule_data, dict):
                    rules.append(rule_data)
        
        return rules
    
    def add_custom_firewall_rule(self, rule_id: str, action: str = "Accept", 
                                protocol: str = "6", destination_port: str = "",
                                source_port: str = "", destination_prefix: str = "",
                                source_prefix: str = "", ip_version: int = 4,
                                chain: str = None, enabled: bool = True) -> str:
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
                "enable": enabled
            }
        )
        
        # Return rule ID if successful
        if isinstance(result, dict) and 'status' in result:
            return result['status']
        
        return ""
    
    def delete_custom_firewall_rule(self, rule_id: str, ip_version: int = 4, 
                                   chain: str = None) -> bool:
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
            parameters={
                "id": rule_id,
                "chain": chain
            }
        )
        
        return result.get('status', False) == True
    
    def update_custom_firewall_rule(self, rule_id: str, **kwargs) -> str:
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
    
    def manage_custom_firewall_rule(self, action: str, rule_id: str, **kwargs) -> Union[str, bool]:
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
            ip_version = kwargs.get('ip_version', 4)
            chain = kwargs.get('chain')
            return self.delete_custom_firewall_rule(rule_id, ip_version, chain)
        
        elif action == "enable":
            # Get current rule and enable it
            rules = self.get_custom_firewall_rules()
            current_rule = next((r for r in rules if r.get('Id') == rule_id), None)
            if current_rule:
                # Update with enabled=True
                return self.add_custom_firewall_rule(
                    rule_id=rule_id,
                    action=current_rule.get('Target', 'Accept'),
                    protocol=current_rule.get('Protocol', '6'),
                    destination_port=current_rule.get('DestinationPort', ''),
                    source_port=current_rule.get('SourcePort', ''),
                    destination_prefix=current_rule.get('DestinationPrefix', ''),
                    source_prefix=current_rule.get('SourcePrefix', ''),
                    ip_version=current_rule.get('IPVersion', 4),
                    enabled=True
                ) != ""
            return False
        
        elif action == "disable":
            # Get current rule and disable it
            rules = self.get_custom_firewall_rules()
            current_rule = next((r for r in rules if r.get('Id') == rule_id), None)
            if current_rule:
                # Update with enabled=False
                return self.add_custom_firewall_rule(
                    rule_id=rule_id,
                    action=current_rule.get('Target', 'Accept'),
                    protocol=current_rule.get('Protocol', '6'),
                    destination_port=current_rule.get('DestinationPort', ''),
                    source_port=current_rule.get('SourcePort', ''),
                    destination_prefix=current_rule.get('DestinationPrefix', ''),
                    source_prefix=current_rule.get('SourcePrefix', ''),
                    ip_version=current_rule.get('IPVersion', 4),
                    enabled=False
                ) != ""
            return False
        
        else:
            raise ValueError("action must be 'add', 'update', 'delete', 'enable', or 'disable'")

    def get_wifi_mac_filter_status(self) -> Dict[str, Any]:
        """
        Get WiFi MAC filtering status and current whitelist.
        
        Returns:
            Dictionary with MAC filtering status including:
            - enabled: Whether MAC filtering is enabled
            - mode: Current filtering mode ("WhiteList" or "Off")
            - allowed_devices: List of MAC addresses on whitelist
            - count: Number of devices on whitelist
        
        Note:
            MAC filtering only affects home and extra WiFi networks.
            Guest networks and wired devices are not affected.
        """
        # Get current WiFi configuration
        wifi_networks = self.get_wifi_networks()
        
        status = {
            'enabled': False,
            'mode': 'Off',
            'allowed_devices': [],
            'count': 0
        }
        
        # Check 2.4GHz home network for MAC filtering status
        for network in wifi_networks:
            if network.get('Name') == 'vap2g0priv':
                mac_filtering = network.get('MACFiltering', {})
                status['mode'] = mac_filtering.get('Mode', 'Off')
                status['enabled'] = status['mode'] == 'WhiteList'
                
                # Extract MAC addresses from entries
                entries = mac_filtering.get('Entry', {})
                if isinstance(entries, dict):
                    for entry in entries.values():
                        if isinstance(entry, dict) and 'MACAddress' in entry:
                            mac_addr = entry['MACAddress']
                            if mac_addr not in status['allowed_devices']:
                                status['allowed_devices'].append(mac_addr)
                
                break
        
        status['count'] = len(status['allowed_devices'])
        return status
    
    def set_wifi_mac_filtering(self, enabled: bool = True, mac_addresses: List[str] = None) -> bool:
        """
        Enable or disable WiFi MAC filtering with optional device list.
        
        Args:
            enabled: Whether to enable MAC filtering (default: True)
            mac_addresses: List of MAC addresses to allow (default: None = keep current list)
        
        Returns:
            True if successful
        
        Note:
            - When enabled, only devices on the whitelist can connect to WiFi
            - Affects home and extra networks only (not guest networks)
            - Wired devices are always allowed regardless of this setting
            - If mac_addresses is None, keeps current whitelist
        """
        # Get current MAC filter list if not provided
        if mac_addresses is None:
            current_status = self.get_wifi_mac_filter_status()
            mac_addresses = current_status.get('allowed_devices', [])
        
        # Create entry dictionary from MAC addresses
        entry_dict = {}
        for i, mac_addr in enumerate(mac_addresses, 1):
            entry_dict[str(i)] = {"MACAddress": mac_addr}
        
        # Set mode based on enabled flag
        mode = "WhiteList" if enabled else "Off"
        
        # Configure MAC filtering for all relevant VAPs
        result = self._make_api_call(
            service="NeMo.Intf.lan",
            method="setWLANConfig",
            parameters={
                "mibs": {
                    "wlanvap": {
                        "vap2g0priv": {
                            "MACFiltering": {
                                "Mode": mode,
                                "Entry": entry_dict
                            }
                        },
                        "vap5g0priv": {
                            "MACFiltering": {
                                "Mode": mode,
                                "Entry": entry_dict
                            }
                        },
                        "vap2g0ext": {
                            "MACFiltering": {
                                "Mode": mode,
                                "Entry": entry_dict
                            }
                        },
                        "vap5g0ext": {
                            "MACFiltering": {
                                "Mode": mode,
                                "Entry": entry_dict
                            }
                        }
                    }
                }
            }
        )
        
        return result.get('status') is None  # API returns null on success
    
    def enable_wifi_mac_filtering(self, mac_addresses: List[str] = None) -> bool:
        """
        Enable WiFi MAC filtering with optional device list.
        
        Args:
            mac_addresses: List of MAC addresses to allow (default: None = keep current list)
        
        Returns:
            True if successful
        
        Note: Convenience method that calls set_wifi_mac_filtering(True, mac_addresses).
        """
        return self.set_wifi_mac_filtering(True, mac_addresses)
    
    def disable_wifi_mac_filtering(self) -> bool:
        """
        Disable WiFi MAC filtering (allow all devices).
        
        Returns:
            True if successful
        
        Note: 
            - Convenience method that calls set_wifi_mac_filtering(False)
            - Keeps the current whitelist for when filtering is re-enabled
        """
        return self.set_wifi_mac_filtering(False)
    
    def get_wifi_mac_filter_list(self) -> List[str]:
        """
        Get list of MAC addresses on WiFi whitelist.
        
        Returns:
            List of MAC addresses currently on the whitelist
        """
        status = self.get_wifi_mac_filter_status()
        return status.get('allowed_devices', [])
    
    def add_wifi_mac_filter(self, mac_addresses: Union[str, List[str]]) -> bool:
        """
        Add MAC addresses to WiFi whitelist.
        
        Args:
            mac_addresses: Single MAC address (str) or list of MAC addresses to add
        
        Returns:
            True if successful
        
        Note:
            - Automatically enables MAC filtering if not already enabled
            - Avoids duplicates when adding addresses
        """
        # Convert single MAC address to list
        if isinstance(mac_addresses, str):
            mac_addresses = [mac_addresses]
        
        # Get current whitelist
        current_list = self.get_wifi_mac_filter_list()
        
        # Add new MAC addresses (avoid duplicates)
        updated_list = current_list.copy()
        for mac_addr in mac_addresses:
            if mac_addr not in updated_list:
                updated_list.append(mac_addr)
        
        # Enable filtering with updated list
        return self.set_wifi_mac_filtering(True, updated_list)
    
    def remove_wifi_mac_filter(self, mac_addresses: Union[str, List[str]]) -> bool:
        """
        Remove MAC addresses from WiFi whitelist.
        
        Args:
            mac_addresses: Single MAC address (str) or list of MAC addresses to remove
        
        Returns:
            True if successful
        
        Note: Keeps MAC filtering enabled even if list becomes empty.
        """
        # Convert single MAC address to list
        if isinstance(mac_addresses, str):
            mac_addresses = [mac_addresses]
        
        # Get current whitelist
        current_list = self.get_wifi_mac_filter_list()
        
        # Remove specified MAC addresses
        updated_list = [mac for mac in current_list if mac not in mac_addresses]
        
        # Get current filtering state
        current_status = self.get_wifi_mac_filter_status()
        is_enabled = current_status.get('enabled', False)
        
        # Update with new list, keeping current enabled state
        return self.set_wifi_mac_filtering(is_enabled, updated_list)
    
    def clear_wifi_mac_filter(self) -> bool:
        """
        Clear all MAC addresses from WiFi whitelist.
        
        Returns:
            True if successful
        
        Note: Keeps MAC filtering enabled but with empty whitelist (blocks all WiFi devices).
        """
        return self.set_wifi_mac_filtering(True, [])
    
    def set_wifi_mac_filter_list(self, mac_addresses: List[str], enabled: bool = True) -> bool:
        """
        Set complete WiFi MAC filter whitelist.
        
        Args:
            mac_addresses: Complete list of MAC addresses to allow
            enabled: Whether to enable MAC filtering (default: True)
        
        Returns:
            True if successful
        
        Note: Replaces entire whitelist with provided list.
        """
        return self.set_wifi_mac_filtering(enabled, mac_addresses)
    
    def add_connected_wifi_devices_to_filter(self) -> Dict[str, Any]:
        """
        Add all currently connected WiFi devices to MAC filter whitelist.
        
        Returns:
            Dictionary with operation results including:
            - added_devices: List of devices added to whitelist
            - already_allowed: List of devices already on whitelist
            - total_devices: Total number of WiFi devices found
            - success: Whether operation was successful
        
        Note:
            - Only adds WiFi-connected devices (excludes wired devices)
            - Automatically enables MAC filtering
            - Useful for quickly allowing all current WiFi devices
        """
        # Get all connected devices
        devices = self.get_devices('active')
        
        # Filter for WiFi devices only (exclude ETH0 = wired)
        wifi_devices = []
        for device in devices:
            interface = device.get('Layer2Interface', '')
            if interface and interface != 'ETH0':  # ETH0 is wired
                wifi_devices.append({
                    'mac_address': device.get('PhysAddress', ''),
                    'name': device.get('Name', 'Unknown'),
                    'interface': interface
                })
        
        # Get current whitelist
        current_list = self.get_wifi_mac_filter_list()
        
        # Determine which devices to add
        added_devices = []
        already_allowed = []
        
        for device in wifi_devices:
            mac_addr = device['mac_address']
            if mac_addr:
                if mac_addr in current_list:
                    already_allowed.append(device)
                else:
                    added_devices.append(device)
                    current_list.append(mac_addr)
        
        # Update MAC filter with new list
        success = self.set_wifi_mac_filtering(True, current_list)
        
        return {
            'added_devices': added_devices,
            'already_allowed': already_allowed,
            'total_devices': len(wifi_devices),
            'success': success
        }
    
    def manage_wifi_mac_filter(self, action: str, mac_addresses: Union[str, List[str]] = None, 
                              enabled: bool = None) -> Union[bool, Dict[str, Any], List[str]]:
        """
        Unified WiFi MAC filter management interface.
        
        Args:
            action: Action to perform - "enable", "disable", "add", "remove", "clear", 
                   "set", "list", "status", "add_connected"
            mac_addresses: MAC addresses for add/remove/set actions
            enabled: Enable state for "set" action
        
        Returns:
            - For enable/disable/add/remove/clear/set: True if successful
            - For list: List of MAC addresses
            - For status: Dictionary with status information
            - For add_connected: Dictionary with operation results
        
        Raises:
            ValueError: If action is not valid or required parameters are missing
        
        Examples:
            # Enable filtering
            api.manage_wifi_mac_filter("enable")
            
            # Add device
            api.manage_wifi_mac_filter("add", "AA:BB:CC:DD:EE:FF")
            
            # Set complete list
            api.manage_wifi_mac_filter("set", ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"])
            
            # Get status
            status = api.manage_wifi_mac_filter("status")
        """
        if action == "enable":
            return self.enable_wifi_mac_filtering(mac_addresses)
        
        elif action == "disable":
            return self.disable_wifi_mac_filtering()
        
        elif action == "add":
            if mac_addresses is None:
                raise ValueError("mac_addresses is required for 'add' action")
            return self.add_wifi_mac_filter(mac_addresses)
        
        elif action == "remove":
            if mac_addresses is None:
                raise ValueError("mac_addresses is required for 'remove' action")
            return self.remove_wifi_mac_filter(mac_addresses)
        
        elif action == "clear":
            return self.clear_wifi_mac_filter()
        
        elif action == "set":
            if mac_addresses is None:
                raise ValueError("mac_addresses is required for 'set' action")
            if enabled is None:
                enabled = True
            return self.set_wifi_mac_filter_list(mac_addresses, enabled)
        
        elif action == "list":
            return self.get_wifi_mac_filter_list()
        
        elif action == "status":
            return self.get_wifi_mac_filter_status()
        
        elif action == "add_connected":
            return self.add_connected_wifi_devices_to_filter()
        
        else:
            raise ValueError(f"action must be one of: enable, disable, add, remove, clear, set, list, status, add_connected")

    def get_device_mst_status(self, mac_address: str) -> Dict[str, Any]:
        """
        Get Managed Screen Time (MST) status for a specific device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
        
        Returns:
            Dictionary with MST status including:
            - subject: Device identifier (e.g., "MAC:A8:A1:59:33:F1:E4")
            - enable: Whether MST is enabled for this device
            - status: Current status ("Active" or other status)
            - allowedTime: Dictionary with daily time limits in minutes per day
                          (Mon, Tue, Wed, Thu, Fri, Sat, Sun)
            
            Returns empty dict if no MST is configured for the device.
        
        Raises:
            ValueError: If mac_address format is invalid
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        # Create MST ID by removing colons
        mst_id = mac_address.replace(':', '').upper()
        
        response = self._make_api_call(
            service="ToD",
            method="getMST",
            parameters={
                "id": mst_id
            }
        )
        
        # Extract MST data from response
        if isinstance(response, dict) and 'data' in response:
            return response['data']
        
        return {}
    
    def set_device_mst(self, mac_address: str, daily_limits: Dict[str, int] = None, 
                      enabled: bool = True) -> bool:
        """
        Set Managed Screen Time (MST) daily limits for a specific device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            daily_limits: Dictionary with daily time limits in minutes per day.
                         Keys: Mon, Tue, Wed, Thu, Fri, Sat, Sun
                         Values: Minutes allowed per day (0-1440)
                         Example: {"Mon": 120, "Tue": 180, "Wed": 120, ...}
            enabled: Whether to enable MST for this device (default: True)
        
        Returns:
            True if successful
        
        Raises:
            ValueError: If mac_address format is invalid or daily_limits contains invalid values
        
        Note:
            - Automatically removes existing time-based schedules when setting MST
            - Time limits are in minutes per day (0-1440, where 1440 = 24 hours)
            - When MST is active, device will be blocked after time limit is reached
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        # Default daily limits if not provided (2 hours per day)
        if daily_limits is None:
            daily_limits = {
                "Mon": 120, "Tue": 120, "Wed": 120, "Thu": 120,
                "Fri": 120, "Sat": 240, "Sun": 240
            }
        
        # Validate daily limits
        valid_days = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
        for day, minutes in daily_limits.items():
            if day not in valid_days:
                raise ValueError(f"Invalid day: {day}. Must be one of: {valid_days}")
            if not isinstance(minutes, int) or minutes < 0 or minutes > 1440:
                raise ValueError(f"Invalid time limit for {day}: {minutes}. Must be 0-1440 minutes")
        
        # Remove existing time-based schedules first (MST and schedules conflict)
        self.remove_device_schedule(mac_address)
        
        # Create MST ID by removing colons
        mst_id = mac_address.replace(':', '').upper()
        
        # Set MST configuration
        result = self._make_api_call(
            service="ToD",
            method="setMST",
            parameters={
                "id": mst_id,
                "subject": f"MAC:{mac_address}",
                "enable": enabled,
                "allowedTime": daily_limits
            }
        )
        
        return result.get('status') is None  # API returns null on success
    
    def delete_device_mst(self, mac_address: str) -> bool:
        """
        Delete Managed Screen Time (MST) configuration for a specific device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
        
        Returns:
            True if successful (also returns True if MST was not configured)
        
        Raises:
            ValueError: If mac_address format is invalid
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        # Create MST ID by removing colons
        mst_id = mac_address.replace(':', '').upper()
        
        result = self._make_api_call(
            service="ToD",
            method="deleteMST",
            parameters={
                "id": mst_id
            }
        )
        
        # API returns null on success, but also returns errors if MST doesn't exist
        # We consider both cases as success since the goal is to not have MST
        return True
    
    def set_device_daily_time_limits(self, mac_address: str, 
                                   weekday_minutes: int = 120, 
                                   weekend_minutes: int = 240,
                                   enabled: bool = True) -> bool:
        """
        Set daily time limits for a device (simplified MST setup).
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            weekday_minutes: Time limit for Mon-Fri in minutes (default: 120 = 2 hours)
            weekend_minutes: Time limit for Sat-Sun in minutes (default: 240 = 4 hours)
            enabled: Whether to enable time limits (default: True)
        
        Returns:
            True if successful
        
        Raises:
            ValueError: If mac_address format is invalid or time limits are invalid
        
        Note: Convenience method that calls set_device_mst with weekday/weekend limits.
        """
        # Validate time limits
        if not isinstance(weekday_minutes, int) or weekday_minutes < 0 or weekday_minutes > 1440:
            raise ValueError("weekday_minutes must be 0-1440")
        if not isinstance(weekend_minutes, int) or weekend_minutes < 0 or weekend_minutes > 1440:
            raise ValueError("weekend_minutes must be 0-1440")
        
        # Create daily limits
        daily_limits = {
            "Mon": weekday_minutes,
            "Tue": weekday_minutes,
            "Wed": weekday_minutes,
            "Thu": weekday_minutes,
            "Fri": weekday_minutes,
            "Sat": weekend_minutes,
            "Sun": weekend_minutes
        }
        
        return self.set_device_mst(mac_address, daily_limits, enabled)
    
    def set_device_parental_control(self, mac_address: str, control_type: str, 
                                  **kwargs) -> bool:
        """
        Unified parental control management for a device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
            control_type: Type of control to apply:
                         - "none": Remove all restrictions
                         - "block": Block device completely
                         - "schedule": Time-based schedule restrictions
                         - "daily_limits": Daily time limits (MST)
            **kwargs: Additional parameters based on control_type:
                     
                     For "schedule":
                     - schedule_blocks: List of time blocks when device should be disabled
                     - enabled: Whether schedule should be enabled (default: True)
                     
                     For "daily_limits":
                     - daily_limits: Dict with daily time limits or
                     - weekday_minutes: Time limit for Mon-Fri (default: 120)
                     - weekend_minutes: Time limit for Sat-Sun (default: 240)
                     - enabled: Whether limits should be enabled (default: True)
        
        Returns:
            True if successful
        
        Raises:
            ValueError: If control_type is invalid or required parameters are missing
        
        Examples:
            # Remove all restrictions
            api.set_device_parental_control("AA:BB:CC:DD:EE:FF", "none")
            
            # Block device completely
            api.set_device_parental_control("AA:BB:CC:DD:EE:FF", "block")
            
            # Set bedtime schedule (block 10 PM to 6 AM)
            api.set_device_parental_control("AA:BB:CC:DD:EE:FF", "schedule",
                schedule_blocks=[{"begin": 79200, "end": 108000}])
            
            # Set daily time limits (2 hours weekdays, 4 hours weekends)
            api.set_device_parental_control("AA:BB:CC:DD:EE:FF", "daily_limits",
                weekday_minutes=120, weekend_minutes=240)
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        if control_type == "none":
            # Remove all restrictions
            self.remove_device_schedule(mac_address)
            self.delete_device_mst(mac_address)
            return True
        
        elif control_type == "block":
            # Block device completely using schedule override
            self.delete_device_mst(mac_address)  # Remove MST first
            return self.set_device_schedule(
                mac_address,
                schedule_blocks=[],
                enabled=True,
                override="Disable"
            )
        
        elif control_type == "schedule":
            # Time-based schedule restrictions
            self.delete_device_mst(mac_address)  # Remove MST first
            
            schedule_blocks = kwargs.get('schedule_blocks', [])
            enabled = kwargs.get('enabled', True)
            
            return self.set_device_schedule(
                mac_address,
                schedule_blocks=schedule_blocks,
                enabled=enabled
            )
        
        elif control_type == "daily_limits":
            # Daily time limits (MST)
            self.remove_device_schedule(mac_address)  # Remove schedule first
            
            # Check if daily_limits dict is provided
            if 'daily_limits' in kwargs:
                daily_limits = kwargs['daily_limits']
                enabled = kwargs.get('enabled', True)
                return self.set_device_mst(mac_address, daily_limits, enabled)
            else:
                # Use weekday/weekend simplified setup
                weekday_minutes = kwargs.get('weekday_minutes', 120)
                weekend_minutes = kwargs.get('weekend_minutes', 240)
                enabled = kwargs.get('enabled', True)
                return self.set_device_daily_time_limits(
                    mac_address, weekday_minutes, weekend_minutes, enabled
                )
        
        else:
            raise ValueError(f"control_type must be one of: none, block, schedule, daily_limits")
    
    def get_device_parental_control_status(self, mac_address: str) -> Dict[str, Any]:
        """
        Get comprehensive parental control status for a device.
        
        Args:
            mac_address: MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
        
        Returns:
            Dictionary with parental control status including:
            - control_type: Type of control ("none", "block", "schedule", "daily_limits")
            - enabled: Whether any control is enabled
            - schedule: Schedule information (if applicable)
            - mst: MST information (if applicable)
            - summary: Human-readable summary of current restrictions
        
        Raises:
            ValueError: If mac_address format is invalid
        """
        # Basic MAC address validation
        if not mac_address or ':' not in mac_address:
            raise ValueError("Invalid MAC address format")
        
        # Get schedule status
        schedule_status = self.get_device_schedule(mac_address)
        
        # Get MST status
        mst_status = self.get_device_mst_status(mac_address)
        
        result = {
            'control_type': 'none',
            'enabled': False,
            'schedule': schedule_status,
            'mst': mst_status,
            'summary': 'No restrictions'
        }
        
        # Determine control type and summary
        if mst_status and mst_status.get('enable'):
            result['control_type'] = 'daily_limits'
            result['enabled'] = True
            
            # Calculate total weekly minutes
            allowed_time = mst_status.get('allowedTime', {})
            total_minutes = sum(allowed_time.values())
            avg_daily = total_minutes // 7
            
            result['summary'] = f"Daily time limits enabled (avg {avg_daily} min/day)"
        
        elif schedule_status and schedule_status.get('enable'):
            result['control_type'] = 'schedule'
            result['enabled'] = True
            
            override = schedule_status.get('override', '')
            if override == 'Disable':
                result['control_type'] = 'block'
                result['summary'] = 'Device completely blocked'
            else:
                schedule_blocks = schedule_status.get('schedule', [])
                if schedule_blocks:
                    result['summary'] = f"Time-based restrictions ({len(schedule_blocks)} time blocks)"
                else:
                    result['summary'] = 'Schedule enabled but no restrictions'
        
        return result
    
    def list_devices_with_parental_controls(self) -> List[Dict[str, Any]]:
        """
        Get list of all devices that have parental controls configured.
        
        Returns:
            List of devices with parental control information including:
            - mac_address: Device MAC address
            - name: Device name
            - device_type: Device type
            - active: Whether device is currently connected
            - control_type: Type of parental control
            - enabled: Whether controls are enabled
            - summary: Summary of current restrictions
        """
        # Get all device schedules
        all_schedules = self.get_device_schedules("ToD")
        
        # Get all devices for name/type lookup
        all_devices = self.get_devices('all')
        device_lookup = {d.get('PhysAddress'): d for d in all_devices}
        
        controlled_devices = []
        
        # Process devices with schedules
        for schedule in all_schedules:
            if schedule.get('enable'):
                mac_address = schedule.get('ID')
                if mac_address:
                    device_info = device_lookup.get(mac_address, {})
                    
                    # Get full parental control status
                    control_status = self.get_device_parental_control_status(mac_address)
                    
                    controlled_devices.append({
                        'mac_address': mac_address,
                        'name': device_info.get('Name', 'Unknown'),
                        'device_type': device_info.get('DeviceType', 'Unknown'),
                        'active': device_info.get('Active', False),
                        'control_type': control_status.get('control_type'),
                        'enabled': control_status.get('enabled'),
                        'summary': control_status.get('summary')
                    })
        
        # TODO: Also check for devices with MST but no schedules
        # This would require iterating through all devices and checking MST status
        # For now, the schedule-based approach covers most cases
        
        return controlled_devices
    
    def format_time_seconds_to_readable(self, seconds: int) -> str:
        """
        Convert seconds from Monday 00:00 to human-readable time.
        
        Args:
            seconds: Seconds from Monday 00:00
        
        Returns:
            Human-readable time string (e.g., "Monday 08:30", "Friday 22:00")
        """
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        
        day_index = seconds // 86400  # 86400 seconds in a day
        remaining_seconds = seconds % 86400
        
        hours = remaining_seconds // 3600
        minutes = (remaining_seconds % 3600) // 60
        
        if day_index >= 7:
            # Handle overflow to next week
            day_index = day_index % 7
        
        return f"{days[day_index]} {hours:02d}:{minutes:02d}"
    
    def create_bedtime_schedule_blocks(self, bedtime_hour: int = 22, wakeup_hour: int = 6,
                                     days: List[int] = None) -> List[Dict[str, int]]:
        """
        Create schedule blocks for bedtime restrictions.
        
        Args:
            bedtime_hour: Hour when device should be blocked (0-23, default: 22 = 10 PM)
            wakeup_hour: Hour when device should be unblocked (0-23, default: 6 = 6 AM)
            days: List of days to apply (0=Monday, 6=Sunday, default: [0,1,2,3,4] = weekdays)
        
        Returns:
            List of schedule blocks suitable for set_device_schedule
        """
        if days is None:
            days = [0, 1, 2, 3, 4]  # Weekdays only
        
        schedule_blocks = []
        
        for day in days:
            # Calculate start time (bedtime)
            bedtime_seconds = day * 86400 + bedtime_hour * 3600
            
            # Calculate end time (next day wakeup)
            if wakeup_hour <= bedtime_hour:
                # Wakeup is next day
                wakeup_seconds = (day + 1) * 86400 + wakeup_hour * 3600
            else:
                # Wakeup is same day (shouldn't happen for bedtime, but handle it)
                wakeup_seconds = day * 86400 + wakeup_hour * 3600
            
            schedule_blocks.append({
                "begin": bedtime_seconds,
                "end": wakeup_seconds
            })
        
        return schedule_blocks

    def add_port_forwarding_rule(self, rule_id: str, internal_port: str, external_port: str,
                                destination_ip: str, protocol: str = "6", description: str = "",
                                enabled: bool = True, source_interface: str = "data",
                                origin: str = "webui") -> str:
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
        valid_protocols = {"6", "17", "6,17", "17,6"}
        if protocol not in valid_protocols:
            raise ValueError(f"protocol must be one of: {valid_protocols}")
        
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
                "sourcePrefix": ""
            }
        )
        
        # Extract the full rule ID from response
        if isinstance(result, dict) and 'status' in result:
            return result['status']
        elif isinstance(result, dict) and 'data' in result and 'rule' in result['data']:
            return result['data']['rule'].get('Id', clean_rule_id)
        
        return clean_rule_id
    
    def update_port_forwarding_rule(self, rule_id: str, internal_port: str = None,
                                   external_port: str = None, destination_ip: str = None,
                                   protocol: str = None, description: str = None,
                                   enabled: bool = None, source_interface: str = "data",
                                   origin: str = "webui") -> str:
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
            valid_protocols = {"6", "17", "6,17", "17,6"}
            if protocol not in valid_protocols:
                raise ValueError(f"protocol must be one of: {valid_protocols}")
        
        # Get current rule to fill in missing parameters
        existing_rules = self.get_port_forwarding(origin)
        current_rule = None
        
        for rule in existing_rules:
            if rule.get('Id') == rule_id or rule.get('Id') == f"{origin}_{rule_id}":
                current_rule = rule
                break
        
        if not current_rule:
            raise ValueError(f"Port forwarding rule '{rule_id}' not found")
        
        # Use current values for unspecified parameters
        update_params = {
            "id": current_rule['Id'],
            "internalPort": str(internal_port) if internal_port is not None else current_rule['InternalPort'],
            "externalPort": str(external_port) if external_port is not None else current_rule['ExternalPort'],
            "destinationIPAddress": destination_ip if destination_ip is not None else current_rule['DestinationIPAddress'],
            "enable": enabled if enabled is not None else current_rule['Enable'],
            "persistent": True,
            "protocol": protocol if protocol is not None else current_rule['Protocol'],
            "description": description if description is not None else current_rule['Description'],
            "sourceInterface": source_interface,
            "origin": origin,
            "destinationMACAddress": current_rule.get('DestinationMACAddress', ''),
            "sourcePrefix": current_rule.get('SourcePrefix', '')
        }
        
        result = self._make_api_call(
            service="Firewall",
            method="setPortForwarding",
            parameters=update_params
        )
        
        # Extract the full rule ID from response
        if isinstance(result, dict) and 'status' in result:
            return result['status']
        elif isinstance(result, dict) and 'data' in result and 'rule' in result['data']:
            return result['data']['rule'].get('Id', rule_id)
        
        return rule_id
    
    def delete_port_forwarding_rule(self, rule_id: str, destination_ip: str = None,
                                   origin: str = "webui") -> bool:
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
        full_rule_id = rule_id if rule_id.startswith(f"{origin}_") else f"{origin}_{rule_id}"
        
        # If destination_ip not provided, try to get it from existing rule
        if destination_ip is None:
            existing_rules = self.get_port_forwarding(origin)
            for rule in existing_rules:
                if rule.get('Id') == full_rule_id:
                    destination_ip = rule.get('DestinationIPAddress')
                    break
        
        if not destination_ip:
            raise ValueError(f"destination_ip is required or rule '{rule_id}' not found")
        
        result = self._make_api_call(
            service="Firewall",
            method="deletePortForwarding",
            parameters={
                "id": full_rule_id,
                "origin": origin,
                "destinationIPAddress": destination_ip
            }
        )
        
        return result.get('status', False) == True
    
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
            self.update_port_forwarding_rule(rule_id, enabled=True, origin=origin)
            return True
        except Exception:
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
            self.update_port_forwarding_rule(rule_id, enabled=False, origin=origin)
            return True
        except Exception:
            return False
    
    def add_ipv6_pinhole(self, destination_ip: str, destination_port: str,
                        protocol: str = "6", description: str = "", enabled: bool = True,
                        source_interface: str = "data", source_port: str = "",
                        origin: str = "webui") -> str:
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
        valid_protocols = {"6", "17", "6,17", "17,6"}
        if protocol not in valid_protocols:
            raise ValueError(f"protocol must be one of: {valid_protocols}")
        
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
                "persistent": True
            }
        )
        
        # Extract the full rule ID from response
        if isinstance(result, dict) and 'status' in result:
            return result['status']
        elif isinstance(result, dict) and 'data' in result and 'rule' in result['data']:
            return result['data']['rule'].get('Id', '')
        
        return ''
    
    def update_ipv6_pinhole(self, rule_id: str, destination_ip: str = None,
                           destination_port: str = None, protocol: str = None,
                           description: str = None, enabled: bool = None,
                           source_interface: str = "data", source_port: str = None,
                           origin: str = "webui") -> str:
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
            valid_protocols = {"6", "17", "6,17", "17,6"}
            if protocol not in valid_protocols:
                raise ValueError(f"protocol must be one of: {valid_protocols}")
        
        # Get current rule to fill in missing parameters
        existing_rules = self.get_ipv6_pinholes()
        current_rule = None
        
        for rule in existing_rules:
            if rule.get('Id') == rule_id:
                current_rule = rule
                break
        
        if not current_rule:
            raise ValueError(f"IPv6 pinhole rule '{rule_id}' not found")
        
        # Use current values for unspecified parameters
        update_params = {
            "id": rule_id,
            "enable": enabled if enabled is not None else current_rule['Enable'],
            "description": description if description is not None else current_rule['Description'],
            "origin": origin,
            "sourceInterface": source_interface,
            "sourcePort": source_port if source_port is not None else current_rule.get('SourcePort', ''),
            "destinationPort": str(destination_port) if destination_port is not None else current_rule['DestinationPort'],
            "destinationIPAddress": destination_ip if destination_ip is not None else current_rule['DestinationIPAddress'],
            "protocol": protocol if protocol is not None else current_rule['Protocol'],
            "ipversion": 6,
            "persistent": True
        }
        
        result = self._make_api_call(
            service="Firewall",
            method="setPinhole",
            parameters=update_params
        )
        
        # Extract the full rule ID from response
        if isinstance(result, dict) and 'status' in result:
            return result['status']
        elif isinstance(result, dict) and 'data' in result and 'rule' in result['data']:
            return result['data']['rule'].get('Id', rule_id)
        
        return rule_id
    
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
            parameters={
                "id": rule_id,
                "origin": origin
            }
        )
        
        return result.get('status', False) == True
    
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
            self.update_ipv6_pinhole(rule_id, enabled=True, origin=origin)
            return True
        except Exception:
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
            self.update_ipv6_pinhole(rule_id, enabled=False, origin=origin)
            return True
        except Exception:
            return False
    
    def manage_port_forwarding(self, action: str, rule_id: str = None, **kwargs) -> Union[str, bool, List[Dict[str, Any]]]:
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
        ip_version = kwargs.get('ip_version', 4)
        origin = kwargs.get('origin', 'webui')
        
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
                if rule.get('Id') == rule_id or rule.get('Id') == f"{origin}_{rule_id}":
                    return rule
            return None
        
        elif action == "add":
            if ip_version == 6:
                destination_ip = kwargs.get('destination_ip')
                destination_port = kwargs.get('destination_port')
                if not destination_ip or not destination_port:
                    raise ValueError("destination_ip and destination_port are required for IPv6 pinholes")
                
                return self.add_ipv6_pinhole(
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    protocol=kwargs.get('protocol', '6'),
                    description=kwargs.get('description', ''),
                    enabled=kwargs.get('enabled', True),
                    source_port=kwargs.get('source_port', ''),
                    origin=origin
                )
            else:
                if not rule_id:
                    raise ValueError("rule_id is required for IPv4 port forwarding")
                
                internal_port = kwargs.get('internal_port')
                external_port = kwargs.get('external_port')
                destination_ip = kwargs.get('destination_ip')
                if not internal_port or not external_port or not destination_ip:
                    raise ValueError("internal_port, external_port, and destination_ip are required for IPv4 port forwarding")
                
                return self.add_port_forwarding_rule(
                    rule_id=rule_id,
                    internal_port=internal_port,
                    external_port=external_port,
                    destination_ip=destination_ip,
                    protocol=kwargs.get('protocol', '6'),
                    description=kwargs.get('description', ''),
                    enabled=kwargs.get('enabled', True),
                    origin=origin
                )
        
        elif action == "update":
            if not rule_id:
                raise ValueError("rule_id is required for 'update' action")
            
            if ip_version == 6:
                return self.update_ipv6_pinhole(
                    rule_id=rule_id,
                    destination_ip=kwargs.get('destination_ip'),
                    destination_port=kwargs.get('destination_port'),
                    protocol=kwargs.get('protocol'),
                    description=kwargs.get('description'),
                    enabled=kwargs.get('enabled'),
                    source_port=kwargs.get('source_port'),
                    origin=origin
                )
            else:
                return self.update_port_forwarding_rule(
                    rule_id=rule_id,
                    internal_port=kwargs.get('internal_port'),
                    external_port=kwargs.get('external_port'),
                    destination_ip=kwargs.get('destination_ip'),
                    protocol=kwargs.get('protocol'),
                    description=kwargs.get('description'),
                    enabled=kwargs.get('enabled'),
                    origin=origin
                )
        
        elif action == "delete":
            if not rule_id:
                raise ValueError("rule_id is required for 'delete' action")
            
            if ip_version == 6:
                return self.delete_ipv6_pinhole(rule_id, origin)
            else:
                destination_ip = kwargs.get('destination_ip')
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
            raise ValueError(f"action must be one of: add, update, delete, enable, disable, list, get")

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
        try:
            result = self._make_api_call(
                service="Firewall",
                method="set",
                parameters={"UpnpPortForwardingEnable": enabled}
            )
            
            return result.get('status') is True
            
        except Exception:
            return False

    def set_dmz_host(self, destination_ip: str, enabled: bool = True, 
                     dmz_id: str = "webui", source_interface: str = "data") -> str:
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
            
        try:
            result = self._make_api_call(
                service="Firewall",
                method="setDMZ",
                parameters={
                    "id": dmz_id,
                    "sourceInterface": source_interface,
                    "destinationIPAddress": destination_ip,
                    "enable": enabled
                }
            )
            
            return result.get('status', '')
            
        except Exception:
            return ''

    def delete_dmz_host(self, dmz_id: str = "webui") -> bool:
        """
        Delete DMZ host configuration.
        
        Args:
            dmz_id: DMZ configuration ID to delete (default: "webui")
            
        Returns:
            True if successful
        """
        try:
            result = self._make_api_call(
                service="Firewall",
                method="deleteDMZ",
                parameters={"id": dmz_id}
            )
            
            return result.get('status') is True
            
        except Exception:
            return False

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
            
        try:
            result = self._make_api_call(
                service="Time",
                method="setNTPServers",
                parameters={"servers": servers}
            )
            
            # API returns null status for this call, so we assume success if no exception
            return True
            
        except Exception:
            return False
        

    def change_password(self, new_password: str, old_password: str, username: str = "admin") -> bool:
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
            
        try:
            result = self._make_api_call(
                service="UserManagement",
                method="changePasswordSec",
                parameters={
                    "name": username,
                    "password": new_password,
                    "old_password": old_password
                }
            )
            
            return result.get('status') is True
            
        except Exception:
            return False

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
        try:
            result = self._make_api_call(
                service="NMC",
                method="reboot",
                parameters={"reason": reason}
            )
            
            return True  # Command sent successfully
            
        except Exception:
            return False

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
        try:
            result = self._make_api_call(
                service="NMC",
                method="reset",
                parameters={"reason": reason}
            )
            
            return True  # Command sent successfully
            
        except Exception:
            return False

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
        try:
            result = self._make_api_call(
                service="NMC.Wifi",
                method="wififactoryReset",
                parameters={}
            )
            
            return True  # Command sent successfully
            
        except Exception:
            return False

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
        try:
            result = self._make_api_call(
                service="NMC.GroupFunction",
                method="reboot",
                parameters={"reason": reason}
            )
            
            return True  # Command sent successfully
            
        except Exception:
            return False

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
        try:
            result = self._make_api_call(
                service="NMC.GroupFunction",
                method="factoryReset",
                parameters={"reason": reason}
            )
            
            return True  # Command sent successfully
            
        except Exception:
            return False    
    
    def get_system_stats(self, device_mac: str = None) -> Dict[str, Any]:
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
        # If no MAC provided, try to get router's own MAC address
        if not device_mac:
            try:
                device_info = self.get_hgw_device_info()
                device_mac = device_info.get('Key', '')

                if not device_mac:
                    raise ValueError("Could not auto-detect router MAC address. Please provide device_mac parameter.")
                    
            except Exception as e:
                raise ValueError(f"Could not auto-detect router MAC address: {e}. Please provide device_mac parameter.")
        
        # Clean MAC address format
        device_mac = device_mac.replace('-', ':').upper()
        
        try:
            result = self._make_api_call(
                service="eventmanager",
                method="get_events",
                parameters={
                    "events": [
                        {
                            "service": f"Devices.Device.{device_mac}",
                            "event": "cpu"
                        },
                        {
                            "service": f"Devices.Device.{device_mac}",
                            "event": "sysinfo",
                            "data": {"types": "sysinfo"}
                        },
                        {
                            "service": "Devices.Device.LAN",
                            "event": "network",
                            "data": {"types": "network"}
                        }
                    ],
                    "channelid": 0
                }
            )
            
            # Extract system info from response
            if not result or 'status' not in result:
                return {}
                
            events = result.get('status', {}).get('events', [])
            if not events:
                return {}
                
            # Find the sysinfo event
            sysinfo_data = None
            for event in events:
                event_data = event.get('data', {})
                if event_data.get('object', {}).get('reason') == 'sysinfo':
                    attributes = event_data.get('object', {}).get('attributes', {})
                    sysinfo_data = attributes.get(device_mac)
                    break
                    
            if not sysinfo_data:
                return {}
                
            # Parse and format the data
            total_ram = sysinfo_data.get('totalram', 0)
            free_ram = sysinfo_data.get('freeram', 0)
            used_ram = total_ram - free_ram
            
            # Format uptime
            uptime_seconds = sysinfo_data.get('uptime', 0)
            days = uptime_seconds // 86400
            hours = (uptime_seconds % 86400) // 3600
            minutes = (uptime_seconds % 3600) // 60
            uptime_formatted = f"{days}d {hours}h {minutes}m"
            
            # Normalize load averages (divide by 1000 to get percentage-like values)
            load_1min = sysinfo_data.get('loadaverage_1min', 0) / 1000
            load_5min = sysinfo_data.get('loadaverage_5min', 0) / 1000  
            load_15min = sysinfo_data.get('loadaverage_15min', 0) / 1000
            
            return {
                'timestamp': sysinfo_data.get('Timestamp', ''),
                'uptime_seconds': uptime_seconds,
                'uptime_formatted': uptime_formatted,
                'load_average': {
                    '1min': round(load_1min, 1),
                    '5min': round(load_5min, 1),
                    '15min': round(load_15min, 1)
                },
                'memory': {
                    'total_bytes': total_ram,
                    'used_bytes': used_ram,
                    'free_bytes': free_ram,
                    'shared_bytes': sysinfo_data.get('sharedram', 0),
                    'buffer_bytes': sysinfo_data.get('bufferram', 0),
                    'cached_bytes': sysinfo_data.get('cachedram', 0),
                    'used_percentage': round((used_ram / total_ram * 100), 1) if total_ram > 0 else 0,
                    'free_percentage': round((free_ram / total_ram * 100), 1) if total_ram > 0 else 0
                },
                'swap': {
                    'total_bytes': sysinfo_data.get('totalswap', 0),
                    'free_bytes': sysinfo_data.get('freeswap', 0)
                },
                'processes': sysinfo_data.get('procs', 0),
                'device_mac': device_mac
            }
            
        except Exception:
            return {} 
    
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
            
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        size = float(bytes_value)
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
            
        return f"{size:.1f} {units[unit_index]}" 
    
    def __enter__(self):
        """Context manager entry."""
        return self 