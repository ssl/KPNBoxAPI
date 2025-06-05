# KPNBoxAPI

Python library for interacting with KPN Box modem/router. Tested with Box 14.

## Installation

```bash
pip install kpnboxapi
```

## Quick Start

```python
from kpnboxapi import KPNBoxAPI

# Connect and authenticate
api = KPNBoxAPI(host="192.168.2.254")
api.login(username="admin", password="your_password")

# Get all connected devices
devices = api.get_devices()

# Get only currently connected devices
active_devices = api.get_devices(filter='active')

# Get previously connected devices
inactive_devices = api.get_devices(filter='inactive')
```

more examples in the `examples/` folder and down below in this readme.

```bash
python examples/basic_usage.py
```

## API Reference

### KPNBoxAPI(host="192.168.2.254", timeout=30)

Initialize the API client.

**Parameters:**
- `host` (str): KPN Box IP address (default: "192.168.2.254")
- `timeout` (int): Request timeout in seconds (default: 30)

### login(username="admin", password="")

Authenticate with the KPN Box.

**Parameters:**
- `username` (str): Username (default: "admin")
- `password` (str): Password

**Returns:** `bool` - True if successful

### get_connected_devices()

Get raw device data from the KPN Box API.

**Returns:** Raw device data (dict/list)

### get_devices(filter='all')

Get filtered list of connected devices.

**Parameters:**
- `filter` (str): Filter devices - `'all'`, `'active'`, or `'inactive'` (default: 'all')

**Returns:** List of device dictionaries

**Device Fields:**
- `Name`: Device name
- `PhysAddress`: MAC address
- `IPAddress`: IP address
- `Active`: Connection status (True/False)
- `DeviceType`: Device type (e.g., "Computer", "Mobile", "TV")
- `Layer2Interface`: Network interface (e.g., "ETH0", "ETH3")
- `FirstSeen`: First connection timestamp
- `LastConnection`: Last connection timestamp
- `VendorClassID`: DHCP vendor class
- `ClientID`: DHCP client ID
- `UniqueID`: Device unique identifier
- `Index`: Device index
- `Names`: List of device names from different sources
- `DeviceTypes`: List of device types from different sources
- `IPv4Address`: List of IPv4 addresses
- `IPv6Address`: List of IPv6 addresses
- `Security`: Security scoring information
- `Priority`: Traffic priority settings
- And many other fields from the KPN Box API

### delete_device(mac_address)

Delete/destroy a device from the router's device list.

**Parameters:**
- `mac_address` (str): MAC address of the device to delete (e.g., "96:16:1A:D6:0F:30")

**Returns:** `bool` - True if device was successfully deleted

**Note:** 
- This only removes the device from the router's memory
- If the device reconnects, it will reappear in the device list
- Typically used for inactive devices to clean up the device list
- Device schedules and restrictions are also removed

### cleanup_inactive_devices(days_inactive=30)

Clean up devices that haven't been seen for a specified number of days.

**Parameters:**
- `days_inactive` (int): Number of days of inactivity before considering device for cleanup (default: 30)

**Returns:** Dictionary with cleanup results

**Cleanup Result Fields:**
- `candidates`: List of devices eligible for cleanup
- `deleted`: List of devices that were deleted
- `failed`: List of devices that failed to delete
- `total_candidates`: Number of devices eligible for cleanup
- `total_deleted`: Number of devices successfully deleted
- `total_failed`: Number of devices that failed to delete

**Note:** This function will automatically delete devices, use with caution.

### list_inactive_devices(days_inactive=7)

List devices that haven't been seen for a specified number of days.

**Parameters:**
- `days_inactive` (int): Number of days of inactivity to filter by (default: 7)

**Returns:** List of inactive device dictionaries with additional fields

**Additional Fields:**
- `days_since_seen`: Number of days since last connection
- All standard device management fields

### get_device_info()

Get information about the KPN Box modem itself.

**Returns:** Dictionary with modem information

**Modem Info Fields:**
- `Manufacturer`: Modem manufacturer (e.g., "Arcadyan")
- `ModelName`: Modem model (e.g., "BoxV14")
- `SerialNumber`: Modem serial number
- `SoftwareVersion`: Current firmware version
- `HardwareVersion`: Hardware version
- `UpTime`: Modem uptime in seconds
- `ExternalIPAddress`: External/WAN IP address
- `DeviceStatus`: Current device status
- `BaseMAC`: Modem base MAC address
- `Country`: Country code
- `NumberOfReboots`: Total number of reboots
- `ManufacturerOUI`: Manufacturer OUI
- `Description`: Device description
- `ProductClass`: Product class
- `RescueVersion`: Rescue firmware version
- `FirstUseDate`: First use timestamp
- And other modem details

### get_public_ipv6()

Get the public IPv6 address of the KPN Box modem.

**Returns:** `str` - Public IPv6 address

### get_wifi_networks()

Get WiFi network configurations (regular networks, not guest).

**Returns:** List of WiFi network dictionaries

**WiFi Network Fields:**
- `VAPName`: Virtual Access Point name (e.g., "vap2g0priv", "vap5g0priv")
- `SSID`: Network name
- `VAPStatus`: Status ("Up" or "Down")
- `BSSID`: MAC address of the access point
- `MACAddress`: MAC address
- `Security`: Security configuration including:
  - `ModeEnabled`: Security mode (e.g., "WPA2-Personal")
  - `KeyPassPhrase`: WiFi password
  - `ModesSupported`: List of supported security modes
- `MaxAssociatedDevices`: Maximum number of devices
- `AssociatedDeviceNumberOfEntries`: Current connected devices
- `EssIdentifier`: Network identifier ("Primary", "Secondary")
- `BridgeInterface`: Network bridge interface
- `WPS`: WPS configuration
- `IEEE80211r`: Fast roaming configuration
- `MACFiltering`: MAC filtering settings
- And many other WiFi configuration fields

### get_guest_wifi_networks()

Get guest WiFi network configurations.

**Returns:** List of guest WiFi network dictionaries with same structure as `get_wifi_networks()` but for guest networks

### get_all_wifi_networks()

Get all WiFi networks (both regular and guest).

**Returns:** Dictionary with keys:
- `'regular'`: List of regular WiFi networks
- `'guest'`: List of guest WiFi networks

### set_wifi_config(ssid_2g=None, ssid_5g=None, password_2g=None, password_5g=None, security_mode_2g=None, security_mode_5g=None, mfp_config_2g="", mfp_config_5g="")

Configure WiFi network settings (SSID, password, security).

**Parameters:**
- `ssid_2g` (str): 2.4GHz network name/SSID
- `ssid_5g` (str): 5GHz network name/SSID
- `password_2g` (str): 2.4GHz network password
- `password_5g` (str): 5GHz network password
- `security_mode_2g` (str): 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
- `security_mode_5g` (str): 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
- `mfp_config_2g` (str): 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
- `mfp_config_5g` (str): 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")

**Returns:** `bool` - True if successful

### set_wifi_visibility(visible_2g=None, visible_5g=None)

Enable or disable WiFi network visibility (SSID advertisement).

**Parameters:**
- `visible_2g` (bool): Whether 2.4GHz network should be visible (broadcast SSID)
- `visible_5g` (bool): Whether 5GHz network should be visible (broadcast SSID)

**Returns:** `bool` - True if successful

### set_wps_enabled(enabled_2g=None, enabled_5g=None)

Enable or disable WPS (WiFi Protected Setup) for WiFi networks.

**Parameters:**
- `enabled_2g` (bool): Whether to enable WPS on 2.4GHz network
- `enabled_5g` (bool): Whether to enable WPS on 5GHz network

**Returns:** Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band

### get_dhcp_server(pool_id="default")

Get DHCP server configuration for a specific pool.

**Parameters:**
- `pool_id` (str): DHCP pool ID - `"default"` or `"guest"` (default: "default")

**Returns:** Dictionary with DHCP server configuration

**DHCP Server Fields:**
- `PoolID`: DHCP pool identifier ("default" or "guest")
- `Enable`: Whether DHCP server is enabled (True/False)
- `Status`: Current status ("Enabled" or "Disabled")
- `MinAddress`: Start of IP address range (e.g., "192.168.2.100")
- `MaxAddress`: End of IP address range (e.g., "192.168.2.200")
- `SubnetMask`: Network subnet mask (e.g., "255.255.255.0")
- `IPRouters`: Gateway IP address (e.g., "192.168.2.254")
- `LeaseTime`: DHCP lease duration in seconds (e.g., 14400 = 4 hours)
- `DNSServers`: DNS server addresses (comma-separated)
- `DomainName`: Network domain name (e.g., "home")
- `Interface`: Network interface (e.g., "bridge", "brguest")
- `LeaseNumberOfEntries`: Number of active DHCP leases
- `StaticAddressNumberOfEntries`: Number of static IP assignments
- `Allocation`: DHCP allocation method ("dynamic")
- `ARPProtect`: ARP protection enabled
- And many other DHCP configuration fields

### get_default_dhcp_server()

Get default network DHCP server configuration.

**Returns:** Dictionary with default DHCP server configuration

### get_guest_dhcp_server()

Get guest network DHCP server configuration.

**Returns:** Dictionary with guest DHCP server configuration

### get_all_dhcp_servers()

Get all DHCP server configurations (both default and guest).

**Returns:** Dictionary with keys:
- `'default'`: Default network DHCP configuration
- `'guest'`: Guest network DHCP configuration

### set_dhcp_server_config(network="lan", gateway_ip=None, subnet_mask=None, dhcp_enabled=None, dhcp_min_ip=None, dhcp_max_ip=None, lease_time_seconds=None, dhcp_authoritative=None, dns_servers=None)

Configure DHCP server settings for a network.

**Parameters:**
- `network` (str): Network to configure ("lan" for home, "guest" for guest network)
- `gateway_ip` (str): Gateway IP address (e.g., "192.168.2.254")
- `subnet_mask` (int): Subnet prefix length (e.g., 24 for /24)
- `dhcp_enabled` (bool): Enable/disable DHCP server
- `dhcp_min_ip` (str): Minimum IP address for DHCP pool (e.g., "192.168.2.100")
- `dhcp_max_ip` (str): Maximum IP address for DHCP pool (e.g., "192.168.2.200")
- `lease_time_seconds` (int): DHCP lease time in seconds (e.g., 14400 for 4 hours)
- `dhcp_authoritative` (bool): Whether DHCP server is authoritative
- `dns_servers` (str): DNS servers as comma-separated string (e.g., "9.9.9.9,149.112.112.112")

**Returns:** `bool` - True if configuration was successful

### set_home_dhcp_config(gateway_ip=None, subnet_mask=None, dhcp_enabled=None, dhcp_min_ip=None, dhcp_max_ip=None, lease_time_seconds=None, dhcp_authoritative=None, dns_servers=None)

Configure DHCP server settings for the home network.

**Parameters:**
- `gateway_ip` (str): Gateway IP address (default: "192.168.2.254")
- `subnet_mask` (int): Subnet prefix length (default: 24)
- `dhcp_enabled` (bool): Enable/disable DHCP server (default: True)
- `dhcp_min_ip` (str): Minimum IP for DHCP pool (default: "192.168.2.100")
- `dhcp_max_ip` (str): Maximum IP for DHCP pool (default: "192.168.2.200")
- `lease_time_seconds` (int): DHCP lease time in seconds (default: 14400)
- `dhcp_authoritative` (bool): Whether DHCP server is authoritative (default: True)
- `dns_servers` (str): DNS servers comma-separated (default: "9.9.9.9,149.112.112.112")

**Returns:** `bool` - True if configuration was successful

### set_guest_dhcp_config(gateway_ip=None, subnet_mask=None, dhcp_enabled=None, dhcp_min_ip=None, dhcp_max_ip=None, lease_time_seconds=None, dns_servers=None)

Configure DHCP server settings for the guest network.

**Parameters:**
- `gateway_ip` (str): Gateway IP address (default: "192.168.3.254")
- `subnet_mask` (int): Subnet prefix length (default: 24)
- `dhcp_enabled` (bool): Enable/disable DHCP server (default: True)
- `dhcp_min_ip` (str): Minimum IP for DHCP pool (default: "192.168.3.1")
- `dhcp_max_ip` (str): Maximum IP for DHCP pool (default: "192.168.3.32")
- `lease_time_seconds` (int): DHCP lease time in seconds (default: 14400)
- `dns_servers` (str): DNS servers comma-separated (default: "9.9.9.9,149.112.112.112")

**Returns:** `bool` - True if configuration was successful

### configure_network_isolation(home_subnet="192.168.2.0/24", guest_subnet="192.168.3.0/24", home_dhcp_range=("192.168.2.100", "192.168.2.200"), guest_dhcp_range=("192.168.3.1", "192.168.3.32"), dns_servers="9.9.9.9,149.112.112.112")

Configure network isolation between home and guest networks.

**Parameters:**
- `home_subnet` (str): Home network subnet in CIDR notation
- `guest_subnet` (str): Guest network subnet in CIDR notation
- `home_dhcp_range` (tuple): Tuple of (min_ip, max_ip) for home DHCP
- `guest_dhcp_range` (tuple): Tuple of (min_ip, max_ip) for guest DHCP
- `dns_servers` (str): DNS servers for both networks

**Returns:** Dictionary with configuration results for home and guest networks

**Note:** This sets up proper IP ranges and DHCP pools to keep networks separated.

### get_dhcp_leases(pool_id="default")

Get DHCP leases for a specific pool.

**Parameters:**
- `pool_id` (str): DHCP pool ID - `"default"` or `"guest"` (default: "default")

**Returns:** List of DHCP lease dictionaries

**DHCP Lease Fields:**
- `PoolID`: DHCP pool identifier ("default" or "guest")
- `ClientID`: DHCP client identifier
- `IPAddress`: Assigned IP address (e.g., "192.168.2.117")
- `MACAddress`: Device MAC address
- `FriendlyName`: Device name/hostname (e.g., "Studio", "iPhone")
- `Active`: Whether lease is currently active (True/False)
- `Reserved`: Whether IP is reserved for this device (True/False)
- `LeaseTime`: Total lease duration in seconds
- `LeaseTimeRemaining`: Remaining lease time in seconds (-1 = permanent)
- `Gateway`: Gateway configuration
- `Flags`: DHCP flags and options
- `TransactionID`: DHCP transaction identifier
- Various DHCP protocol fields

### get_default_dhcp_leases()

Get DHCP leases for the default network.

**Returns:** List of DHCP lease dictionaries for default network

### get_guest_dhcp_leases()

Get DHCP leases for the guest network.

**Returns:** List of DHCP lease dictionaries for guest network

### get_all_dhcp_leases()

Get all DHCP leases (both default and guest networks).

**Returns:** Dictionary with keys:
- `'default'`: List of default network DHCP leases
- `'guest'`: List of guest network DHCP leases

### get_active_dhcp_leases(pool_id="default")

Get only active DHCP leases for a specific pool.

**Parameters:**
- `pool_id` (str): DHCP pool ID - `"default"` or `"guest"` (default: "default")

**Returns:** List of active DHCP lease dictionaries

### get_dyndns_hosts()

Get Dynamic DNS host configurations.

**Returns:** List of DynDNS host dictionaries

**DynDNS Host Fields:**
- `service`: DynDNS provider service (e.g., "No-IP", "DynDNS")
- `hostname`: Dynamic DNS hostname (e.g., "example.ddns.net")
- `username`: DynDNS account username
- `password`: DynDNS account password
- `last_update`: Last update timestamp (ISO format, e.g., "2025-06-03T23:58:30Z")
- `status`: Current status (e.g., "UPDATED", "ERROR", "PENDING")
- `enable`: Whether DynDNS is enabled (True/False)

### add_dyndns_host(service, username, hostname, password)

Add a new Dynamic DNS host configuration.

**Parameters:**
- `service` (str): DynDNS provider service (e.g., "dyndns", "noip", "freedns")
- `username` (str): DynDNS account username
- `hostname` (str): Dynamic DNS hostname (e.g., "yourdomain.ddns.net")
- `password` (str): DynDNS account password

**Returns:** `bool` - True if host was successfully added

### delete_dyndns_host(hostname)

Delete a Dynamic DNS host configuration.

**Parameters:**
- `hostname` (str): Dynamic DNS hostname to delete (e.g., "yourdomain.ddns.net")

**Returns:** `bool` - True if host was successfully deleted

### update_dyndns_host(hostname, service=None, username=None, password=None)

Update an existing Dynamic DNS host configuration.

**Parameters:**
- `hostname` (str): Dynamic DNS hostname to update (e.g., "yourdomain.ddns.net")
- `service` (str): New DynDNS provider service (if changing)
- `username` (str): New DynDNS account username (if changing)
- `password` (str): New DynDNS account password (if changing)

**Returns:** `bool` - True if host was successfully updated

**Note:** This method deletes the existing host and adds it back with new configuration.

### get_dyndns_status(hostname=None)

Get Dynamic DNS status for a specific hostname or all hosts.

**Parameters:**
- `hostname` (str): Specific hostname to check (optional, returns all if not specified)

**Returns:** Dictionary with DynDNS status information or single host if hostname specified

**Status Fields (when hostname=None):**
- `total_hosts`: Total number of configured hosts
- `hosts`: List of all host configurations
- `active_hosts`: List of enabled hosts only
- `last_updated`: Most recent update timestamp

### manage_dyndns_service(action, hostname, service=None, username=None, password=None)

Comprehensive DynDNS management method.

**Parameters:**
- `action` (str): Action to perform ("add", "delete", "update")
- `hostname` (str): Dynamic DNS hostname
- `service` (str): DynDNS provider service (required for add)
- `username` (str): DynDNS account username (required for add)
- `password` (str): DynDNS account password (required for add)

**Returns:** `bool` - True if action was successful

### get_network_stats(interface="ETH0")

Get network device statistics for a specific interface.

**Parameters:**
- `interface` (str): Interface name - `"ETH0"`, `"ETH1"`, `"ETH2"`, `"ETH3"`, `"eth4"`, or `"ppp_vdata"` (default: "ETH0")
  - ETH0-ETH3: Individual Ethernet ports
  - eth4: Total WAN statistics (all WAN traffic combined)
  - ppp_vdata: PPP connection statistics

**Returns:** Dictionary with network statistics

**Network Statistics Fields:**
- `Interface`: Interface name (e.g., "ETH0", "eth4", "ppp_vdata")
- `RxPackets`: Received packets count
- `TxPackets`: Transmitted packets count
- `RxBytes`: Received bytes count
- `TxBytes`: Transmitted bytes count
- `RxErrors`: Received errors count
- `TxErrors`: Transmitted errors count
- `RxDropped`: Received dropped packets count
- `TxDropped`: Transmitted dropped packets count
- `Multicast`: Multicast packets count
- `Collisions`: Network collisions count
- `RxLengthErrors`: Received length errors
- `RxOverErrors`: Received overflow errors
- `RxCrcErrors`: Received CRC errors
- `RxFrameErrors`: Received frame errors
- `RxFifoErrors`: Received FIFO errors
- `RxMissedErrors`: Received missed errors
- `TxAbortedErrors`: Transmitted aborted errors
- `TxCarrierErrors`: Transmitted carrier errors
- `TxFifoErrors`: Transmitted FIFO errors
- `TxHeartbeatErrors`: Transmitted heartbeat errors
- `TxWindowErrors`: Transmitted window errors

### get_all_network_stats()

Get network device statistics for all interfaces (ETH0-ETH3, WAN total, PPP).

**Returns:** Dictionary with keys for all interfaces containing their respective statistics

### get_wan_total_stats()

Get total WAN network statistics (all WAN traffic combined).

**Returns:** Dictionary with total WAN network statistics

### get_ppp_stats()

Get PPP connection network statistics.

**Returns:** Dictionary with PPP connection network statistics

### format_bytes(bytes_count)

Helper method to format byte counts in human-readable format.

**Parameters:**
- `bytes_count` (int): Number of bytes

**Returns:** `str` - Formatted string (e.g., "1.2 GB", "45.6 MB")

### get_port_forwarding(origin="webui")

Get firewall port forwarding rules.

**Parameters:**
- `origin` (str): Rule origin filter - `"webui"`, `"upnp"`, or other origin (default: "webui")

**Returns:** List of port forwarding rule dictionaries

**Port Forwarding Rule Fields:**
- `Id`: Rule identifier (e.g., "webui_pi")
- `Origin`: Rule origin (e.g., "webui", "upnp")
- `Description`: Human-readable description (e.g., "pi", "HTTP")
- `Status`: Current status ("Enabled" or "Disabled")
- `Enable`: Whether rule is enabled (True/False)
- `SourceInterface`: Source interface (e.g., "data")
- `Protocol`: Protocol numbers (6=TCP, 17=UDP, comma-separated)
- `ExternalPort`: External port number (e.g., "1339", "8080")
- `InternalPort`: Internal port number
- `DestinationIPAddress`: Target internal IP address
- `DestinationMACAddress`: Target MAC address (if specified)
- `LeaseDuration`: Rule lease duration in seconds
- `HairpinNAT`: Whether hairpin NAT is enabled
- `SymmetricSNAT`: Whether symmetric SNAT is enabled
- `UPnPV1Compat`: Whether UPnP v1 compatibility is enabled

### get_all_port_forwarding()

Get all port forwarding rules from different origins.

**Returns:** Dictionary with keys for different origins containing their respective rules

### get_active_port_forwarding(origin="webui")

Get only enabled port forwarding rules.

**Parameters:**
- `origin` (str): Rule origin filter - `"webui"`, `"upnp"`, or other origin (default: "webui")

**Returns:** List of enabled port forwarding rule dictionaries

### format_protocol(protocol_str)

Helper method to format protocol numbers into readable names.

**Parameters:**
- `protocol_str` (str): Protocol string (e.g., "6,17" or "6")

**Returns:** `str` - Formatted protocol string (e.g., "TCP,UDP" or "TCP")

### get_ipv6_pinholes()

Get IPv6 pinhole (port forwarding) rules.

**Returns:** List of IPv6 pinhole rule dictionaries

**IPv6 Pinhole Rule Fields:**
- `Id`: Rule identifier (e.g., "webui_1")
- `Origin`: Rule origin (e.g., "webui", "upnp")
- `Description`: Human-readable description (e.g., "FTP")
- `Status`: Current status ("Enabled" or "Disabled")
- `Enable`: Whether rule is enabled (True/False)
- `SourceInterface`: Source interface (e.g., "data")
- `Protocol`: Protocol numbers (6=TCP, 17=UDP, comma-separated)
- `IPVersion`: IP version (6 for IPv6)
- `SourcePort`: Source port filter (if specified)
- `DestinationPort`: Destination port or port range (e.g., "20-21", "80")
- `SourcePrefix`: Source IP prefix filter (if specified)
- `DestinationIPAddress`: Target IPv6 address
- `DestinationMACAddress`: Target MAC address (if specified)

### get_active_ipv6_pinholes()

Get only enabled IPv6 pinhole rules.

**Returns:** List of enabled IPv6 pinhole rule dictionaries

### get_all_firewall_rules()

Get all firewall rules (both IPv4 port forwarding and IPv6 pinholes).

**Returns:** Dictionary with keys:
- `'port_forwarding'`: IPv4 port forwarding rules organized by origin
- `'ipv6_pinholes'`: IPv6 pinhole rules

### get_wan_status()

Get WAN connection status and information.

**Returns:** Dictionary with WAN connection information

**WAN Status Fields:**
- `LinkType`: Connection link type (e.g., "ethernet")
- `LinkState`: Physical link state (e.g., "up", "down")
- `MACAddress`: WAN interface MAC address
- `Protocol`: Connection protocol (e.g., "ppp")
- `ConnectionState`: Connection state (e.g., "Connected", "Disconnected")
- `LastConnectionError`: Last connection error (if any)
- `IPAddress`: Current public IPv4 address
- `RemoteGateway`: ISP gateway IP address
- `DNSServers`: DNS server addresses (comma-separated)
- `IPv6Address`: Current public IPv6 address
- `IPv6DelegatedPrefix`: IPv6 prefix delegated by ISP

### get_ppp_info()

Get detailed PPP connection information.

**Returns:** Dictionary with PPP connection details

**PPP Info Fields:**
- `Interface`: PPP interface name (e.g., "ppp_vdata")
- `Username`: PPP authentication username
- `Password`: PPP authentication password
- `ConnectionStatus`: Current connection status
- `LastConnectionError`: Last connection error code
- `MaxMRUSize`: Maximum Receive Unit size
- `PPPoESessionID`: PPPoE session identifier
- `PPPoEACName`: PPPoE Access Concentrator name
- `PPPoEServiceName`: PPPoE service name
- `RemoteIPAddress`: Remote PPP endpoint IP
- `LocalIPAddress`: Local PPP endpoint IP
- `LastChangeTime`: Time since last status change
- `LastChange`: Last change timestamp
- `DNSServers`: DNS servers from PPP negotiation
- `TransportType`: Transport protocol (e.g., "PPPoE")
- `LCPEcho`: LCP echo interval
- `LCPEchoRetry`: LCP echo retry count
- `IPCPEnable`: Whether IPCP is enabled
- `IPv6CPEnable`: Whether IPv6CP is enabled
- `IPv6CPLocalInterfaceIdentifier`: Local IPv6 interface ID
- `IPv6CPRemoteInterfaceIdentifier`: Remote IPv6 interface ID
- `ConnectionTrigger`: Connection trigger mode
- `IdleDisconnectTime`: Idle disconnect timeout

### get_connection_info()

Get comprehensive internet connection information (WAN + PPP).

**Returns:** Dictionary with keys:
- `'wan_status'`: WAN connection status
- `'ppp_info'`: Detailed PPP connection information

### is_connected()

Check if the internet connection is active.

**Returns:** `bool` - True if connected to the internet, False otherwise

### get_wwan_status()

Get WWAN (mobile internet backup) interface status and configuration.

**Returns:** Dictionary with WWAN interface information

**WWAN Status Fields:**
- `Name`: Interface name ("wwan")
- `Enable`: Whether WWAN interface is enabled
- `Status`: Current status (True/False)
- `Flags`: Interface flags
- `Alias`: Interface alias (e.g., "cpe-wwan")
- `APN`: Access Point Name (e.g., "basicinternet")
- `PINCode`: SIM PIN code (if configured)
- `Username`: Authentication username
- `Password`: Authentication password
- `AuthenticationMethod`: Auth method (e.g., "chap")
- `DNSServers`: DNS servers for mobile connection
- `IPRouter`: Gateway IP address
- `LocalIPAddress`: Assigned local IP address
- `ConnectionStatus`: Connection status (e.g., "NotPresent", "Connected")
- `ConnectionError`: Last connection error
- `ConnectionErrorSource`: Source of connection error
- `AutoConnection`: Whether auto-connection is enabled
- `SignalStrength`: Signal strength (0-100)
- `Technology`: Mobile technology (e.g., "4G", "5G", "none")
- `Manufacturer`: Modem manufacturer
- `Model`: Modem model
- `IMEI`: Device IMEI number
- `PinType`: PIN type required
- `PinRetryCount`: Remaining PIN retry attempts
- `PukRetryCount`: Remaining PUK retry attempts
- `IMSI`: SIM IMSI number
- `ICCID`: SIM card identifier
- `MSISDN`: Mobile number
- `LastChange`: Last change timestamp
- `LastChangeTime`: Last change time
- `TechnologyPreference`: Preferred technology
- `NATEnabled`: Whether NAT is enabled
- `MTU`: Maximum Transmission Unit
- `IPv4Forwarding`: Whether IPv4 forwarding is enabled
- `IPv6Disable`: Whether IPv6 is disabled
- And other network interface settings

### get_lan_ipv4_config()

Get LAN IPv4 network configuration.

**Returns:** Dictionary with LAN IPv4 configuration

**LAN IPv4 Config Fields:**
- `Address`: LAN IPv4 address (e.g., "192.168.2.254")
- `PrefixLength`: Network prefix length (e.g., 24)
- `DHCPEnable`: Whether DHCP server is enabled
- `DHCPAuthoritative`: Whether DHCP server is authoritative
- `DHCPMinAddress`: DHCP range start address
- `DHCPMaxAddress`: DHCP range end address
- `LeaseTime`: DHCP lease time in seconds
- `DNSServers`: DNS server addresses (comma-separated)
- `NTPServers`: NTP server addresses (comma-separated)
- `DomainSearchList`: Domain search list
- `Enable`: Whether IPv4 is enabled
- `AllowPublic`: Whether public access is allowed
- `NATEnable`: Whether NAT is enabled

### get_lan_ipv6_config()

Get LAN IPv6 network configuration.

**Returns:** Dictionary with LAN IPv6 configuration

**LAN IPv6 Config Fields:**
- `Address`: LAN IPv6 address
- `PrefixLength`: Network prefix length
- `Intf`: Interface name (e.g., "data")
- `SubnetOffset`: Subnet offset value
- `DHCPEnable`: Whether DHCPv6 server is enabled
- `DHCPIAPDEnable`: Whether DHCPv6 Identity Association for Prefix Delegation is enabled
- `DHCPIANAEnable`: Whether DHCPv6 Identity Association for Non-temporary Addresses is enabled
- `DNSServers`: IPv6 DNS server addresses (comma-separated)
- `NTPServers`: IPv6 NTP server addresses (comma-separated)
- `Enable`: Whether IPv6 is enabled

### get_lan_config()

Get comprehensive LAN network configuration (both IPv4 and IPv6).

**Returns:** Dictionary with keys:
- `'ipv4'`: LAN IPv4 configuration
- `'ipv6'`: LAN IPv6 configuration

### get_dns_servers()

Get DNS server configuration for both IPv4 and IPv6.

**Returns:** Dictionary with keys:
- `'ipv4'`: IPv4 DNS servers (comma-separated)
- `'ipv6'`: IPv6 DNS servers (comma-separated)

### set_ipv6_enabled(enabled=True, prefix_mode="DHCPv6")

Enable or disable IPv6 globally on the router.

**Parameters:**
- `enabled` (bool): Whether to enable IPv6 (default: True)
- `prefix_mode` (str): IPv6 prefix mode when enabling - "DHCPv6" or "RA" (default: "DHCPv6")

**Returns:** `bool` - True if successful

### set_ipv6_prefix_delegation(mode="off")

Configure IPv6 prefix delegation settings.

**Parameters:**
- `mode` (str): IPv6 prefix delegation mode - "off", "on", or "on_with_dhcpv6" (default: "off")

**Returns:** `bool` - True if all configuration calls were successful

**IPv6 Prefix Delegation Modes:**
- `"off"`: Disable prefix delegation, use DHCPv6 mode for single address
- `"on"`: Enable prefix delegation with RA (Router Advertisement) mode
- `"on_with_dhcpv6"`: Enable prefix delegation with RA + DHCPv6 mode

**Note:** This function makes multiple API calls (2-4 depending on mode) to configure both LAN and guest network prefix delegation.

### disable_ipv6_prefix_delegation()

Disable IPv6 prefix delegation.

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_ipv6_prefix_delegation("off")`.

### enable_ipv6_prefix_delegation(use_dhcpv6=False)

Enable IPv6 prefix delegation.

**Parameters:**
- `use_dhcpv6` (bool): Whether to enable with DHCPv6 mode (True) or RA mode (False, default)

**Returns:** `bool` - True if successful

**Note:** 
- When `use_dhcpv6=False`: Uses RA (Router Advertisement) mode only
- When `use_dhcpv6=True`: Uses RA + DHCPv6 combined mode

### configure_ipv6_prefix_delegation(enabled=True, use_dhcpv6=False, prefix_length=56)

Comprehensive IPv6 prefix delegation configuration.

**Parameters:**
- `enabled` (bool): Whether to enable prefix delegation (default: True)
- `use_dhcpv6` (bool): Whether to enable DHCPv6 mode when enabling (default: False = RA mode)
- `prefix_length` (int): Prefix length for delegation (default: 56)

**Returns:** `bool` - True if successful

**Note:** This is the most comprehensive method that combines all prefix delegation options into a single call.

### set_lan_ipv4_config(network="lan", dns_servers=None, address=None, dhcp_enabled=None, dhcp_min_address=None, dhcp_max_address=None, prefix_length=None)

Configure LAN IPv4 settings including DNS servers and DHCP.

**Parameters:**
- `network` (str): Network to configure - "lan" (default) or "guest"
- `dns_servers` (str): DNS servers (comma-separated, e.g., "9.9.9.9,149.112.112.112")
- `address` (str): LAN gateway IP address (e.g., "192.168.2.254")
- `dhcp_enabled` (bool): Whether to enable DHCP server
- `dhcp_min_address` (str): DHCP range start (e.g., "192.168.2.100")
- `dhcp_max_address` (str): DHCP range end (e.g., "192.168.2.200")
- `prefix_length` (int): Network prefix length (e.g., 24 for /24)

**Returns:** `bool` - True if successful

### set_lan_ipv6_config(network="lan", dns_servers=None)

Configure LAN IPv6 DNS servers.

**Parameters:**
- `network` (str): Network to configure - "lan" (default) or "guest"
- `dns_servers` (str): IPv6 DNS servers (comma-separated, e.g., "2620:fe::fe,2620:fe::9")

**Returns:** `bool` - True if successful

### set_dns_servers(ipv4_dns=None, ipv6_dns=None, network="lan")

Set DNS servers for both IPv4 and IPv6 on specified network.

**Parameters:**
- `ipv4_dns` (str): IPv4 DNS servers (comma-separated, e.g., "9.9.9.9,149.112.112.112")
- `ipv6_dns` (str): IPv6 DNS servers (comma-separated, e.g., "2620:fe::fe,2620:fe::9")
- `network` (str): Network to configure - "lan" (default) or "guest"

**Returns:** Dictionary with 'ipv4' and 'ipv6' keys indicating success for each

### get_netmaster_config()

Get NetMaster network configuration settings.

**Returns:** Dictionary with network master configuration

**NetMaster Config Fields:**
- `EnableInterfaces`: Whether interfaces are enabled
- `EnableIPv6`: Whether IPv6 is globally enabled
- `IPv6PrefixMode`: IPv6 prefix mode (e.g., "RA" for Router Advertisement)
- `DisablePhysicalInterfaces`: Whether physical interfaces are disabled
- `WANMode`: WAN connection mode (e.g., "Ethernet_PPP")

### get_dhcpv6_client_status()

Get DHCPv6 client status (router acting as DHCPv6 client to ISP).

**Returns:** Dictionary with DHCPv6 client information

**DHCPv6 Client Status Fields:**
- `Name`: Interface name (e.g., "dhcpv6_pdata")
- `Enable`: Whether DHCPv6 client is enabled
- `Status`: Current status (True/False)
- `Flags`: Status flags (e.g., "dhcpv6 enabled up")
- `Alias`: Interface alias
- `DHCPStatus`: DHCP status (e.g., "Bound", "Requesting")
- `LastConnectionError`: Last connection error (e.g., "RenewTimeout")
- `Uptime`: Client uptime in seconds
- `DSCPMark`: DSCP marking value
- `DUID`: DHCP Unique Identifier
- `RequestAddresses`: Whether requesting individual addresses
- `RequestPrefixes`: Whether requesting prefix delegation
- `RapidCommit`: Whether using rapid commit
- `IAID`: Identity Association Identifier
- `SuggestedT1`: Suggested renewal time (-1 = not set)
- `SuggestedT2`: Suggested rebind time (-1 = not set)
- `SupportedOptions`: Supported DHCP options
- `RequestedOptions`: Requested DHCP options (comma-separated)
- `Reason`: Status reason
- `Renew`: Whether currently renewing
- `ResetOnPhysDownTimeout`: Reset timeout on physical down
- `CheckAuthentication`: Whether checking authentication
- `AuthenticationInfo`: Authentication information
- `RetryOnFailedAuth`: Whether retrying on failed authentication

### get_firewall_level()

Get the current firewall security level.

**Returns:** `str` - Firewall level (e.g., "Low", "Medium", "High")

### get_ping_response_settings(source_interface="data")

Get ping response settings for a specific interface.

**Parameters:**
- `source_interface` (str): Source interface to check (default: "data")

**Returns:** Dictionary with ping response settings

**Ping Response Settings Fields:**
- `enableIPv4`: Whether responding to IPv4 pings is enabled
- `enableIPv6`: Whether responding to IPv6 pings is enabled

### get_firewall_config()

Get comprehensive firewall configuration.

**Returns:** Dictionary with firewall configuration

**Firewall Config Fields:**
- `Status`: Firewall status ("Enabled" or "Disabled")
- `AdvancedLevel`: Advanced firewall level for IPv4
- `AdvancedIPv6Level`: Advanced firewall level for IPv6
- `ExcludedOriginsPCP`: Excluded origins for PCP
- `UpnpPortForwardingStatus`: Current UPnP port forwarding status
- `UpnpPortForwardingEnable`: Whether UPnP port forwarding is enabled
- `ChainNumberOfEntries`: Number of firewall chain entries
- `ProtocolForwardingNumberOfEntries`: Number of protocol forwarding entries
- `PinholeNumberOfEntries`: Number of pinhole entries
- `ListNumberOfEntries`: Number of list entries

### get_dmz_config()

Get DMZ (Demilitarized Zone) configuration.

**Returns:** Dictionary with DMZ configuration

**DMZ Config Fields:**
- `Origin`: Configuration origin (e.g., "webui")
- `SourceInterface`: Source interface (e.g., "data")
- `DestinationIPAddress`: IP address of DMZ host
- `SourcePrefix`: Source prefix filter
- `Status`: DMZ status ("Enabled" or "Disabled")
- `Enable`: Whether DMZ is enabled

### set_upnp_enabled(enabled=True)

Enable or disable UPnP port forwarding.

**Parameters:**
- `enabled` (bool): Whether to enable UPnP port forwarding (default: True)

**Returns:** `bool` - True if successful

**Note:**
When enabled, devices on the network can automatically open ports through UPnP protocol. This can be convenient but may reduce security.

### set_dmz_host(destination_ip, enabled=True, dmz_id="webui", source_interface="data")

Set up a DMZ (Demilitarized Zone) host.

**Parameters:**
- `destination_ip` (str): IP address of the DMZ host (e.g., "192.168.2.108")
- `enabled` (bool): Whether to enable the DMZ (default: True)
- `dmz_id` (str): DMZ configuration ID (default: "webui")
- `source_interface` (str): Source interface (default: "data")

**Returns:** `str` - DMZ ID if successful, empty string if failed

**Note:**
DMZ forwards all incoming traffic to the specified host. This effectively puts the host outside the firewall protection. Only one DMZ host can be active at a time.

### delete_dmz_host(dmz_id="webui")

Delete DMZ host configuration.

**Parameters:**
- `dmz_id` (str): DMZ configuration ID to delete (default: "webui")

**Returns:** `bool` - True if successful

### set_ping_response(source_interface="data", enable_ipv4=True, enable_ipv6=True)

Configure ping response settings for router.

**Parameters:**
- `source_interface` (str): Source interface to configure (default: "data")
- `enable_ipv4` (bool): Whether to respond to IPv4 pings (default: True)
- `enable_ipv6` (bool): Whether to respond to IPv6 pings (default: True)

**Returns:** `bool` - True if successful

**Note:** When disabled, the router will not respond to ping requests from the internet, improving security but making connectivity testing harder.

### enable_ping_response(ipv4=True, ipv6=True)

Enable ping response for IPv4 and/or IPv6.

**Parameters:**
- `ipv4` (bool): Enable IPv4 ping response (default: True)
- `ipv6` (bool): Enable IPv6 ping response (default: True)

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_ping_response(enable_ipv4=ipv4, enable_ipv6=ipv6)`.

### disable_ping_response()

Disable ping response for both IPv4 and IPv6.

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_ping_response(enable_ipv4=False, enable_ipv6=False)`.

### set_firewall_level(level="Medium", ipv6_level=None)

Set firewall security level for IPv4 and optionally IPv6.

**Parameters:**
- `level` (str): Firewall level - "Low", "Medium", "High", or "Custom" (default: "Medium")
- `ipv6_level` (str): IPv6 firewall level - if None, uses same as IPv4 level (default: None)

**Returns:** Dictionary with 'ipv4' and 'ipv6' keys indicating success for each

**Firewall Levels:**
- `Low`: Minimal protection, allows most traffic
- `Medium`: Balanced protection and functionality
- `High`: Maximum protection, blocks more traffic
- `Custom`: Allows custom firewall rules (required for custom rule methods)

### set_firewall_level_ipv4(level="Medium")

Set IPv4 firewall security level.

**Parameters:**
- `level` (str): Firewall level - "Low", "Medium", "High", or "Custom" (default: "Medium")

**Returns:** `bool` - True if successful

### set_firewall_level_ipv6(level="Medium")

Set IPv6 firewall security level.

**Parameters:**
- `level` (str): Firewall level - "Low", "Medium", "High", or "Custom" (default: "Medium")

**Returns:** `bool` - True if successful

### enable_custom_firewall()

Enable custom firewall mode for both IPv4 and IPv6.

**Returns:** Dictionary with 'ipv4' and 'ipv6' keys indicating success for each

**Note:** This is required before using custom firewall rule methods. Sets both IPv4 and IPv6 firewall levels to "Custom".

### get_custom_firewall_rules()

Get all custom firewall rules.

**Returns:** List of custom firewall rule dictionaries

**Custom Rule Fields:**
- `Id`: Rule identifier (e.g., "ssh", "http", "myshit")
- `Target`: Rule action ("Accept" or "Drop")
- `Status`: Rule status ("Enabled" or "Disabled")
- `Class`: Rule class (e.g., "Forward")
- `IPVersion`: IP version (4 or 6)
- `Protocol`: Protocol number (6=TCP, 17=UDP, comma-separated)
- `DestinationPort`: Destination port or port range (e.g., "22", "6660-6669")
- `SourcePort`: Source port filter
- `DestinationPrefix`: Destination IP prefix filter
- `SourcePrefix`: Source IP prefix filter
- `DestinationMACAddress`: Destination MAC address filter
- `SourceMACAddress`: Source MAC address filter
- `TargetChain`: Target firewall chain
- `Description`: Rule description
- `Enable`: Whether rule is enabled

**Note:** This method requires Custom firewall level to be enabled.

### add_custom_firewall_rule(rule_id, action="Accept", protocol="6", destination_port="", source_port="", destination_prefix="", source_prefix="", ip_version=4, chain=None, enabled=True)

Add or update a custom firewall rule.

**Parameters:**
- `rule_id` (str): Unique identifier for the rule (e.g., "ssh", "myapp")
- `action` (str): Rule action - "Accept" or "Drop" (default: "Accept")
- `protocol` (str): Protocol number - "6" (TCP), "17" (UDP), or "6,17" (default: "6")
- `destination_port` (str): Destination port or range (e.g., "22", "8080", "6660-6669")
- `source_port` (str): Source port filter (default: "")
- `destination_prefix` (str): Destination IP address/prefix (e.g., "192.168.2.100")
- `source_prefix` (str): Source IP address/prefix filter (default: "")
- `ip_version` (int): IP version - 4 or 6 (default: 4)
- `chain` (str): Firewall chain - auto-determined if None (default: None)
- `enabled` (bool): Whether to enable the rule (default: True)

**Returns:** `str` - Rule ID if successful, empty string if failed

**Notes:**
- Requires Custom firewall level to be enabled
- Chain is auto-determined: "Custom" for IPv4, "Custom_V6Out" for IPv6
- Protocol numbers: 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6
- Port ranges: "80", "80-90", "80,443,8080"

### delete_custom_firewall_rule(rule_id, ip_version=4, chain=None)

Delete a custom firewall rule.

**Parameters:**
- `rule_id` (str): Rule identifier to delete
- `ip_version` (int): IP version of the rule - 4 or 6 (default: 4)
- `chain` (str): Firewall chain - auto-determined if None (default: None)

**Returns:** `bool` - True if successful

**Note:** Chain is auto-determined: "Custom" for IPv4, "Custom_V6Out" for IPv6

### update_custom_firewall_rule(rule_id, **kwargs)

Update an existing custom firewall rule.

**Parameters:**
- `rule_id` (str): Rule identifier to update
- `**kwargs`: Rule parameters to update (same as add_custom_firewall_rule)

**Returns:** `str` - Rule ID if successful, empty string if failed

**Note:** This is equivalent to calling add_custom_firewall_rule with the same rule_id. Only specified parameters will be updated.

### manage_custom_firewall_rule(action, rule_id, **kwargs)

Manage custom firewall rules with a unified interface.

**Parameters:**
- `action` (str): Action to perform - "add", "update", "delete", "enable", "disable"
- `rule_id` (str): Rule identifier
- `**kwargs`: Rule parameters (for add/update actions)

**Returns:** 
- For add/update: Rule ID if successful, empty string if failed
- For delete/enable/disable: True if successful, False if failed

### get_dhcp_static_leases(pool_id="default")

Get DHCP static lease reservations for a specific pool.

**Parameters:**
- `pool_id` (str): DHCP pool ID - `"default"` or `"guest"` (default: "default")

**Returns:** List of static lease dictionaries

**Static Lease Fields:**
- `PoolID`: DHCP pool identifier ("default" or "guest")
- `IPAddress`: Reserved IP address
- `MACAddress`: Device MAC address
- `LeasePath`: Internal lease path identifier

### get_default_dhcp_static_leases()

Get DHCP static lease reservations for the default network.

**Returns:** List of static lease dictionaries for default network

### get_guest_dhcp_static_leases()

Get DHCP static lease reservations for the guest network.

**Returns:** List of static lease dictionaries for guest network

### get_all_dhcp_static_leases()

Get static DHCP leases (IP reservations) for all pools.

**Returns:** Dictionary with keys:
- `'default'`: List of default network static leases
- `'guest'`: List of guest network static leases

### add_static_lease(mac_address, ip_address, pool_id="default")

Add a static DHCP lease (IP reservation) for a device.

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "50:DE:06:9A:A6:98")
- `ip_address` (str): IP address to reserve (e.g., "192.168.2.118")
- `pool_id` (str): DHCP pool ID ("default" for home network, "guest" for guest network)

**Returns:** `bool` - True if static lease was successfully added

**Note:** This ensures a device with the specified MAC address will always receive the same IP address from the DHCP server.

### delete_static_lease(mac_address, pool_id="default")

Delete a static DHCP lease (IP reservation) for a device.

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "50:DE:06:9A:A6:98")
- `pool_id` (str): DHCP pool ID ("default" for home network, "guest" for guest network)

**Returns:** `bool` - True if static lease was successfully deleted

**Note:** This removes the IP reservation, allowing the device to receive any available IP address from the DHCP pool.

### set_static_lease(mac_address, ip_address, pool_id="default")

Set/update a static DHCP lease (IP reservation) for a device.

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "00:17:88:4A:40:B4")
- `ip_address` (str): IP address to reserve (e.g., "192.168.2.124")
- `pool_id` (str): DHCP pool ID ("default" for home network, "guest" for guest network)

**Returns:** `bool` - True if static lease was successfully set/updated

**Note:** This modifies an existing IP reservation or creates a new one if it doesn't exist.

### manage_device_ip_reservation(mac_address, ip_address=None, action="add", pool_id="default")

Comprehensive IP reservation management for a device.

**Parameters:**
- `mac_address` (str): MAC address of the device
- `ip_address` (str): IP address to reserve (required for add/set actions)
- `action` (str): Action to perform ("add", "delete", "set", "update")
- `pool_id` (str): DHCP pool ID ("default" or "guest")

**Returns:** `bool` - True if action was successful

### reserve_device_ip(device_identifier, ip_address, pool_id="default", auto_detect_mac=True)

Reserve an IP address for a device (with smart device detection).

**Parameters:**
- `device_identifier` (str): MAC address or device name
- `ip_address` (str): IP address to reserve
- `pool_id` (str): DHCP pool ID ("default" or "guest")
- `auto_detect_mac` (bool): If True, try to find MAC address from device name

**Returns:** `bool` - True if reservation was successful

### get_device_ip_reservation(mac_address, pool_id="default")

Get IP reservation information for a specific device.

**Parameters:**
- `mac_address` (str): MAC address of the device
- `pool_id` (str): DHCP pool ID ("default" or "guest")

**Returns:** Dictionary with reservation information or empty dict if not found

### list_ip_reservations(pool_id="default", include_device_info=True)

List all IP reservations with enhanced device information.

**Parameters:**
- `pool_id` (str): DHCP pool ID ("default" or "guest")
- `include_device_info` (bool): Include device names and types from device list

**Returns:** List of IP reservations with device information

**Enhanced Fields (when include_device_info=True):**
- `device_name`: Device name from device list
- `device_type`: Device type from device list
- `active`: Whether device is currently connected
- `last_seen`: Last connection timestamp

### suggest_available_ips(pool_id="default", count=5)

Suggest available IP addresses for new reservations.

**Parameters:**
- `pool_id` (str): DHCP pool ID ("default" or "guest")
- `count` (int): Number of IP suggestions to return

**Returns:** List of suggested available IP addresses

### cleanup_invalid_reservations(pool_id="default")

Clean up invalid or conflicting IP reservations.

**Parameters:**
- `pool_id` (str): DHCP pool ID ("default" or "guest")

**Returns:** Dictionary with cleanup results

**Cleanup Result Fields:**
- `invalid_range`: List of reservations with IPs outside DHCP range
- `duplicate_ips`: Dictionary of duplicate IP assignments
- `total_issues`: Total number of issues found
- `recommendations`: List of recommended actions

### get_device_schedules(schedule_type="ToD")

Get device access schedules (Time of Day restrictions).

**Parameters:**
- `schedule_type` (str): Type of schedule to retrieve (default: "ToD")

**Returns:** List of device schedule dictionaries

**Device Schedule Fields:**
- `ID`: Device identifier (usually MAC address)
- `name`: Device name
- `enable`: Whether scheduling is enabled for this device
- `base`: Schedule base type (e.g., "Weekly")
- `def`: Default state ("Enable" or "Disable")
- `stateMode`: Current state mode ("Default", "Override")
- `override`: Override setting ("Enable", "Disable", or "")
- `temporaryOverride`: Whether temporary override is active
- `value`: Current effective value ("Enable" or "Disable")
- `schedule`: List of schedule rules
- `device`: Device location ("LOCAL")
- `target`: List of target devices

### get_hgw_device_info()

Get detailed Home Gateway (HGW) device information.

**Returns:** Dictionary with comprehensive HGW device information

**HGW Device Info Fields:**
- `Key`: Device key (MAC address)
- `DiscoverySource`: How device was discovered (e.g., "selfhgw")
- `Name`: Device name
- `DeviceType`: Device type ("SAH HGW")
- `Active`: Whether device is active
- `Tags`: Device tags (space-separated)
- `FirstSeen`: First discovery timestamp
- `LastConnection`: Last connection timestamp
- `LastChanged`: Last change timestamp
- `Master`: Master device identifier
- `Manufacturer`: Device manufacturer (e.g., "Arcadyan")
- `ModelName`: Device model (e.g., "BoxV14")
- `Description`: Device description
- `SerialNumber`: Device serial number
- `ProductClass`: Product class
- `HardwareVersion`: Hardware version
- `SoftwareVersion`: Software/firmware version
- `BootLoaderVersion`: Bootloader version
- `FirewallLevel`: Current firewall level
- `LinkType`: Link type (e.g., "ethernet")
- `LinkState`: Link state (e.g., "up", "down")
- `ConnectionProtocol`: Connection protocol (e.g., "ppp")
- `ConnectionState`: Connection state (e.g., "Connected")
- `LastConnectionError`: Last connection error
- `ConnectionIPv4Address`: Current public IPv4 address
- `ConnectionIPv6Address`: Current public IPv6 address
- `RemoteGateway`: ISP gateway address
- `DNSServers`: DNS servers (comma-separated)
- `Internet`: Whether internet is available
- `IPTV`: Whether IPTV service is available
- `Telephony`: Whether telephony service is available
- `IPAddress`: Local IP address
- `IPAddressSource`: IP address source (e.g., "Static")
- `Index`: Device index
- `Actions`: Available device actions
- `IPv6Address`: List of IPv6 addresses with details
- `Names`: List of device names from different sources
- `DeviceTypes`: List of device types from different sources

### get_router_time()

Get the current time from the router.

**Returns:** `str` - Current time (e.g., "Wed, 04 Jun 2025 19:50:34 GMT+0200")

### get_ntp_servers()

Get configured NTP (Network Time Protocol) servers.

**Returns:** Dictionary with NTP servers where keys are server numbers and values are server addresses

### get_ntp_servers_list()

Get configured NTP servers as a list.

**Returns:** List of NTP server addresses

### set_ntp_servers(servers)

Configure NTP (Network Time Protocol) servers.

**Parameters:**
- `servers` (dict): Dictionary mapping server numbers to server addresses
  Example: {
    "1": "time.kpn.net",
    "2": "0.nl.pool.ntp.org", 
    "3": "1.nl.pool.ntp.org",
    "4": "2.nl.pool.ntp.org",
    "5": "3.nl.pool.ntp.org"
  }

**Returns:** `bool` - True if successful

**Note:**
- Server numbers should be strings ("1", "2", etc.)
- You can configure up to 5 NTP servers
- Common NTP servers: time.kpn.net, pool.ntp.org servers

### get_time_config()

Get comprehensive time configuration including current time and NTP servers.

**Returns:** Dictionary with keys:
- `'current_time'`: Current router time
- `'ntp_servers'`: Dictionary of NTP servers
- `'ntp_servers_list'`: List of NTP server addresses

### run_download_speedtest()

Run a download speed test using KPN's speed test service.

**Note:** This test takes several seconds to complete and will consume bandwidth.

**Returns:** Dictionary with download speed test results

**Download Speedtest Fields:**
- `RetrievedStartTS`: Test start timestamp (ISO format)
- `RetrievedTS`: Test end timestamp (ISO format)
- `testserver`: Speed test server used (e.g., "speedtests.kpn.com")
- `interface`: Network interface used (e.g., "data")
- `latency`: Network latency in milliseconds
- `suite`: Test suite used (e.g., "BCMSpeedSvc")
- `duration`: Test duration in milliseconds
- `rxbytes`: Total bytes received during test
- `throughput`: Download throughput in kilobits per second

### run_upload_speedtest()

Run an upload speed test using KPN's speed test service.

**Note:** This test takes several seconds to complete and will consume bandwidth.

**Returns:** Dictionary with upload speed test results

**Upload Speedtest Fields:**
- `RetrievedStartTS`: Test start timestamp (ISO format)
- `RetrievedTS`: Test end timestamp (ISO format)
- `testserver`: Speed test server used (e.g., "speedtests.kpn.com")
- `interface`: Network interface used (e.g., "data")
- `latency`: Network latency in milliseconds
- `suite`: Test suite used (e.g., "BCMSpeedSvc")
- `duration`: Test duration in milliseconds
- `rxbytes`: Total bytes sent during test
- `throughput`: Upload throughput in kilobits per second

### run_full_speedtest()

Run both download and upload speed tests sequentially.

**Note:** This test takes 10+ seconds to complete and will consume significant bandwidth.

**Returns:** Dictionary with keys:
- `'download'`: Download speed test results
- `'upload'`: Upload speed test results

### format_speed(kilobits_per_second)

Helper method to format speed in human-readable format.

**Parameters:**
- `kilobits_per_second` (int): Speed in kilobits per second (as returned by KPN Box API)

**Returns:** `str` - Formatted speed string (e.g., "100.5 Mbps", "1.2 Gbps")

### run_traceroute(host, ip_version="IPv4")

Run a traceroute diagnostic to a target host.

**Parameters:**
- `host` (str): Target hostname or IP address (e.g., "www.google.com", "8.8.8.8")
- `ip_version` (str): IP version to use - "IPv4", "IPv6", or "Any" (default: "IPv4")

**Returns:** Dictionary with traceroute results

**Traceroute Result Fields:**
- `DiagnosticState`: Test state ("Complete", "Error", "InProgress")
- `Interface`: Network interface used
- `ProtocolVersion`: IP version used ("IPv4" or "IPv6")
- `Host`: Target hostname or IP
- `NumberOfTries`: Number of attempts per hop (default: 3)
- `Timeout`: Timeout per hop in milliseconds (default: 5000)
- `DataBlockSize`: Packet size in bytes
- `DSCP`: DSCP marking value
- `MaxHopCount`: Maximum number of hops (default: 30)
- `IPAddressUsed`: Resolved IP address of target
- `ResponseTime`: Total test duration in milliseconds
- `RouteHopsNumberOfEntries`: Number of hops in route
- `RouteHops`: Dictionary of hop information with hop number as key and values:
  - `Host`: Reverse DNS hostname (may be empty)
  - `HostAddress`: IP address of hop router
  - `ErrorCode`: Error code (0=success, 11=TTL exceeded, 4294967295=no response)
  - `RTTimes`: Round-trip times in milliseconds (comma-separated, e.g., "18,2,2")

### run_ping(host, protocol_version="Any")

Run a ping diagnostic to a target host.

**Parameters:**
- `host` (str): Target hostname or IP address (e.g., "www.google.com", "8.8.8.8")
- `protocol_version` (str): Protocol version - "Any", "IPv4", or "IPv6" (default: "Any")

**Returns:** Dictionary with ping results

**Ping Result Fields:**
- `DiagnosticsState`: Test state ("Success", "Error", "InProgress")
- `ipHost`: Resolved IP address of target
- `packetsSuccess`: Number of successful ping packets
- `packetsFailed`: Number of failed ping packets
- `packetSize`: Size of ping packets in bytes
- `averageResponseTime`: Average response time in milliseconds
- `minimumResponseTime`: Minimum response time in milliseconds
- `maximumResponseTime`: Maximum response time in milliseconds

### set_interface_duplex(interface="eth4", duplex_mode="Auto")

Set network interface duplex mode.

**Parameters:**
- `interface` (str): Interface name (default: "eth4" for WAN)
- `duplex_mode` (str): Duplex mode - "Auto", "Half", or "Full" (default: "Auto")

**Returns:** `bool` - True if successful

### set_interface_speed(interface="eth4", max_speed=-1)

Set network interface maximum link speed.

**Parameters:**
- `interface` (str): Interface name (default: "eth4" for WAN)
- `max_speed` (int): Maximum speed in Mbps, or -1 for Auto (default: -1)

**Returns:** `bool` - True if successful

### get_iptv_ip()

Get the IP address of the IPTV interface.

**Returns:** `str` - IPTV interface IP address (e.g., "10.233.241.178")

### get_voice_profiles()

Get voice service profiles configuration.

**Returns:** Dictionary with voice profiles

**Voice Profile Fields:**
- `SIP-Trunk1`, `SIP-Trunk2`, `SIP-Trunk3`, `SIP-Trunk4`: SIP trunk profiles
- `ATA`: Analog Telephone Adapter profile with Name field
- `SIP-Extensions`: SIP extensions profile with Name field

### get_voice_trunks()

Get SIP trunk configurations for telephone service.

**Returns:** List of SIP trunk dictionaries

**Voice Trunk Fields:**
- `name`: Trunk name (e.g., "SIP-Trunk1")
- `trunkName`: Trunk identifier
- `signalingProtocol`: Protocol used ("SIP")
- `enable`: Whether trunk is enabled ("Enabled"/"Disabled")
- `dtmfMethod`: DTMF method (e.g., "RFC2833")
- `trunk_lines`: List of trunk lines with details:
  - `name`: Line name (e.g., "LINE11")
  - `enable`: Line enable status
  - `status`: Line status
  - `directoryNumber`: Phone number
  - `uri`: SIP URI
  - `authUserName`: Authentication username
  - `friendlyName`: Display name
- `sip`: SIP configuration:
  - `proxyServer`: SIP proxy server
  - `proxyServerPort`: Proxy port (default: 5060)
  - `registrarServer`: SIP registrar server
  - `userAgentDomain`: User agent domain
  - `sessionExpire`: Session expiration time
- `rtp`: RTP configuration:
  - `localPortMin`: Minimum local port
  - `localPortMax`: Maximum local port

### get_voice_groups()

Get voice groups configuration.

**Returns:** List of voice group dictionaries

**Voice Group Fields:**
- `group_id`: Group identifier (e.g., "Group1")
- `ep_names`: List of endpoint names in the group

### get_voice_handsets()

Get voice handsets/endpoints configuration.

**Returns:** List of handset dictionaries

**Voice Handset Fields:**
- `line`: Line identifier (e.g., "FXS1", "Account1")
- `name`: Handset name
- `enable`: Whether handset is enabled ("Enabled"/"Disabled")
- `status`: Current status ("Up"/"Down"/"Disabled")
- `directoryNumber`: Phone number or extension
- `endpointType`: Type of endpoint ("FXS", "SIP")
- `dtmfMethod`: DTMF method ("Inherit" or specific)
- `outgoingTrunkLine`: Associated trunk line
- `outgoingSubscriberNumberId`: Subscriber number ID
- `callWaitingEnable`: Whether call waiting is enabled
- `sipExtensionIPAddress`: SIP extension IP (for SIP endpoints)
- `authUserName`: Authentication username (for SIP endpoints)

### ring_test_phone()

Ring the phone for testing purposes.

**Returns:** `bool` - True if ring test command was sent successfully

### enable_guest_network(enabled=True)

Enable or disable the guest WiFi network completely.

**Parameters:**
- `enabled` (bool): Whether to enable guest network (default: True)

**Returns:** `bool` - True if all operations successful

**Note:** This function makes 3 API calls to fully enable/disable guest networking.

### set_guest_wifi_config(ssid_2g=None, ssid_5g=None, password_2g=None, password_5g=None, security_mode_2g=None, security_mode_5g=None, mfp_config_2g="", mfp_config_5g="")

Configure guest WiFi network settings (SSID, password, security).

**Parameters:**
- `ssid_2g` (str): 2.4GHz guest network name/SSID
- `ssid_5g` (str): 5GHz guest network name/SSID
- `password_2g` (str): 2.4GHz guest network password
- `password_5g` (str): 5GHz guest network password
- `security_mode_2g` (str): 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
- `security_mode_5g` (str): 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
- `mfp_config_2g` (str): 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
- `mfp_config_5g` (str): 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")

**Returns:** `bool` - True if successful

**Note:** Uses the same underlying API as regular WiFi configuration but targets guest network VAPs.

### set_guest_wifi_visibility(visible_2g=None, visible_5g=None)

Enable or disable guest WiFi network visibility (SSID advertisement).

**Parameters:**
- `visible_2g` (bool): Whether 2.4GHz guest network should be visible (broadcast SSID)
- `visible_5g` (bool): Whether 5GHz guest network should be visible (broadcast SSID)

**Returns:** `bool` - True if successful

**Note:** Uses the same underlying API as regular WiFi visibility but targets guest network VAPs (vap2g0guest, vap5g0guest).

### set_guest_bandwidth_limit(limit_mbps=0)

Set bandwidth limitation for guest network.

**Parameters:**
- `limit_mbps` (int): Bandwidth limit in Mbps (0 = unlimited, max 50000 = 50 Gbps)

**Returns:** `bool` - True if successful

### enable_extra_wifi(enabled_2g=None, enabled_5g=None)

Enable or disable extra WiFi networks.

**Parameters:**
- `enabled_2g` (bool): Whether to enable 2.4GHz extra network
- `enabled_5g` (bool): Whether to enable 5GHz extra network

**Returns:** Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band

**Note:** Extra WiFi networks provide a third set of WiFi networks (beyond regular and guest).

### set_extra_wifi_config(ssid_2g=None, ssid_5g=None, password_2g=None, password_5g=None, security_mode_2g=None, security_mode_5g=None, mfp_config_2g="", mfp_config_5g="")

Configure extra WiFi network settings (SSID, password, security).

**Parameters:**
- `ssid_2g` (str): 2.4GHz extra network name/SSID
- `ssid_5g` (str): 5GHz extra network name/SSID
- `password_2g` (str): 2.4GHz extra network password
- `password_5g` (str): 5GHz extra network password
- `security_mode_2g` (str): 2.4GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
- `security_mode_5g` (str): 5GHz security mode (e.g., "WPA2-Personal", "WPA3-Personal")
- `mfp_config_2g` (str): 2.4GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")
- `mfp_config_5g` (str): 5GHz Management Frame Protection - "", "Optioneel", "Benodigd", "Uit" (default: "")

**Returns:** `bool` - True if successful

**Note:** Uses the same underlying API as regular WiFi configuration but targets extra network VAPs (vap2g0ext, vap5g0ext).

### set_extra_wifi_visibility(visible_2g=None, visible_5g=None)

Enable or disable extra WiFi network visibility (SSID advertisement).

**Parameters:**
- `visible_2g` (bool): Whether 2.4GHz extra network should be visible (broadcast SSID)
- `visible_5g` (bool): Whether 5GHz extra network should be visible (broadcast SSID)

**Returns:** `bool` - True if successful

**Note:** Uses the same underlying API as regular WiFi visibility but targets extra network VAPs (vap2g0ext, vap5g0ext).

### get_wifi_status()

Get overall WiFi status and configuration.

**Returns:** Dictionary with WiFi status including:
- `Enable`: Whether WiFi is globally enabled
- `Status`: Current WiFi status
- Various WiFi configuration fields

### set_wifi_enabled(enabled=True, sync_extenders=True)

Enable or disable WiFi radios completely.

**Parameters:**
- `enabled` (bool): Whether to enable WiFi (default: True)
- `sync_extenders` (bool): Whether to keep WiFi on extenders enabled (default: True)

**Returns:** `bool` - True if all operations successful

**Note:** This function makes 5-6 API calls to completely enable/disable WiFi radios and networks.

### set_wifi_radio_config(band_2g_config=None, band_5g_config=None)

Configure WiFi radio settings for 2.4GHz and/or 5GHz bands.

**Parameters:**
- `band_2g_config` (dict): 2.4GHz radio configuration dictionary with keys:
  - `AutoChannelEnable`: Whether to enable auto channel selection (bool)
  - `OperatingChannelBandwidth`: Channel bandwidth ("20MHz", "40MHz")
  - `OperatingStandards`: Supported standards (e.g., "g,n,ax")
- `band_5g_config` (dict): 5GHz radio configuration dictionary with keys:
  - `AutoChannelEnable`: Whether to enable auto channel selection (bool)
  - `OperatingChannelBandwidth`: Channel bandwidth ("20MHz", "40MHz", "80MHz", "160MHz")
  - `OperatingStandards`: Supported standards (e.g., "a,n,ac,ax")

**Returns:** Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band

### set_wifi_radio_defaults()

Set WiFi radio configuration to recommended defaults.

**Returns:** Dictionary with 'band_2g' and 'band_5g' keys indicating success for each band

**Note:** Sets auto channel, 20MHz for 2.4GHz, 80MHz for 5GHz, and modern standards.

### enable_wifi_schedule(network_id="wl0", enabled=True)

Enable or disable WiFi time scheduling.

**Parameters:**
- `network_id` (str): WiFi network identifier (default: "wl0")
- `enabled` (bool): Whether to enable scheduling (default: True)

**Returns:** `bool` - True if successful

### set_wifi_schedule(network_id="wl0", disable_blocks=None, enabled=True)

Set WiFi time schedule with specific disable periods.

**Parameters:**
- `network_id` (str): WiFi network identifier (default: "wl0")
- `disable_blocks` (list): List of time blocks when WiFi should be disabled. Each block is a dict with 'begin' and 'end' keys (seconds from Monday 00:00)
- `enabled` (bool): Whether the schedule should be enabled (default: True)

**Returns:** `bool` - True if successful

**Example:**
```python
# Disable WiFi from 10 PM to 6 AM on Monday
api.set_wifi_schedule(disable_blocks=[
    {"begin": 79200, "end": 108000}  # Monday 22:00 to Tuesday 06:00
])
```

### set_wifi_bedtime_schedule(network_id="wl0", bedtime_hour=22, wakeup_hour=6, weekdays_only=True)

Set a simple bedtime WiFi schedule (disable during night hours).

**Parameters:**
- `network_id` (str): WiFi network identifier (default: "wl0")
- `bedtime_hour` (int): Hour to disable WiFi (0-23, default: 22 = 10 PM)
- `wakeup_hour` (int): Hour to enable WiFi (0-23, default: 6 = 6 AM)
- `weekdays_only` (bool): Whether to apply only on weekdays (default: True)

**Returns:** `bool` - True if successful

### clear_wifi_schedule(network_id="wl0")

Clear WiFi schedule (remove all time restrictions).

**Parameters:**
- `network_id` (str): WiFi network identifier (default: "wl0")

**Returns:** `bool` - True if successful

### set_interface_speed(interface="eth4", max_speed=-1)

Set network interface maximum link speed.

**Parameters:**
- `interface` (str): Interface name (default: "eth4" for WAN)
- `max_speed` (int): Maximum speed in Mbps, or -1 for Auto (default: -1)

**Returns:** `bool` - True if successful

### set_port4_guest_network(enabled=True)

Enable or disable guest network on Ethernet port 4.

**Parameters:**
- `enabled` (bool): Whether to enable guest network on port 4 (default: True)
  - When `True`: Port 4 connects to guest network
  - When `False`: Port 4 connects to home LAN network

**Returns:** `bool` - True if both API calls were successful

**Note:** 
- Port 4 corresponds to ETH3 interface in the KPN Box
- This function makes 2 API calls to remove and add the interface to the appropriate bridge (lan or guest)
- Devices connected to port 4 will receive IP addresses from the selected network

### enable_port4_guest_network()

Enable guest network on Ethernet port 4.

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_port4_guest_network(True)`.

### disable_port4_guest_network()

Disable guest network on Ethernet port 4 (return to home LAN).

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_port4_guest_network(False)`.

### configure_ethernet_port(port=4, guest_network=False)

Configure Ethernet port network assignment.

**Parameters:**
- `port` (int): Ethernet port number (currently only port 4 is supported)
- `guest_network` (bool): Whether to assign port to guest network (default: False)

**Returns:** `bool` - True if successful

**Note:** Currently only port 4 (ETH3) configuration is supported.

### set_stp_enabled(enabled=True)

Enable or disable STP (Spanning Tree Protocol) on the bridge.

**Parameters:**
- `enabled` (bool): Whether to enable STP (default: True)

**Returns:** `bool` - True if successful

**Note:**
- STP helps prevent network loops in bridged networks
- Disabling STP can improve performance but may cause loops if multiple network paths exist

### enable_stp()

Enable STP (Spanning Tree Protocol).

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_stp_enabled(True)`.

### disable_stp()

Disable STP (Spanning Tree Protocol).

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_stp_enabled(False)`.

### get_wifi_mac_filter_status()

Get WiFi MAC filtering status and current whitelist.

**Returns:** Dictionary with MAC filtering status

**MAC Filter Status Fields:**
- `enabled`: Whether MAC filtering is enabled (True/False)
- `mode`: Current filtering mode ("WhiteList" or "Off")
- `allowed_devices`: List of MAC addresses on whitelist
- `count`: Number of devices on whitelist

**Note:** MAC filtering only affects home and extra WiFi networks. Guest networks and wired devices are not affected.

### set_wifi_mac_filtering(enabled=True, mac_addresses=None)

Enable or disable WiFi MAC filtering with optional device list.

**Parameters:**
- `enabled` (bool): Whether to enable MAC filtering (default: True)
- `mac_addresses` (list): List of MAC addresses to allow (default: None = keep current list)

**Returns:** `bool` - True if successful

**Note:**
- When enabled, only devices on the whitelist can connect to WiFi
- Affects home and extra networks only (not guest networks)
- Wired devices are always allowed regardless of this setting
- If mac_addresses is None, keeps current whitelist

### enable_wifi_mac_filtering(mac_addresses=None)

Enable WiFi MAC filtering with optional device list.

**Parameters:**
- `mac_addresses` (list): List of MAC addresses to allow (default: None = keep current list)

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_wifi_mac_filtering(True, mac_addresses)`.

### disable_wifi_mac_filtering()

Disable WiFi MAC filtering (allow all devices).

**Returns:** `bool` - True if successful

**Note:**
- Convenience method that calls `set_wifi_mac_filtering(False)`
- Keeps the current whitelist for when filtering is re-enabled

### get_wifi_mac_filter_list()

Get list of MAC addresses on WiFi whitelist.

**Returns:** List of MAC addresses currently on the whitelist

### add_wifi_mac_filter(mac_addresses)

Add MAC addresses to WiFi whitelist.

**Parameters:**
- `mac_addresses` (str or list): Single MAC address (str) or list of MAC addresses to add

**Returns:** `bool` - True if successful

**Note:**
- Automatically enables MAC filtering if not already enabled
- Avoids duplicates when adding addresses

### remove_wifi_mac_filter(mac_addresses)

Remove MAC addresses from WiFi whitelist.

**Parameters:**
- `mac_addresses` (str or list): Single MAC address (str) or list of MAC addresses to remove

**Returns:** `bool` - True if successful

**Note:** Keeps MAC filtering enabled even if list becomes empty.

### clear_wifi_mac_filter()

Clear all MAC addresses from WiFi whitelist.

**Returns:** `bool` - True if successful

**Note:** Keeps MAC filtering enabled but with empty whitelist (blocks all WiFi devices).

### set_wifi_mac_filter_list(mac_addresses, enabled=True)

Set complete WiFi MAC filter whitelist.

**Parameters:**
- `mac_addresses` (list): Complete list of MAC addresses to allow
- `enabled` (bool): Whether to enable MAC filtering (default: True)

**Returns:** `bool` - True if successful

**Note:** Replaces entire whitelist with provided list.

### add_connected_wifi_devices_to_filter()

Add all currently connected WiFi devices to MAC filter whitelist.

**Returns:** Dictionary with operation results

**Operation Result Fields:**
- `added_devices`: List of devices added to whitelist
- `already_allowed`: List of devices already on whitelist
- `total_devices`: Total number of WiFi devices found
- `success`: Whether operation was successful

**Note:**
- Only adds WiFi-connected devices (excludes wired devices)
- Automatically enables MAC filtering
- Useful for quickly allowing all current WiFi devices

### manage_wifi_mac_filter(action, mac_addresses=None, enabled=None)

Unified WiFi MAC filter management interface.

**Parameters:**
- `action` (str): Action to perform - "enable", "disable", "add", "remove", "clear", "set", "list", "status", "add_connected"
- `mac_addresses` (str or list): MAC addresses for add/remove/set actions
- `enabled` (bool): Enable state for "set" action

**Returns:**
- For enable/disable/add/remove/clear/set: `bool` - True if successful
- For list: List of MAC addresses
- For status: Dictionary with status information
- For add_connected: Dictionary with operation results

### get_device_mst_status(mac_address)

Get Managed Screen Time (MST) status for a specific device.

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "A8:A1:59:33:F1:E4")

**Returns:** Dictionary with MST status

**MST Status Fields:**
- `subject`: Device identifier (e.g., "MAC:A8:A1:59:33:F1:E4")
- `enable`: Whether MST is enabled for this device
- `status`: Current status ("Active" or other status)
- `allowedTime`: Dictionary with daily time limits in minutes per day (Mon, Tue, Wed, Thu, Fri, Sat, Sun)

**Returns:** Empty dict if no MST is configured for the device

### set_device_mst(mac_address, daily_limits=None, enabled=True)

Set Managed Screen Time (MST) daily limits for a specific device.

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
- `daily_limits` (dict): Dictionary with daily time limits in minutes per day. Keys: Mon, Tue, Wed, Thu, Fri, Sat, Sun. Values: Minutes allowed per day (0-1440)
- `enabled` (bool): Whether to enable MST for this device (default: True)

**Returns:** `bool` - True if successful

**Note:**
- Automatically removes existing time-based schedules when setting MST
- Time limits are in minutes per day (0-1440, where 1440 = 24 hours)
- When MST is active, device will be blocked after time limit is reached

### delete_device_mst(mac_address)

Delete Managed Screen Time (MST) configuration for a specific device.

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "A8:A1:59:33:F1:E4")

**Returns:** `bool` - True if successful (also returns True if MST was not configured)

### set_device_daily_time_limits(mac_address, weekday_minutes=120, weekend_minutes=240, enabled=True)

Set daily time limits for a device (simplified MST setup).

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
- `weekday_minutes` (int): Time limit for Mon-Fri in minutes (default: 120 = 2 hours)
- `weekend_minutes` (int): Time limit for Sat-Sun in minutes (default: 240 = 4 hours)
- `enabled` (bool): Whether to enable time limits (default: True)

**Returns:** `bool` - True if successful

**Note:** Convenience method that calls `set_device_mst` with weekday/weekend limits.

### set_device_parental_control(mac_address, control_type, **kwargs)

Unified parental control management for a device.

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "A8:A1:59:33:F1:E4")
- `control_type` (str): Type of control to apply - "none", "block", "schedule", "daily_limits"
- `**kwargs`: Additional parameters based on control_type

**Control Types:**
- `"none"`: Remove all restrictions
- `"block"`: Block device completely
- `"schedule"`: Time-based schedule restrictions (requires schedule_blocks parameter)
- `"daily_limits"`: Daily time limits (requires daily_limits or weekday_minutes/weekend_minutes parameters)

**Returns:** `bool` - True if successful

### get_device_parental_control_status(mac_address)

Get comprehensive parental control status for a device.

**Parameters:**
- `mac_address` (str): MAC address of the device (e.g., "A8:A1:59:33:F1:E4")

**Returns:** Dictionary with parental control status

**Parental Control Status Fields:**
- `control_type`: Type of control ("none", "block", "schedule", "daily_limits")
- `enabled`: Whether any control is enabled
- `schedule`: Schedule information (if applicable)
- `mst`: MST information (if applicable)
- `summary`: Human-readable summary of current restrictions

### list_devices_with_parental_controls()

Get list of all devices that have parental controls configured.

**Returns:** List of devices with parental control information

**Device Parental Control Fields:**
- `mac_address`: Device MAC address
- `name`: Device name
- `device_type`: Device type
- `active`: Whether device is currently connected
- `control_type`: Type of parental control
- `enabled`: Whether controls are enabled
- `summary`: Summary of current restrictions

### format_time_seconds_to_readable(seconds)

Convert seconds from Monday 00:00 to human-readable time.

**Parameters:**
- `seconds` (int): Seconds from Monday 00:00

**Returns:** `str` - Human-readable time string (e.g., "Monday 08:30", "Friday 22:00")

### create_bedtime_schedule_blocks(bedtime_hour=22, wakeup_hour=6, days=None)

Create schedule blocks for bedtime restrictions.

**Parameters:**
- `bedtime_hour` (int): Hour when device should be blocked (0-23, default: 22 = 10 PM)
- `wakeup_hour` (int): Hour when device should be unblocked (0-23, default: 6 = 6 AM)
- `days` (list): List of days to apply (0=Monday, 6=Sunday, default: [0,1,2,3,4] = weekdays)

**Returns:** List of schedule blocks suitable for `set_device_schedule`

### add_port_forwarding_rule(rule_id, internal_port, external_port, destination_ip, protocol="6", description="", enabled=True, source_interface="data", origin="webui")

Add a new IPv4 port forwarding rule.

**Parameters:**
- `rule_id` (str): Unique identifier for the rule (e.g., "SSH", "WebServer")
- `internal_port` (str): Internal port number or range (e.g., "22", "8080-8090")
- `external_port` (str): External port number or range (e.g., "22", "8080-8090")
- `destination_ip` (str): Internal IP address to forward to (e.g., "192.168.2.100")
- `protocol` (str): Protocol type - "6" (TCP), "17" (UDP), or "6,17" (both) (default: "6")
- `description` (str): Human-readable description (default: empty)
- `enabled` (bool): Whether rule should be enabled (default: True)
- `source_interface` (str): Source interface (default: "data")
- `origin` (str): Rule origin (default: "webui")

**Returns:** `str` - Full rule ID created by the router (e.g., "webui_SSH")

**Note:**
- Protocol 6 = TCP, 17 = UDP
- Port ranges use format "start-end" (e.g., "8080-8090")
- Individual ports use single numbers (e.g., "22")

### update_port_forwarding_rule(rule_id, internal_port=None, external_port=None, destination_ip=None, protocol=None, description=None, enabled=None, source_interface="data", origin="webui")

Update an existing IPv4 port forwarding rule.

**Parameters:**
- `rule_id` (str): Full rule ID (e.g., "webui_SSH") or simple ID (e.g., "SSH")
- `internal_port` (str): Internal port number or range (optional)
- `external_port` (str): External port number or range (optional)
- `destination_ip` (str): Internal IP address to forward to (optional)
- `protocol` (str): Protocol type - "6" (TCP), "17" (UDP), or "6,17" (both) (optional)
- `description` (str): Human-readable description (optional)
- `enabled` (bool): Whether rule should be enabled (optional)
- `source_interface` (str): Source interface (default: "data")
- `origin` (str): Rule origin (default: "webui")

**Returns:** `str` - Full rule ID

**Note:** Only specified parameters will be updated. Others remain unchanged.

### delete_port_forwarding_rule(rule_id, destination_ip=None, origin="webui")

Delete an IPv4 port forwarding rule.

**Parameters:**
- `rule_id` (str): Full rule ID (e.g., "webui_SSH") or simple ID (e.g., "SSH")
- `destination_ip` (str): Destination IP address (optional, for verification)
- `origin` (str): Rule origin (default: "webui")

**Returns:** `bool` - True if successful

### enable_port_forwarding_rule(rule_id, origin="webui") / disable_port_forwarding_rule(rule_id, origin="webui")

Enable or disable an existing IPv4 port forwarding rule.

**Parameters:**
- `rule_id` (str): Full rule ID (e.g., "webui_SSH") or simple ID (e.g., "SSH")
- `origin` (str): Rule origin (default: "webui")

**Returns:** `bool` - True if successful

### add_ipv6_pinhole(destination_ip, destination_port, protocol="6", description="", enabled=True, source_interface="data", source_port="", origin="webui")

Add a new IPv6 pinhole (firewall rule).

**Parameters:**
- `destination_ip` (str): IPv6 address to allow access to (e.g., "2a02:a46f:ff52:0:f5a6:3bb7:c600:efc0")
- `destination_port` (str): Destination port number or range (e.g., "22", "8080-8090")
- `protocol` (str): Protocol type - "6" (TCP), "17" (UDP), or "6,17" (both) (default: "6")
- `description` (str): Human-readable description (default: empty)
- `enabled` (bool): Whether rule should be enabled (default: True)
- `source_interface` (str): Source interface (default: "data")
- `source_port` (str): Source port filter (default: empty = any)
- `origin` (str): Rule origin (default: "webui")

**Returns:** `str` - Full rule ID created by the router (e.g., "webui_1")

**Note:**
- Protocol 6 = TCP, 17 = UDP
- Port ranges use format "start-end" (e.g., "8080-8090")
- IPv6 pinholes don't use external/internal port mapping like IPv4 port forwarding

### update_ipv6_pinhole(rule_id, destination_ip=None, destination_port=None, protocol=None, description=None, enabled=None, source_interface="data", source_port=None, origin="webui")

Update an existing IPv6 pinhole rule.

**Parameters:**
- `rule_id` (str): Full rule ID (e.g., "webui_1")
- `destination_ip` (str): IPv6 address to allow access to (optional)
- `destination_port` (str): Destination port number or range (optional)
- `protocol` (str): Protocol type - "6" (TCP), "17" (UDP), or "6,17" (both) (optional)
- `description` (str): Human-readable description (optional)
- `enabled` (bool): Whether rule should be enabled (optional)
- `source_interface` (str): Source interface (default: "data")
- `source_port` (str): Source port filter (optional)
- `origin` (str): Rule origin (default: "webui")

**Returns:** `str` - Full rule ID

### delete_ipv6_pinhole(rule_id, origin="webui")

Delete an IPv6 pinhole rule.

**Parameters:**
- `rule_id` (str): Full rule ID (e.g., "webui_1")
- `origin` (str): Rule origin (default: "webui")

**Returns:** `bool` - True if successful

### enable_ipv6_pinhole(rule_id, origin="webui") / disable_ipv6_pinhole(rule_id, origin="webui")

Enable or disable an existing IPv6 pinhole rule.

**Parameters:**
- `rule_id` (str): Full rule ID (e.g., "webui_1")
- `origin` (str): Rule origin (default: "webui")

**Returns:** `bool` - True if successful

### manage_port_forwarding(action, rule_id=None, **kwargs)

Unified port forwarding management for both IPv4 and IPv6.

**Parameters:**
- `action` (str): Action to perform - "add", "update", "delete", "enable", "disable", "list", "get"
- `rule_id` (str): Rule identifier (required for most actions except "list")
- `**kwargs`: Additional parameters based on action and IP version

**Common Parameters:**
- `ip_version`: 4 or 6 (default: 4)
- `origin`: Rule origin (default: "webui")

**For IPv4 port forwarding (ip_version=4):**
- `internal_port`: Internal port number or range
- `external_port`: External port number or range
- `destination_ip`: Internal IP address to forward to
- `protocol`: "6" (TCP), "17" (UDP), or "6,17" (both)
- `description`: Human-readable description
- `enabled`: Whether rule should be enabled

**For IPv6 pinholes (ip_version=6):**
- `destination_ip`: IPv6 address to allow access to
- `destination_port`: Destination port number or range
- `protocol`: "6" (TCP), "17" (UDP), or "6,17" (both)
- `description`: Human-readable description
- `enabled`: Whether rule should be enabled
- `source_port`: Source port filter (optional)

**Returns:**
- For "add": Rule ID (str)
- For "update": Rule ID (str)
- For "delete", "enable", "disable": Success status (bool)
- For "list": List of rules (List[Dict])
- For "get": Single rule details (Dict) or None

### change_password(new_password, old_password, username="admin")

Change the login password for a user account.

**Parameters:**
- `new_password` (str): The new password to set
- `old_password` (str): The current password for authentication
- `username` (str): Username to change password for (default: "admin")

**Returns:** `bool` - True if password change was successful

**Note:**
- New password should be strong (recommended: 8+ chars with mixed case, numbers, symbols)
- You must provide the correct current password
- After changing password, you'll need to login again with the new password


### get_system_stats(device_mac=None)

Get system CPU and RAM statistics from the KPN Box router.

**Parameters:**
- `device_mac` (str): MAC address of the device to monitor (default: auto-detect router MAC)

**Returns:** `Dict[str, Any]` - Dictionary containing system statistics:

**System Statistics Fields:**
- `timestamp`: ISO timestamp of the data
- `uptime_seconds`: System uptime in seconds
- `uptime_formatted`: Human-readable uptime (e.g., "2d 14h 35m")
- `load_average`: Dict with CPU load averages:
  - `1min`: 1-minute load average (0-100%)
  - `5min`: 5-minute load average (0-100%)
  - `15min`: 15-minute load average (0-100%)
- `memory`: Dict with RAM statistics:
  - `total_bytes`: Total RAM in bytes
  - `used_bytes`: Used RAM in bytes
  - `free_bytes`: Free RAM in bytes
  - `shared_bytes`: Shared RAM in bytes
  - `buffer_bytes`: Buffer RAM in bytes
  - `cached_bytes`: Cached RAM in bytes
  - `used_percentage`: Used RAM percentage (0-100%)
  - `free_percentage`: Free RAM percentage (0-100%)
- `swap`: Dict with swap statistics:
  - `total_bytes`: Total swap space in bytes
  - `free_bytes`: Free swap space in bytes
- `processes`: Number of running processes
- `device_mac`: MAC address of the monitored device


**Note:**
- If `device_mac` is not provided, attempts to auto-detect the router's MAC address
- Load averages are normalized from raw kernel values to percentage-like values (0-100)
- Memory values are provided in both bytes and percentages for convenience
- Returns empty dict `{}` if unable to retrieve system statistics

### reboot_system(reason="API reboot")

Reboot the KPN Box system.

**Parameters:**
- `reason` (str): Reason for the reboot (default: "API reboot")

**Returns:** `bool` - True if reboot command was sent successfully

**⚠️ Warning:**
This will reboot the entire KPN Box router. All network connections will be temporarily lost during the reboot process (typically 2-3 minutes).

### factory_reset_system(reason="API reset")

Perform a factory reset of the entire KPN Box system.

**Parameters:**
- `reason` (str): Reason for the factory reset (default: "API reset")

**Returns:** `bool` - True if factory reset command was sent successfully

**🚨 WARNING:**
This will completely reset the KPN Box to factory defaults! ALL settings will be lost including:
- WiFi passwords and network names
- Port forwarding rules
- Device schedules and restrictions  
- DHCP reservations
- All custom configurations
Use with extreme caution!

### factory_reset_wifi()

Perform a factory reset of WiFi settings only.

**Returns:** `bool` - True if WiFi factory reset command was sent successfully

**⚠️ Warning:**
This will reset ALL WiFi settings to factory defaults including:
- WiFi network names (SSIDs)
- WiFi passwords
- WiFi security settings
- Guest network configuration
- WiFi scheduling settings
You will need to reconfigure WiFi after this operation!

### restart_home_network(reason="API reboot")

Restart the home network group function.

**Parameters:**
- `reason` (str): Reason for the restart (default: "API reboot")

**Returns:** `bool` - True if restart command was sent successfully

**Note:**
This restarts network services without a full system reboot. May cause temporary network disruption.

### factory_reset_home_network(reason="API reset")

Perform a factory reset of home network settings.

**Parameters:**
- `reason` (str): Reason for the factory reset (default: "API reset")

**Returns:** `bool` - True if factory reset command was sent successfully

**⚠️ Warning:**
This will reset home network settings to factory defaults including:
- Network configuration
- DHCP settings  
- Port forwarding rules
- Device schedules and restrictions
- Network security settings
Use with caution!


## Usage Examples

### Basic Device Management

```python
from kpnboxapi import KPNBoxAPI

with KPNBoxAPI() as api:
    api.login(password="your_password")
    
    # Get currently connected devices
    active_devices = api.get_devices(filter='active')
    print(f"Active devices: {len(active_devices)}")
    
    # Show device details
    for device in active_devices[:3]:  # Show first 3
        print(f"{device['Name']} - {device['IPAddress']} ({device['PhysAddress']})")
```

### Modem Information

```python
# Get modem details
modem_info = api.get_device_info()
print(f"Model: {modem_info['Manufacturer']} {modem_info['ModelName']}")
print(f"Firmware: {modem_info['SoftwareVersion']}")
print(f"External IP: {modem_info['ExternalIPAddress']}")
```

### WiFi Networks

```python
# Get all WiFi networks
wifi_networks = api.get_all_wifi_networks()

# Regular networks
for network in wifi_networks['regular']:
    print(f"SSID: {network['SSID']} - Status: {network['VAPStatus']}")
    print(f"Security: {network['Security']['ModeEnabled']}")
    print(f"Connected: {network['AssociatedDeviceNumberOfEntries']}")

# Guest networks  
for network in wifi_networks['guest']:
    print(f"Guest: {network['SSID']} - Status: {network['VAPStatus']}")
```

### WiFi Configuration

```python
# Change WiFi name and password for both bands
success = api.set_wifi_config(
    ssid_2g="MyNetwork_2G",
    ssid_5g="MyNetwork_5G", 
    password_2g="NewPassword123",
    password_5g="NewPassword123",
    security_mode_2g="WPA2-Personal",
    security_mode_5g="WPA2-Personal"
)
print(f"WiFi configured: {success}")

# Change only the SSID (keep existing password)
success = api.set_wifi_config(
    ssid_2g="NewNetworkName",
    ssid_5g="NewNetworkName"
)
print(f"SSID updated: {success}")

# Hide WiFi networks (disable SSID broadcast)
success = api.set_wifi_visibility(visible_2g=False, visible_5g=False)
print(f"WiFi hidden: {success}")

# Show WiFi networks again
success = api.set_wifi_visibility(visible_2g=True, visible_5g=True)
print(f"WiFi visible: {success}")

# Disable WPS for security
results = api.set_wps_enabled(enabled_2g=False, enabled_5g=False)
print(f"WPS disabled - 2.4G: {results.get('band_2g')}, 5G: {results.get('band_5g')}")

# Enable WPS
results = api.set_wps_enabled(enabled_2g=True, enabled_5g=True)
print(f"WPS enabled - 2.4G: {results.get('band_2g')}, 5G: {results.get('band_5g')}")
```

### Guest Network Configuration

```python
# Enable guest network
success = api.enable_guest_network(enabled=True)
print(f"Guest network enabled: {success}")

# Configure guest WiFi with simple settings
success = api.set_guest_wifi_config(
    ssid_2g="Guest_WiFi",
    ssid_5g="Guest_WiFi",
    password_2g="GuestPass123",
    password_5g="GuestPass123",
    security_mode_2g="WPA2-Personal",
    security_mode_5g="WPA2-Personal"
)
print(f"Guest WiFi configured: {success}")

# Set bandwidth limit for guests (10 Mbps)
success = api.set_guest_bandwidth_limit(10)
print(f"Guest bandwidth limited to 10 Mbps: {success}")

# Hide guest networks
success = api.set_guest_wifi_visibility(visible_2g=False, visible_5g=False)
print(f"Guest networks hidden: {success}")

# Remove bandwidth limit (unlimited)
success = api.set_guest_bandwidth_limit(0)
print(f"Guest bandwidth unlimited: {success}")

# Disable guest network completely
success = api.enable_guest_network(enabled=False)
print(f"Guest network disabled: {success}")

# Check current guest networks
guest_networks = api.get_guest_wifi_networks()
for network in guest_networks:
    print(f"Guest: {network['SSID']} - Status: {network['VAPStatus']}")
```

### Extra WiFi Configuration

```python
# Enable extra WiFi networks (third set of networks)
results = api.enable_extra_wifi(enabled_2g=True, enabled_5g=True)
print(f"Extra WiFi enabled - 2.4G: {results.get('band_2g')}, 5G: {results.get('band_5g')}")

# Configure extra WiFi with specific purpose (e.g., IoT devices)
success = api.set_extra_wifi_config(
    ssid_2g="IoT_Network",
    ssid_5g="IoT_Network_5G",
    password_2g="IoTSecure2024!",
    password_5g="IoTSecure2024!",
    security_mode_2g="WPA2-Personal",
    security_mode_5g="WPA2-Personal"
)
print(f"Extra WiFi configured for IoT: {success}")

# Configure extra WiFi for different purposes per band
success = api.set_extra_wifi_config(
    ssid_2g="Devices_2G",      # 2.4GHz for legacy devices
    ssid_5g="Work_5G",         # 5GHz for work devices
    password_2g="DevicePass123",
    password_5g="WorkPass456",
    security_mode_2g="WPA2-Personal",
    security_mode_5g="WPA2-Personal"
)
print(f"Extra WiFi configured with different purposes: {success}")

# Hide extra networks for security
success = api.set_extra_wifi_visibility(visible_2g=False, visible_5g=False)
print(f"Extra networks hidden: {success}")

# Show only the 5GHz extra network
success = api.set_extra_wifi_visibility(visible_2g=False, visible_5g=True)
print(f"5GHz extra network visible, 2.4GHz hidden: {success}")

# Disable extra WiFi networks
results = api.enable_extra_wifi(enabled_2g=False, enabled_5g=False)
print(f"Extra WiFi disabled - 2.4G: {results.get('band_2g')}, 5G: {results.get('band_5g')}")
```

### WiFi Radio Control and Scheduling

```python
# Enable/disable WiFi completely
api.set_wifi_enabled(True)  # Enable all WiFi
api.set_wifi_enabled(False)  # Disable all WiFi

# Get WiFi status
status = api.get_wifi_status()
print(f"WiFi enabled: {status.get('Enable')}")

# Configure radio settings
api.set_wifi_radio_config(
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

# Apply recommended defaults
api.set_wifi_radio_defaults()
```

### WiFi Spectrum Analysis
```python
# Get detailed radio information
radio_2g = api.get_wifi_radio_info("2g")
radio_5g = api.get_wifi_radio_info("5g")
all_radios = api.get_all_wifi_radio_info()

print(f"2.4GHz Channel: {radio_2g.get('Channel')}")
print(f"5GHz Bandwidth: {radio_5g.get('CurrentOperatingChannelBandwidth')}")
print(f"Channel Load: {radio_2g.get('ChannelLoad')}%")
print(f"Interference: {radio_2g.get('Interference')}%")

# Analyze spectrum and channel usage
spectrum_2g = api.get_wifi_spectrum_info("2g")
spectrum_5g = api.get_wifi_spectrum_info("5g")
all_spectrum = api.get_all_wifi_spectrum_info()

for channel in spectrum_2g:
    print(f"Channel {channel['channel']}: {channel['availability']}% available, "
          f"{channel['accesspoints']} APs, {channel['noiselevel']} dBm noise")

# Scan for nearby networks
networks_2g = api.get_wifi_scan_results("2g")
networks_5g = api.get_wifi_scan_results("5g")
all_networks = api.get_all_wifi_scan_results()

for network in networks_2g:
    if network.get('SSID'):  # Skip hidden networks
        print(f"Network: {network['SSID']}, Channel: {network['Channel']}, "
              f"Signal: {network['RSSI']} dBm, Security: {network['SecurityModeEnabled']}")

# Get best channel recommendations
best_2g = api.get_best_wifi_channels("2g", top_n=3)
best_5g = api.get_best_wifi_channels("5g", top_n=3)

print("Best 2.4GHz channels:")
for i, channel in enumerate(best_2g, 1):
    print(f"  {i}. Channel {channel['channel']} (score: {channel['score']}, "
          f"congestion: {channel['congestion_level']})")

# Comprehensive WiFi environment analysis
analysis = api.analyze_wifi_environment()
print(f"Environment: {analysis['summary']}")
print(f"Total networks: {analysis['total_networks']}")

for recommendation in analysis['recommendations']:
    print(f"💡 {recommendation}")
```

### WiFi Scheduling

```python
# Enable/disable scheduling
success = api.enable_wifi_schedule(enabled=True)
print(f"WiFi scheduling enabled: {'✅ Success' if success else '❌ Failed'}")

# Set custom WiFi schedule (disable specific time blocks)
disable_blocks = [
    {"begin": 79200, "end": 108000},   # Monday 22:00-06:00
    {"begin": 165600, "end": 194400},  # Tuesday 22:00-06:00
    {"begin": 252000, "end": 280800},  # Wednesday 22:00-06:00
]
success = api.set_wifi_schedule(disable_blocks=disable_blocks, enabled=True)
print(f"Custom schedule set: {'✅ Success' if success else '❌ Failed'}")

# Set up bedtime WiFi schedule (disable 10 PM to 6 AM on weekdays)
success = api.set_wifi_bedtime_schedule(
    bedtime_hour=22,    # 10 PM
    wakeup_hour=6,      # 6 AM
    weekdays_only=True  # Only Monday-Friday
)
print(f"Bedtime schedule set: {'✅ Success' if success else '❌ Failed'}")

# Clear all WiFi time restrictions
success = api.clear_wifi_schedule()
print(f"WiFi schedule cleared: {'✅ Success' if success else '❌ Failed'}")
```

### DHCP Configuration

```python
# Get DHCP servers
dhcp_servers = api.get_all_dhcp_servers()

# Default network
default = dhcp_servers['default']
print(f"Default DHCP: {default['Status']}")
print(f"Range: {default['MinAddress']} - {default['MaxAddress']}")
print(f"Active leases: {default['LeaseNumberOfEntries']}")

# Get actual leases
leases = api.get_active_dhcp_leases("default")
for lease in leases:
    print(f"{lease['FriendlyName']}: {lease['IPAddress']}")

# Configure DHCP server settings
success = api.set_home_dhcp_config(
    gateway_ip="192.168.2.254",
    subnet_mask=24,
    dhcp_enabled=True,
    dhcp_min_ip="192.168.2.100",
    dhcp_max_ip="192.168.2.200",
    lease_time_seconds=14400,  # 4 hours
    dns_servers="9.9.9.9,149.112.112.112"
)
print(f"Home DHCP configured: {success}")

# Configure guest network DHCP
success = api.set_guest_dhcp_config(
    gateway_ip="192.168.3.254",
    dhcp_min_ip="192.168.3.1",
    dhcp_max_ip="192.168.3.32",
    lease_time_seconds=3600,  # 1 hour for guests
    dns_servers="9.9.9.9,149.112.112.112"
)
print(f"Guest DHCP configured: {success}")

# Set up network isolation
results = api.configure_network_isolation(
    home_subnet="192.168.2.0/24",
    guest_subnet="192.168.3.0/24",
    home_dhcp_range=("192.168.2.100", "192.168.2.200"),
    guest_dhcp_range=("192.168.3.1", "192.168.3.32"),
    dns_servers="9.9.9.9,149.112.112.112"
)
print(f"Network isolation - Home: {results['home']}, Guest: {results['guest']}")
```

### IP Reservations (Static DHCP Leases)

```python
# Add IP reservation for a printer
success = api.add_static_lease("50:DE:06:9A:A6:98", "192.168.2.118")
print(f"Printer IP reserved: {success}")

# Reserve IP for a server using device name auto-detection
success = api.reserve_device_ip("My NAS", "192.168.2.100")
print(f"NAS IP reserved: {success}")

# Get all current IP reservations
reservations = api.list_ip_reservations()
for res in reservations:
    print(f"{res['device_name']}: {res['ip_address']} ({res['mac_address']})")

# Update existing reservation
success = api.set_static_lease("50:DE:06:9A:A6:98", "192.168.2.120")
print(f"Printer IP updated: {success}")

# Get suggested available IPs
available_ips = api.suggest_available_ips(count=5)
print(f"Available IPs: {available_ips}")

# Comprehensive reservation management
success = api.manage_device_ip_reservation(
    "AA:BB:CC:DD:EE:FF", 
    "192.168.2.150", 
    action="add"
)

# Remove IP reservation
success = api.delete_static_lease("50:DE:06:9A:A6:98")
print(f"Reservation removed: {success}")

# Clean up invalid reservations
cleanup_result = api.cleanup_invalid_reservations()
print(f"Found {cleanup_result['total_issues']} issues")
for recommendation in cleanup_result['recommendations']:
    print(f"💡 {recommendation}")
```

### Device Management

```python
# List all devices with management status
devices = api.list_managed_devices()
for device in devices:
    status = "🔴 Blocked" if device['blocked'] else "⏰ Scheduled" if device['scheduled'] else "✅ Unrestricted"
    print(f"{device['name']}: {device['device_type']} - {status}")

# Clean up old inactive devices
inactive_devices = api.list_inactive_devices(days_inactive=30)
print(f"Found {len(inactive_devices)} devices inactive for 30+ days")

for device in inactive_devices[:5]:  # Show first 5
    days = device['days_since_seen']
    print(f"- {device['name']}: {days} days ago")

# Automatically clean up devices inactive for 90+ days
cleanup_result = api.cleanup_inactive_devices(days_inactive=90)
print(f"Cleaned up {cleanup_result['total_deleted']} old devices")

# Manually delete a specific device
success = api.delete_device("96:16:1A:D6:0F:30")
print(f"Device deleted: {success}")
```

### Dynamic DNS Management

```python
# Get current DynDNS hosts
hosts = api.get_dyndns_hosts()
for host in hosts:
    print(f"Host: {host['hostname']} - Status: {host['status']}")

# Add new DynDNS host
success = api.add_dyndns_host(
    service="dyndns",
    username="myuser",
    hostname="myhome.ddns.net", 
    password="mypassword"
)
print(f"DynDNS host added: {success}")

# Update existing host password
success = api.update_dyndns_host(
    hostname="myhome.ddns.net",
    password="newpassword123"
)
print(f"DynDNS password updated: {success}")

# Get status for specific host
host_status = api.get_dyndns_status("myhome.ddns.net")
if host_status:
    print(f"Host status: {host_status['status']}")
    print(f"Last update: {host_status['last_update']}")

# Get overall DynDNS status
all_status = api.get_dyndns_status()
print(f"Total hosts: {all_status['total_hosts']}")
print(f"Active hosts: {len(all_status['active_hosts'])}")

# Delete DynDNS host
success = api.delete_dyndns_host("myhome.ddns.net")
print(f"DynDNS host deleted: {success}")

# Comprehensive DynDNS management
success = api.manage_dyndns_service(
    action="add",
    hostname="test.ddns.net",
    service="dyndns",
    username="testuser",
    password="testpass"
)
print(f"DynDNS service managed: {success}")
```

### Network Statistics

```python
# Get WAN statistics
wan_stats = api.get_wan_total_stats()
print(f"Downloaded: {api.format_bytes(wan_stats['RxBytes'])}")
print(f"Uploaded: {api.format_bytes(wan_stats['TxBytes'])}")

# Get interface statistics
all_stats = api.get_all_network_stats()
for interface, stats in all_stats.items():
    if stats.get('Available', True):
        print(f"{interface}: ↓{api.format_bytes(stats['RxBytes'])} ↑{api.format_bytes(stats['TxBytes'])}")
```

### Firewall Rules

```python
# Get port forwarding rules
pf_rules = api.get_all_port_forwarding()
for origin, rules in pf_rules.items():
    print(f"\n{origin.upper()} Rules:")
    for rule in rules:
        if rule.get('Enable'):
            print(f"  {rule['Description']}: {rule['ExternalPort']} → {rule['DestinationIPAddress']}")

# Get IPv6 pinholes
ipv6_rules = api.get_active_ipv6_pinholes()
for rule in ipv6_rules:
    print(f"IPv6: {rule['Description']} - Port {rule['DestinationPort']}")
```

### Internet Connection

```python
# Check connectivity
if api.is_connected():
    wan_status = api.get_wan_status()
    print(f"✅ Connected - IP: {wan_status.get('IPAddress')}")
    
    # Get connection details
    connection = api.get_connection_info()
    ppp = connection['ppp_info']
    print(f"PPPoE Session: {ppp.get('PPPoESessionID')}")
else:
    print("❌ No internet connection")
```

### Mobile Internet Backup

```python
# Check WWAN (mobile backup) status
wwan_status = api.get_wwan_status()
print(f"Mobile Backup: {'Enabled' if wwan_status.get('Enable') else 'Disabled'}")

if wwan_status.get('Enable'):
    status = wwan_status.get('ConnectionStatus', 'Unknown')
    signal = wwan_status.get('SignalStrength', 0)
    technology = wwan_status.get('Technology', 'none')
    print(f"Status: {status}")
    print(f"Signal: {signal}% ({technology})")
    
    if wwan_status.get('IMEI'):
        print(f"IMEI: {wwan_status.get('IMEI')}")
```

### Network Configuration

```python
# Get LAN configuration
lan_config = api.get_lan_config()
ipv4 = lan_config['ipv4']
print(f"LAN IP: {ipv4['Address']}/{ipv4['PrefixLength']}")
print(f"DHCP: {'Enabled' if ipv4['DHCPEnable'] else 'Disabled'}")

# Get DNS servers
dns = api.get_dns_servers()
print(f"IPv4 DNS: {dns['ipv4']}")
print(f"IPv6 DNS: {dns['ipv6']}")

# IPv6 Prefix Delegation Configuration
print("\n=== IPv6 Prefix Delegation ===")

# Check current IPv6 status
netmaster_config = api.get_netmaster_config()
ipv6_enabled = netmaster_config.get('EnableIPv6', False)
prefix_mode = netmaster_config.get('IPv6PrefixMode', 'Unknown')
print(f"IPv6 Enabled: {ipv6_enabled}")
print(f"IPv6 Prefix Mode: {prefix_mode}")

# Disable IPv6 prefix delegation (single address mode)
success = api.disable_ipv6_prefix_delegation()
print(f"IPv6 prefix delegation disabled: {success}")

# Enable IPv6 prefix delegation with RA mode
success = api.enable_ipv6_prefix_delegation(use_dhcpv6=False)
print(f"IPv6 prefix delegation enabled (RA mode): {success}")

# Enable IPv6 prefix delegation with RA + DHCPv6 mode
success = api.enable_ipv6_prefix_delegation(use_dhcpv6=True)
print(f"IPv6 prefix delegation enabled (RA + DHCPv6 mode): {success}")

# Advanced IPv6 prefix delegation configuration
success = api.configure_ipv6_prefix_delegation(
    enabled=True,
    use_dhcpv6=False,  # Use RA mode only
    prefix_length=56   # Standard prefix length
)
print(f"IPv6 prefix delegation configured: {success}")

# Specific mode configuration
success = api.set_ipv6_prefix_delegation("on_with_dhcpv6")  # or "on", "off"
print(f"IPv6 prefix delegation mode set: {success}")

# Get IPv6 configuration details
ipv6_config = api.get_lan_ipv6_config()
dhcpv6_status = api.get_dhcpv6_client_status()
print(f"IPv6 Address: {ipv6_config.get('Address', 'Not configured')}")
print(f"DHCPv6 Status: {dhcpv6_status.get('DHCPStatus', 'Unknown')}")
print(f"Request Prefixes: {dhcpv6_status.get('RequestPrefixes', False)}")
```

### Security Settings

```python
# Get firewall status
firewall_level = api.get_firewall_level()
firewall_config = api.get_firewall_config()
print(f"Firewall: {firewall_level} Level - {firewall_config['Status']}")

# Check ping response
ping_settings = api.get_ping_response_settings()
print(f"Ping Response - IPv4: {ping_settings['enableIPv4']}, IPv6: {ping_settings['enableIPv6']}")

# Check DMZ
dmz_config = api.get_dmz_config()
if dmz_config.get('Enable'):
    print(f"DMZ Host: {dmz_config['DestinationIPAddress']}")
```

### Device Schedules

```python
# Get device access schedules
schedules = api.get_device_schedules()
for schedule in schedules:
    if schedule.get('enable'):
        name = schedule.get('name', schedule.get('ID'))
        status = schedule.get('value', 'Unknown')
        print(f"{name}: {status}")
```

### Speed Tests

```python
# Run download speed test
print("Running download speed test...")
download_result = api.run_download_speedtest()
speed = api.format_speed(download_result.get('throughput', 0))
print(f"Download Speed: {speed}")

# Run full speed test
results = api.run_full_speedtest()
download_speed = api.format_speed(results['download']['throughput'])
upload_speed = api.format_speed(results['upload']['throughput'])
print(f"Download: {download_speed}, Upload: {upload_speed}")
```

### Network Diagnostics

```python
# Ping test
result = api.run_ping("8.8.8.8", "IPv4")
if result.get('DiagnosticsState') == 'Success':
    print(f"Ping successful: {result['averageResponseTime']}ms")

# Traceroute
result = api.run_traceroute("www.google.com", "IPv4")
if result.get('DiagnosticState') == 'Complete':
    hops = result.get('RouteHopsNumberOfEntries', 0)
    print(f"Route found: {hops} hops")
```

### Time Configuration

```python
# Get time information
time_config = api.get_time_config()
print(f"Router time: {time_config['current_time']}")
print(f"NTP servers: {', '.join(time_config['ntp_servers_list'])}")
```

### Configuration Changes (SET Functions)

```python
# Configure network interface settings
success = api.set_interface_duplex("eth4", "Auto")  # Auto, Half, Full
print(f"Duplex mode set: {success}")

success = api.set_interface_speed("eth4", -1)  # -1 = Auto, or speed in Mbps
print(f"Link speed set: {success}")

# Ethernet Port 4 Guest Network Configuration
print("\\n=== Port 4 Guest Network Configuration ===")

# Enable guest network on port 4 (ETH3)
success = api.enable_port4_guest_network()
print(f"Port 4 guest network enabled: {success}")

# Disable guest network on port 4 (return to home LAN)
success = api.disable_port4_guest_network()
print(f"Port 4 returned to home LAN: {success}")

# Advanced port configuration
success = api.configure_ethernet_port(port=4, guest_network=True)
print(f"Port 4 configured for guest network: {success}")

# Check port statistics after configuration
all_stats = api.get_all_network_stats()
eth3_stats = all_stats.get("ETH3", {})
if eth3_stats.get('Available', True):
    rx_bytes = api.format_bytes(eth3_stats.get('RxBytes', 0))
    tx_bytes = api.format_bytes(eth3_stats.get('TxBytes', 0))
    print(f"Port 4 traffic: ↓{rx_bytes} ↑{tx_bytes}")

# STP (Spanning Tree Protocol) Configuration
print("\\n=== STP Configuration ===")

# Enable STP to prevent network loops
success = api.enable_stp()
print(f"STP enabled: {success}")

# Disable STP for better performance (use with caution)
success = api.disable_stp()
print(f"STP disabled: {success}")

# Advanced STP control
success = api.set_stp_enabled(True)
print(f"STP status configured: {success}")

# Enable/disable IPv6 globally
success = api.set_ipv6_enabled(True, "DHCPv6")  # or "RA" for Router Advertisement
print(f"IPv6 enabled: {success}")

# Configure DNS servers
results = api.set_dns_servers(
    ipv4_dns="9.9.9.9,149.112.112.112",
    ipv6_dns="2620:fe::fe,2620:fe::9",
    network="lan"  # or "guest"
)
print(f"DNS configured - IPv4: {results.get('ipv4')}, IPv6: {results.get('ipv6')}")

# Configure LAN settings (more granular control)
success = api.set_lan_ipv4_config(
    network="guest",
    dns_servers="8.8.8.8,8.8.4.4",
    address="192.168.3.254",
    dhcp_enabled=True,
    dhcp_min_address="192.168.3.10",
    dhcp_max_address="192.168.3.100",
    prefix_length=24
)
print(f"Guest network configured: {success}")

# Complete Guest Network + Port 4 Setup Example
print("\\n=== Complete Guest Network Setup ===")

# 1. Configure guest network DHCP settings
guest_dhcp_success = api.set_guest_dhcp_config(
    gateway_ip="192.168.3.254",
    subnet_mask=24,
    dhcp_enabled=True,
    dhcp_min_ip="192.168.3.10",
    dhcp_max_ip="192.168.3.100",
    lease_time_seconds=3600,  # 1 hour
    dns_servers="8.8.8.8,8.8.4.4"
)

# 2. Enable guest WiFi network
guest_wifi_success = api.enable_guest_network(True)

# 3. Configure guest WiFi settings
guest_config_success = api.set_guest_wifi_config(
    ssid_2g="KPN-Guest-2G",
    ssid_5g="KPN-Guest-5G",
    password_2g="guest123!",
    password_5g="guest123!",
    security_mode_2g="WPA2-Personal",
    security_mode_5g="WPA2-Personal"
)

# 4. Enable port 4 for guest network (wired guest access)
port4_success = api.enable_port4_guest_network()

# 5. Set guest bandwidth limit
bandwidth_success = api.set_guest_bandwidth_limit(50)  # 50 Mbps limit

print(f"Guest DHCP configured: {guest_dhcp_success}")
print(f"Guest WiFi enabled: {guest_wifi_success}")
print(f"Guest WiFi configured: {guest_config_success}")
print(f"Port 4 guest network: {port4_success}")
print(f"Bandwidth limit set: {bandwidth_success}")

if all([guest_dhcp_success, guest_wifi_success, guest_config_success, port4_success]):
    print("✅ Complete guest network setup successful!")
    print("Guests can now connect via:")
    print("  - WiFi: KPN-Guest-2G/5G networks with password 'guest123!'")
    print("  - Wired: Ethernet cable to port 4")
    print("  - Both will get 192.168.3.x IP addresses")
    print("  - Bandwidth limited to 50 Mbps")
```

### IPTV Information

```python
# Get IPTV interface IP
iptv_ip = api.get_iptv_ip()
if iptv_ip:
    print(f"IPTV Interface IP: {iptv_ip}")
else:
    print("IPTV not available or not configured")
```

### VoIP/Telephone Information

```python
# Get voice service profiles
voice_profiles = api.get_voice_profiles()
for profile_name, profile_config in voice_profiles.items():
    print(f"Voice Profile {profile_name}: {profile_config.get('Name', 'N/A')}")

# Get SIP trunks
voice_trunks = api.get_voice_trunks()
for trunk in voice_trunks:
    print(f"Trunk {trunk['name']}: {trunk['enable']} ({trunk['signalingProtocol']})")
    
    # Show trunk lines
    for line in trunk.get('trunk_lines', []):
        if line.get('directoryNumber'):
            print(f"  Line {line['name']}: {line['directoryNumber']} - {line['status']}")

# Get voice handsets/endpoints
handsets = api.get_voice_handsets()
for handset in handsets:
    print(f"Handset {handset['name']}: {handset['status']} ({handset['endpointType']})")
    if handset.get('directoryNumber'):
        print(f"  Number: {handset['directoryNumber']}")

# Test phone ring
if api.ring_test_phone():
    print("Phone ring test sent successfully")
```

### WiFi MAC Filtering (WiFi Protection)

```python
# Get current MAC filtering status
status = api.get_wifi_mac_filter_status()
print(f"MAC Filtering: {'Enabled' if status['enabled'] else 'Disabled'}")
print(f"Mode: {status['mode']}")
print(f"Allowed devices: {status['count']}")

if status['allowed_devices']:
    print("Whitelist:")
    for mac in status['allowed_devices']:
        print(f"  - {mac}")

# Enable MAC filtering (with current connected WiFi devices)
result = api.add_connected_wifi_devices_to_filter()
print(f"Added {len(result['added_devices'])} devices to whitelist:")
for device in result['added_devices']:
    print(f"  + {device['name']} ({device['mac_address']}) - {device['interface']}")

if result['already_allowed']:
    print(f"Already allowed ({len(result['already_allowed'])}):")
    for device in result['already_allowed']:
        print(f"  ✓ {device['name']} ({device['mac_address']})")

# Manually add specific devices to whitelist
success = api.add_wifi_mac_filter("AA:BB:CC:DD:EE:FF")
print(f"Device added to whitelist: {success}")

# Add multiple devices at once
success = api.add_wifi_mac_filter([
    "11:22:33:44:55:66",
    "77:88:99:AA:BB:CC"
])
print(f"Multiple devices added: {success}")

# Set complete whitelist (replaces all)
success = api.set_wifi_mac_filter_list([
    "AA:BB:CC:DD:EE:FF",
    "11:22:33:44:55:66",
    "77:88:99:AA:BB:CC",
    "DD:EE:FF:00:11:22"
])
print(f"Complete whitelist set: {success}")

# Remove specific device from whitelist
success = api.remove_wifi_mac_filter("77:88:99:AA:BB:CC")
print(f"Device removed from whitelist: {success}")

# Remove multiple devices
success = api.remove_wifi_mac_filter([
    "11:22:33:44:55:66",
    "DD:EE:FF:00:11:22"
])
print(f"Multiple devices removed: {success}")

# Get current whitelist
allowed_devices = api.get_wifi_mac_filter_list()
print(f"Current whitelist: {allowed_devices}")

# Clear all devices from whitelist (keeps filtering enabled)
success = api.clear_wifi_mac_filter()
print(f"Whitelist cleared: {success}")
print("⚠️  All WiFi devices are now blocked!")

# Disable MAC filtering (allow all devices)
success = api.disable_wifi_mac_filtering()
print(f"MAC filtering disabled: {success}")

# Re-enable with previous list
success = api.enable_wifi_mac_filtering()
print(f"MAC filtering re-enabled: {success}")

# Unified interface examples
print("\\n=== Unified Interface Examples ===")

# Enable filtering
success = api.manage_wifi_mac_filter("enable")
print(f"Filtering enabled: {success}")

# Add device via unified interface
success = api.manage_wifi_mac_filter("add", "AA:BB:CC:DD:EE:FF")
print(f"Device added: {success}")

# Set complete list via unified interface
success = api.manage_wifi_mac_filter("set", [
    "AA:BB:CC:DD:EE:FF",
    "11:22:33:44:55:66"
], enabled=True)
print(f"List set: {success}")

# Get status via unified interface
status = api.manage_wifi_mac_filter("status")
print(f"Status: {status}")

# Add all connected WiFi devices via unified interface
result = api.manage_wifi_mac_filter("add_connected")
print(f"Connected devices added: {result['success']}")

# Security recommendations example
print("\\n=== Security Setup Example ===")

# 1. Get all currently connected WiFi devices
current_devices = api.get_devices('active')
wifi_devices = [d for d in current_devices if d.get('Layer2Interface') != 'ETH0']

print(f"Found {len(wifi_devices)} WiFi devices currently connected:")
for device in wifi_devices:
    print(f"  - {device['Name']} ({device['PhysAddress']})")

# 2. Add all current WiFi devices to whitelist and enable filtering
if wifi_devices:
    result = api.add_connected_wifi_devices_to_filter()
    if result['success']:
        print(f"✅ MAC filtering enabled with {len(result['added_devices'])} devices")
        print("📱 Only these devices can now connect to WiFi:")
        
        all_allowed = result['added_devices'] + result['already_allowed']
        for device in all_allowed:
            print(f"   ✓ {device['name']} ({device['mac_address']})")
        
        print("\\n🔒 Security Notes:")
        print("- New devices must be manually added to connect")
        print("- Wired devices (Ethernet) are not affected")
        print("- Guest network is not affected by this filter")
        print("- WiFi extenders are automatically allowed")
    else:
        print("❌ Failed to enable MAC filtering")
else:
    print("No WiFi devices found to add to whitelist")

# 3. Maintenance example - check and clean up whitelist
print("\\n=== Whitelist Maintenance ===")

# Get current status
status = api.get_wifi_mac_filter_status()
if status['enabled']:
    print(f"MAC filtering is active with {status['count']} allowed devices")
    
    # Get list of devices that haven't been seen recently
    inactive_devices = api.list_inactive_devices(days_inactive=30)
    inactive_macs = [d['PhysAddress'] for d in inactive_devices if d.get('Layer2Interface') != 'ETH0']
    
    # Find MAC addresses in whitelist that belong to inactive devices
    whitelist = api.get_wifi_mac_filter_list()
    cleanup_candidates = [mac for mac in whitelist if mac in inactive_macs]
    
    if cleanup_candidates:
        print(f"Found {len(cleanup_candidates)} inactive devices in whitelist:")
        for mac in cleanup_candidates:
            device_name = next((d['Name'] for d in inactive_devices if d['PhysAddress'] == mac), 'Unknown')
            print(f"  - {device_name} ({mac})")
        
        # Optionally remove inactive devices (uncomment to enable)
        # success = api.remove_wifi_mac_filter(cleanup_candidates)
        # print(f"Inactive devices removed: {success}")
        print("💡 Run api.remove_wifi_mac_filter(cleanup_candidates) to clean up")
    else:
        print("No inactive devices found in whitelist")
```

### Parental Controls & Device Management

```python
# Get current parental control status for a device
mac_address = "A8:A1:59:33:F1:E4"
status = api.get_device_parental_control_status(mac_address)

print(f"Device: {mac_address}")
print(f"Control Type: {status['control_type']}")
print(f"Enabled: {status['enabled']}")
print(f"Summary: {status['summary']}")

# Set up different types of parental controls
print("\\n=== Parental Control Examples ===")

# 1. Remove all restrictions
api.set_device_parental_control(mac_address, "none")
print("✅ All restrictions removed")

# 2. Block device completely
api.set_device_parental_control(mac_address, "block")
print("🚫 Device completely blocked")

# 3. Set bedtime schedule (block 10 PM to 6 AM on weekdays)
bedtime_blocks = api.create_bedtime_schedule_blocks(
    bedtime_hour=22,  # 10 PM
    wakeup_hour=6,    # 6 AM
    days=[0,1,2,3,4]  # Monday-Friday
)
api.set_device_parental_control(mac_address, "schedule", 
                               schedule_blocks=bedtime_blocks)
print("🌙 Bedtime schedule set (10 PM - 6 AM weekdays)")

# 4. Set daily time limits (2 hours weekdays, 4 hours weekends)
api.set_device_parental_control(mac_address, "daily_limits",
                               weekday_minutes=120,   # 2 hours
                               weekend_minutes=240)   # 4 hours
print("⏰ Daily time limits set")

# 5. Custom daily limits for each day
custom_limits = {
    "Mon": 90,   # 1.5 hours
    "Tue": 90,   # 1.5 hours
    "Wed": 90,   # 1.5 hours
    "Thu": 90,   # 1.5 hours
    "Fri": 180,  # 3 hours
    "Sat": 300,  # 5 hours
    "Sun": 240   # 4 hours
}
api.set_device_parental_control(mac_address, "daily_limits",
                               daily_limits=custom_limits)
print("📅 Custom daily limits set")

# Get MST status for detailed information
mst_status = api.get_device_mst_status(mac_address)
if mst_status:
    print("\\n📊 Screen Time Details:")
    allowed_time = mst_status.get('allowedTime', {})
    for day, minutes in allowed_time.items():
        hours = minutes // 60
        mins = minutes % 60
        print(f"   {day}: {hours}h {mins}m")

# Advanced schedule example - study hours (block 7-9 PM on weekdays)
study_blocks = []
for day in [0,1,2,3,4]:  # Monday-Friday
    study_start = day * 86400 + 19 * 3600  # 7 PM
    study_end = day * 86400 + 21 * 3600    # 9 PM
    study_blocks.append({"begin": study_start, "end": study_end})

api.set_device_parental_control(mac_address, "schedule",
                               schedule_blocks=study_blocks)
print("📚 Study hours restriction set (7-9 PM weekdays)")

# List all devices with parental controls
print("\\n=== Devices with Parental Controls ===")
controlled_devices = api.list_devices_with_parental_controls()

for device in controlled_devices:
    status_icon = "🔴" if device['control_type'] == 'block' else "⏰" if device['control_type'] == 'daily_limits' else "📅"
    active_icon = "🟢" if device['active'] else "⚪"
    
    print(f"{status_icon} {device['name']} ({device['device_type']}) {active_icon}")
    print(f"   MAC: {device['mac_address']}")
    print(f"   Control: {device['summary']}")

# Device management examples
print("\\n=== Device Management ===")

# Set device name and type for better organization
api.set_device_name(mac_address, "John's Laptop")
api.set_device_type(mac_address, "Laptop")

# Get comprehensive device information
device_details = api.get_device_details(mac_address)
print(f"Device: {device_details.get('Name', 'Unknown')}")
print(f"Type: {device_details.get('DeviceType', 'Unknown')}")
print(f"IP: {device_details.get('IPAddress', 'Unknown')}")
print(f"Active: {device_details.get('Active', False)}")

# Get device management summary
management_info = api.get_device_management_info(mac_address)
print(f"\\nManagement Summary: {management_info.get('summary', 'No restrictions')}")
print(f"Scheduled: {management_info.get('is_scheduled', False)}")
print(f"Blocked: {management_info.get('is_blocked', False)}")

# Helper functions for time formatting
print("\\n=== Time Helper Examples ===")

# Convert schedule times to readable format
sample_time = 79200  # Monday 10 PM
readable_time = api.format_time_seconds_to_readable(sample_time)
print(f"Schedule time {sample_time} seconds = {readable_time}")

# Create bedtime schedule for different scenarios
# Weekdays only
weekday_bedtime = api.create_bedtime_schedule_blocks(22, 6, [0,1,2,3,4])
print(f"Weekday bedtime blocks: {len(weekday_bedtime)} periods")

# Every day
daily_bedtime = api.create_bedtime_schedule_blocks(23, 7, [0,1,2,3,4,5,6])
print(f"Daily bedtime blocks: {len(daily_bedtime)} periods")

# Weekend different hours
weekend_bedtime = api.create_bedtime_schedule_blocks(24, 8, [5,6])  # Sat-Sun
print(f"Weekend bedtime blocks: {len(weekend_bedtime)} periods")

# Quick setup examples for common scenarios
print("\\n=== Quick Setup Examples ===")

# Scenario 1: Young child (strict limits)
child_mac = "AA:BB:CC:DD:EE:FF"
api.set_device_daily_time_limits(child_mac, 
                                weekday_minutes=60,   # 1 hour weekdays
                                weekend_minutes=120)  # 2 hours weekends
print("👶 Young child limits set: 1h weekdays, 2h weekends")

# Scenario 2: Teenager (moderate limits with bedtime)
teen_mac = "11:22:33:44:55:66"
api.set_device_daily_time_limits(teen_mac,
                                weekday_minutes=180,  # 3 hours weekdays
                                weekend_minutes=360)  # 6 hours weekends

# Add bedtime for teenager
teen_bedtime = api.create_bedtime_schedule_blocks(23, 7, [0,1,2,3,4])
api.set_device_parental_control(teen_mac, "schedule", 
                               schedule_blocks=teen_bedtime)
print("👦 Teenager limits: 3h/6h + bedtime 11 PM - 7 AM")

# Scenario 3: Gaming console (weekend only with time limits)
console_mac = "77:88:99:AA:BB:CC"
console_limits = {
    "Mon": 0, "Tue": 0, "Wed": 0, "Thu": 0, "Fri": 60,  # No gaming Mon-Thu, 1h Friday
    "Sat": 240, "Sun": 180  # 4h Saturday, 3h Sunday
}
api.set_device_parental_control(console_mac, "daily_limits",
                               daily_limits=console_limits)
print("🎮 Gaming console: Fri-Sun only with time limits")

# Scenario 4: Homework time (block during study hours)
student_mac = "DD:EE:FF:00:11:22"
homework_blocks = []
for day in [0,1,2,3,4]:  # Monday-Friday
    # Block 4-6 PM (homework time)
    homework_start = day * 86400 + 16 * 3600  # 4 PM
    homework_end = day * 86400 + 18 * 3600    # 6 PM
    homework_blocks.append({"begin": homework_start, "end": homework_end})

api.set_device_parental_control(student_mac, "schedule",
                               schedule_blocks=homework_blocks)
print("📖 Student device: Blocked 4-6 PM for homework")

# Check final status
print("\\n=== Final Status Check ===")
for mac, name in [
    (child_mac, "Child"),
    (teen_mac, "Teenager"), 
    (console_mac, "Console"),
    (student_mac, "Student")
]:
    status = api.get_device_parental_control_status(mac)
    print(f"{name}: {status['summary']}")
```

## Device Management

### Device Information
```python
# Get detailed device information
device_info = api.get_device_details("DC:A6:32:C2:61:E3")
print(f"Device: {device_info['Name']} ({device_info['DeviceType']})")
print(f"Status: {'Online' if device_info['Active'] else 'Offline'}")
print(f"IP: {device_info['IPAddress']}")

# Get comprehensive management info
management_info = api.get_device_management_info("DC:A6:32:C2:61:E3")
print(f"Summary: {management_info['summary']}")
print(f"Scheduled: {management_info['is_scheduled']}")
print(f"Blocked: {management_info['is_blocked']}")

# List all devices with management status
devices = api.list_managed_devices()
for device in devices:
    print(f"{device['name']}: {device['device_type']} - {device['mac_address']}")
```

### Device Organization
```python
# Set device name and type for better organization
api.set_device_name("A8:A1:59:33:F1:E4", "John's Laptop")
api.set_device_type("A8:A1:59:33:F1:E4", "Laptop")

# Available device types
device_types = api.get_common_device_types()
# Returns: ["Computer", "Laptop", "Tablet", "Smartphone", "Printer", 
#          "Television", "MediaPlayer", "GameConsole", "SmartSpeaker", ...]
```

### Parental Controls & Device Scheduling
```python
# Get current device schedule
schedule = api.get_device_schedule("A8:A1:59:33:F1:E4")
if schedule:
    print(f"Device has active schedule: {schedule['enable']}")

# Set bedtime schedule (10 PM - 7 AM, weekdays only)
api.set_device_bedtime_schedule(
    "A8:A1:59:33:F1:E4",
    bedtime_hour=22,  # 10 PM
    wakeup_hour=7,    # 7 AM  
    weekdays_only=True
)

# Set study hours (disable device during study time)
api.set_device_study_hours(
    "A8:A1:59:33:F1:E4",
    study_start_hour=19,  # 7 PM
    study_end_hour=21,    # 9 PM
    study_days=[0,1,2,3,4]  # Monday-Friday
)

# Custom time schedule (advanced)
schedule_blocks = [
    {"begin": 72000, "end": 115200},   # Monday 20:00 - Tuesday 08:00
    {"begin": 439200, "end": 442800}   # Friday 19:00 - 21:00
]
api.set_device_schedule("A8:A1:59:33:F1:E4", schedule_blocks)

# Block/unblock devices
api.block_device_permanently("A8:A1:59:33:F1:E4")  # Permanent block
api.unblock_device("A8:A1:59:33:F1:E4")             # Remove all restrictions
api.remove_device_schedule("A8:A1:59:33:F1:E4")    # Remove schedule only
```

### Time Format Helper
```python
# Helper function for calculating time blocks
def time_to_seconds(day, hour, minute=0):
    """Convert day/hour/minute to seconds from Monday 00:00"""
    return day * 24 * 3600 + hour * 3600 + minute * 60

# Examples:
monday_8pm = time_to_seconds(0, 20)      # Monday 8:00 PM
friday_6am = time_to_seconds(4, 6)       # Friday 6:00 AM
sunday_11pm = time_to_seconds(6, 23)     # Sunday 11:00 PM
```

### Port Forwarding

```python
# Get current port forwarding rules
print("=== Current IPv4 Port Forwarding Rules ===")
ipv4_rules = api.get_port_forwarding("webui")

for rule in ipv4_rules:
    status_icon = "🟢" if rule['Enable'] else "🔴"
    protocol = api.format_protocol(rule['Protocol'])
    
    print(f"{status_icon} {rule['Description'] or rule['Id']}")
    print(f"   {rule['ExternalPort']} → {rule['DestinationIPAddress']}:{rule['InternalPort']} ({protocol})")
    print(f"   Status: {rule['Status']}")

print("\\n=== Current IPv6 Pinholes ===")
ipv6_rules = api.get_ipv6_pinholes()

for rule in ipv6_rules:
    status_icon = "🟢" if rule['Enable'] else "🔴"
    protocol = api.format_protocol(rule['Protocol'])
    
    print(f"{status_icon} {rule['Description'] or rule['Id']}")
    print(f"   Port {rule['DestinationPort']} → {rule['DestinationIPAddress']} ({protocol})")
    print(f"   Status: {rule['Status']}")

# Add IPv4 port forwarding rules
print("\\n=== Adding IPv4 Port Forwarding Rules ===")

# SSH access to a server
ssh_rule_id = api.add_port_forwarding_rule(
    rule_id="SSH",
    internal_port="22",
    external_port="22",
    destination_ip="192.168.2.100",
    protocol="6",  # TCP
    description="SSH Server Access",
    enabled=True
)
print(f"✅ SSH rule created: {ssh_rule_id}")

# Web server with custom port
web_rule_id = api.add_port_forwarding_rule(
    rule_id="WebServer",
    internal_port="80",
    external_port="8080",
    destination_ip="192.168.2.101",
    protocol="6",  # TCP
    description="Web Server",
    enabled=True
)
print(f"✅ Web server rule created: {web_rule_id}")

# Game server with UDP
game_rule_id = api.add_port_forwarding_rule(
    rule_id="GameServer",
    internal_port="7777",
    external_port="7777",
    destination_ip="192.168.2.102",
    protocol="17",  # UDP
    description="Game Server",
    enabled=True
)
print(f"✅ Game server rule created: {game_rule_id}")

# Multiple protocols (TCP + UDP)
dns_rule_id = api.add_port_forwarding_rule(
    rule_id="DNS",
    internal_port="53",
    external_port="5353",
    destination_ip="192.168.2.104",
    protocol="6,17",  # TCP + UDP
    description="DNS Server",
    enabled=True
)
print(f"✅ DNS rule created: {dns_rule_id}")

# Add IPv6 pinholes
print("\\n=== Adding IPv6 Pinholes ===")

# SSH access to IPv6 server
ipv6_ssh_rule_id = api.add_ipv6_pinhole(
    destination_ip="2a02:a46f:ff52:0:f5a6:3bb7:c600:efc0",
    destination_port="22",
    protocol="6",  # TCP
    description="SSH IPv6 Server",
    enabled=True
)
print(f"✅ IPv6 SSH rule created: {ipv6_ssh_rule_id}")

# Web server on IPv6
ipv6_web_rule_id = api.add_ipv6_pinhole(
    destination_ip="2a02:a46f:ff52:0:a1b2:c3d4:e5f6:7890",
    destination_port="443",
    protocol="6",  # TCP
    description="HTTPS Server IPv6",
    enabled=True
)
print(f"✅ IPv6 HTTPS rule created: {ipv6_web_rule_id}")

# Rule management examples
print("\\n=== Rule Management ===")

# Update existing rule
api.update_port_forwarding_rule(
    rule_id=ssh_rule_id,
    external_port="2222",  # Change external port
    description="SSH Server (Custom Port)"
)
print("🔧 SSH rule updated to use external port 2222")

# Disable a rule temporarily
api.disable_port_forwarding_rule(game_rule_id)
print("⏸️ Game server rule disabled")

# Enable it back
api.enable_port_forwarding_rule(game_rule_id)
print("▶️ Game server rule enabled")

# Update IPv6 pinhole
api.update_ipv6_pinhole(
    rule_id=ipv6_web_rule_id,
    destination_port="80,443",  # Allow both HTTP and HTTPS
    description="Web Server IPv6 (HTTP+HTTPS)"
)
print("🔧 IPv6 web rule updated for HTTP+HTTPS")

# Using the unified management interface
print("\\n=== Unified Management Interface ===")

# List all IPv4 rules
ipv4_rules = api.manage_port_forwarding("list")
print(f"📋 IPv4 rules: {len(ipv4_rules)} found")

# List all IPv6 rules
ipv6_rules = api.manage_port_forwarding("list", ip_version=6)
print(f"📋 IPv6 rules: {len(ipv6_rules)} found")

# Add rule using unified interface
minecraft_rule_id = api.manage_port_forwarding(
    "add", "Minecraft",
    internal_port="25565",
    external_port="25565",
    destination_ip="192.168.2.105",
    protocol="6",
    description="Minecraft Server"
)
print(f"🎮 Minecraft rule created: {minecraft_rule_id}")

# Add IPv6 rule using unified interface
ipv6_minecraft_rule_id = api.manage_port_forwarding(
    "add",
    ip_version=6,
    destination_ip="2a02:a46f:ff52:0:1234:5678:9abc:def0",
    destination_port="25565",
    protocol="6",
    description="Minecraft Server IPv6"
)
print(f"🎮 IPv6 Minecraft rule created: {ipv6_minecraft_rule_id}")

# Get specific rule details
ssh_details = api.manage_port_forwarding("get", ssh_rule_id)
if ssh_details:
    print(f"🔍 SSH rule details:")
    print(f"   External: {ssh_details['ExternalPort']}")
    print(f"   Internal: {ssh_details['DestinationIPAddress']}:{ssh_details['InternalPort']}")
    print(f"   Protocol: {api.format_protocol(ssh_details['Protocol'])}")
    print(f"   Status: {ssh_details['Status']}")

# Common service examples with standard ports
print("\\n=== Common Services Setup ===")

common_services = [
    {"name": "HTTP", "port": "80", "protocol": "6", "description": "Web Server HTTP"},
    {"name": "HTTPS", "port": "443", "protocol": "6", "description": "Web Server HTTPS"},
    {"name": "SMTP", "port": "25", "protocol": "6", "description": "Mail Server SMTP"},
    {"name": "POP3", "port": "110", "protocol": "6", "description": "Mail Server POP3"},
    {"name": "IMAP", "port": "143", "protocol": "6", "description": "Mail Server IMAP"},
    {"name": "FTP", "port": "21", "protocol": "6", "description": "FTP Server"},
    {"name": "DNS", "port": "53", "protocol": "6,17", "description": "DNS Server"},
    {"name": "Minecraft", "port": "25565", "protocol": "6", "description": "Minecraft Server"},
]

print("Available common service templates:")
for service in common_services:
    protocol_name = "TCP" if service["protocol"] == "6" else "UDP" if service["protocol"] == "17" else "TCP+UDP"
    print(f"   • {service['name']}: Port {service['port']} ({protocol_name}) - {service['description']}")

# Example: Set up a complete web server
target_ip = "192.168.2.120"
print(f"\\n🌐 Setting up complete web server at {target_ip}:")

# HTTP
http_rule = api.add_port_forwarding_rule(
    rule_id="WebHTTP",
    internal_port="80",
    external_port="80",
    destination_ip=target_ip,
    protocol="6",
    description="Web Server HTTP"
)

# HTTPS
https_rule = api.add_port_forwarding_rule(
    rule_id="WebHTTPS",
    internal_port="443",
    external_port="443",
    destination_ip=target_ip,
    protocol="6",
    description="Web Server HTTPS"
)

print(f"✅ Web server ready: HTTP ({http_rule}) + HTTPS ({https_rule})")
```


## Not Supported Yet

The following APIs are available on KPN Box routers but not yet implemented in this library due to lack of access for testing:

| Feature Category | Available (GET) | Missing (SET/Configuration) | Notes |
|---|---|---|---|
| **Mobile Internet Backup** | ✅ `get_wwan_status()` | ❌ WWAN configuration functions | Can monitor mobile backup status, signal strength, and technology |
| **Television/IPTV** | ✅ `get_iptv_ip()` | ❌ IPTV service configuration<br>❌ Set-top box management | Can get IPTV interface IP address |
| **Telephone/VoIP** | ✅ `get_voice_profiles()`<br>✅ `get_voice_trunks()`<br>✅ `get_voice_handsets()`<br>✅ `get_voice_groups()`<br>✅ `ring_test_phone()` | ❌ VoIP service configuration<br>❌ Phone book management<br>❌ Call history access | Can monitor VoIP status, SIP trunks, handsets, and test phone functionality |

### Why These Features Are Missing

- **Hardware Dependencies**: These features require specific hardware modules (mobile modem, IPTV decoder, telephone ports) that may not be available on all KPN Box models
- **Service Dependencies**: IPTV and telephony require active KPN service subscriptions
- **Testing Limitations**: I don't have access to test environments with these services enabled

### Contributions Welcome

If you have access to KPN Box routers with these services active and can help test the SET/configuration functions, contributions are very welcome! The GET functions show that the basic API structure is there - we just need to figure out the configuration parameters.

## Error Handling

```python
from kpnboxapi import KPNBoxAPI, AuthenticationError, ConnectionError

try:
    with KPNBoxAPI() as api:
        api.login(password="wrong_password")
        devices = api.get_devices()
except AuthenticationError:
    print("Invalid credentials")
except ConnectionError:
    print("Cannot connect to KPN Box")
```

## Supported Models

- ✅ KPN Box 14 (fully tested)
- ❓ KPN Box 12 (may work)
- ❓ Other models (untested)

## Requirements

- Python 3.8+
- requests >= 2.25.0
- Network access to KPN Box

## License

MIT License