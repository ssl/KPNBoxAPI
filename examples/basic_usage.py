#!/usr/bin/env python3
"""
Basic usage example for KPNBoxAPI.

This script demonstrates:
1. How to connect and login to a KPN Box
2. How to get device data
3. How to display basic device information
"""

from kpnboxapi import KPNBoxAPI, AuthenticationError, ConnectionError


def main():
    """Basic example of using KPNBoxAPI."""
    print("KPNBoxAPI - Basic Example")
    print("=" * 40)
    
    # Get password from user
    password = input("Enter your KPN Box password: ")
    
    try:
        # Create API client and login
        api = KPNBoxAPI(host="192.168.2.254")
        print("\nConnecting and logging in...")
        api.login(username="admin", password=password)
        print("✅ Login successful!")
        
        # Get router information
        print("\nGetting modem information...")
        router_info = api.get_device_info()
        print(f"📡 Modem: {router_info.get('Manufacturer', 'Unknown')} {router_info.get('ModelName', 'Unknown')}")
        print(f"🔧 Firmware: {router_info.get('SoftwareVersion', 'Unknown')}")
        print(f"🌐 External IP: {router_info.get('ExternalIPAddress', 'Unknown')}")
        print(f"⏰ Uptime: {router_info.get('UpTime', 0)} seconds")
        
        # Get internet connection status
        print("\nGetting internet connection information...")
        connection_info = api.get_connection_info()
        wan_status = connection_info['wan_status']
        ppp_info = connection_info['ppp_info']
        
        connected = api.is_connected()
        status_icon = "🟢" if connected else "🔴"
        
        print(f"🌐 Internet Connection:")
        print("-" * 40)
        print(f"{status_icon} Status: {wan_status.get('ConnectionState', 'Unknown')}")
        
        if connected:
            print(f"🌍 Public IPv4: {wan_status.get('IPAddress', 'Unknown')}")
            print(f"🌍 Public IPv6: {wan_status.get('IPv6Address', 'Unknown')}")
            print(f"🌍 Gateway: {wan_status.get('RemoteGateway', 'Unknown')}")
            print(f"🌍 DNS: {wan_status.get('DNSServers', 'Unknown')}")
            
            if ppp_info:
                print(f"🔗 PPPoE Session: {ppp_info.get('PPPoESessionID', 'Unknown')}")
                print(f"🔗 Transport: {ppp_info.get('TransportType', 'Unknown')}")
                
                # Protocol status
                ipcp = "✅" if ppp_info.get('IPCPEnable') else "❌"
                ipv6cp = "✅" if ppp_info.get('IPv6CPEnable') else "❌"
                print(f"🔗 Protocols: IPCP {ipcp} | IPv6CP {ipv6cp}")
        else:
            last_error = wan_status.get('LastConnectionError', 'Unknown')
            print(f"❌ Last Error: {last_error}")
        
        print()
        
        # Get public IPv6 address
        print("\nGetting public IPv6 address...")
        ipv6_address = api.get_public_ipv6()
        print(f"🌐 Public IPv6: {ipv6_address}")
        
        # Get WiFi networks
        print("\nGetting WiFi network information...")
        all_wifi = api.get_all_wifi_networks()
        
        print("📶 WiFi Networks:")
        print("-" * 40)
        
        # Show regular networks
        regular_networks = all_wifi['regular']
        print(f"🏠 Regular Networks ({len(regular_networks)}):")
        for network in regular_networks:
            ssid = network.get('SSID', 'Unknown')
            status = network.get('VAPStatus', 'Unknown')
            security = network.get('Security', {}).get('ModeEnabled', 'Unknown')
            password = network.get('Security', {}).get('KeyPassPhrase', 'Unknown')
            connected = network.get('AssociatedDeviceNumberOfEntries', 0)
            
            status_icon = "🟢" if status == "Up" else "🔴"
            print(f"  {status_icon} {ssid}")
            print(f"     Security: {security}")
            print(f"     Password: {password}")
            print(f"     Connected devices: {connected}")
            print()
        
        # Show guest networks
        guest_networks = all_wifi['guest']
        print(f"👥 Guest Networks ({len(guest_networks)}):")
        for network in guest_networks:
            ssid = network.get('SSID', 'Unknown')
            status = network.get('VAPStatus', 'Unknown')
            security = network.get('Security', {}).get('ModeEnabled', 'Unknown')
            password = network.get('Security', {}).get('KeyPassPhrase', 'Unknown')
            connected = network.get('AssociatedDeviceNumberOfEntries', 0)
            
            status_icon = "🟢" if status == "Up" else "🔴"
            print(f"  {status_icon} {ssid}")
            print(f"     Security: {security}")
            print(f"     Password: {password}")
            print(f"     Connected devices: {connected}")
            print()
        
        # Get DHCP server information
        print("\nGetting DHCP server information...")
        dhcp_servers = api.get_all_dhcp_servers()
        
        print("🌐 DHCP Servers:")
        print("-" * 40)
        
        # Show default DHCP
        default_dhcp = dhcp_servers['default']
        status_icon = "🟢" if default_dhcp.get('Enable') else "🔴"
        print(f"{status_icon} Default Network DHCP:")
        print(f"   Status: {default_dhcp.get('Status', 'Unknown')}")
        print(f"   IP Range: {default_dhcp.get('MinAddress', 'Unknown')} - {default_dhcp.get('MaxAddress', 'Unknown')}")
        print(f"   Gateway: {default_dhcp.get('IPRouters', 'Unknown')}")
        print(f"   DNS: {default_dhcp.get('DNSServers', 'Unknown')}")
        print(f"   Lease Time: {default_dhcp.get('LeaseTime', 0)} seconds")
        print(f"   Active Leases: {default_dhcp.get('LeaseNumberOfEntries', 0)}")
        print()
        
        # Show guest DHCP
        guest_dhcp = dhcp_servers['guest']
        status_icon = "🟢" if guest_dhcp.get('Enable') else "🔴"
        print(f"{status_icon} Guest Network DHCP:")
        print(f"   Status: {guest_dhcp.get('Status', 'Unknown')}")
        print(f"   IP Range: {guest_dhcp.get('MinAddress', 'Unknown')} - {guest_dhcp.get('MaxAddress', 'Unknown')}")
        print(f"   Gateway: {guest_dhcp.get('IPRouters', 'Unknown')}")
        print(f"   Active Leases: {guest_dhcp.get('LeaseNumberOfEntries', 0)}")
        print()
        
        # Get DHCP lease details
        print("\nGetting DHCP lease details...")
        dhcp_leases = api.get_all_dhcp_leases()
        
        # Show default network leases
        default_leases = dhcp_leases['default']
        active_default = [lease for lease in default_leases if lease.get('Active', False)]
        
        print(f"💻 Default Network Devices ({len(active_default)} active / {len(default_leases)} total):")
        print("-" * 40)
        
        for lease in active_default[:10]:  # Show first 10 active devices
            name = lease.get('FriendlyName', 'Unknown Device')
            ip = lease.get('IPAddress', 'No IP')
            mac = lease.get('MACAddress', 'No MAC')
            reserved = lease.get('Reserved', False)
            
            reserve_icon = "📌" if reserved else "🔄"
            print(f"  {reserve_icon} {name}")
            print(f"     IP: {ip} | MAC: {mac}")
            
            # Show lease time
            remaining = lease.get('LeaseTimeRemaining', 0)
            if remaining == -1:
                print(f"     Lease: Permanent")
            elif remaining > 0:
                hours = remaining // 3600
                minutes = (remaining % 3600) // 60
                print(f"     Lease: {hours}h {minutes}m remaining")
            print()
        
        if len(active_default) > 10:
            print(f"   ... and {len(active_default) - 10} more active devices")
            print()
        
        # Show guest network leases if any
        guest_leases = dhcp_leases['guest']
        active_guest = [lease for lease in guest_leases if lease.get('Active', False)]
        
        if active_guest:
            print(f"👥 Guest Network Devices ({len(active_guest)} active):")
            print("-" * 40)
            
            for lease in active_guest:
                name = lease.get('FriendlyName', 'Unknown Device')
                ip = lease.get('IPAddress', 'No IP')
                print(f"  🌐 {name} - {ip}")
            print()
        
        # Get Dynamic DNS information
        print("\nGetting Dynamic DNS information...")
        dyndns_hosts = api.get_dyndns_hosts()
        
        if dyndns_hosts:
            print("🌍 Dynamic DNS Hosts:")
            print("-" * 40)
            
            for host in dyndns_hosts:
                hostname = host.get('hostname', 'Unknown')
                service = host.get('service', 'Unknown')
                status = host.get('status', 'Unknown')
                enabled = host.get('enable', False)
                last_update = host.get('last_update', '')
                
                status_icon = "🟢" if enabled and status == "UPDATED" else "🔴"
                print(f"{status_icon} {hostname}")
                print(f"   Service: {service}")
                print(f"   Status: {status}")
                print(f"   Enabled: {'Yes' if enabled else 'No'}")
                
                if last_update:
                    from datetime import datetime
                    try:
                        dt = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
                        print(f"   Last Update: {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    except:
                        print(f"   Last Update: {last_update}")
                print()
        else:
            print("🌍 No Dynamic DNS hosts configured")
            print()
        
        # Get network statistics
        print("\nGetting network statistics...")
        all_net_stats = api.get_all_network_stats()
        
        print("📊 Ethernet Interface Statistics:")
        print("-" * 40)
        
        for interface, stats in all_net_stats.items():
            if stats.get('Available', True):  # Interface is available
                rx_bytes = stats.get('RxBytes', 0)
                tx_bytes = stats.get('TxBytes', 0)
                rx_packets = stats.get('RxPackets', 0)
                tx_packets = stats.get('TxPackets', 0)
                rx_errors = stats.get('RxErrors', 0)
                tx_errors = stats.get('TxErrors', 0)
                
                print(f"🔌 {interface}:")
                print(f"   Traffic: ↓{api.format_bytes(rx_bytes)} ↑{api.format_bytes(tx_bytes)}")
                print(f"   Packets: ↓{rx_packets:,} ↑{tx_packets:,}")
                
                # Check for errors
                total_errors = rx_errors + tx_errors
                if total_errors > 0:
                    print(f"   ⚠️  Errors: {total_errors}")
                else:
                    print(f"   ✅ No errors")
                print()
            else:
                print(f"🔌 {interface}: Not available")
                print()
        
        # Show specific WAN and PPP statistics
        wan_total = all_net_stats.get('eth4', {})
        ppp_stats = all_net_stats.get('ppp_vdata', {})
        
        if wan_total.get('Available', True):
            print("🌐 Total WAN Traffic:")
            print(f"   Download: {api.format_bytes(wan_total.get('RxBytes', 0))}")
            print(f"   Upload: {api.format_bytes(wan_total.get('TxBytes', 0))}")
            print(f"   Packets: ↓{wan_total.get('RxPackets', 0):,} ↑{wan_total.get('TxPackets', 0):,}")
            print()
        
        if ppp_stats.get('Available', True):
            print("🔗 PPP Connection Traffic:")
            print(f"   Download: {api.format_bytes(ppp_stats.get('RxBytes', 0))}")
            print(f"   Upload: {api.format_bytes(ppp_stats.get('TxBytes', 0))}")
            
            # PPP error checking
            ppp_rx_errors = ppp_stats.get('RxErrors', 0)
            ppp_tx_errors = ppp_stats.get('TxErrors', 0)
            if ppp_rx_errors > 0 or ppp_tx_errors > 0:
                print(f"   ⚠️  PPP Errors: RX={ppp_rx_errors}, TX={ppp_tx_errors}")
            else:
                print(f"   ✅ No PPP errors")
            print()
        
        # Get port forwarding rules
        print("\nGetting port forwarding rules...")
        all_pf_rules = api.get_all_port_forwarding()
        
        if all_pf_rules:
            total_rules = sum(len(rules) for rules in all_pf_rules.values())
            print(f"🔓 Port Forwarding Rules ({total_rules} total):")
            print("-" * 40)
            
            for origin, rules in all_pf_rules.items():
                if rules:
                    print(f"{origin.upper()} Rules:")
                    
                    for rule in rules:
                        description = rule.get('Description', 'Unnamed')
                        external_port = rule.get('ExternalPort', 'Unknown')
                        internal_port = rule.get('InternalPort', 'Unknown')
                        target_ip = rule.get('DestinationIPAddress', 'Unknown')
                        protocol = api.format_protocol(rule.get('Protocol', ''))
                        enabled = rule.get('Enable', False)
                        
                        status_icon = "🟢" if enabled else "🔴"
                        print(f"  {status_icon} {description}")
                        print(f"     {protocol} {external_port} → {target_ip}:{internal_port}")
                        print()
        else:
            print("🔓 No port forwarding rules configured")
            print()
        
        # Get IPv6 pinhole rules
        print("\nGetting IPv6 pinhole rules...")
        ipv6_rules = api.get_ipv6_pinholes()
        
        if ipv6_rules:
            active_ipv6 = [rule for rule in ipv6_rules if rule.get('Enable', False)]
            print(f"🌐 IPv6 Pinhole Rules ({len(active_ipv6)} active / {len(ipv6_rules)} total):")
            print("-" * 40)
            
            for rule in ipv6_rules:
                description = rule.get('Description', 'Unnamed')
                dest_port = rule.get('DestinationPort', 'Unknown')
                target_ipv6 = rule.get('DestinationIPAddress', 'Unknown')
                protocol = api.format_protocol(rule.get('Protocol', ''))
                enabled = rule.get('Enable', False)
                
                status_icon = "🟢" if enabled else "🔴"
                print(f"  {status_icon} {description}")
                print(f"     {protocol} {dest_port} → {target_ipv6}")
                print()
        else:
            print("🌐 No IPv6 pinhole rules configured")
            print()
        
        # Get device data
        print("\nGetting device data...")
        
        # Get active devices
        active_devices = api.get_devices(filter='active')
        print(f"✅ Found {len(active_devices)} currently connected devices")
        
        # Get inactive devices  
        inactive_devices = api.get_devices(filter='inactive')
        print(f"✅ Found {len(inactive_devices)} previously connected devices")
        
        # Show currently connected devices
        print("\n🟢 Currently Connected Devices:")
        print("-" * 40)
        
        for i, device in enumerate(active_devices, 1):
            name = device.get('Name', 'Unknown')
            ip = device.get('IPAddress', 'No IP')
            mac = device.get('PhysAddress', 'No MAC')
            
            print(f"{i}. {name}")
            print(f"   MAC: {mac}")
            print(f"   IP:  {ip}")
            print()
        
        if not active_devices:
            print("   No devices currently connected")
            print()
        
        # Show previously connected devices
        print("🔴 Previously Connected Devices:")
        print("-" * 40)
        
        for i, device in enumerate(inactive_devices, 1):
            name = device.get('Name', 'Unknown')
            mac = device.get('PhysAddress', 'No MAC')
            last_connection = device.get('LastConnection', 'Unknown')
            
            print(f"{i}. {name}")
            print(f"   MAC: {mac}")
            print(f"   Last seen: {last_connection}")
            print()
        
        if not inactive_devices:
            print("   No previously connected devices found")
            print()
        
        # Get LAN configuration
        print("\nGetting LAN configuration...")
        lan_config = api.get_lan_config()
        
        print("🌐 LAN Network Configuration:")
        print("-" * 40)
        
        # IPv4 configuration
        ipv4_config = lan_config['ipv4']
        print("IPv4 Settings:")
        print(f"  Router IP: {ipv4_config.get('Address', 'Unknown')}")
        print(f"  Network: {ipv4_config.get('Address', 'Unknown')}/{ipv4_config.get('PrefixLength', 0)}")
        print(f"  DHCP: {'Enabled' if ipv4_config.get('DHCPEnable') else 'Disabled'}")
        print(f"  DHCP Range: {ipv4_config.get('DHCPMinAddress', 'Unknown')} - {ipv4_config.get('DHCPMaxAddress', 'Unknown')}")
        lease_time = ipv4_config.get('LeaseTime', 0)
        print(f"  Lease Time: {lease_time // 3600}h {(lease_time % 3600) // 60}m")
        print(f"  DNS Servers: {ipv4_config.get('DNSServers', 'Unknown')}")
        print(f"  NAT: {'Enabled' if ipv4_config.get('NATEnable') else 'Disabled'}")
        print()
        
        # IPv6 configuration
        ipv6_config = lan_config['ipv6']
        print("IPv6 Settings:")
        ipv6_enabled = ipv6_config.get('Enable', False)
        print(f"  IPv6: {'Enabled' if ipv6_enabled else 'Disabled'}")
        
        if ipv6_enabled:
            ipv6_address = ipv6_config.get('Address', '')
            if ipv6_address:
                print(f"  Address: {ipv6_address}/{ipv6_config.get('PrefixLength', 0)}")
            else:
                print(f"  Address: Auto-configured")
            
            print(f"  Interface: {ipv6_config.get('Intf', 'Unknown')}")
            print(f"  DHCPv6: {'Enabled' if ipv6_config.get('DHCPEnable') else 'Disabled'}")
            print(f"  IAPD: {'Enabled' if ipv6_config.get('DHCPIAPDEnable') else 'Disabled'}")
            print(f"  DNS Servers: {ipv6_config.get('DNSServers', 'Unknown')}")
        print()
        
        # DNS summary
        dns_servers = api.get_dns_servers()
        print("🌍 DNS Server Summary:")
        print("-" * 40)
        
        ipv4_dns = dns_servers['ipv4']
        if ipv4_dns:
            ipv4_list = ipv4_dns.split(',')
            print(f"IPv4 DNS ({len(ipv4_list)} servers): {ipv4_dns}")
        else:
            print("IPv4 DNS: Not configured")
            
        ipv6_dns = dns_servers['ipv6']
        if ipv6_dns:
            ipv6_list = ipv6_dns.split(',')
            print(f"IPv6 DNS ({len(ipv6_list)} servers): {ipv6_dns}")
        else:
            print("IPv6 DNS: Not configured")
        print()
        
        # Get NetMaster configuration
        print("\nGetting network master configuration...")
        netmaster_config = api.get_netmaster_config()
        
        print("🔧 Network Master Configuration:")
        print("-" * 40)
        print(f"  Interfaces Enabled: {'Yes' if netmaster_config.get('EnableInterfaces') else 'No'}")
        print(f"  IPv6 Globally Enabled: {'Yes' if netmaster_config.get('EnableIPv6') else 'No'}")
        print(f"  IPv6 Prefix Mode: {netmaster_config.get('IPv6PrefixMode', 'Unknown')}")
        print(f"  Physical Interfaces Disabled: {'Yes' if netmaster_config.get('DisablePhysicalInterfaces') else 'No'}")
        print(f"  WAN Mode: {netmaster_config.get('WANMode', 'Unknown')}")
        print()
        
        # Get DHCPv6 client status
        print("\nGetting DHCPv6 client status...")
        dhcpv6_status = api.get_dhcpv6_client_status()
        
        if dhcpv6_status:
            print("🌐 DHCPv6 Client Status (Router to ISP):")
            print("-" * 40)
            
            enabled = dhcpv6_status.get('Enable', False)
            status = dhcpv6_status.get('Status', False)
            dhcp_status = dhcpv6_status.get('DHCPStatus', 'Unknown')
            
            status_icon = "🟢" if enabled and status else "🔴"
            print(f"  {status_icon} DHCPv6 Client: {'Enabled' if enabled else 'Disabled'}")
            print(f"  Status: {dhcp_status}")
            print(f"  Interface: {dhcpv6_status.get('Name', 'Unknown')}")
            
            # Uptime
            uptime = dhcpv6_status.get('Uptime', 0)
            uptime_hours = uptime // 3600
            uptime_minutes = (uptime % 3600) // 60
            print(f"  Uptime: {uptime_hours}h {uptime_minutes}m")
            
            # DHCP details
            print(f"  DUID: {dhcpv6_status.get('DUID', 'Unknown')}")
            print(f"  Request Addresses: {'Yes' if dhcpv6_status.get('RequestAddresses') else 'No'}")
            print(f"  Request Prefixes: {'Yes' if dhcpv6_status.get('RequestPrefixes') else 'No'}")
            
            # Error checking
            last_error = dhcpv6_status.get('LastConnectionError', 'None')
            if last_error and last_error not in ['RenewTimeout', 'ERROR_NONE']:
                print(f"  ⚠️  Last Error: {last_error}")
            
            # Requested options
            requested_opts = dhcpv6_status.get('RequestedOptions', '')
            if requested_opts:
                opts_list = requested_opts.split(',')
                print(f"  Requested Options: {len(opts_list)} options")
            print()
        else:
            print("🌐 DHCPv6 Client: Not available")
            print()
        
        # Get HGW device information
        print("\nGetting Home Gateway device information...")
        hgw_info = api.get_hgw_device_info()
        
        print("🏠 Home Gateway Device Information:")
        print("-" * 40)
        
        # Basic device identity
        manufacturer = hgw_info.get('Manufacturer', 'Unknown')
        model = hgw_info.get('ModelName', 'Unknown')
        serial = hgw_info.get('SerialNumber', 'Unknown')
        firmware = hgw_info.get('SoftwareVersion', 'Unknown')
        hardware = hgw_info.get('HardwareVersion', 'Unknown')
        bootloader = hgw_info.get('BootLoaderVersion', 'Unknown')
        
        print(f"  📱 Device: {manufacturer} {model}")
        print(f"  🔑 Serial: {serial}")
        print(f"  💾 Firmware: {firmware}")
        print(f"  🔧 Hardware: {hardware}")
        print(f"  ⚙️  Bootloader: {bootloader}")
        
        # Connection status
        connection_state = hgw_info.get('ConnectionState', 'Unknown')
        connection_protocol = hgw_info.get('ConnectionProtocol', 'Unknown')
        ipv4_addr = hgw_info.get('ConnectionIPv4Address', 'Unknown')
        ipv6_addr = hgw_info.get('ConnectionIPv6Address', 'Unknown')
        gateway = hgw_info.get('RemoteGateway', 'Unknown')
        
        connection_icon = "🟢" if connection_state == "Connected" else "🔴"
        print(f"  {connection_icon} Connection: {connection_state}")
        print(f"  🔗 Protocol: {connection_protocol}")
        print(f"  🌐 Public IPv4: {ipv4_addr}")
        print(f"  🌐 Public IPv6: {ipv6_addr}")
        print(f"  🚪 Gateway: {gateway}")
        
        # Services status
        internet_available = hgw_info.get('Internet', False)
        iptv_available = hgw_info.get('IPTV', False)
        telephony_available = hgw_info.get('Telephony', False)
        
        print(f"  📡 Services:")
        internet_icon = "🟢" if internet_available else "🔴"
        iptv_icon = "🟢" if iptv_available else "🔴"
        telephony_icon = "🟢" if telephony_available else "🔴"
        
        print(f"     {internet_icon} Internet: {'Available' if internet_available else 'Unavailable'}")
        print(f"     {iptv_icon} IPTV: {'Available' if iptv_available else 'Unavailable'}")
        print(f"     {telephony_icon} Telephony: {'Available' if telephony_available else 'Unavailable'}")
        
        # Security and network link
        firewall_level = hgw_info.get('FirewallLevel', 'Unknown')
        link_state = hgw_info.get('LinkState', 'Unknown')
        link_type = hgw_info.get('LinkType', 'Unknown')
        
        link_icon = "🟢" if link_state == "up" else "🔴"
        print(f"  🔒 Firewall Level: {firewall_level}")
        print(f"  {link_icon} Network Link: {link_state} ({link_type})")
        print()
        
        # Get router time and NTP configuration
        print("\nGetting router time and NTP configuration...")
        time_config = api.get_time_config()
        
        print("🕒 Time Configuration:")
        print("-" * 40)
        
        # Current router time
        router_time = time_config['current_time']
        print(f"  Router Time: {router_time}")
        
        # NTP servers
        ntp_servers = time_config['ntp_servers']
        ntp_list = time_config['ntp_servers_list']
        
        print(f"  NTP Servers ({len(ntp_list)} configured):")
        for server_num, server_addr in ntp_servers.items():
            # Highlight KPN's official server
            if 'kpn.net' in server_addr:
                print(f"     {server_num}. {server_addr} ⭐ (KPN Official)")
            elif 'nl.pool.ntp.org' in server_addr:
                print(f"     {server_num}. {server_addr} 🇳🇱 (Dutch Pool)")
            else:
                print(f"     {server_num}. {server_addr}")
        
        # NTP analysis
        kpn_ntp = any('kpn.net' in server for server in ntp_list)
        nl_pool_count = sum(1 for server in ntp_list if 'nl.pool.ntp.org' in server)
        
        if kpn_ntp:
            print(f"  ✅ Using KPN's official NTP server")
        if nl_pool_count > 0:
            print(f"  ✅ Using {nl_pool_count} Dutch NTP pool servers")
        print()
        
        # Get system performance statistics
        print("\n📊 Getting system performance statistics...")
        stats = api.get_system_stats()
        if stats:
            print(f"✅ System Stats Retrieved:")
            print(f"   📅 Timestamp: {stats.get('timestamp', 'N/A')}")
            print(f"   ⏱️  Uptime: {stats.get('uptime_formatted', 'N/A')}")
            print(f"   🖥️  CPU Load:")
            load = stats.get('load_average', {})
            print(f"      1min: {load.get('1min', 0)}%")
            print(f"      5min: {load.get('5min', 0)}%") 
            print(f"      15min: {load.get('15min', 0)}%")
            print(f"   🧠 Memory:")
            memory = stats.get('memory', {})
            print(f"      Used: {memory.get('used_percentage', 0)}% ({api.format_memory_size(memory.get('used_bytes', 0))})")
            print(f"      Free: {memory.get('free_percentage', 0)}% ({api.format_memory_size(memory.get('free_bytes', 0))})")
            print(f"      Total: {api.format_memory_size(memory.get('total_bytes', 0))}")
            print(f"   🔧 Processes: {stats.get('processes', 0)}")
        else:
            print("❌ Could not retrieve system statistics")

        print("✅ Done!")
        
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main() 