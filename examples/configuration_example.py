#!/usr/bin/env python3

"""
Network Configuration example for KPNBoxAPI.

This script demonstrates how to:
1. Configure network interface settings (duplex mode and link speed)
2. Enable/disable IPv6 globally
3. Configure DNS servers for different networks
4. Modify LAN and guest network settings

Note: These changes affect your router configuration. Use with caution.
"""

from kpnboxapi import KPNBoxAPI, AuthenticationError, ConnectionError


def main():
    try:
        with KPNBoxAPI() as api:
            # Login to the router
            password = input("Enter router password: ")
            api.login(password=password)
            print("✅ Successfully logged in\n")
            
            # Show current configuration first
            print("📋 Current Configuration:")
            print("-" * 50)
            
            # Show current LAN configuration
            lan_config = api.get_lan_config()
            ipv4_config = lan_config['ipv4']
            ipv6_config = lan_config['ipv6']
            
            print(f"LAN IPv4: {ipv4_config.get('Address')}/{ipv4_config.get('PrefixLength')}")
            print(f"DHCP: {'Enabled' if ipv4_config.get('DHCPEnable') else 'Disabled'}")
            print(f"DHCP Range: {ipv4_config.get('DHCPMinAddress')} - {ipv4_config.get('DHCPMaxAddress')}")
            
            # Show current DNS servers
            dns_servers = api.get_dns_servers()
            print(f"IPv4 DNS: {dns_servers.get('ipv4', 'Not set')}")
            print(f"IPv6 DNS: {dns_servers.get('ipv6', 'Not set')}")
            
            # Show current IPv6 status
            netmaster_config = api.get_netmaster_config()
            ipv6_enabled = netmaster_config.get('EnableIPv6', False)
            ipv6_mode = netmaster_config.get('IPv6PrefixMode', 'Unknown')
            print(f"IPv6: {'Enabled' if ipv6_enabled else 'Disabled'} ({ipv6_mode})")
            
            print("\n" + "=" * 60)
            print("CONFIGURATION MENU")
            print("=" * 60)
            
            while True:
                print("\nSelect an option:")
                print("1. Configure network interface (duplex/speed)")
                print("2. Enable/disable IPv6")
                print("3. Configure DNS servers")
                print("4. Configure LAN IPv4 settings")
                print("5. Configure guest network")
                print("6. Show current configuration")
                print("0. Exit")
                
                choice = input("\nEnter your choice (0-6): ").strip()
                
                if choice == "0":
                    print("\n👋 Goodbye!")
                    break
                elif choice == "1":
                    configure_interface(api)
                elif choice == "2":
                    configure_ipv6(api)
                elif choice == "3":
                    configure_dns_servers(api)
                elif choice == "4":
                    configure_lan_ipv4(api)
                elif choice == "5":
                    configure_guest_network(api)
                elif choice == "6":
                    show_current_config(api)
                else:
                    print("❌ Invalid choice. Please try again.")
    
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def configure_interface(api):
    """Configure network interface settings."""
    print("\n🔧 Network Interface Configuration")
    print("-" * 40)
    
    interface = input("Interface name (default: eth4): ").strip() or "eth4"
    
    # Configure duplex mode
    print("\nDuplex modes: Auto, Half, Full")
    duplex = input("Duplex mode (default: Auto): ").strip() or "Auto"
    
    if duplex not in ["Auto", "Half", "Full"]:
        print("❌ Invalid duplex mode")
        return
    
    try:
        success = api.set_interface_duplex(interface, duplex)
        if success:
            print(f"✅ Duplex mode set to {duplex}")
        else:
            print("❌ Failed to set duplex mode")
    except Exception as e:
        print(f"❌ Error setting duplex: {e}")
    
    # Configure link speed
    print("\nLink speed: -1 for Auto, or speed in Mbps (e.g., 100, 1000)")
    speed_input = input("Link speed (default: -1 for Auto): ").strip() or "-1"
    
    try:
        speed = int(speed_input)
        success = api.set_interface_speed(interface, speed)
        if success:
            speed_desc = "Auto" if speed == -1 else f"{speed} Mbps"
            print(f"✅ Link speed set to {speed_desc}")
        else:
            print("❌ Failed to set link speed")
    except ValueError:
        print("❌ Invalid speed value")
    except Exception as e:
        print(f"❌ Error setting speed: {e}")


def configure_ipv6(api):
    """Configure IPv6 settings."""
    print("\n🌐 IPv6 Configuration")
    print("-" * 30)
    
    current_config = api.get_netmaster_config()
    current_status = "Enabled" if current_config.get('EnableIPv6') else "Disabled"
    current_mode = current_config.get('IPv6PrefixMode', 'Unknown')
    
    print(f"Current status: {current_status} ({current_mode})")
    
    enable_input = input("Enable IPv6? (y/n, default: y): ").strip().lower()
    enabled = enable_input != 'n'
    
    if enabled:
        print("\nPrefix modes: DHCPv6, RA")
        prefix_mode = input("Prefix mode (default: DHCPv6): ").strip() or "DHCPv6"
        
        if prefix_mode not in ["DHCPv6", "RA"]:
            print("❌ Invalid prefix mode")
            return
    else:
        prefix_mode = "DHCPv6"  # Default for disable
    
    try:
        success = api.set_ipv6_enabled(enabled, prefix_mode)
        if success:
            status = "enabled" if enabled else "disabled"
            print(f"✅ IPv6 {status} with {prefix_mode} mode")
        else:
            print("❌ Failed to configure IPv6")
    except Exception as e:
        print(f"❌ Error configuring IPv6: {e}")


def configure_dns_servers(api):
    """Configure DNS servers."""
    print("\n🌍 DNS Server Configuration")
    print("-" * 35)
    
    # Show current DNS servers
    current_dns = api.get_dns_servers()
    print(f"Current IPv4 DNS: {current_dns.get('ipv4', 'Not set')}")
    print(f"Current IPv6 DNS: {current_dns.get('ipv6', 'Not set')}")
    
    network = input("\\nNetwork (lan/guest, default: lan): ").strip() or "lan"
    if network not in ["lan", "guest"]:
        print("❌ Invalid network")
        return
    
    # Configure IPv4 DNS
    print("\\nIPv4 DNS servers (comma-separated, e.g., 9.9.9.9,149.112.112.112)")
    ipv4_dns = input("IPv4 DNS (enter to skip): ").strip()
    
    # Configure IPv6 DNS
    print("\\nIPv6 DNS servers (comma-separated, e.g., 2620:fe::fe,2620:fe::9)")
    ipv6_dns = input("IPv6 DNS (enter to skip): ").strip()
    
    if not ipv4_dns and not ipv6_dns:
        print("❌ No DNS servers provided")
        return
    
    try:
        results = api.set_dns_servers(
            ipv4_dns=ipv4_dns if ipv4_dns else None,
            ipv6_dns=ipv6_dns if ipv6_dns else None,
            network=network
        )
        
        if results.get('ipv4'):
            print(f"✅ IPv4 DNS configured for {network} network")
        if results.get('ipv6'):
            print(f"✅ IPv6 DNS configured for {network} network")
        
        if not any(results.values()):
            print("❌ Failed to configure DNS servers")
            
    except Exception as e:
        print(f"❌ Error configuring DNS: {e}")


def configure_lan_ipv4(api):
    """Configure LAN IPv4 settings."""
    print("\n🏠 LAN IPv4 Configuration")
    print("-" * 30)
    
    # Show current configuration
    current_config = api.get_lan_ipv4_config()
    print(f"Current address: {current_config.get('Address')}/{current_config.get('PrefixLength')}")
    print(f"Current DHCP: {'Enabled' if current_config.get('DHCPEnable') else 'Disabled'}")
    print(f"Current DHCP range: {current_config.get('DHCPMinAddress')} - {current_config.get('DHCPMaxAddress')}")
    
    print("\\nEnter new values (press Enter to keep current):")
    
    # Collect new settings
    address = input(f"Gateway IP ({current_config.get('Address')}): ").strip()
    prefix = input(f"Prefix length ({current_config.get('PrefixLength')}): ").strip()
    dhcp_enable = input("Enable DHCP (y/n): ").strip().lower()
    dhcp_min = input(f"DHCP min ({current_config.get('DHCPMinAddress')}): ").strip()
    dhcp_max = input(f"DHCP max ({current_config.get('DHCPMaxAddress')}): ").strip()
    dns_servers = input("DNS servers (comma-separated): ").strip()
    
    # Convert inputs
    try:
        params = {}
        if address:
            params['address'] = address
        if prefix:
            params['prefix_length'] = int(prefix)
        if dhcp_enable:
            params['dhcp_enabled'] = dhcp_enable == 'y'
        if dhcp_min:
            params['dhcp_min_address'] = dhcp_min
        if dhcp_max:
            params['dhcp_max_address'] = dhcp_max
        if dns_servers:
            params['dns_servers'] = dns_servers
        
        if not params:
            print("❌ No changes specified")
            return
        
        success = api.set_lan_ipv4_config(network="lan", **params)
        if success:
            print("✅ LAN IPv4 configuration updated")
        else:
            print("❌ Failed to update LAN configuration")
            
    except ValueError:
        print("❌ Invalid prefix length")
    except Exception as e:
        print(f"❌ Error updating LAN configuration: {e}")


def configure_guest_network(api):
    """Configure guest network settings."""
    print("\n🏨 Guest Network Configuration")
    print("-" * 35)
    
    print("Configuring guest network with sensible defaults...")
    
    try:
        # Configure guest network with typical settings
        success = api.set_lan_ipv4_config(
            network="guest",
            dns_servers="8.8.8.8,8.8.4.4",
            address="192.168.3.254",
            dhcp_enabled=True,
            dhcp_min_address="192.168.3.10",
            dhcp_max_address="192.168.3.100",
            prefix_length=24
        )
        
        if success:
            print("✅ Guest network configured successfully")
            print("   Network: 192.168.3.0/24")
            print("   Gateway: 192.168.3.254")
            print("   DHCP: 192.168.3.10 - 192.168.3.100")
            print("   DNS: 8.8.8.8, 8.8.4.4")
        else:
            print("❌ Failed to configure guest network")
            
    except Exception as e:
        print(f"❌ Error configuring guest network: {e}")


def show_current_config(api):
    """Show current router configuration."""
    print("\n📋 Current Router Configuration")
    print("=" * 50)
    
    try:
        # LAN configuration
        lan_config = api.get_lan_config()
        ipv4 = lan_config['ipv4']
        ipv6 = lan_config['ipv6']
        
        print(f"🏠 LAN Network:")
        print(f"   IPv4: {ipv4.get('Address')}/{ipv4.get('PrefixLength')}")
        print(f"   DHCP: {'Enabled' if ipv4.get('DHCPEnable') else 'Disabled'}")
        if ipv4.get('DHCPEnable'):
            print(f"   DHCP Range: {ipv4.get('DHCPMinAddress')} - {ipv4.get('DHCPMaxAddress')}")
        
        # DNS servers
        dns_servers = api.get_dns_servers()
        print(f"\\n🌍 DNS Servers:")
        print(f"   IPv4: {dns_servers.get('ipv4', 'Not configured')}")
        print(f"   IPv6: {dns_servers.get('ipv6', 'Not configured')}")
        
        # IPv6 status
        netmaster = api.get_netmaster_config()
        ipv6_enabled = netmaster.get('EnableIPv6', False)
        ipv6_mode = netmaster.get('IPv6PrefixMode', 'Unknown')
        print(f"\\n🌐 IPv6 Status:")
        print(f"   Status: {'Enabled' if ipv6_enabled else 'Disabled'}")
        print(f"   Mode: {ipv6_mode}")
        
        # Connection status
        if api.is_connected():
            wan_status = api.get_wan_status()
            print(f"\\n🌍 Internet Connection:")
            print(f"   Status: ✅ Connected")
            print(f"   Public IP: {wan_status.get('IPAddress', 'Unknown')}")
        else:
            print(f"\\n🌍 Internet Connection: ❌ Not connected")
        
    except Exception as e:
        print(f"❌ Error retrieving configuration: {e}")


if __name__ == "__main__":
    main() 