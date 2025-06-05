#!/usr/bin/env python3
"""
DHCP Server Configuration Example

This script demonstrates how to use the KPNBoxAPI for comprehensive DHCP server
configuration and network management.

Features demonstrated:
- DHCP server configuration for home and guest networks
- Network isolation setup
- DNS server configuration
- DHCP pool management
- Lease time optimization
- Network security settings
"""

import sys
import os
from datetime import datetime, timedelta
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kpnboxapi import KPNBoxAPI


def print_separator(title=""):
    """Print a visual separator with optional title."""
    if title:
        print(f"\n{'='*20} {title} {'='*20}")
    else:
        print(f"\n{'='*60}")


def display_current_dhcp_config(api):
    """Display current DHCP server configuration."""
    print_separator("Current DHCP Configuration")
    
    print("🏠 Home Network DHCP Settings:")
    try:
        home_dhcp = api.get_default_dhcp_server()
        
        print(f"   Gateway IP: {home_dhcp.get('gateway_ip', 'Unknown')}")
        print(f"   Subnet Mask: /{home_dhcp.get('prefix_length', 'Unknown')}")
        print(f"   DHCP Enabled: {home_dhcp.get('dhcp_enabled', 'Unknown')}")
        print(f"   DHCP Pool: {home_dhcp.get('dhcp_min_address', 'Unknown')} - {home_dhcp.get('dhcp_max_address', 'Unknown')}")
        print(f"   Lease Time: {home_dhcp.get('lease_time', 'Unknown')} seconds")
        print(f"   DNS Servers: {home_dhcp.get('dns_servers', 'Unknown')}")
        
        if home_dhcp.get('dhcp_enabled'):
            # Show active leases
            leases = api.get_default_dhcp_leases()
            active_leases = [lease for lease in leases if lease.get('active', False)]
            print(f"   Active Leases: {len(active_leases)}")
        
    except Exception as e:
        print(f"   ❌ Error getting home DHCP config: {e}")
    
    print("\n🌐 Guest Network DHCP Settings:")
    try:
        guest_dhcp = api.get_guest_dhcp_server()
        
        print(f"   Gateway IP: {guest_dhcp.get('gateway_ip', 'Unknown')}")
        print(f"   Subnet Mask: /{guest_dhcp.get('prefix_length', 'Unknown')}")
        print(f"   DHCP Enabled: {guest_dhcp.get('dhcp_enabled', 'Unknown')}")
        print(f"   DHCP Pool: {guest_dhcp.get('dhcp_min_address', 'Unknown')} - {guest_dhcp.get('dhcp_max_address', 'Unknown')}")
        print(f"   Lease Time: {guest_dhcp.get('lease_time', 'Unknown')} seconds")
        print(f"   DNS Servers: {guest_dhcp.get('dns_servers', 'Unknown')}")
        
        if guest_dhcp.get('dhcp_enabled'):
            # Show active leases
            leases = api.get_guest_dhcp_leases()
            active_leases = [lease for lease in leases if lease.get('active', False)]
            print(f"   Active Leases: {len(active_leases)}")
        
    except Exception as e:
        print(f"   ❌ Error getting guest DHCP config: {e}")


def demonstrate_dhcp_configuration(api):
    """Demonstrate DHCP server configuration."""
    print_separator("DHCP Configuration Examples")
    
    print("🔧 DHCP Server Configuration Features:")
    print("   Configure IP ranges, lease times, DNS servers, and more")
    print("   Separate configuration for home and guest networks")
    print("   Network isolation and security settings")
    
    print("\n💡 Basic DHCP Configuration Examples:")
    
    # Home network example
    print("\n📋 Home Network Configuration:")
    print("   # Configure home network with standard settings")
    print("   api.set_home_dhcp_config(")
    print("       gateway_ip='192.168.2.254',")
    print("       subnet_mask=24,")
    print("       dhcp_enabled=True,")
    print("       dhcp_min_ip='192.168.2.100',")
    print("       dhcp_max_ip='192.168.2.200',")
    print("       lease_time_seconds=14400,  # 4 hours")
    print("       dns_servers='9.9.9.9,149.112.112.112'")
    print("   )")
    
    # Guest network example
    print("\n📋 Guest Network Configuration:")
    print("   # Configure guest network with limited access")
    print("   api.set_guest_dhcp_config(")
    print("       gateway_ip='192.168.3.254',")
    print("       dhcp_min_ip='192.168.3.1',")
    print("       dhcp_max_ip='192.168.3.32',  # Only 32 IPs")
    print("       lease_time_seconds=3600,     # 1 hour for guests")
    print("       dns_servers='9.9.9.9,149.112.112.112'")
    print("   )")
    
    # Network isolation example
    print("\n📋 Complete Network Isolation Setup:")
    print("   # Set up isolated home and guest networks")
    print("   result = api.configure_network_isolation(")
    print("       home_subnet='192.168.2.0/24',")
    print("       guest_subnet='192.168.3.0/24',")
    print("       home_dhcp_range=('192.168.2.100', '192.168.2.200'),")
    print("       guest_dhcp_range=('192.168.3.1', '192.168.3.50')")
    print("   )")


def demonstrate_dns_configuration(api):
    """Demonstrate DNS server configuration options."""
    print_separator("DNS Server Configuration")
    
    print("🌐 DNS Server Configuration Options:")
    
    # Popular DNS providers
    dns_options = {
        "Quad9 (Privacy & Security)": "9.9.9.9,149.112.112.112",
        "Cloudflare (Fast)": "1.1.1.1,1.0.0.1", 
        "Google DNS": "8.8.8.8,8.8.4.4",
        "OpenDNS (Family Safe)": "208.67.222.222,208.67.220.220",
        "ISP Default": "auto"
    }
    
    for name, servers in dns_options.items():
        print(f"\n📡 {name}:")
        print(f"   DNS Servers: {servers}")
        if "Privacy" in name:
            print("   ✅ Blocks malicious domains")
            print("   ✅ Privacy focused")
        elif "Fast" in name:
            print("   ⚡ Ultra-fast response times")
            print("   🌍 Global network")
        elif "Family" in name:
            print("   👨‍👩‍👧‍👦 Blocks adult content")
            print("   🛡️ Phishing protection")
    
    print("\n💡 DNS Configuration Examples:")
    print("   # Set secure DNS for home network")
    print("   api.set_home_dhcp_config(dns_servers='9.9.9.9,149.112.112.112')")
    print("")
    print("   # Set fast DNS for guest network")
    print("   api.set_guest_dhcp_config(dns_servers='1.1.1.1,1.0.0.1')")
    print("")
    print("   # Family-safe DNS for all networks")
    print("   family_dns = '208.67.222.222,208.67.220.220'")
    print("   api.set_home_dhcp_config(dns_servers=family_dns)")
    print("   api.set_guest_dhcp_config(dns_servers=family_dns)")


def demonstrate_lease_time_optimization(api):
    """Demonstrate DHCP lease time optimization."""
    print_separator("DHCP Lease Time Optimization")
    
    print("⏰ DHCP Lease Time Guidelines:")
    
    lease_scenarios = [
        {
            "scenario": "Home Devices (Desktops, Smart TVs)",
            "time": 86400,  # 24 hours
            "reason": "Stable devices that don't move"
        },
        {
            "scenario": "Mobile Devices (Phones, Laptops)", 
            "time": 14400,  # 4 hours
            "reason": "Devices that connect/disconnect frequently"
        },
        {
            "scenario": "Guest Network",
            "time": 3600,   # 1 hour
            "reason": "Temporary access, faster IP recycling"
        },
        {
            "scenario": "IoT Devices (Smart Home)",
            "time": 43200,  # 12 hours
            "reason": "Usually stable but may reconnect"
        },
        {
            "scenario": "Office Hours Only",
            "time": 28800,  # 8 hours
            "reason": "Matches typical work day"
        }
    ]
    
    for scenario in lease_scenarios:
        hours = scenario["time"] // 3600
        print(f"\n📱 {scenario['scenario']}:")
        print(f"   Lease Time: {scenario['time']} seconds ({hours} hours)")
        print(f"   Reason: {scenario['reason']}")
    
    print("\n💡 Lease Time Configuration Examples:")
    print("   # Optimize for home network (mixed devices)")
    print("   api.set_home_dhcp_config(lease_time_seconds=14400)  # 4 hours")
    print("")
    print("   # Optimize for guest network (short stays)")
    print("   api.set_guest_dhcp_config(lease_time_seconds=3600)  # 1 hour")
    print("")
    print("   # Long leases for stable devices")
    print("   api.set_home_dhcp_config(lease_time_seconds=86400)  # 24 hours")


def interactive_dhcp_configurator(api):
    """Interactive DHCP configuration tool."""
    print_separator("Interactive DHCP Configurator")
    
    print("🔧 Interactive DHCP Configuration Tool")
    print("Configure your network settings step by step.")
    
    while True:
        print(f"\n📋 Configuration Options:")
        print(f"   1. Configure Home Network DHCP")
        print(f"   2. Configure Guest Network DHCP")
        print(f"   3. Set up Network Isolation")
        print(f"   4. Quick DNS Server Change")
        print(f"   5. Optimize Lease Times")
        print(f"   6. View Current Configuration")
        print(f"   7. Exit")
        
        try:
            choice = input("\nEnter choice (1-7): ").strip()
            
            if choice == '1':
                configure_home_network_interactive(api)
                
            elif choice == '2':
                configure_guest_network_interactive(api)
                
            elif choice == '3':
                configure_network_isolation_interactive(api)
                
            elif choice == '4':
                configure_dns_interactive(api)
                
            elif choice == '5':
                configure_lease_times_interactive(api)
                
            elif choice == '6':
                display_current_dhcp_config(api)
                
            elif choice == '7':
                print("👋 Exiting DHCP configurator!")
                break
                
            else:
                print("❌ Invalid choice")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


def configure_home_network_interactive(api):
    """Interactive home network configuration."""
    print(f"\n🏠 Home Network Configuration")
    
    try:
        # Get current config
        current = api.get_default_dhcp_server()
        
        print(f"Current settings:")
        print(f"   Gateway: {current.get('gateway_ip', 'Unknown')}")
        print(f"   DHCP Pool: {current.get('dhcp_min_address', 'Unknown')} - {current.get('dhcp_max_address', 'Unknown')}")
        print(f"   DNS: {current.get('dns_servers', 'Unknown')}")
        
        print(f"\nEnter new values (press Enter to keep current):")
        
        gateway = input(f"Gateway IP [{current.get('gateway_ip', '192.168.2.254')}]: ").strip()
        if not gateway:
            gateway = current.get('gateway_ip', '192.168.2.254')
        
        dhcp_min = input(f"DHCP Min IP [{current.get('dhcp_min_address', '192.168.2.100')}]: ").strip()
        if not dhcp_min:
            dhcp_min = current.get('dhcp_min_address', '192.168.2.100')
        
        dhcp_max = input(f"DHCP Max IP [{current.get('dhcp_max_address', '192.168.2.200')}]: ").strip()
        if not dhcp_max:
            dhcp_max = current.get('dhcp_max_address', '192.168.2.200')
        
        # DNS options
        print(f"\nDNS Options:")
        print(f"   1. Quad9 (9.9.9.9,149.112.112.112) - Privacy & Security")
        print(f"   2. Cloudflare (1.1.1.1,1.0.0.1) - Fast")
        print(f"   3. Google (8.8.8.8,8.8.4.4) - Reliable")
        print(f"   4. Custom")
        print(f"   5. Keep current")
        
        dns_choice = input("Select DNS option (1-5): ").strip()
        dns_servers = current.get('dns_servers', '9.9.9.9,149.112.112.112')
        
        if dns_choice == '1':
            dns_servers = '9.9.9.9,149.112.112.112'
        elif dns_choice == '2':
            dns_servers = '1.1.1.1,1.0.0.1'
        elif dns_choice == '3':
            dns_servers = '8.8.8.8,8.8.4.4'
        elif dns_choice == '4':
            custom_dns = input("Enter DNS servers (comma-separated): ").strip()
            if custom_dns:
                dns_servers = custom_dns
        
        # Confirm changes
        print(f"\n📋 Configuration Summary:")
        print(f"   Gateway IP: {gateway}")
        print(f"   DHCP Pool: {dhcp_min} - {dhcp_max}")
        print(f"   DNS Servers: {dns_servers}")
        
        confirm = input("\nApply these settings? (y/n): ")
        if confirm.lower().startswith('y'):
            print("🔄 Applying configuration...")
            
            success = api.set_home_dhcp_config(
                gateway_ip=gateway,
                dhcp_min_ip=dhcp_min,
                dhcp_max_ip=dhcp_max,
                dns_servers=dns_servers
            )
            
            print(f"Configuration: {'✅ Success' if success else '❌ Failed'}")
        else:
            print("❌ Configuration cancelled")
            
    except Exception as e:
        print(f"❌ Error: {e}")


def configure_guest_network_interactive(api):
    """Interactive guest network configuration."""
    print(f"\n🌐 Guest Network Configuration")
    
    try:
        # Get current config
        current = api.get_guest_dhcp_server()
        
        print(f"Current settings:")
        print(f"   Gateway: {current.get('gateway_ip', 'Unknown')}")
        print(f"   DHCP Pool: {current.get('dhcp_min_address', 'Unknown')} - {current.get('dhcp_max_address', 'Unknown')}")
        
        print(f"\nGuest network presets:")
        print(f"   1. Small (10 devices) - 192.168.3.1 to 192.168.3.10")
        print(f"   2. Medium (25 devices) - 192.168.3.1 to 192.168.3.25")
        print(f"   3. Large (50 devices) - 192.168.3.1 to 192.168.3.50")
        print(f"   4. Custom range")
        
        preset = input("Select preset (1-4): ").strip()
        
        if preset == '1':
            dhcp_min, dhcp_max = '192.168.3.1', '192.168.3.10'
        elif preset == '2':
            dhcp_min, dhcp_max = '192.168.3.1', '192.168.3.25'
        elif preset == '3':
            dhcp_min, dhcp_max = '192.168.3.1', '192.168.3.50'
        elif preset == '4':
            dhcp_min = input("DHCP Min IP: ").strip()
            dhcp_max = input("DHCP Max IP: ").strip()
        else:
            print("❌ Invalid preset")
            return
        
        # Lease time
        print(f"\nLease time options:")
        print(f"   1. 1 hour (guests)")
        print(f"   2. 4 hours (visitors)")
        print(f"   3. 24 hours (extended stay)")
        
        lease_choice = input("Select lease time (1-3): ").strip()
        lease_times = {'1': 3600, '2': 14400, '3': 86400}
        lease_time = lease_times.get(lease_choice, 3600)
        
        # Apply configuration
        print(f"\n📋 Guest Network Summary:")
        print(f"   DHCP Pool: {dhcp_min} - {dhcp_max}")
        print(f"   Lease Time: {lease_time // 3600} hours")
        
        confirm = input("\nApply these settings? (y/n): ")
        if confirm.lower().startswith('y'):
            print("🔄 Applying guest network configuration...")
            
            success = api.set_guest_dhcp_config(
                dhcp_min_ip=dhcp_min,
                dhcp_max_ip=dhcp_max,
                lease_time_seconds=lease_time,
                dns_servers='9.9.9.9,149.112.112.112'
            )
            
            print(f"Guest network configuration: {'✅ Success' if success else '❌ Failed'}")
        else:
            print("❌ Configuration cancelled")
            
    except Exception as e:
        print(f"❌ Error: {e}")


def configure_network_isolation_interactive(api):
    """Interactive network isolation setup."""
    print(f"\n🔒 Network Isolation Setup")
    
    print(f"This will configure separate networks for home and guest access.")
    print(f"Recommended for security and performance.")
    
    presets = {
        '1': {
            'name': 'Standard Setup',
            'home_subnet': '192.168.2.0/24',
            'guest_subnet': '192.168.3.0/24',
            'home_range': ('192.168.2.100', '192.168.2.200'),
            'guest_range': ('192.168.3.1', '192.168.3.50')
        },
        '2': {
            'name': 'Large Home Network',
            'home_subnet': '192.168.1.0/24',
            'guest_subnet': '192.168.3.0/24',
            'home_range': ('192.168.1.50', '192.168.1.200'),
            'guest_range': ('192.168.3.1', '192.168.3.25')
        },
        '3': {
            'name': 'Business Setup',
            'home_subnet': '10.0.1.0/24',
            'guest_subnet': '10.0.100.0/24',
            'home_range': ('10.0.1.100', '10.0.1.200'),
            'guest_range': ('10.0.100.1', '10.0.100.50')
        }
    }
    
    print(f"\nNetwork Isolation Presets:")
    for key, preset in presets.items():
        print(f"   {key}. {preset['name']}")
        print(f"      Home: {preset['home_subnet']} (DHCP: {preset['home_range'][0]} - {preset['home_range'][1]})")
        print(f"      Guest: {preset['guest_subnet']} (DHCP: {preset['guest_range'][0]} - {preset['guest_range'][1]})")
    
    choice = input("\nSelect preset (1-3): ").strip()
    
    if choice in presets:
        preset = presets[choice]
        
        print(f"\n📋 Network Isolation Summary:")
        print(f"   Setup: {preset['name']}")
        print(f"   Home Network: {preset['home_subnet']}")
        print(f"   Guest Network: {preset['guest_subnet']}")
        print(f"   DNS: Quad9 (secure)")
        
        confirm = input("\nApply network isolation? (y/n): ")
        if confirm.lower().startswith('y'):
            print("🔄 Configuring network isolation...")
            
            result = api.configure_network_isolation(
                home_subnet=preset['home_subnet'],
                guest_subnet=preset['guest_subnet'],
                home_dhcp_range=preset['home_range'],
                guest_dhcp_range=preset['guest_range'],
                dns_servers='9.9.9.9,149.112.112.112'
            )
            
            print(f"\n📊 Results:")
            print(f"   Home Network: {'✅ Success' if result.get('home') else '❌ Failed'}")
            print(f"   Guest Network: {'✅ Success' if result.get('guest') else '❌ Failed'}")
            
            if result.get('error'):
                print(f"   Error: {result['error']}")
        else:
            print("❌ Configuration cancelled")
    else:
        print("❌ Invalid preset")


def configure_dns_interactive(api):
    """Interactive DNS configuration."""
    print(f"\n🌐 DNS Server Configuration")
    
    dns_options = {
        '1': ('9.9.9.9,149.112.112.112', 'Quad9 - Privacy & Security'),
        '2': ('1.1.1.1,1.0.0.1', 'Cloudflare - Ultra Fast'),
        '3': ('8.8.8.8,8.8.4.4', 'Google - Reliable'),
        '4': ('208.67.222.222,208.67.220.220', 'OpenDNS - Family Safe'),
        '5': ('custom', 'Custom DNS Servers')
    }
    
    print(f"DNS Server Options:")
    for key, (servers, desc) in dns_options.items():
        print(f"   {key}. {desc}")
        if servers != 'custom':
            print(f"      Servers: {servers}")
    
    choice = input("\nSelect DNS option (1-5): ").strip()
    
    if choice in dns_options:
        servers, desc = dns_options[choice]
        
        if servers == 'custom':
            servers = input("Enter DNS servers (comma-separated): ").strip()
            if not servers:
                print("❌ No DNS servers provided")
                return
        
        print(f"\nApply {desc} to:")
        print(f"   1. Home network only")
        print(f"   2. Guest network only")
        print(f"   3. Both networks")
        
        network_choice = input("Select option (1-3): ").strip()
        
        if network_choice in ['1', '3']:
            success_home = api.set_home_dhcp_config(dns_servers=servers)
            print(f"Home network DNS: {'✅ Success' if success_home else '❌ Failed'}")
        
        if network_choice in ['2', '3']:
            success_guest = api.set_guest_dhcp_config(dns_servers=servers)
            print(f"Guest network DNS: {'✅ Success' if success_guest else '❌ Failed'}")
    else:
        print("❌ Invalid option")


def configure_lease_times_interactive(api):
    """Interactive lease time configuration."""
    print(f"\n⏰ DHCP Lease Time Configuration")
    
    scenarios = {
        '1': (14400, 'Mixed Devices (4 hours) - Recommended'),
        '2': (3600, 'High Turnover (1 hour) - Guest/Cafe'),
        '3': (86400, 'Stable Devices (24 hours) - Office'),
        '4': (43200, 'IoT Devices (12 hours) - Smart Home'),
        '5': ('custom', 'Custom lease time')
    }
    
    print(f"Lease Time Scenarios:")
    for key, (time, desc) in scenarios.items():
        print(f"   {key}. {desc}")
    
    choice = input("\nSelect scenario (1-5): ").strip()
    
    if choice in scenarios:
        lease_time, desc = scenarios[choice]
        
        if lease_time == 'custom':
            try:
                hours = float(input("Enter lease time in hours: "))
                lease_time = int(hours * 3600)
                desc = f"Custom ({hours} hours)"
            except ValueError:
                print("❌ Invalid time format")
                return
        
        print(f"\nApply {desc} to:")
        print(f"   1. Home network only")
        print(f"   2. Guest network only")
        print(f"   3. Both networks")
        
        network_choice = input("Select option (1-3): ").strip()
        
        if network_choice in ['1', '3']:
            success_home = api.set_home_dhcp_config(lease_time_seconds=lease_time)
            print(f"Home network lease time: {'✅ Success' if success_home else '❌ Failed'}")
        
        if network_choice in ['2', '3']:
            success_guest = api.set_guest_dhcp_config(lease_time_seconds=lease_time)
            print(f"Guest network lease time: {'✅ Success' if success_guest else '❌ Failed'}")
    else:
        print("❌ Invalid option")


def main():
    """Main function demonstrating DHCP configuration features."""
    print("🌐 KPN Box - DHCP Server Configuration Demo")
    print("=" * 60)
    
    try:
        # Initialize API connection
        from kpnboxapi import KPNBoxAPI
        
        api = KPNBoxAPI()
        print(f"🔌 Connecting to KPN Box...")
        
        if not api.login():
            print("❌ Failed to login to KPN Box")
            return
        
        print(f"✅ Successfully connected to KPN Box!")
        
        while True:
            print(f"\n📋 DHCP Configuration Demonstrations:")
            print(f"   1. View current DHCP configuration")
            print(f"   2. DHCP configuration examples")
            print(f"   3. DNS server configuration")
            print(f"   4. Lease time optimization")
            print(f"   5. Interactive DHCP configurator")
            print(f"   6. Exit")
            
            try:
                choice = input("\nSelect demonstration (1-6): ").strip()
                
                if choice == '1':
                    display_current_dhcp_config(api)
                    
                elif choice == '2':
                    demonstrate_dhcp_configuration(api)
                    
                elif choice == '3':
                    demonstrate_dns_configuration(api)
                    
                elif choice == '4':
                    demonstrate_lease_time_optimization(api)
                    
                elif choice == '5':
                    interactive_dhcp_configurator(api)
                    
                elif choice == '6':
                    print("\n👋 Thank you for using the DHCP Configuration Demo!")
                    break
                    
                else:
                    print("❌ Invalid choice. Please select 1-6.")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                
    except ImportError:
        print("❌ Could not import KPNBoxAPI. Make sure it's installed.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main() 