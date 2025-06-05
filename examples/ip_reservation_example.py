#!/usr/bin/env python3
"""
IP Reservation Management Example

This script demonstrates how to use the KPNBoxAPI for managing DHCP static leases
(IP reservations) to ensure devices always get the same IP address.

Features demonstrated:
- Adding IP reservations for devices
- Removing IP reservations
- Updating/modifying existing reservations
- Smart device lookup by name
- Available IP suggestions
- Reservation validation and cleanup
- Comprehensive reservation management
"""

import sys
import os
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kpnboxapi import KPNBoxAPI


def print_separator(title=""):
    """Print a visual separator with optional title."""
    if title:
        print(f"\n{'='*20} {title} {'='*20}")
    else:
        print(f"\n{'='*60}")


def display_current_reservations(api):
    """Display current IP reservations for all networks."""
    print_separator("Current IP Reservations")
    
    # Home network reservations
    print("🏠 Home Network IP Reservations:")
    try:
        home_reservations = api.list_ip_reservations(pool_id="default", include_device_info=True)
        
        if home_reservations:
            print(f"   {'Device Name':<25} {'IP Address':<15} {'MAC Address':<18} {'Status'}")
            print(f"   {'-'*25} {'-'*15} {'-'*18} {'-'*10}")
            
            for res in home_reservations:
                status = "🟢 Active" if res.get('active') else "🔴 Inactive"
                device_name = res.get('device_name', 'Unknown')[:24]
                ip_addr = res.get('ip_address', 'Unknown')
                mac_addr = res.get('mac_address', 'Unknown')
                
                print(f"   {device_name:<25} {ip_addr:<15} {mac_addr:<18} {status}")
            
            print(f"\n   Total Home Reservations: {len(home_reservations)}")
        else:
            print("   No IP reservations found")
            
    except Exception as e:
        print(f"   ❌ Error getting home reservations: {e}")
    
    # Guest network reservations
    print("\n🌐 Guest Network IP Reservations:")
    try:
        guest_reservations = api.list_ip_reservations(pool_id="guest", include_device_info=True)
        
        if guest_reservations:
            print(f"   {'Device Name':<25} {'IP Address':<15} {'MAC Address':<18} {'Status'}")
            print(f"   {'-'*25} {'-'*15} {'-'*18} {'-'*10}")
            
            for res in guest_reservations:
                status = "🟢 Active" if res.get('active') else "🔴 Inactive"
                device_name = res.get('device_name', 'Unknown')[:24]
                ip_addr = res.get('ip_address', 'Unknown')
                mac_addr = res.get('mac_address', 'Unknown')
                
                print(f"   {device_name:<25} {ip_addr:<15} {mac_addr:<18} {status}")
            
            print(f"\n   Total Guest Reservations: {len(guest_reservations)}")
        else:
            print("   No guest network IP reservations found")
            
    except Exception as e:
        print(f"   ❌ Error getting guest reservations: {e}")


def demonstrate_ip_reservation_basics(api):
    """Demonstrate basic IP reservation operations."""
    print_separator("IP Reservation Basics")
    
    print("📋 IP Reservation Management:")
    print("   IP reservations ensure devices always get the same IP address")
    print("   Useful for servers, printers, NAS devices, and gaming consoles")
    print("   Helps with port forwarding and static configuration")
    
    print("\n💡 Basic Reservation Examples:")
    
    # Add reservation example
    print("\n📝 Adding IP Reservations:")
    print("   # Reserve IP for a printer")
    print("   success = api.add_static_lease('50:DE:06:9A:A6:98', '192.168.2.118')")
    print("   ")
    print("   # Reserve IP for a NAS device")
    print("   success = api.add_static_lease('AA:BB:CC:DD:EE:FF', '192.168.2.100')")
    print("   ")
    print("   # Reserve IP in guest network")
    print("   success = api.add_static_lease('11:22:33:44:55:66', '192.168.3.10', 'guest')")
    
    # Update reservation example  
    print("\n✏️ Updating IP Reservations:")
    print("   # Change device's reserved IP")
    print("   success = api.set_static_lease('00:17:88:4A:40:B4', '192.168.2.124')")
    print("   ")
    print("   # Smart device lookup by name")
    print("   success = api.reserve_device_ip('My Printer', '192.168.2.100')")
    
    # Remove reservation example
    print("\n🗑️ Removing IP Reservations:")
    print("   # Remove reservation by MAC address")
    print("   success = api.delete_static_lease('50:DE:06:9A:A6:98')")
    print("   ")
    print("   # Comprehensive management")
    print("   api.manage_device_ip_reservation('AA:BB:CC:DD:EE:FF', action='delete')")


def demonstrate_smart_reservations(api):
    """Demonstrate intelligent IP reservation features."""
    print_separator("Smart IP Reservation Features")
    
    print("🧠 Intelligent Reservation Management:")
    
    # Available IP suggestions
    print("\n💡 Finding Available IPs:")
    try:
        available_ips = api.suggest_available_ips(count=5)
        print(f"   Available IPs for home network:")
        for ip in available_ips:
            print(f"   • {ip}")
        
        guest_ips = api.suggest_available_ips(pool_id="guest", count=3)
        print(f"\n   Available IPs for guest network:")
        for ip in guest_ips:
            print(f"   • {ip}")
            
    except Exception as e:
        print(f"   ❌ Error getting available IPs: {e}")
    
    # Device lookup example
    print(f"\n🔍 Smart Device Lookup:")
    print(f"   # Reserve IP by device name (auto-finds MAC)")
    print(f"   api.reserve_device_ip('My Printer', '192.168.2.100')")
    print(f"   api.reserve_device_ip('Gaming Console', '192.168.2.101')")
    print(f"   api.reserve_device_ip('NAS Server', '192.168.2.102')")
    
    # Validation and cleanup
    print(f"\n🛠️ Reservation Validation:")
    try:
        validation_result = api.cleanup_invalid_reservations()
        
        print(f"   Issues found: {validation_result.get('total_issues', 0)}")
        
        if validation_result.get('recommendations'):
            print(f"   Recommendations:")
            for rec in validation_result['recommendations']:
                print(f"   • {rec}")
        else:
            print(f"   ✅ All reservations are valid")
            
    except Exception as e:
        print(f"   ❌ Error validating reservations: {e}")


def demonstrate_common_scenarios(api):
    """Demonstrate common IP reservation use cases."""
    print_separator("Common IP Reservation Scenarios")
    
    scenarios = [
        {
            "title": "🖨️ Network Printer",
            "description": "Always accessible at the same IP",
            "ip_range": "192.168.2.100-109",
            "example": "api.reserve_device_ip('HP Printer', '192.168.2.100')"
        },
        {
            "title": "🎮 Gaming Console",
            "description": "Stable connection for gaming and media",
            "ip_range": "192.168.2.110-119", 
            "example": "api.reserve_device_ip('PlayStation 5', '192.168.2.110')"
        },
        {
            "title": "💾 NAS/File Server",
            "description": "Critical infrastructure needs static IP",
            "ip_range": "192.168.2.120-129",
            "example": "api.reserve_device_ip('NAS Server', '192.168.2.120')"
        },
        {
            "title": "🏠 Smart Home Hub",
            "description": "IoT devices need consistent access",
            "ip_range": "192.168.2.130-139",
            "example": "api.reserve_device_ip('SmartThings Hub', '192.168.2.130')"
        },
        {
            "title": "📡 Access Point/Extender",
            "description": "Network infrastructure components",
            "ip_range": "192.168.2.140-149",
            "example": "api.reserve_device_ip('WiFi Extender', '192.168.2.140')"
        },
        {
            "title": "🔧 Development/Testing",
            "description": "Servers and development machines",
            "ip_range": "192.168.2.150-159",
            "example": "api.reserve_device_ip('Dev Server', '192.168.2.150')"
        }
    ]
    
    print("📋 Recommended IP Reservation Strategies:")
    
    for scenario in scenarios:
        print(f"\n{scenario['title']}")
        print(f"   Purpose: {scenario['description']}")
        print(f"   IP Range: {scenario['ip_range']}")
        print(f"   Example: {scenario['example']}")
    
    print(f"\n💡 Best Practices:")
    print(f"   • Reserve lower IPs (100-199) for important devices")
    print(f"   • Group similar devices in IP ranges")
    print(f"   • Leave space between groups for expansion")
    print(f"   • Document your IP allocation scheme")
    print(f"   • Regularly review and clean up unused reservations")


def interactive_reservation_manager(api):
    """Interactive IP reservation management tool."""
    print_separator("Interactive IP Reservation Manager")
    
    print("📋 Interactive IP Reservation Manager")
    print("Manage your device IP reservations step by step.")
    
    while True:
        print(f"\n📋 Reservation Management Options:")
        print(f"   1. View current reservations")
        print(f"   2. Add new IP reservation")
        print(f"   3. Update existing reservation") 
        print(f"   4. Remove IP reservation")
        print(f"   5. Smart device reservation (by name)")
        print(f"   6. Suggest available IPs")
        print(f"   7. Validate and cleanup reservations")
        print(f"   8. Bulk reservation wizard")
        print(f"   9. Exit")
        
        try:
            choice = input("\nEnter choice (1-9): ").strip()
            
            if choice == '1':
                display_current_reservations(api)
                
            elif choice == '2':
                add_reservation_interactive(api)
                
            elif choice == '3':
                update_reservation_interactive(api)
                
            elif choice == '4':
                remove_reservation_interactive(api)
                
            elif choice == '5':
                smart_reservation_interactive(api)
                
            elif choice == '6':
                suggest_ips_interactive(api)
                
            elif choice == '7':
                validate_reservations_interactive(api)
                
            elif choice == '8':
                bulk_reservation_wizard(api)
                
            elif choice == '9':
                print("👋 Exiting reservation manager!")
                break
                
            else:
                print("❌ Invalid choice")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


def add_reservation_interactive(api):
    """Interactive tool to add IP reservations."""
    print(f"\n📝 Add New IP Reservation")
    
    try:
        # Network selection
        print(f"Select network:")
        print(f"   1. Home network (default)")
        print(f"   2. Guest network")
        
        network_choice = input("Enter choice (1-2): ").strip()
        pool_id = "guest" if network_choice == "2" else "default"
        
        # MAC address
        mac_address = input("Enter device MAC address: ").strip()
        if not mac_address:
            print("❌ MAC address is required")
            return
        
        # Suggest available IPs
        print(f"\n💡 Available IP addresses:")
        try:
            available_ips = api.suggest_available_ips(pool_id=pool_id, count=5)
            for i, ip in enumerate(available_ips, 1):
                print(f"   {i}. {ip}")
        except Exception:
            print("   Could not fetch available IPs")
        
        # IP address
        ip_address = input("\nEnter IP address to reserve: ").strip()
        if not ip_address:
            print("❌ IP address is required")
            return
        
        # Confirmation
        network_name = "Guest" if pool_id == "guest" else "Home"
        print(f"\n📋 Reservation Summary:")
        print(f"   Network: {network_name}")
        print(f"   MAC Address: {mac_address}")
        print(f"   IP Address: {ip_address}")
        
        confirm = input("\nAdd this reservation? (y/n): ")
        if confirm.lower().startswith('y'):
            print("🔄 Adding IP reservation...")
            
            success = api.add_static_lease(mac_address, ip_address, pool_id)
            print(f"Reservation: {'✅ Success' if success else '❌ Failed'}")
        else:
            print("❌ Reservation cancelled")
            
    except Exception as e:
        print(f"❌ Error: {e}")


def update_reservation_interactive(api):
    """Interactive tool to update IP reservations."""
    print(f"\n✏️ Update IP Reservation")
    
    try:
        # Show current reservations
        print(f"Current reservations:")
        home_reservations = api.list_ip_reservations(pool_id="default")
        guest_reservations = api.list_ip_reservations(pool_id="guest")
        
        all_reservations = []
        for res in home_reservations:
            res['pool'] = 'default'
            all_reservations.append(res)
        for res in guest_reservations:
            res['pool'] = 'guest'
            all_reservations.append(res)
        
        if not all_reservations:
            print("   No reservations found to update")
            return
        
        for i, res in enumerate(all_reservations, 1):
            network = "Home" if res['pool'] == 'default' else "Guest"
            device_name = res.get('device_name', 'Unknown')
            print(f"   {i}. {device_name} - {res['ip_address']} ({res['mac_address']}) [{network}]")
        
        # Select reservation
        try:
            selection = int(input(f"\nSelect reservation to update (1-{len(all_reservations)}): "))
            if 1 <= selection <= len(all_reservations):
                selected = all_reservations[selection - 1]
            else:
                print("❌ Invalid selection")
                return
        except ValueError:
            print("❌ Invalid selection")
            return
        
        # New IP address
        current_ip = selected['ip_address']
        print(f"\nCurrent IP: {current_ip}")
        
        # Suggest available IPs
        try:
            available_ips = api.suggest_available_ips(pool_id=selected['pool'], count=5)
            print(f"Available IPs:")
            for ip in available_ips:
                print(f"   • {ip}")
        except Exception:
            pass
        
        new_ip = input("Enter new IP address: ").strip()
        if not new_ip:
            print("❌ IP address is required")
            return
        
        # Update reservation
        print(f"\n📋 Update Summary:")
        print(f"   Device: {selected.get('device_name', 'Unknown')}")
        print(f"   MAC: {selected['mac_address']}")
        print(f"   Old IP: {current_ip}")
        print(f"   New IP: {new_ip}")
        
        confirm = input("\nUpdate this reservation? (y/n): ")
        if confirm.lower().startswith('y'):
            print("🔄 Updating IP reservation...")
            
            success = api.set_static_lease(selected['mac_address'], new_ip, selected['pool'])
            print(f"Update: {'✅ Success' if success else '❌ Failed'}")
        else:
            print("❌ Update cancelled")
            
    except Exception as e:
        print(f"❌ Error: {e}")


def remove_reservation_interactive(api):
    """Interactive tool to remove IP reservations."""
    print(f"\n🗑️ Remove IP Reservation")
    
    try:
        # Show current reservations
        print(f"Current reservations:")
        home_reservations = api.list_ip_reservations(pool_id="default")
        guest_reservations = api.list_ip_reservations(pool_id="guest")
        
        all_reservations = []
        for res in home_reservations:
            res['pool'] = 'default'
            all_reservations.append(res)
        for res in guest_reservations:
            res['pool'] = 'guest'
            all_reservations.append(res)
        
        if not all_reservations:
            print("   No reservations found to remove")
            return
        
        for i, res in enumerate(all_reservations, 1):
            network = "Home" if res['pool'] == 'default' else "Guest"
            device_name = res.get('device_name', 'Unknown')
            status = "🟢" if res.get('active') else "🔴"
            print(f"   {i}. {status} {device_name} - {res['ip_address']} ({res['mac_address']}) [{network}]")
        
        # Select reservation to remove
        try:
            selection = int(input(f"\nSelect reservation to remove (1-{len(all_reservations)}): "))
            if 1 <= selection <= len(all_reservations):
                selected = all_reservations[selection - 1]
            else:
                print("❌ Invalid selection")
                return
        except ValueError:
            print("❌ Invalid selection")
            return
        
        # Confirmation
        device_name = selected.get('device_name', 'Unknown')
        print(f"\n⚠️ Remove Reservation:")
        print(f"   Device: {device_name}")
        print(f"   MAC: {selected['mac_address']}")
        print(f"   IP: {selected['ip_address']}")
        
        confirm = input("\nRemove this reservation? (y/n): ")
        if confirm.lower().startswith('y'):
            print("🔄 Removing IP reservation...")
            
            success = api.delete_static_lease(selected['mac_address'], selected['pool'])
            print(f"Removal: {'✅ Success' if success else '❌ Failed'}")
        else:
            print("❌ Removal cancelled")
            
    except Exception as e:
        print(f"❌ Error: {e}")


def smart_reservation_interactive(api):
    """Interactive tool for smart device reservations."""
    print(f"\n🧠 Smart Device Reservation")
    
    try:
        # Show connected devices
        print(f"🔍 Available devices for reservation:")
        devices = api.list_managed_devices()
        
        # Filter devices without reservations
        home_reservations = api.list_ip_reservations(pool_id="default")
        guest_reservations = api.list_ip_reservations(pool_id="guest")
        reserved_macs = set()
        
        for res in home_reservations + guest_reservations:
            reserved_macs.add(res.get('mac_address', '').lower())
        
        unreserved_devices = []
        for device in devices:
            if device['mac_address'].lower() not in reserved_macs:
                unreserved_devices.append(device)
        
        if not unreserved_devices:
            print("   All devices already have IP reservations")
            return
        
        for i, device in enumerate(unreserved_devices, 1):
            status = "🟢 Online" if device.get('active') else "🔴 Offline"
            print(f"   {i}. {device['name']} ({device['device_type']}) - {status}")
            print(f"      MAC: {device['mac_address']}")
        
        # Select device
        try:
            selection = int(input(f"\nSelect device (1-{len(unreserved_devices)}): "))
            if 1 <= selection <= len(unreserved_devices):
                selected_device = unreserved_devices[selection - 1]
            else:
                print("❌ Invalid selection")
                return
        except ValueError:
            print("❌ Invalid selection")
            return
        
        # Network selection
        print(f"\nSelect network:")
        print(f"   1. Home network (default)")
        print(f"   2. Guest network")
        
        network_choice = input("Enter choice (1-2): ").strip()
        pool_id = "guest" if network_choice == "2" else "default"
        
        # Suggest IP based on device type
        device_type = selected_device.get('device_type', '').lower()
        
        print(f"\n💡 Suggested IP addresses for {device_type}:")
        try:
            available_ips = api.suggest_available_ips(pool_id=pool_id, count=3)
            for ip in available_ips:
                print(f"   • {ip}")
        except Exception:
            print("   Could not fetch available IPs")
        
        # IP selection
        ip_address = input(f"\nEnter IP address for {selected_device['name']}: ").strip()
        if not ip_address:
            print("❌ IP address is required")
            return
        
        # Confirmation
        network_name = "Guest" if pool_id == "guest" else "Home"
        print(f"\n📋 Smart Reservation Summary:")
        print(f"   Device: {selected_device['name']}")
        print(f"   Type: {selected_device['device_type']}")
        print(f"   MAC: {selected_device['mac_address']}")
        print(f"   IP: {ip_address}")
        print(f"   Network: {network_name}")
        
        confirm = input("\nCreate this reservation? (y/n): ")
        if confirm.lower().startswith('y'):
            print("🔄 Creating smart reservation...")
            
            success = api.reserve_device_ip(
                selected_device['name'], 
                ip_address, 
                pool_id, 
                auto_detect_mac=True
            )
            print(f"Smart reservation: {'✅ Success' if success else '❌ Failed'}")
        else:
            print("❌ Reservation cancelled")
            
    except Exception as e:
        print(f"❌ Error: {e}")


def suggest_ips_interactive(api):
    """Interactive tool to suggest available IPs."""
    print(f"\n💡 Available IP Suggestions")
    
    try:
        # Network selection
        print(f"Select network:")
        print(f"   1. Home network (default)")
        print(f"   2. Guest network")
        print(f"   3. Both networks")
        
        network_choice = input("Enter choice (1-3): ").strip()
        
        # Number of suggestions
        try:
            count = int(input("Number of IP suggestions (default 5): ") or "5")
            count = min(max(count, 1), 20)  # Limit between 1-20
        except ValueError:
            count = 5
        
        if network_choice in ['1', '3']:
            print(f"\n🏠 Home Network Available IPs:")
            try:
                home_ips = api.suggest_available_ips(pool_id="default", count=count)
                for ip in home_ips:
                    print(f"   • {ip}")
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        if network_choice in ['2', '3']:
            print(f"\n🌐 Guest Network Available IPs:")
            try:
                guest_ips = api.suggest_available_ips(pool_id="guest", count=count)
                for ip in guest_ips:
                    print(f"   • {ip}")
            except Exception as e:
                print(f"   ❌ Error: {e}")
                
    except Exception as e:
        print(f"❌ Error: {e}")


def validate_reservations_interactive(api):
    """Interactive reservation validation and cleanup."""
    print(f"\n🛠️ Reservation Validation & Cleanup")
    
    try:
        print(f"🔍 Checking reservation validity...")
        
        # Validate home network
        print(f"\n🏠 Home Network Validation:")
        home_result = api.cleanup_invalid_reservations(pool_id="default")
        
        print(f"   Issues found: {home_result.get('total_issues', 0)}")
        
        if home_result.get('invalid_range'):
            print(f"   IPs outside DHCP range: {len(home_result['invalid_range'])}")
        
        if home_result.get('duplicate_ips'):
            print(f"   Duplicate IP conflicts: {len(home_result['duplicate_ips'])}")
        
        if home_result.get('recommendations'):
            print(f"   Recommendations:")
            for rec in home_result['recommendations']:
                print(f"   • {rec}")
        
        # Validate guest network
        print(f"\n🌐 Guest Network Validation:")
        guest_result = api.cleanup_invalid_reservations(pool_id="guest")
        
        print(f"   Issues found: {guest_result.get('total_issues', 0)}")
        
        if guest_result.get('recommendations'):
            print(f"   Recommendations:")
            for rec in guest_result['recommendations']:
                print(f"   • {rec}")
        
        # Overall status
        total_issues = home_result.get('total_issues', 0) + guest_result.get('total_issues', 0)
        
        if total_issues == 0:
            print(f"\n✅ All IP reservations are valid!")
        else:
            print(f"\n⚠️ Found {total_issues} total issues")
            print(f"   Review and manually resolve conflicts")
            
    except Exception as e:
        print(f"❌ Error during validation: {e}")


def bulk_reservation_wizard(api):
    """Wizard for creating multiple reservations."""
    print(f"\n🎯 Bulk Reservation Wizard")
    
    print(f"This wizard helps you create multiple IP reservations quickly.")
    
    # Device type categories
    device_categories = {
        '1': {'name': 'Printers', 'range': '100-109', 'devices': ['Printer', 'Scanner', 'MFP']},
        '2': {'name': 'Gaming/Media', 'range': '110-119', 'devices': ['PlayStation', 'Xbox', 'Apple TV', 'Roku']},
        '3': {'name': 'Servers/NAS', 'range': '120-129', 'devices': ['Server', 'NAS', 'Raspberry Pi']},
        '4': {'name': 'Smart Home', 'range': '130-139', 'devices': ['Hub', 'Bridge', 'Camera', 'Thermostat']},
        '5': {'name': 'Network Infrastructure', 'range': '140-149', 'devices': ['Access Point', 'Switch', 'Extender']}
    }
    
    print(f"\nDevice Categories:")
    for key, category in device_categories.items():
        print(f"   {key}. {category['name']} (IP range: 192.168.2.{category['range']})")
    
    category_choice = input("Select category (1-5): ").strip()
    
    if category_choice not in device_categories:
        print("❌ Invalid category")
        return
    
    selected_category = device_categories[category_choice]
    
    print(f"\n📋 {selected_category['name']} Reservation Wizard")
    print(f"   Suggested IP range: 192.168.2.{selected_category['range']}")
    
    # Get available IPs in range
    try:
        available_ips = api.suggest_available_ips(count=10)
        range_start, range_end = selected_category['range'].split('-')
        range_start, range_end = int(range_start), int(range_end)
        
        category_ips = []
        for ip in available_ips:
            last_octet = int(ip.split('.')[-1])
            if range_start <= last_octet <= range_end:
                category_ips.append(ip)
        
        if category_ips:
            print(f"   Available IPs in range: {', '.join(category_ips[:5])}")
        else:
            print(f"   ⚠️ No available IPs in suggested range")
            
    except Exception:
        print(f"   Could not check available IPs")
    
    print(f"\n💡 This wizard is for planning purposes.")
    print(f"   Use the interactive manager to actually create reservations.")
    print(f"   Suggested device types: {', '.join(selected_category['devices'])}")


def main():
    """Main function demonstrating IP reservation management."""
    print("🌐 KPN Box - IP Reservation Management Demo")
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
            print(f"\n📋 IP Reservation Management:")
            print(f"   1. View current IP reservations")
            print(f"   2. IP reservation basics")
            print(f"   3. Smart reservation features")
            print(f"   4. Common reservation scenarios")
            print(f"   5. Interactive reservation manager")
            print(f"   6. Exit")
            
            try:
                choice = input("\nSelect demonstration (1-6): ").strip()
                
                if choice == '1':
                    display_current_reservations(api)
                    
                elif choice == '2':
                    demonstrate_ip_reservation_basics(api)
                    
                elif choice == '3':
                    demonstrate_smart_reservations(api)
                    
                elif choice == '4':
                    demonstrate_common_scenarios(api)
                    
                elif choice == '5':
                    interactive_reservation_manager(api)
                    
                elif choice == '6':
                    print("\n👋 Thank you for using the IP Reservation Demo!")
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