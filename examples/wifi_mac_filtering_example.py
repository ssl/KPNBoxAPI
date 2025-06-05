#!/usr/bin/env python3
"""
WiFi MAC Filtering Example for KPN Box API

This example demonstrates how to use WiFi MAC filtering (WiFi Protection) 
to control which devices can connect to your WiFi networks.

WiFi MAC filtering creates a whitelist of allowed MAC addresses that can 
connect to your home and extra WiFi networks. This provides an additional 
layer of security by preventing unauthorized devices from connecting.

Key Features:
- Enable/disable MAC filtering
- Add/remove specific devices
- Manage complete whitelist
- Add all currently connected WiFi devices
- Maintenance and cleanup operations

Important Notes:
- Only affects home (main) and extra WiFi networks
- Guest networks are NOT affected (by design)
- Wired devices (Ethernet) are always allowed
- WiFi extenders are automatically included
"""

import sys
import os
from datetime import datetime, timedelta

# Add the parent directory to Python path for importing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.kpnboxapi import KPNBoxAPI


def print_header(title):
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def print_status(api):
    """Display current MAC filtering status."""
    print_header("Current MAC Filtering Status")
    
    status = api.get_wifi_mac_filter_status()
    
    if status['enabled']:
        print("🔒 MAC Filtering: ENABLED")
        print(f"📋 Mode: {status['mode']}")
        print(f"📱 Allowed devices: {status['count']}")
        
        if status['allowed_devices']:
            print("\n✅ Whitelist:")
            for i, mac in enumerate(status['allowed_devices'], 1):
                print(f"   {i:2d}. {mac}")
        else:
            print("\n⚠️  Whitelist is empty - all WiFi devices are blocked!")
    else:
        print("🔓 MAC Filtering: DISABLED")
        print("🌐 All devices can connect to WiFi")
        
        if status['count'] > 0:
            print(f"💾 Saved whitelist has {status['count']} devices (will be used when re-enabled)")


def show_connected_wifi_devices(api):
    """Show currently connected WiFi devices."""
    print_header("Currently Connected WiFi Devices")
    
    devices = api.get_devices('active')
    wifi_devices = [d for d in devices if d.get('Layer2Interface') != 'ETH0']
    
    if wifi_devices:
        print(f"Found {len(wifi_devices)} WiFi devices:")
        for i, device in enumerate(wifi_devices, 1):
            name = device.get('Name', 'Unknown')
            mac = device.get('PhysAddress', 'Unknown')
            interface = device.get('Layer2Interface', 'Unknown')
            ip = device.get('IPAddress', 'Unknown')
            device_type = device.get('DeviceType', 'Unknown')
            
            print(f"{i:2d}. {name}")
            print(f"     MAC: {mac}")
            print(f"     IP: {ip}")
            print(f"     Interface: {interface}")
            print(f"     Type: {device_type}")
    else:
        print("No WiFi devices currently connected.")
    
    return wifi_devices


def quick_setup_security(api):
    """Quick security setup - enable filtering with current devices."""
    print_header("Quick Security Setup")
    
    print("This will:")
    print("1. Find all currently connected WiFi devices")
    print("2. Add them to the MAC filter whitelist")
    print("3. Enable MAC filtering")
    print("4. Block any new/unknown devices from connecting")
    
    response = input("\nProceed with quick security setup? (y/N): ").strip().lower()
    if response != 'y':
        print("Setup cancelled.")
        return
    
    print("\n🔍 Finding connected WiFi devices...")
    result = api.add_connected_wifi_devices_to_filter()
    
    if result['success']:
        print(f"✅ Success! MAC filtering enabled.")
        print(f"📱 Added {len(result['added_devices'])} new devices to whitelist:")
        
        for device in result['added_devices']:
            print(f"   + {device['name']} ({device['mac_address']}) - {device['interface']}")
        
        if result['already_allowed']:
            print(f"\n📋 Already allowed ({len(result['already_allowed'])}):")
            for device in result['already_allowed']:
                print(f"   ✓ {device['name']} ({device['mac_address']})")
        
        print(f"\n🔒 Security Status:")
        print(f"   - Total allowed devices: {result['total_devices']}")
        print(f"   - New devices cannot connect without manual approval")
        print(f"   - Wired devices (Ethernet) are not affected")
        print(f"   - Guest network is not affected")
        
    else:
        print("❌ Failed to enable MAC filtering.")


def manage_devices_menu(api):
    """Interactive device management menu."""
    while True:
        print_header("Device Management")
        print("1. Add device to whitelist")
        print("2. Remove device from whitelist")
        print("3. Add multiple devices")
        print("4. Remove multiple devices")
        print("5. Set complete whitelist")
        print("6. Clear all devices (emergency block)")
        print("7. Add all connected WiFi devices")
        print("8. Back to main menu")
        
        choice = input("\nEnter choice (1-8): ").strip()
        
        if choice == '1':
            add_single_device(api)
        elif choice == '2':
            remove_single_device(api)
        elif choice == '3':
            add_multiple_devices(api)
        elif choice == '4':
            remove_multiple_devices(api)
        elif choice == '5':
            set_complete_whitelist(api)
        elif choice == '6':
            clear_whitelist(api)
        elif choice == '7':
            add_connected_devices(api)
        elif choice == '8':
            break
        else:
            print("Invalid choice. Please try again.")


def add_single_device(api):
    """Add a single device to whitelist."""
    print("\n--- Add Device to Whitelist ---")
    
    mac_address = input("Enter MAC address (AA:BB:CC:DD:EE:FF): ").strip()
    if not mac_address:
        print("❌ MAC address is required.")
        return
    
    try:
        success = api.add_wifi_mac_filter(mac_address)
        if success:
            print(f"✅ Device {mac_address} added to whitelist.")
            if not api.get_wifi_mac_filter_status()['enabled']:
                print("💡 MAC filtering has been automatically enabled.")
        else:
            print(f"❌ Failed to add device {mac_address}.")
    except Exception as e:
        print(f"❌ Error: {e}")


def remove_single_device(api):
    """Remove a single device from whitelist."""
    print("\n--- Remove Device from Whitelist ---")
    
    # Show current whitelist
    whitelist = api.get_wifi_mac_filter_list()
    if not whitelist:
        print("📭 Whitelist is empty.")
        return
    
    print("Current whitelist:")
    for i, mac in enumerate(whitelist, 1):
        print(f"{i:2d}. {mac}")
    
    choice = input("\nEnter MAC address or number: ").strip()
    
    # Handle numeric selection
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(whitelist):
            mac_address = whitelist[idx]
        else:
            print("❌ Invalid number.")
            return
    else:
        mac_address = choice
    
    try:
        success = api.remove_wifi_mac_filter(mac_address)
        if success:
            print(f"✅ Device {mac_address} removed from whitelist.")
        else:
            print(f"❌ Failed to remove device {mac_address}.")
    except Exception as e:
        print(f"❌ Error: {e}")


def add_multiple_devices(api):
    """Add multiple devices to whitelist."""
    print("\n--- Add Multiple Devices ---")
    print("Enter MAC addresses one per line. Empty line to finish.")
    
    mac_addresses = []
    while True:
        mac = input(f"MAC {len(mac_addresses)+1}: ").strip()
        if not mac:
            break
        mac_addresses.append(mac)
    
    if not mac_addresses:
        print("❌ No MAC addresses entered.")
        return
    
    try:
        success = api.add_wifi_mac_filter(mac_addresses)
        if success:
            print(f"✅ Added {len(mac_addresses)} devices to whitelist:")
            for mac in mac_addresses:
                print(f"   + {mac}")
        else:
            print("❌ Failed to add devices.")
    except Exception as e:
        print(f"❌ Error: {e}")


def remove_multiple_devices(api):
    """Remove multiple devices from whitelist."""
    print("\n--- Remove Multiple Devices ---")
    
    whitelist = api.get_wifi_mac_filter_list()
    if not whitelist:
        print("📭 Whitelist is empty.")
        return
    
    print("Current whitelist:")
    for i, mac in enumerate(whitelist, 1):
        print(f"{i:2d}. {mac}")
    
    print("\nEnter numbers or MAC addresses to remove (comma-separated):")
    selection = input("Selection: ").strip()
    
    if not selection:
        print("❌ No selection made.")
        return
    
    # Parse selection
    to_remove = []
    for item in selection.split(','):
        item = item.strip()
        if item.isdigit():
            idx = int(item) - 1
            if 0 <= idx < len(whitelist):
                to_remove.append(whitelist[idx])
        else:
            to_remove.append(item)
    
    if not to_remove:
        print("❌ No valid devices selected.")
        return
    
    try:
        success = api.remove_wifi_mac_filter(to_remove)
        if success:
            print(f"✅ Removed {len(to_remove)} devices:")
            for mac in to_remove:
                print(f"   - {mac}")
        else:
            print("❌ Failed to remove devices.")
    except Exception as e:
        print(f"❌ Error: {e}")


def set_complete_whitelist(api):
    """Set complete whitelist (replaces existing)."""
    print("\n--- Set Complete Whitelist ---")
    print("⚠️  This will replace the entire current whitelist!")
    print("Enter MAC addresses one per line. Empty line to finish.")
    
    mac_addresses = []
    while True:
        mac = input(f"MAC {len(mac_addresses)+1}: ").strip()
        if not mac:
            break
        mac_addresses.append(mac)
    
    if not mac_addresses:
        print("❌ No MAC addresses entered.")
        return
    
    print(f"\nThis will set whitelist to {len(mac_addresses)} devices:")
    for mac in mac_addresses:
        print(f"   • {mac}")
    
    confirm = input("\nConfirm replacement? (y/N): ").strip().lower()
    if confirm != 'y':
        print("Operation cancelled.")
        return
    
    try:
        success = api.set_wifi_mac_filter_list(mac_addresses, enabled=True)
        if success:
            print(f"✅ Whitelist updated with {len(mac_addresses)} devices.")
        else:
            print("❌ Failed to update whitelist.")
    except Exception as e:
        print(f"❌ Error: {e}")


def clear_whitelist(api):
    """Clear all devices from whitelist (emergency block)."""
    print("\n--- Clear Whitelist (Emergency Block) ---")
    print("⚠️  WARNING: This will block ALL WiFi devices!")
    print("Only wired devices will be able to access the network.")
    print("Guest networks will still work normally.")
    
    confirm = input("\nConfirm emergency block? (y/N): ").strip().lower()
    if confirm != 'y':
        print("Operation cancelled.")
        return
    
    try:
        success = api.clear_wifi_mac_filter()
        if success:
            print("🚫 All WiFi devices are now blocked!")
            print("💡 Use 'Add connected devices' to restore access.")
        else:
            print("❌ Failed to clear whitelist.")
    except Exception as e:
        print(f"❌ Error: {e}")


def add_connected_devices(api):
    """Add all connected WiFi devices to whitelist."""
    print("\n--- Add Connected WiFi Devices ---")
    
    try:
        result = api.add_connected_wifi_devices_to_filter()
        
        if result['success']:
            print(f"✅ Operation successful!")
            print(f"📱 Total WiFi devices found: {result['total_devices']}")
            
            if result['added_devices']:
                print(f"\n➕ Added {len(result['added_devices'])} new devices:")
                for device in result['added_devices']:
                    print(f"   + {device['name']} ({device['mac_address']}) - {device['interface']}")
            
            if result['already_allowed']:
                print(f"\n✅ Already allowed ({len(result['already_allowed'])}):")
                for device in result['already_allowed']:
                    print(f"   ✓ {device['name']} ({device['mac_address']})")
            
            if not result['added_devices'] and not result['already_allowed']:
                print("📭 No WiFi devices found to add.")
        else:
            print("❌ Failed to add connected devices.")
    except Exception as e:
        print(f"❌ Error: {e}")


def maintenance_menu(api):
    """Maintenance and cleanup operations."""
    print_header("Maintenance & Cleanup")
    
    status = api.get_wifi_mac_filter_status()
    if not status['enabled']:
        print("💡 MAC filtering is disabled. Enable it first to perform maintenance.")
        return
    
    if status['count'] == 0:
        print("📭 Whitelist is empty. Nothing to maintain.")
        return
    
    print("1. Check for inactive devices in whitelist")
    print("2. Show whitelist with device names")
    print("3. Backup current whitelist")
    print("4. Back to main menu")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == '1':
        check_inactive_devices(api)
    elif choice == '2':
        show_whitelist_with_names(api)
    elif choice == '3':
        backup_whitelist(api)
    elif choice == '4':
        return
    else:
        print("Invalid choice.")


def check_inactive_devices(api):
    """Check for inactive devices in whitelist."""
    print("\n--- Inactive Device Check ---")
    
    days = input("Check for devices inactive for how many days? (default: 30): ").strip()
    try:
        days = int(days) if days else 30
    except ValueError:
        days = 30
    
    print(f"🔍 Checking for devices inactive for {days}+ days...")
    
    # Get inactive devices
    inactive_devices = api.list_inactive_devices(days_inactive=days)
    inactive_macs = [d['PhysAddress'] for d in inactive_devices if d.get('Layer2Interface') != 'ETH0']
    
    # Get current whitelist
    whitelist = api.get_wifi_mac_filter_list()
    cleanup_candidates = [mac for mac in whitelist if mac in inactive_macs]
    
    if cleanup_candidates:
        print(f"\n📋 Found {len(cleanup_candidates)} inactive devices in whitelist:")
        for mac in cleanup_candidates:
            device = next((d for d in inactive_devices if d['PhysAddress'] == mac), None)
            if device:
                name = device.get('Name', 'Unknown')
                days_since = device.get('days_since_seen', 0)
                print(f"   • {name} ({mac}) - {days_since} days ago")
        
        remove = input(f"\nRemove these {len(cleanup_candidates)} devices from whitelist? (y/N): ").strip().lower()
        if remove == 'y':
            success = api.remove_wifi_mac_filter(cleanup_candidates)
            if success:
                print(f"✅ Removed {len(cleanup_candidates)} inactive devices.")
            else:
                print("❌ Failed to remove inactive devices.")
        else:
            print("Cleanup cancelled.")
    else:
        print("✅ No inactive devices found in whitelist.")


def show_whitelist_with_names(api):
    """Show whitelist with device names if available."""
    print("\n--- Whitelist with Device Names ---")
    
    whitelist = api.get_wifi_mac_filter_list()
    if not whitelist:
        print("📭 Whitelist is empty.")
        return
    
    # Get all devices to match names
    all_devices = api.get_devices('all')
    device_map = {d.get('PhysAddress'): d.get('Name', 'Unknown') for d in all_devices}
    
    print(f"📋 Whitelist ({len(whitelist)} devices):")
    for i, mac in enumerate(whitelist, 1):
        name = device_map.get(mac, 'Unknown Device')
        print(f"{i:2d}. {name}")
        print(f"     MAC: {mac}")


def backup_whitelist(api):
    """Create a backup of current whitelist."""
    print("\n--- Backup Whitelist ---")
    
    whitelist = api.get_wifi_mac_filter_list()
    if not whitelist:
        print("📭 Whitelist is empty. Nothing to backup.")
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"wifi_mac_whitelist_backup_{timestamp}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write(f"# WiFi MAC Filter Whitelist Backup\n")
            f.write(f"# Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Device count: {len(whitelist)}\n\n")
            
            # Get device names
            all_devices = api.get_devices('all')
            device_map = {d.get('PhysAddress'): d.get('Name', 'Unknown') for d in all_devices}
            
            for mac in whitelist:
                name = device_map.get(mac, 'Unknown Device')
                f.write(f"{mac}  # {name}\n")
        
        print(f"✅ Whitelist backed up to: {filename}")
        print(f"📄 Contains {len(whitelist)} MAC addresses")
    except Exception as e:
        print(f"❌ Failed to create backup: {e}")


def main_menu():
    """Main interactive menu."""
    try:
        with KPNBoxAPI() as api:
            # Get credentials
            password = input("Enter router admin password: ").strip()
            if not password:
                print("❌ Password is required.")
                return
            
            # Login
            print("🔐 Logging in...")
            if not api.login(password=password):
                print("❌ Login failed. Check your password.")
                return
            
            print("✅ Connected to KPN Box")
            
            while True:
                print_status(api)
                
                print("\n📋 Main Menu:")
                print("1. Quick Security Setup (recommended)")
                print("2. Enable MAC filtering")
                print("3. Disable MAC filtering")
                print("4. Show connected WiFi devices")
                print("5. Manage devices")
                print("6. Maintenance & cleanup")
                print("7. Exit")
                
                choice = input("\nEnter choice (1-7): ").strip()
                
                if choice == '1':
                    quick_setup_security(api)
                elif choice == '2':
                    try:
                        success = api.enable_wifi_mac_filtering()
                        if success:
                            print("✅ MAC filtering enabled.")
                        else:
                            print("❌ Failed to enable MAC filtering.")
                    except Exception as e:
                        print(f"❌ Error: {e}")
                elif choice == '3':
                    confirm = input("⚠️  Disable MAC filtering (allow all devices)? (y/N): ").strip().lower()
                    if confirm == 'y':
                        try:
                            success = api.disable_wifi_mac_filtering()
                            if success:
                                print("✅ MAC filtering disabled. All devices can now connect.")
                            else:
                                print("❌ Failed to disable MAC filtering.")
                        except Exception as e:
                            print(f"❌ Error: {e}")
                elif choice == '4':
                    show_connected_wifi_devices(api)
                elif choice == '5':
                    manage_devices_menu(api)
                elif choice == '6':
                    maintenance_menu(api)
                elif choice == '7':
                    print("👋 Goodbye!")
                    break
                else:
                    print("❌ Invalid choice. Please try again.")
                
                input("\nPress Enter to continue...")
    
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user. Goodbye!")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    print("🔒 KPN Box WiFi MAC Filtering Management")
    print("=" * 50)
    print()
    print("This tool helps you manage WiFi device access control using MAC filtering.")
    print("Only devices on the whitelist will be able to connect to your WiFi networks.")
    print()
    print("📝 Important Notes:")
    print("   • Only affects home and extra WiFi networks (not guest)")
    print("   • Wired devices (Ethernet) are always allowed")
    print("   • WiFi extenders are automatically included")
    print("   • New devices need manual approval when filtering is enabled")
    print()
    
    main_menu() 