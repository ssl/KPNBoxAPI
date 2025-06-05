#!/usr/bin/env python3
"""
Device Management Example

This script demonstrates how to use the KPNBoxAPI for comprehensive device management,
including parental controls, device organization, and time-based access restrictions.

Features demonstrated:
- Device discovery and detailed information
- Device naming and type assignment
- Parental control with time schedules
- Bedtime and study hour restrictions
- Device blocking and unblocking
- Comprehensive device management overview
"""

import sys
import os
from datetime import datetime, timedelta
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kpnboxapi import KPNBoxAPI


def print_separator(title=""):
    """Print a section separator."""
    print("\n" + "="*60)
    if title:
        print(f" {title}")
        print("="*60)


def list_all_devices(api):
    """Display all connected devices with their current status."""
    print_separator("Connected Devices Overview")
    
    devices = api.list_managed_devices()
    
    if not devices:
        print("No devices found.")
        return devices
    
    print(f"\n📱 Found {len(devices)} devices:")
    print(f"{'Name':<20} {'Type':<12} {'Status':<12} {'MAC Address':<18} {'IP Address':<15} {'Interface'}")
    print("-" * 95)
    
    for device in devices:
        name = device['name'][:19]  # Truncate long names
        device_type = device['device_type'][:11]
        
        # Status with emoji
        if device['blocked']:
            status = "🚫 BLOCKED"
        elif device['scheduled']:
            status = "⏰ SCHEDULED"
        elif device['active']:
            status = "🟢 ONLINE"
        else:
            status = "⚫ OFFLINE"
        
        mac = device['mac_address']
        ip = device['ip_address'][:14]
        interface = device['interface']
        
        print(f"{name:<20} {device_type:<12} {status:<12} {mac:<18} {ip:<15} {interface}")
    
    return devices


def show_device_details(api, mac_address):
    """Show detailed information for a specific device."""
    print_separator(f"Device Details: {mac_address}")
    
    try:
        info = api.get_device_management_info(mac_address)
        device_details = info['device_details']
        schedule = info['schedule']
        
        print(f"\n📋 Device Information:")
        print(f"   Name: {device_details.get('Name', 'Unknown')}")
        print(f"   Type: {device_details.get('DeviceType', 'Unknown')}")
        print(f"   Status: {'🟢 Connected' if device_details.get('Active') else '⚫ Offline'}")
        print(f"   MAC Address: {device_details.get('PhysAddress', 'Unknown')}")
        print(f"   IP Address: {device_details.get('IPAddress', 'Unknown')}")
        print(f"   Interface: {device_details.get('Layer2Interface', 'Unknown')}")
        print(f"   First Seen: {device_details.get('FirstSeen', 'Unknown')}")
        print(f"   Last Connection: {device_details.get('LastConnection', 'Unknown')}")
        
        # IPv6 addresses
        ipv6_addresses = device_details.get('IPv6Address', [])
        if ipv6_addresses:
            print(f"   IPv6 Addresses:")
            for addr in ipv6_addresses[:2]:  # Show first 2
                print(f"     {addr.get('Address', '')} ({addr.get('Scope', '')})")
        
        # Management status
        print(f"\n🛡️  Management Status:")
        print(f"   Summary: {info['summary']}")
        print(f"   Time Restrictions: {'✅ Active' if info['is_scheduled'] else '❌ None'}")
        print(f"   Permanently Blocked: {'✅ Yes' if info['is_blocked'] else '❌ No'}")
        
        # Show schedule details if present
        if schedule and isinstance(schedule, dict) and schedule.get('schedule'):
            print(f"\n⏰ Time Schedule:")
            print(f"   Default State: {schedule.get('def', 'Unknown')}")
            print(f"   Override: {schedule.get('override', 'None')}")
            print(f"   Schedule Blocks:")
            
            for i, block in enumerate(schedule['schedule'][:3], 1):  # Show first 3 blocks
                begin_time = format_time_from_seconds(block['begin'])
                end_time = format_time_from_seconds(block['end'])
                print(f"     {i}. {begin_time} - {end_time} (Disabled)")
            
            if len(schedule['schedule']) > 3:
                print(f"     ... and {len(schedule['schedule']) - 3} more blocks")
        
        return device_details
        
    except Exception as e:
        print(f"❌ Error getting device details: {e}")
        return None


def format_time_from_seconds(seconds):
    """Convert seconds from Monday 00:00 to human readable format."""
    total_seconds = seconds
    day = total_seconds // (24 * 3600)
    remaining = total_seconds % (24 * 3600)
    hour = remaining // 3600
    minute = (remaining % 3600) // 60
    
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    day_name = days[day] if day < 7 else f"Day{day}"
    
    return f"{day_name} {hour:02d}:{minute:02d}"


def demonstrate_device_naming(api, devices):
    """Demonstrate device naming and type assignment."""
    print_separator("Device Organization")
    
    if not devices:
        print("No devices available for demonstration.")
        return
    
    # Find a device to demonstrate with
    demo_device = None
    for device in devices:
        if device['active']:  # Prefer online devices
            demo_device = device
            break
    
    if not demo_device:
        demo_device = devices[0]  # Use first device if none online
    
    mac_address = demo_device['mac_address']
    current_name = demo_device['name']
    current_type = demo_device['device_type']
    
    print(f"\n🏷️  Device Organization Demo with: {mac_address}")
    print(f"   Current Name: {current_name}")
    print(f"   Current Type: {current_type}")
    
    # Show available device types
    device_types = api.get_common_device_types()
    print(f"\n📱 Available Device Types:")
    for i, dtype in enumerate(device_types[:10], 1):  # Show first 10
        print(f"   {i:2d}. {dtype}")
    if len(device_types) > 10:
        print(f"   ... and {len(device_types) - 10} more types")
    
    print(f"\n💡 Example Operations:")
    print(f"   # Set friendly name")
    print(f"   api.set_device_name('{mac_address}', 'Living Room TV')")
    print(f"   ")
    print(f"   # Set device type/icon")
    print(f"   api.set_device_type('{mac_address}', 'Television')")
    
    # Actually demonstrate if user wants (commented out for demo)
    # print(f"\n🔧 Demonstrating name change...")
    # success = api.set_device_name(mac_address, f"Demo-{current_name}")
    # print(f"   Name change: {'✅ Success' if success else '❌ Failed'}")


def demonstrate_parental_controls(api, devices):
    """Demonstrate parental control features."""
    print_separator("Parental Control Examples")
    
    if not devices:
        print("No devices available for demonstration.")
        return
    
    # Find a device for demo
    demo_device = devices[0]
    mac_address = demo_device['mac_address']
    device_name = demo_device['name']
    
    print(f"\n👨‍👩‍👧‍👦 Parental Control Demo with: {device_name} ({mac_address})")
    
    # Show current schedule
    try:
        schedule = api.get_device_schedule(mac_address)
        if schedule and schedule != False:
            print(f"   Current Schedule: ✅ Active")
            if isinstance(schedule, dict) and schedule.get('override') == 'Disable':
                print(f"   Device Status: 🚫 Permanently Blocked")
        else:
            print(f"   Current Schedule: ❌ None")
    except:
        print(f"   Current Schedule: ❓ Cannot determine")
    
    print(f"\n📋 Parental Control Options:")
    print(f"   1. Bedtime Schedule (10 PM - 7 AM, weekdays only)")
    print(f"   2. Study Hours (7 PM - 9 PM, weekdays)")
    print(f"   3. Permanent Block (always disabled)")
    print(f"   4. Remove All Restrictions")
    
    print(f"\n💡 Example Code:")
    
    # Bedtime schedule example
    print(f"   # Set bedtime schedule")
    print(f"   api.set_device_bedtime_schedule(")
    print(f"       '{mac_address}',")
    print(f"       bedtime_hour=22,  # 10 PM")
    print(f"       wakeup_hour=7,    # 7 AM")
    print(f"       weekdays_only=True")
    print(f"   )")
    
    # Study hours example
    print(f"   ")
    print(f"   # Set study hours (disable device)")
    print(f"   api.set_device_study_hours(")
    print(f"       '{mac_address}',")
    print(f"       study_start_hour=19,  # 7 PM")
    print(f"       study_end_hour=21,    # 9 PM")
    print(f"       study_days=[0,1,2,3,4]  # Mon-Fri")
    print(f"   )")
    
    # Permanent block example
    print(f"   ")
    print(f"   # Permanently block device")
    print(f"   api.block_device_permanently('{mac_address}')")
    print(f"   ")
    print(f"   # Remove all restrictions")
    print(f"   api.unblock_device('{mac_address}')")


def demonstrate_custom_schedules(api, devices):
    """Demonstrate custom time schedule creation."""
    print_separator("Custom Time Schedules")
    
    if not devices:
        print("No devices available for demonstration.")
        return
    
    demo_device = devices[0]
    mac_address = demo_device['mac_address']
    device_name = demo_device['name']
    
    print(f"\n⏰ Custom Schedule Demo with: {device_name}")
    
    print(f"\n📅 Creating Custom Schedules:")
    print(f"   Time format: Seconds from Monday 00:00")
    print(f"   Monday 00:00 = 0, Tuesday 00:00 = 86400, etc.")
    
    # Calculate some example time blocks
    monday_8pm = 20 * 3600  # Monday 8 PM
    tuesday_6am = 24 * 3600 + 6 * 3600  # Tuesday 6 AM
    
    wednesday_7pm = 2 * 24 * 3600 + 19 * 3600  # Wednesday 7 PM
    wednesday_9pm = 2 * 24 * 3600 + 21 * 3600  # Wednesday 9 PM
    
    print(f"\n💡 Example: Block Monday 8PM - Tuesday 6AM + Wednesday 7-9PM")
    print(f"   schedule_blocks = [")
    print(f"       {{\"begin\": {monday_8pm}, \"end\": {tuesday_6am}}},  # Mon 20:00 - Tue 06:00")
    print(f"       {{\"begin\": {wednesday_7pm}, \"end\": {wednesday_9pm}}}   # Wed 19:00 - 21:00")
    print(f"   ]")
    print(f"   ")
    print(f"   api.set_device_schedule(")
    print(f"       '{mac_address}',")
    print(f"       schedule_blocks=schedule_blocks,")
    print(f"       enabled=True")
    print(f"   )")
    
    print(f"\n🔧 Time Calculation Helper:")
    print(f"   def time_to_seconds(day, hour, minute=0):")
    print(f"       return day * 24 * 3600 + hour * 3600 + minute * 60")
    print(f"   ")
    print(f"   # Monday 8:30 PM = time_to_seconds(0, 20, 30)")
    print(f"   # Friday 6:00 AM = time_to_seconds(4, 6, 0)")


def device_security_overview(api):
    """Show device security and management overview."""
    print_separator("Device Security Overview")
    
    devices = api.list_managed_devices()
    
    if not devices:
        print("No devices found.")
        return
    
    # Categorize devices
    active_devices = [d for d in devices if d['active']]
    scheduled_devices = [d for d in devices if d['scheduled']]
    blocked_devices = [d for d in devices if d['blocked']]
    unmanaged_devices = [d for d in devices if not d['scheduled'] and not d['blocked']]
    
    print(f"\n🛡️  Device Security Summary:")
    print(f"   Total Devices: {len(devices)}")
    print(f"   Currently Online: {len(active_devices)}")
    print(f"   With Time Restrictions: {len(scheduled_devices)}")
    print(f"   Permanently Blocked: {len(blocked_devices)}")
    print(f"   Unmanaged (no restrictions): {len(unmanaged_devices)}")
    
    if blocked_devices:
        print(f"\n🚫 Blocked Devices:")
        for device in blocked_devices[:5]:  # Show first 5
            print(f"   • {device['name']} ({device['device_type']})")
    
    if scheduled_devices:
        print(f"\n⏰ Devices with Time Restrictions:")
        for device in scheduled_devices[:5]:  # Show first 5
            if not device['blocked']:  # Don't double-count blocked devices
                print(f"   • {device['name']} ({device['device_type']})")
    
    if unmanaged_devices:
        print(f"\n⚠️  Unmanaged Devices (Consider adding restrictions):")
        for device in unmanaged_devices[:5]:  # Show first 5
            print(f"   • {device['name']} ({device['device_type']})")
    
    print(f"\n💡 Security Recommendations:")
    if len(unmanaged_devices) > 5:
        print(f"   • Consider managing {len(unmanaged_devices)} unmanaged devices")
    if len(active_devices) > 20:
        print(f"   • High device count ({len(active_devices)}) - review unknown devices")
    print(f"   • Regularly review device names and types for accuracy")
    print(f"   • Use time restrictions for children's devices")
    print(f"   • Block unused or unknown devices for security")


def demonstrate_device_cleanup(api):
    """Demonstrate device cleanup and deletion features."""
    print_separator("Device Cleanup & Deletion")
    
    print(f"\n🧹 Device Cleanup Features:")
    print(f"   The router stores information about all devices that have")
    print(f"   ever connected. Over time, this can include many old devices")
    print(f"   that are no longer used. Cleanup helps maintain a tidy device list.")
    
    # List inactive devices
    print(f"\n📋 Checking for inactive devices...")
    try:
        inactive_7_days = api.list_inactive_devices(days_inactive=7)
        inactive_30_days = api.list_inactive_devices(days_inactive=30)
        
        print(f"   Devices inactive for 7+ days: {len(inactive_7_days)}")
        print(f"   Devices inactive for 30+ days: {len(inactive_30_days)}")
        
        if inactive_30_days:
            print(f"\n📊 Oldest Inactive Devices (30+ days):")
            for device in inactive_30_days[:5]:  # Show first 5
                days_since = device.get('days_since_seen', 'Unknown')
                print(f"   • {device['name'][:20]:<20} ({device['device_type']:<10}) - {days_since} days ago")
                print(f"     MAC: {device['mac_address']}")
        
        if inactive_7_days:
            print(f"\n⚠️  Recently Inactive Devices (7+ days):")
            for device in inactive_7_days[:3]:  # Show first 3
                days_since = device.get('days_since_seen', 'Unknown')
                print(f"   • {device['name'][:20]:<20} - {days_since} days ago")
    
    except Exception as e:
        print(f"   ❌ Error checking inactive devices: {e}")
    
    print(f"\n💡 Device Cleanup Examples:")
    
    # Manual deletion example
    print(f"   # Delete a specific device")
    print(f"   api.delete_device('96:16:1A:D6:0F:30')")
    print(f"   ")
    
    # List inactive devices example
    print(f"   # List devices inactive for 30+ days")
    print(f"   old_devices = api.list_inactive_devices(days_inactive=30)")
    print(f"   for device in old_devices:")
    print(f"       print(f\"{{device['name']}} - {{device['days_since_seen']}} days\")")
    print(f"   ")
    
    # Automatic cleanup example
    print(f"   # Automatically clean up devices older than 90 days")
    print(f"   cleanup_result = api.cleanup_inactive_devices(days_inactive=90)")
    print(f"   print(f\"Deleted {{cleanup_result['total_deleted']}} old devices\")")
    
    print(f"\n⚠️  Important Notes:")
    print(f"   • Deleted devices will reappear if they reconnect")
    print(f"   • Device schedules and restrictions are also removed")
    print(f"   • Consider backing up device names before cleanup")
    print(f"   • Start with longer inactive periods (90+ days) for safety")


def interactive_device_cleanup(api):
    """Interactive device cleanup tool."""
    print_separator("Interactive Device Cleanup")
    
    print(f"\n🧹 Interactive Device Cleanup Tool")
    print(f"This tool helps you clean up old inactive devices.")
    
    while True:
        print(f"\n📋 Cleanup Options:")
        print(f"   1. List inactive devices (7+ days)")
        print(f"   2. List inactive devices (30+ days)")
        print(f"   3. List inactive devices (custom period)")
        print(f"   4. Delete specific device")
        print(f"   5. Auto-cleanup old devices (90+ days)")
        print(f"   6. Exit cleanup tool")
        
        try:
            choice = input("\nEnter choice (1-6): ").strip()
            
            if choice == '1':
                devices = api.list_inactive_devices(days_inactive=7)
                print(f"\n📊 Devices inactive for 7+ days ({len(devices)} found):")
                for i, device in enumerate(devices[:10], 1):  # Show first 10
                    days = device.get('days_since_seen', 'Unknown')
                    print(f"   {i:2d}. {device['name'][:25]:<25} - {days} days ago")
                    print(f"       MAC: {device['mac_address']}")
                
            elif choice == '2':
                devices = api.list_inactive_devices(days_inactive=30)
                print(f"\n📊 Devices inactive for 30+ days ({len(devices)} found):")
                for i, device in enumerate(devices[:10], 1):
                    days = device.get('days_since_seen', 'Unknown')
                    print(f"   {i:2d}. {device['name'][:25]:<25} - {days} days ago")
                    print(f"       MAC: {device['mac_address']}")
                
            elif choice == '3':
                try:
                    days = int(input("Enter number of inactive days: "))
                    devices = api.list_inactive_devices(days_inactive=days)
                    print(f"\n📊 Devices inactive for {days}+ days ({len(devices)} found):")
                    for i, device in enumerate(devices[:10], 1):
                        days_since = device.get('days_since_seen', 'Unknown')
                        print(f"   {i:2d}. {device['name'][:25]:<25} - {days_since} days ago")
                        print(f"       MAC: {device['mac_address']}")
                except ValueError:
                    print("❌ Invalid number format")
                
            elif choice == '4':
                mac = input("Enter MAC address to delete: ").strip()
                if mac:
                    confirm = input(f"Delete device {mac}? (y/n): ")
                    if confirm.lower().startswith('y'):
                        success = api.delete_device(mac)
                        print(f"Device deletion: {'✅ Success' if success else '❌ Failed'}")
                
            elif choice == '5':
                print(f"\n⚠️  Auto-cleanup will delete devices inactive for 90+ days")
                confirm = input("Proceed with auto-cleanup? (y/n): ")
                if confirm.lower().startswith('y'):
                    print("🔄 Running cleanup...")
                    result = api.cleanup_inactive_devices(days_inactive=90)
                    
                    print(f"\n📊 Cleanup Results:")
                    print(f"   Devices found for cleanup: {result['total_candidates']}")
                    print(f"   Successfully deleted: {result['total_deleted']}")
                    print(f"   Failed to delete: {result['total_failed']}")
                    
                    if result['deleted']:
                        print(f"\n✅ Deleted Devices:")
                        for device in result['deleted'][:5]:
                            print(f"   • {device['name']} ({device['mac_address']})")
                    
                    if result['failed']:
                        print(f"\n❌ Failed Deletions:")
                        for device in result['failed'][:3]:
                            error = device.get('error', 'Unknown error')
                            print(f"   • {device['name']}: {error}")
                
            elif choice == '6':
                print("👋 Exiting cleanup tool!")
                break
                
            else:
                print("❌ Invalid choice")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


def interactive_device_manager(api):
    """Interactive device management tool."""
    print_separator("Interactive Device Manager")
    
    print("\n🎮 Interactive Device Management")
    print("This tool allows you to manage devices interactively.")
    
    while True:
        print(f"\n📋 Available Actions:")
        print(f"   1. List all devices")
        print(f"   2. Show device details")
        print(f"   3. Set device name")
        print(f"   4. Set device type")
        print(f"   5. Set bedtime schedule")
        print(f"   6. Block device permanently")
        print(f"   7. Remove all restrictions")
        print(f"   8. Device cleanup tools")
        print(f"   9. Exit")
        
        try:
            choice = input("\nEnter choice (1-9): ").strip()
            
            if choice == '1':
                devices = list_all_devices(api)
                
            elif choice == '2':
                mac = input("Enter MAC address: ").strip()
                show_device_details(api, mac)
                
            elif choice == '3':
                mac = input("Enter MAC address: ").strip()
                name = input("Enter new device name: ").strip()
                if mac and name:
                    success = api.set_device_name(mac, name)
                    print(f"Name change: {'✅ Success' if success else '❌ Failed'}")
                
            elif choice == '4':
                mac = input("Enter MAC address: ").strip()
                print("\nCommon device types:")
                types = api.get_common_device_types()[:10]
                for i, dtype in enumerate(types, 1):
                    print(f"  {i}. {dtype}")
                
                device_type = input("Enter device type: ").strip()
                if mac and device_type:
                    success = api.set_device_type(mac, device_type)
                    print(f"Type change: {'✅ Success' if success else '❌ Failed'}")
                
            elif choice == '5':
                mac = input("Enter MAC address: ").strip()
                try:
                    bedtime = int(input("Enter bedtime hour (0-23): "))
                    wakeup = int(input("Enter wakeup hour (0-23): "))
                    weekdays = input("Weekdays only? (y/n): ").lower().startswith('y')
                    
                    success = api.set_device_bedtime_schedule(mac, bedtime, wakeup, weekdays)
                    print(f"Bedtime schedule: {'✅ Success' if success else '❌ Failed'}")
                except ValueError:
                    print("❌ Invalid hour format")
                
            elif choice == '6':
                mac = input("Enter MAC address: ").strip()
                confirm = input(f"Block device {mac} permanently? (y/n): ")
                if confirm.lower().startswith('y'):
                    success = api.block_device_permanently(mac)
                    print(f"Device block: {'✅ Success' if success else '❌ Failed'}")
                
            elif choice == '7':
                mac = input("Enter MAC address: ").strip()
                success = api.unblock_device(mac)
                print(f"Remove restrictions: {'✅ Success' if success else '❌ Failed'}")
                
            elif choice == '8':
                interactive_device_cleanup(api)
                
            elif choice == '9':
                print("👋 Goodbye!")
                break
                
            else:
                print("❌ Invalid choice")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


def main():
    """Main function demonstrating device management features."""
    print("🏠 KPN Box - Advanced Device Management Demo")
    print("=" * 60)
    
    try:
        # Initialize API connection
        api = KPNBoxAPI()
        print(f"🔌 Connecting to KPN Box...")
        
        if not api.login():
            print("❌ Failed to login to KPN Box")
            return
        
        print(f"✅ Successfully connected to KPN Box!")
        
        # Get devices for demonstration
        print(f"\n🔍 Discovering devices...")
        devices = api.list_managed_devices()
        
        if not devices:
            print("❌ No devices found. Make sure some devices are connected.")
            return
        
        print(f"✅ Found {len(devices)} devices")
        
        while True:
            print(f"\n📋 Device Management Demonstrations:")
            print(f"   1. List all devices")
            print(f"   2. Show device details")
            print(f"   3. Device naming demonstration")
            print(f"   4. Parental controls demonstration")
            print(f"   5. Custom schedules demonstration")
            print(f"   6. Device security overview")
            print(f"   7. Device cleanup demonstration")
            print(f"   8. Interactive device manager")
            print(f"   9. Exit")
            
            try:
                choice = input("\nSelect demonstration (1-9): ").strip()
                
                if choice == '1':
                    list_all_devices(api)
                    
                elif choice == '2':
                    mac_address = input("Enter MAC address: ").strip()
                    if mac_address:
                        show_device_details(api, mac_address)
                    
                elif choice == '3':
                    demonstrate_device_naming(api, devices)
                    
                elif choice == '4':
                    demonstrate_parental_controls(api, devices)
                    
                elif choice == '5':
                    demonstrate_custom_schedules(api, devices)
                    
                elif choice == '6':
                    device_security_overview(api)
                    
                elif choice == '7':
                    demonstrate_device_cleanup(api)
                    
                elif choice == '8':
                    interactive_device_manager(api)
                    
                elif choice == '9':
                    print("\n👋 Thank you for using the Device Management Demo!")
                    break
                    
                else:
                    print("❌ Invalid choice. Please select 1-9.")
                    
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