#!/usr/bin/env python3
"""
Parental Controls Example for KPN Box API

This example demonstrates comprehensive parental control functionality including:
- Time-based scheduling (block/allow during specific hours)
- Managed Screen Time (MST) with daily time limits
- Device blocking and unblocking
- Bedtime schedules and study hours
- Device management and monitoring

Parental controls support two main approaches:
1. Schedule-based controls: Block devices during specific time periods
2. MST (Managed Screen Time): Daily time limits that accumulate usage

Important Notes:
- Schedule and MST controls are mutually exclusive
- When switching between types, the previous type is automatically removed
- Time calculations use seconds from Monday 00:00 as reference
- MST uses minutes per day (0-1440 where 1440 = 24 hours)

Security Warning:
Parental controls are enforced at the router level and can be bypassed by:
- Using mobile data instead of WiFi
- Connecting via Ethernet (if not properly configured)
- Changing device MAC address (advanced users)
- Factory resetting the router

Author: KPN Box API Client
"""

import sys
from typing import Dict, List, Any
from kpnboxapi import KPNBoxAPI

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'-'*40}")
    print(f" {title}")
    print(f"{'-'*40}")

def get_device_list(api):
    """Get list of all devices for selection."""
    print("Fetching connected devices...")
    devices = api.get_devices('all')
    
    if not devices:
        print("❌ No devices found!")
        return []
    
    print(f"\n📱 Found {len(devices)} devices:")
    for i, device in enumerate(devices, 1):
        name = device.get('Name', 'Unknown')
        mac = device.get('PhysAddress', 'Unknown')
        device_type = device.get('DeviceType', 'Unknown')
        active = "🟢" if device.get('Active') else "⚪"
        
        print(f"{i:2d}. {active} {name} ({device_type})")
        print(f"     MAC: {mac}")
    
    return devices

def select_device(devices):
    """Allow user to select a device."""
    while True:
        try:
            choice = input(f"\nSelect device (1-{len(devices)}, or 0 to cancel): ").strip()
            
            if choice == '0':
                return None
            
            index = int(choice) - 1
            if 0 <= index < len(devices):
                return devices[index]
            else:
                print(f"Please enter a number between 1 and {len(devices)}")
        
        except ValueError:
            print("Please enter a valid number")
        except KeyboardInterrupt:
            return None

def show_device_status(api, mac_address):
    """Show comprehensive device status."""
    print(f"\n📊 Device Status: {mac_address}")
    
    try:
        # Get parental control status
        status = api.get_device_parental_control_status(mac_address)
        print(f"Control Type: {status['control_type']}")
        print(f"Enabled: {status['enabled']}")
        print(f"Summary: {status['summary']}")
        
        # Show schedule details if present
        if status['schedule']:
            schedule = status['schedule']
            print(f"\n📅 Schedule Details:")
            print(f"   Base: {schedule.get('base', 'N/A')}")
            print(f"   Default: {schedule.get('def', 'N/A')}")
            print(f"   Enabled: {schedule.get('enable', False)}")
            print(f"   Override: {schedule.get('override', 'None')}")
            
            schedule_blocks = schedule.get('schedule', [])
            if schedule_blocks:
                print(f"   Time Blocks: {len(schedule_blocks)}")
                for i, block in enumerate(schedule_blocks, 1):
                    start_time = api.format_time_seconds_to_readable(block['begin'])
                    end_time = api.format_time_seconds_to_readable(block['end'])
                    print(f"     {i}. {start_time} → {end_time}")
        
        # Show MST details if present
        if status['mst']:
            mst = status['mst']
            print(f"\n⏰ Screen Time Details:")
            print(f"   Subject: {mst.get('subject', 'N/A')}")
            print(f"   Enabled: {mst.get('enable', False)}")
            print(f"   Status: {mst.get('status', 'N/A')}")
            
            allowed_time = mst.get('allowedTime', {})
            if allowed_time:
                print(f"   Daily Limits:")
                total_minutes = 0
                for day, minutes in allowed_time.items():
                    hours = minutes // 60
                    mins = minutes % 60
                    total_minutes += minutes
                    print(f"     {day}: {hours}h {mins:02d}m ({minutes} min)")
                
                avg_daily = total_minutes // 7
                avg_hours = avg_daily // 60
                avg_mins = avg_daily % 60
                print(f"   Average: {avg_hours}h {avg_mins:02d}m/day")
        
        # Get device details
        device_details = api.get_device_details(mac_address)
        print(f"\n🔍 Device Details:")
        print(f"   Name: {device_details.get('Name', 'Unknown')}")
        print(f"   Type: {device_details.get('DeviceType', 'Unknown')}")
        print(f"   IP Address: {device_details.get('IPAddress', 'Unknown')}")
        print(f"   Active: {device_details.get('Active', False)}")
        print(f"   Interface: {device_details.get('Layer2Interface', 'Unknown')}")
        
    except Exception as e:
        print(f"❌ Error getting device status: {e}")

def remove_all_restrictions(api, mac_address):
    """Remove all parental control restrictions."""
    try:
        result = api.set_device_parental_control(mac_address, "none")
        if result:
            print("✅ All restrictions removed successfully")
        else:
            print("❌ Failed to remove restrictions")
    except Exception as e:
        print(f"❌ Error removing restrictions: {e}")

def block_device_completely(api, mac_address):
    """Block device completely."""
    try:
        result = api.set_device_parental_control(mac_address, "block")
        if result:
            print("🚫 Device completely blocked")
        else:
            print("❌ Failed to block device")
    except Exception as e:
        print(f"❌ Error blocking device: {e}")

def setup_bedtime_schedule(api, mac_address):
    """Set up bedtime schedule."""
    print("\n🌙 Bedtime Schedule Setup")
    
    try:
        # Get bedtime preferences
        bedtime_hour = int(input("Enter bedtime hour (0-23, default 22): ") or "22")
        wakeup_hour = int(input("Enter wakeup hour (0-23, default 6): ") or "6")
        
        print("\nSelect days to apply bedtime:")
        print("1. Weekdays only (Mon-Fri)")
        print("2. Every day (Mon-Sun)")
        print("3. Custom selection")
        
        choice = input("Choice (1-3, default 1): ").strip() or "1"
        
        if choice == "1":
            days = [0,1,2,3,4]  # Monday-Friday
            days_text = "weekdays"
        elif choice == "2":
            days = [0,1,2,3,4,5,6]  # Every day
            days_text = "every day"
        elif choice == "3":
            days = []
            for i, day_name in enumerate(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]):
                apply = input(f"Apply to {day_name}? (y/n, default n): ").strip().lower()
                if apply in ['y', 'yes']:
                    days.append(i)
            days_text = f"{len(days)} selected days"
        else:
            print("Invalid choice, using weekdays only")
            days = [0,1,2,3,4]
            days_text = "weekdays"
        
        if not days:
            print("❌ No days selected!")
            return
        
        # Create bedtime schedule
        bedtime_blocks = api.create_bedtime_schedule_blocks(bedtime_hour, wakeup_hour, days)
        result = api.set_device_parental_control(mac_address, "schedule", schedule_blocks=bedtime_blocks)
        
        if result:
            print(f"✅ Bedtime schedule set: {bedtime_hour:02d}:00 - {wakeup_hour:02d}:00 on {days_text}")
            print(f"   Created {len(bedtime_blocks)} time blocks")
        else:
            print("❌ Failed to set bedtime schedule")
    
    except ValueError:
        print("❌ Invalid time format entered")
    except Exception as e:
        print(f"❌ Error setting bedtime schedule: {e}")

def setup_daily_time_limits(api, mac_address):
    """Set up daily time limits (MST)."""
    print("\n⏰ Daily Time Limits Setup")
    
    try:
        print("Choose setup type:")
        print("1. Simple (weekday/weekend limits)")
        print("2. Custom (individual day limits)")
        
        choice = input("Choice (1-2, default 1): ").strip() or "1"
        
        if choice == "1":
            # Simple setup
            weekday_hours = float(input("Weekday time limit in hours (default 2.0): ") or "2.0")
            weekend_hours = float(input("Weekend time limit in hours (default 4.0): ") or "4.0")
            
            weekday_minutes = int(weekday_hours * 60)
            weekend_minutes = int(weekend_hours * 60)
            
            # Validate limits
            if weekday_minutes < 0 or weekday_minutes > 1440:
                print("❌ Weekday limit must be 0-24 hours")
                return
            if weekend_minutes < 0 or weekend_minutes > 1440:
                print("❌ Weekend limit must be 0-24 hours")
                return
            
            result = api.set_device_daily_time_limits(mac_address, weekday_minutes, weekend_minutes)
            
            if result:
                print(f"✅ Daily limits set:")
                print(f"   Weekdays: {weekday_hours} hours")
                print(f"   Weekends: {weekend_hours} hours")
            else:
                print("❌ Failed to set daily limits")
        
        elif choice == "2":
            # Custom setup
            daily_limits = {}
            days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            
            print("\nEnter time limit for each day (in hours, 0-24):")
            for day, day_name in zip(days, day_names):
                while True:
                    try:
                        hours = float(input(f"{day_name}: ") or "2.0")
                        if 0 <= hours <= 24:
                            daily_limits[day] = int(hours * 60)
                            break
                        else:
                            print("Please enter 0-24 hours")
                    except ValueError:
                        print("Please enter a valid number")
            
            result = api.set_device_parental_control(mac_address, "daily_limits", daily_limits=daily_limits)
            
            if result:
                print("✅ Custom daily limits set:")
                for day, minutes in daily_limits.items():
                    hours = minutes / 60
                    print(f"   {day}: {hours} hours")
            else:
                print("❌ Failed to set custom limits")
        
        else:
            print("Invalid choice")
    
    except Exception as e:
        print(f"❌ Error setting daily limits: {e}")

def setup_study_hours(api, mac_address):
    """Set up study hours restriction."""
    print("\n📚 Study Hours Setup")
    
    try:
        start_hour = int(input("Study start hour (0-23, default 19): ") or "19")
        end_hour = int(input("Study end hour (0-23, default 21): ") or "21")
        
        print("Select days for study hours:")
        print("1. Weekdays only (Mon-Fri)")
        print("2. Custom selection")
        
        choice = input("Choice (1-2, default 1): ").strip() or "1"
        
        if choice == "1":
            days = [0,1,2,3,4]  # Monday-Friday
        elif choice == "2":
            days = []
            for i, day_name in enumerate(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]):
                apply = input(f"Study hours on {day_name}? (y/n, default n): ").strip().lower()
                if apply in ['y', 'yes']:
                    days.append(i)
        else:
            days = [0,1,2,3,4]
        
        if not days:
            print("❌ No days selected!")
            return
        
        # Create study hour blocks
        study_blocks = []
        for day in days:
            study_start = day * 86400 + start_hour * 3600
            study_end = day * 86400 + end_hour * 3600
            study_blocks.append({"begin": study_start, "end": study_end})
        
        result = api.set_device_parental_control(mac_address, "schedule", schedule_blocks=study_blocks)
        
        if result:
            print(f"✅ Study hours set: {start_hour:02d}:00 - {end_hour:02d}:00")
            print(f"   Applied to {len(days)} days")
        else:
            print("❌ Failed to set study hours")
    
    except ValueError:
        print("❌ Invalid time format entered")
    except Exception as e:
        print(f"❌ Error setting study hours: {e}")

def quick_setup_scenarios(api):
    """Quick setup for common parental control scenarios."""
    print_section("Quick Setup Scenarios")
    
    devices = get_device_list(api)
    if not devices:
        return
    
    device = select_device(devices)
    if not device:
        return
    
    mac_address = device.get('PhysAddress')
    device_name = device.get('Name', 'Unknown Device')
    
    print(f"\n🎯 Quick setup for: {device_name} ({mac_address})")
    print("\nSelect scenario:")
    print("1. Young Child (1h weekdays, 2h weekends, bedtime 9PM-7AM)")
    print("2. Teenager (3h weekdays, 6h weekends, bedtime 11PM-7AM)")
    print("3. Gaming Console (Fri-Sun only, 2-4h limits)")
    print("4. Study Device (blocked during homework 4-6PM)")
    print("5. Complete Block (no internet access)")
    print("6. Remove All Restrictions")
    
    choice = input("Choice (1-6): ").strip()
    
    try:
        if choice == "1":
            # Young child setup
            api.set_device_daily_time_limits(mac_address, 60, 120)  # 1h weekdays, 2h weekends
            bedtime_blocks = api.create_bedtime_schedule_blocks(21, 7, [0,1,2,3,4,5,6])  # 9PM-7AM every day
            api.set_device_parental_control(mac_address, "schedule", schedule_blocks=bedtime_blocks)
            print("👶 Young child setup complete: 1h/2h limits + 9PM-7AM bedtime")
        
        elif choice == "2":
            # Teenager setup
            api.set_device_daily_time_limits(mac_address, 180, 360)  # 3h weekdays, 6h weekends
            bedtime_blocks = api.create_bedtime_schedule_blocks(23, 7, [0,1,2,3,4])  # 11PM-7AM weekdays
            api.set_device_parental_control(mac_address, "schedule", schedule_blocks=bedtime_blocks)
            print("👦 Teenager setup complete: 3h/6h limits + 11PM-7AM bedtime (weekdays)")
        
        elif choice == "3":
            # Gaming console setup
            gaming_limits = {
                "Mon": 0, "Tue": 0, "Wed": 0, "Thu": 0, "Fri": 120,  # No gaming Mon-Thu, 2h Friday
                "Sat": 240, "Sun": 180  # 4h Saturday, 3h Sunday
            }
            api.set_device_parental_control(mac_address, "daily_limits", daily_limits=gaming_limits)
            print("🎮 Gaming console setup complete: Weekend only (Fri-Sun) with time limits")
        
        elif choice == "4":
            # Study device setup
            homework_blocks = []
            for day in [0,1,2,3,4]:  # Monday-Friday
                homework_start = day * 86400 + 16 * 3600  # 4 PM
                homework_end = day * 86400 + 18 * 3600    # 6 PM
                homework_blocks.append({"begin": homework_start, "end": homework_end})
            
            api.set_device_parental_control(mac_address, "schedule", schedule_blocks=homework_blocks)
            print("📖 Study device setup complete: Blocked 4-6PM weekdays for homework")
        
        elif choice == "5":
            # Complete block
            api.set_device_parental_control(mac_address, "block")
            print("🚫 Device completely blocked")
        
        elif choice == "6":
            # Remove restrictions
            api.set_device_parental_control(mac_address, "none")
            print("✅ All restrictions removed")
        
        else:
            print("Invalid choice")
            return
        
        # Show final status
        print_section("Setup Complete")
        show_device_status(api, mac_address)
    
    except Exception as e:
        print(f"❌ Error during quick setup: {e}")

def device_management_menu(api):
    """Device management and monitoring menu."""
    while True:
        print_section("Device Management & Monitoring")
        
        print("1. View All Devices with Parental Controls")
        print("2. Check Individual Device Status")
        print("3. Remove All Restrictions from Device")
        print("4. Block Device Completely")
        print("5. Set Device Name and Type")
        print("6. Back to Main Menu")
        
        choice = input("\nChoice (1-6): ").strip()
        
        if choice == "1":
            # List all controlled devices
            print("\n📋 Devices with Parental Controls:")
            controlled_devices = api.list_devices_with_parental_controls()
            
            if not controlled_devices:
                print("No devices have parental controls configured")
            else:
                for device in controlled_devices:
                    status_icon = "🔴" if device['control_type'] == 'block' else "⏰" if device['control_type'] == 'daily_limits' else "📅"
                    active_icon = "🟢" if device['active'] else "⚪"
                    
                    print(f"\n{status_icon} {device['name']} ({device['device_type']}) {active_icon}")
                    print(f"   MAC: {device['mac_address']}")
                    print(f"   Control: {device['summary']}")
        
        elif choice == "2":
            # Check individual device
            devices = get_device_list(api)
            if devices:
                device = select_device(devices)
                if device:
                    show_device_status(api, device.get('PhysAddress'))
        
        elif choice == "3":
            # Remove restrictions
            devices = get_device_list(api)
            if devices:
                device = select_device(devices)
                if device:
                    remove_all_restrictions(api, device.get('PhysAddress'))
        
        elif choice == "4":
            # Block device
            devices = get_device_list(api)
            if devices:
                device = select_device(devices)
                if device:
                    block_device_completely(api, device.get('PhysAddress'))
        
        elif choice == "5":
            # Set device name and type
            devices = get_device_list(api)
            if devices:
                device = select_device(devices)
                if device:
                    mac_address = device.get('PhysAddress')
                    current_name = device.get('Name', 'Unknown')
                    current_type = device.get('DeviceType', 'Unknown')
                    
                    print(f"\nCurrent: {current_name} ({current_type})")
                    new_name = input(f"New name (Enter to keep '{current_name}'): ").strip()
                    new_type = input(f"New type (Enter to keep '{current_type}'): ").strip()
                    
                    try:
                        if new_name:
                            api.set_device_name(mac_address, new_name)
                            print(f"✅ Name updated to: {new_name}")
                        
                        if new_type:
                            api.set_device_type(mac_address, new_type)
                            print(f"✅ Type updated to: {new_type}")
                        
                        if not new_name and not new_type:
                            print("No changes made")
                    
                    except Exception as e:
                        print(f"❌ Error updating device: {e}")
        
        elif choice == "6":
            break
        
        else:
            print("Invalid choice, please try again")

def parental_control_setup_menu(api):
    """Parental control setup menu."""
    while True:
        print_section("Parental Control Setup")
        
        print("1. Setup Bedtime Schedule")
        print("2. Setup Daily Time Limits")
        print("3. Setup Study Hours")
        print("4. Remove All Restrictions")
        print("5. Block Device Completely")
        print("6. Quick Setup Scenarios")
        print("7. Back to Main Menu")
        
        choice = input("\nChoice (1-7): ").strip()
        
        if choice == "7":
            break
        
        # Get device for most operations
        if choice in ["1", "2", "3", "4", "5"]:
            devices = get_device_list(api)
            if not devices:
                continue
            
            device = select_device(devices)
            if not device:
                continue
            
            mac_address = device.get('PhysAddress')
            device_name = device.get('Name', 'Unknown Device')
            
            print(f"\n🎯 Setting up: {device_name} ({mac_address})")
        
        if choice == "1":
            setup_bedtime_schedule(api, mac_address)
        elif choice == "2":
            setup_daily_time_limits(api, mac_address)
        elif choice == "3":
            setup_study_hours(api, mac_address)
        elif choice == "4":
            remove_all_restrictions(api, mac_address)
        elif choice == "5":
            block_device_completely(api, mac_address)
        elif choice == "6":
            quick_setup_scenarios(api)
        else:
            print("Invalid choice, please try again")

def main():
    """Main program."""
    print_header("KPN Box API - Parental Controls Demo")
    print("This example demonstrates comprehensive parental control features")
    print("including time schedules, daily limits, and device management.")
    
    # Get connection details
    host = input("Enter KPN Box IP (default: 192.168.2.254): ").strip() or "192.168.2.254"
    password = input("Enter admin password: ").strip()
    
    if not password:
        print("❌ Password is required!")
        return
    
    # Initialize API
    try:
        api = KPNBoxAPI(host=host)
        print(f"\n🔗 Connecting to {host}...")
        
        if not api.login("admin", password):
            print("❌ Login failed! Please check your password.")
            return
        
        print("✅ Successfully connected!")
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return
    
    # Main menu loop
    while True:
        print_header("Main Menu")
        
        print("1. Parental Control Setup")
        print("2. Device Management & Monitoring")
        print("3. View All Devices")
        print("4. Quick Setup Scenarios")
        print("5. Exit")
        
        choice = input("\nChoice (1-5): ").strip()
        
        try:
            if choice == "1":
                parental_control_setup_menu(api)
            elif choice == "2":
                device_management_menu(api)
            elif choice == "3":
                get_device_list(api)
            elif choice == "4":
                quick_setup_scenarios(api)
            elif choice == "5":
                print("\n👋 Goodbye!")
                break
            else:
                print("Invalid choice, please try again")
        
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ An error occurred: {e}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main() 