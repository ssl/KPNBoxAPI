#!/usr/bin/env python3
"""
WiFi Scheduling and Radio Control Example

This example demonstrates how to control WiFi radios and set up time-based WiFi schedules
on KPN Box routers. Useful for parental controls, energy saving, and network management.

Features demonstrated:
- Enable/disable WiFi radios completely
- Configure WiFi radio settings (channels, bandwidth, standards)
- Set up bedtime schedules for children
- Create custom time-based schedules
- Manage WiFi scheduling

Requirements:
- KPN Box router (tested with Box 14)
- Admin access to the router
- WiFi capability (available on all KPN Box models)
"""

import time
from datetime import datetime, timedelta
from kpnboxapi import KPNBoxAPI

def main():
    # Configuration
    ROUTER_IP = "192.168.2.254"
    USERNAME = "admin"
    PASSWORD = input("Enter router password: ")
    
    try:
        with KPNBoxAPI(host=ROUTER_IP) as api:
            print("🔌 Connecting to KPN Box...")
            api.login(username=USERNAME, password=PASSWORD)
            print("✅ Connected successfully!\n")
            
            # Show current WiFi status
            show_wifi_status(api)
            
            # Example 1: WiFi Radio Control
            print("📡 Example 1: WiFi Radio Control...")
            
            # Check current status
            wifi_status = api.get_wifi_status()
            current_enabled = wifi_status.get('Enable', False)
            print(f"  Current WiFi status: {'Enabled' if current_enabled else 'Disabled'}")
            
            # Temporarily disable WiFi for demonstration
            if current_enabled:
                print("  🔴 Temporarily disabling WiFi...")
                success = api.set_wifi_enabled(enabled=False, sync_extenders=True)
                print(f"  WiFi disabled: {'✅ Success' if success else '❌ Failed'}")
                
                time.sleep(3)
                
                print("  🟢 Re-enabling WiFi...")
                success = api.set_wifi_enabled(enabled=True, sync_extenders=True)
                print(f"  WiFi enabled: {'✅ Success' if success else '❌ Failed'}")
            print()
            
            time.sleep(2)
            
            # Example 2: Optimize Radio Settings
            print("⚙️ Example 2: Optimizing WiFi radio settings...")
            
            # Set recommended radio configuration
            results = api.set_wifi_radio_defaults()
            print(f"  Default radio config applied:")
            print(f"    2.4GHz: {'✅ Success' if results.get('band_2g') else '❌ Failed'}")
            print(f"    5GHz: {'✅ Success' if results.get('band_5g') else '❌ Failed'}")
            
            # Or set custom configuration
            results = api.set_wifi_radio_config(
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
            print(f"  Custom radio config:")
            print(f"    2.4GHz (20MHz, g/n/ax): {'✅ Success' if results.get('band_2g') else '❌ Failed'}")
            print(f"    5GHz (80MHz, a/n/ac/ax): {'✅ Success' if results.get('band_5g') else '❌ Failed'}")
            print()
            
            time.sleep(2)
            
            # Example 3: Simple Bedtime Schedule
            print("🌙 Example 3: Setting up bedtime WiFi schedule...")
            
            # Set bedtime schedule (10 PM to 6 AM, weekdays only)
            success = api.set_wifi_bedtime_schedule(
                bedtime_hour=22,    # 10 PM
                wakeup_hour=6,      # 6 AM  
                weekdays_only=True  # Monday-Friday only
            )
            print(f"  Bedtime schedule (10 PM - 6 AM, weekdays): {'✅ Success' if success else '❌ Failed'}")
            
            if success:
                print("  📅 WiFi will be disabled:")
                print("    • Monday-Friday: 10:00 PM - 6:00 AM next day")
                print("    • Saturday-Sunday: Always enabled")
            print()
            
            time.sleep(3)
            
            # Example 4: Custom Schedule (Study Hours)
            print("📚 Example 4: Setting up study hours schedule...")
            
            # Create custom schedule for study time (3 PM to 8 PM on weekdays)
            study_blocks = create_study_schedule()
            success = api.set_wifi_schedule(disable_blocks=study_blocks, enabled=True)
            print(f"  Study hours schedule (3-8 PM weekdays): {'✅ Success' if success else '❌ Failed'}")
            
            if success:
                print("  📖 WiFi will be disabled during study hours:")
                print("    • Monday-Friday: 3:00 PM - 8:00 PM")
                print("    • Encourages focused study time without internet distractions")
            print()
            
            time.sleep(3)
            
            # Example 5: Weekend Restriction Schedule
            print("🎮 Example 5: Weekend gaming restriction schedule...")
            
            # Limit weekend gaming time (no WiFi 11 PM - 10 AM weekends)
            weekend_blocks = create_weekend_schedule()
            success = api.set_wifi_schedule(disable_blocks=weekend_blocks, enabled=True)
            print(f"  Weekend restriction schedule: {'✅ Success' if success else '❌ Failed'}")
            
            if success:
                print("  🎯 Weekend WiFi restrictions:")
                print("    • Friday 11:00 PM - Saturday 10:00 AM")
                print("    • Saturday 11:00 PM - Sunday 10:00 AM") 
                print("    • Promotes healthy sleep on weekends")
            print()
            
            time.sleep(3)
            
            # Example 6: Scheduling Management
            print("⏰ Example 6: Managing WiFi scheduling...")
            
            # Enable scheduling
            success = api.enable_wifi_schedule(enabled=True)
            print(f"  WiFi scheduling enabled: {'✅ Success' if success else '❌ Failed'}")
            
            time.sleep(2)
            
            # Disable scheduling
            success = api.enable_wifi_schedule(enabled=False)
            print(f"  WiFi scheduling disabled: {'✅ Success' if success else '❌ Failed'}")
            
            time.sleep(2)
            
            # Clear all schedules
            success = api.clear_wifi_schedule()
            print(f"  All WiFi schedules cleared: {'✅ Success' if success else '❌ Failed'}")
            print()
            
            # Show scheduling options
            show_scheduling_examples()
            
            # Interactive scheduling setup
            if input("\n❓ Set up interactive bedtime schedule? (y/N): ").lower().strip() == 'y':
                setup_interactive_schedule(api)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

def show_wifi_status(api):
    """Show current WiFi status"""
    print("📡 Current WiFi Status:")
    
    wifi_status = api.get_wifi_status()
    enabled = wifi_status.get('Enable', False)
    print(f"  WiFi Global Status: {'🟢 Enabled' if enabled else '🔴 Disabled'}")
    
    if enabled:
        print("  📶 All WiFi networks should be operational")
    else:
        print("  ⚠️  All WiFi networks are disabled")
    print()

def create_study_schedule():
    """Create study hours schedule (3-8 PM weekdays)"""
    disable_blocks = []
    
    # Monday to Friday (days 0-4)
    for day in range(5):
        day_start = day * 24 * 3600  # Start of day in seconds
        study_start = day_start + (15 * 3600)  # 3 PM
        study_end = day_start + (20 * 3600)    # 8 PM
        
        disable_blocks.append({
            "begin": study_start,
            "end": study_end
        })
    
    return disable_blocks

def create_weekend_schedule():
    """Create weekend restriction schedule (11 PM - 10 AM)"""
    disable_blocks = []
    
    # Friday night to Saturday morning
    friday_start = 4 * 24 * 3600  # Friday start
    friday_night = friday_start + (23 * 3600)  # Friday 11 PM
    saturday_start = 5 * 24 * 3600  # Saturday start
    saturday_morning = saturday_start + (10 * 3600)  # Saturday 10 AM
    
    disable_blocks.append({
        "begin": friday_night,
        "end": saturday_morning
    })
    
    # Saturday night to Sunday morning
    saturday_night = saturday_start + (23 * 3600)  # Saturday 11 PM
    sunday_start = 6 * 24 * 3600  # Sunday start
    sunday_morning = sunday_start + (10 * 3600)  # Sunday 10 AM
    
    disable_blocks.append({
        "begin": saturday_night,
        "end": sunday_morning
    })
    
    return disable_blocks

def setup_interactive_schedule(api):
    """Interactive schedule setup"""
    print("\n🛠️  Interactive WiFi Schedule Setup")
    
    try:
        bedtime = int(input("Enter bedtime hour (0-23, e.g., 22 for 10 PM): "))
        wakeup = int(input("Enter wakeup hour (0-23, e.g., 6 for 6 AM): "))
        weekdays_only = input("Apply only on weekdays? (Y/n): ").lower().strip() != 'n'
        
        if not (0 <= bedtime <= 23) or not (0 <= wakeup <= 23):
            print("❌ Invalid hours. Please use 0-23.")
            return
        
        print(f"\n📅 Setting schedule:")
        print(f"  Bedtime: {bedtime}:00 ({'10 PM' if bedtime == 22 else f'{bedtime}:00'})")
        print(f"  Wakeup: {wakeup}:00 ({'6 AM' if wakeup == 6 else f'{wakeup}:00'})")
        print(f"  Days: {'Weekdays only' if weekdays_only else 'All week'}")
        
        success = api.set_wifi_bedtime_schedule(
            bedtime_hour=bedtime,
            wakeup_hour=wakeup,
            weekdays_only=weekdays_only
        )
        
        if success:
            print("✅ Bedtime schedule set successfully!")
            
            # Enable scheduling
            api.enable_wifi_schedule(enabled=True)
            print("✅ WiFi scheduling enabled!")
        else:
            print("❌ Failed to set bedtime schedule")
            
    except ValueError:
        print("❌ Please enter valid numbers")

def show_scheduling_examples():
    """Show common scheduling scenarios"""
    print("📋 Common WiFi Scheduling Scenarios:")
    
    print("\n🌙 Bedtime Schedules:")
    print("  • Young children: 8 PM - 7 AM (all week)")
    print("  • Teenagers: 10 PM - 6 AM (weekdays only)")
    print("  • Adults: 11 PM - 6 AM (weekdays only)")
    
    print("\n📚 Study/Work Schedules:")
    print("  • Homework time: 3 PM - 6 PM (weekdays)")
    print("  • Family dinner: 6 PM - 7 PM (all week)")
    print("  • Study hours: 7 PM - 9 PM (weekdays)")
    
    print("\n🎮 Entertainment Limits:")
    print("  • Weekend mornings: 8 AM - 12 PM (weekends)")
    print("  • Gaming restrictions: 6 PM - 8 PM (all week)")
    print("  • Social media breaks: Various custom times")
    
    print("\n⚡ Energy Saving:")
    print("  • Night mode: 12 AM - 5 AM (all week)")
    print("  • Work hours: 9 AM - 5 PM (weekdays)")
    print("  • Vacation mode: Extended periods")

def time_calculation_helper():
    """Show how to calculate time blocks"""
    print("\n🕐 Time Calculation Helper:")
    print("Time blocks are in seconds from Monday 00:00")
    print()
    print("Day calculations:")
    print("  Monday = 0 * 24 * 3600 = 0")
    print("  Tuesday = 1 * 24 * 3600 = 86400") 
    print("  Wednesday = 2 * 24 * 3600 = 172800")
    print("  Thursday = 3 * 24 * 3600 = 259200")
    print("  Friday = 4 * 24 * 3600 = 345600")
    print("  Saturday = 5 * 24 * 3600 = 432000")
    print("  Sunday = 6 * 24 * 3600 = 518400")
    print()
    print("Hour calculations (add to day):")
    print("  1 AM = 1 * 3600 = 3600")
    print("  6 AM = 6 * 3600 = 21600")
    print("  3 PM = 15 * 3600 = 54000")
    print("  10 PM = 22 * 3600 = 79200")
    print()
    print("Example: Tuesday 3 PM = 172800 + 54000 = 226800")

if __name__ == "__main__":
    print("WiFi Scheduling and Radio Control Example for KPN Box API")
    print("=" * 65)
    
    # Run main examples
    exit_code = main()
    
    # Show additional information
    time_calculation_helper()
    
    print(f"\n{'✅ Examples completed successfully!' if exit_code == 0 else '❌ Examples failed!'}")
    exit(exit_code) 