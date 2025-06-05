#!/usr/bin/env python3
"""
Comprehensive WiFi Management Example

This example demonstrates how to manage all types of WiFi networks on KPN Box routers:
- Regular WiFi networks (primary home networks)
- Guest WiFi networks (for visitors)  
- Extra WiFi networks (for IoT, work, etc.)

Shows configuration, visibility settings, and security options for all network types.

Requirements:
- KPN Box router (tested with Box 14)
- Admin access to the router
- WiFi capability (available on all KPN Box models)
"""

import time
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
            show_current_wifi_status(api)
            
            # Example 1: Configure Regular WiFi Networks
            print("🏠 Example 1: Configuring regular WiFi networks...")
            success = api.set_wifi_config(
                ssid_2g="MyHome_2G",
                ssid_5g="MyHome_5G",
                password_2g="SecureHomePass2024!",
                password_5g="SecureHomePass2024!",
                security_mode_2g="WPA2-Personal",
                security_mode_5g="WPA2-Personal"
            )
            print(f"  Regular WiFi configured: {'✅ Success' if success else '❌ Failed'}")
            print()
            
            time.sleep(2)
            
            # Example 2: Setup Guest Networks
            print("👥 Example 2: Setting up guest networks...")
            
            # Enable guest network
            guest_enable = api.enable_guest_network(enabled=True)
            print(f"  Guest network enabled: {'✅ Success' if guest_enable else '❌ Failed'}")
            
            if guest_enable:
                # Configure guest WiFi
                guest_config = api.set_guest_wifi_config(
                    ssid_2g="Welcome_Guests",
                    ssid_5g="Welcome_Guests_Fast",
                    password_2g="GuestPass123",
                    password_5g="GuestPass123",
                    security_mode_2g="WPA2-Personal",
                    security_mode_5g="WPA2-Personal"
                )
                print(f"  Guest WiFi configured: {'✅ Success' if guest_config else '❌ Failed'}")
                
                # Set bandwidth limit for guests
                bandwidth_limit = api.set_guest_bandwidth_limit(20)  # 20 Mbps
                print(f"  Guest bandwidth limited: {'✅ 20 Mbps' if bandwidth_limit else '❌ Failed'}")
            print()
            
            time.sleep(2)
            
            # Example 3: Setup Extra Networks for IoT/Work
            print("🔧 Example 3: Setting up extra networks for specialized use...")
            
            # Enable extra networks
            extra_enable = api.enable_extra_wifi(enabled_2g=True, enabled_5g=True)
            print(f"  Extra networks enabled:")
            print(f"    2.4GHz: {'✅ Success' if extra_enable.get('band_2g') else '❌ Failed'}")
            print(f"    5GHz: {'✅ Success' if extra_enable.get('band_5g') else '❌ Failed'}")
            
            if extra_enable.get('band_2g') or extra_enable.get('band_5g'):
                # Configure extra WiFi for different purposes
                extra_config = api.set_extra_wifi_config(
                    ssid_2g="IoT_Devices",         # 2.4GHz for IoT devices
                    ssid_5g="WorkFromHome",        # 5GHz for work devices
                    password_2g="IoTSecure2024!",
                    password_5g="WorkSecure2024!",
                    security_mode_2g="WPA2-Personal",
                    security_mode_5g="WPA2-Personal"
                )
                print(f"  Extra WiFi configured: {'✅ Success' if extra_config else '❌ Failed'}")
                print(f"    📱 2.4GHz: IoT_Devices (for smart home devices)")
                print(f"    💼 5GHz: WorkFromHome (for work equipment)")
            print()
            
            time.sleep(2)
            
            # Example 4: WiFi Visibility Management
            print("👁️ Example 4: Managing WiFi network visibility...")
            
            # Hide guest networks for security
            guest_visibility = api.set_guest_wifi_visibility(visible_2g=False, visible_5g=False)
            print(f"  Guest networks hidden: {'✅ Success' if guest_visibility else '❌ Failed'}")
            
            # Hide IoT network but show work network
            extra_visibility = api.set_extra_wifi_visibility(visible_2g=False, visible_5g=True)
            print(f"  Extra network visibility:")
            print(f"    IoT (2.4GHz) hidden: {'✅ Success' if extra_visibility else '❌ Failed'}")
            print(f"    Work (5GHz) visible: {'✅ Success' if extra_visibility else '❌ Failed'}")
            
            # Keep regular networks visible
            regular_visibility = api.set_wifi_visibility(visible_2g=True, visible_5g=True)
            print(f"  Regular networks visible: {'✅ Success' if regular_visibility else '❌ Failed'}")
            print()
            
            time.sleep(3)
            
            # Example 5: WPS Management
            print("🔐 Example 5: Managing WPS (WiFi Protected Setup)...")
            
            # Disable WPS for security on regular networks
            wps_results = api.set_wps_enabled(enabled_2g=False, enabled_5g=False)
            print(f"  Regular WiFi WPS disabled:")
            print(f"    2.4GHz: {'✅ Success' if wps_results.get('band_2g') else '❌ Failed'}")
            print(f"    5GHz: {'✅ Success' if wps_results.get('band_5g') else '❌ Failed'}")
            print()
            
            time.sleep(2)
            
            # Example 6: Show final configuration
            print("📋 Final WiFi Configuration Summary:")
            show_wifi_summary(api)
            
            # Cleanup option
            print("\n❓ Reset all WiFi to default settings? (y/N): ", end="")
            response = input().lower().strip()
            if response == 'y':
                print("\n🔧 Resetting WiFi configuration...")
                reset_wifi_config(api)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

def show_current_wifi_status(api):
    """Display current WiFi network status"""
    print("📡 Current WiFi Network Status:")
    
    # Regular networks
    regular_networks = api.get_wifi_networks()
    if regular_networks:
        print("  🏠 Regular Networks:")
        for network in regular_networks:
            ssid = network['SSID']
            status = network['VAPStatus']
            vap = network['VAPName']
            connected = network.get('AssociatedDeviceNumberOfEntries', 0)
            print(f"    📶 {ssid} ({vap}) - {status} - {connected} devices")
    
    # Guest networks
    guest_networks = api.get_guest_wifi_networks()
    if guest_networks:
        print("  👥 Guest Networks:")
        for network in guest_networks:
            ssid = network['SSID']
            status = network['VAPStatus']
            vap = network['VAPName']
            print(f"    🏨 {ssid} ({vap}) - {status}")
    else:
        print("  👥 Guest Networks: Not configured")
    
    print()

def show_wifi_summary(api):
    """Show comprehensive WiFi configuration summary"""
    all_networks = api.get_all_wifi_networks()
    
    # Regular networks
    regular_networks = all_networks.get('regular', [])
    print("  🏠 Regular Networks:")
    for network in regular_networks:
        ssid = network['SSID']
        status = network['VAPStatus']
        visible = "Visible" if network.get('SSIDAdvertisementEnabled', True) else "Hidden"
        security = network.get('Security', {}).get('ModeEnabled', 'Unknown')
        print(f"    📶 {ssid} - {status} - {visible} - {security}")
    
    # Guest networks
    guest_networks = all_networks.get('guest', [])
    if guest_networks:
        print("  👥 Guest Networks:")
        for network in guest_networks:
            ssid = network['SSID']
            status = network['VAPStatus']
            visible = "Visible" if network.get('SSIDAdvertisementEnabled', True) else "Hidden"
            security = network.get('Security', {}).get('ModeEnabled', 'Unknown')
            print(f"    🏨 {ssid} - {status} - {visible} - {security}")
    else:
        print("  👥 Guest Networks: Disabled")
    
    # Note: Extra networks would be shown here if we had a get_extra_wifi_networks() method
    # For now, we'll just note they exist
    print("  🔧 Extra Networks: See individual VAP status in router interface")

def reset_wifi_config(api):
    """Reset WiFi configuration to safer defaults"""
    
    print("  🏠 Resetting regular WiFi to secure defaults...")
    regular_reset = api.set_wifi_config(
        ssid_2g="KPN_Box_2G",
        ssid_5g="KPN_Box_5G",
        password_2g="DefaultPass2024!",
        password_5g="DefaultPass2024!",
        security_mode_2g="WPA2-Personal",
        security_mode_5g="WPA2-Personal"
    )
    print(f"    Result: {'✅ Success' if regular_reset else '❌ Failed'}")
    
    print("  👥 Disabling guest networks...")
    guest_disable = api.enable_guest_network(enabled=False)
    print(f"    Result: {'✅ Success' if guest_disable else '❌ Failed'}")
    
    print("  🔧 Disabling extra networks...")
    extra_disable = api.enable_extra_wifi(enabled_2g=False, enabled_5g=False)
    success = extra_disable.get('band_2g', False) and extra_disable.get('band_5g', False)
    print(f"    Result: {'✅ Success' if success else '❌ Failed'}")
    
    print("  👁️ Making regular networks visible...")
    visibility = api.set_wifi_visibility(visible_2g=True, visible_5g=True)
    print(f"    Result: {'✅ Success' if visibility else '❌ Failed'}")
    
    print("  🔐 Enabling WPS for easy setup...")
    wps = api.set_wps_enabled(enabled_2g=True, enabled_5g=True)
    success = wps.get('band_2g', False) and wps.get('band_5g', False)
    print(f"    Result: {'✅ Success' if success else '❌ Failed'}")

def wifi_best_practices():
    """Print WiFi management best practices"""
    print("\n📚 WiFi Management Best Practices:")
    print("   🏠 Regular Networks:")
    print("     • Use strong, unique passwords (12+ characters)")
    print("     • Enable WPA2-Personal minimum (WPA3 if supported)")
    print("     • Use descriptive but not personally identifiable SSIDs")
    print("     • Keep networks visible for easy device connection")
    print()
    print("   👥 Guest Networks:")
    print("     • Use simple, shareable passwords")
    print("     • Set reasonable bandwidth limits (10-25 Mbps)")
    print("     • Consider time-based restrictions")
    print("     • Use generic, welcoming network names")
    print("     • Change passwords regularly")
    print()
    print("   🔧 Extra Networks:")
    print("     • Use for specific purposes (IoT, work, gaming)")
    print("     • Consider hiding IoT networks for security")
    print("     • Use different passwords for different purposes")
    print("     • 2.4GHz for IoT devices, 5GHz for high-performance")
    print()
    print("   🔐 Security Guidelines:")
    print("     • Disable WPS when not needed")
    print("     • Use Management Frame Protection when available")
    print("     • Regularly update router firmware")
    print("     • Monitor connected devices")
    print("     • Consider MAC address filtering for sensitive networks")

def network_scenarios():
    """Show common WiFi network scenarios"""
    print("\n🏡 Common WiFi Network Scenarios:")
    
    print("\n1. Basic Home Setup:")
    print("   • Regular: MyHome_2G / MyHome_5G (main devices)")
    print("   • Guest: Guest_WiFi (visitors)")
    print("   • Extra: Not used")
    
    print("\n2. Smart Home Setup:")
    print("   • Regular: Home_2G / Home_5G (phones, laptops)")
    print("   • Guest: Visitors (guests)")
    print("   • Extra: IoT_2G / Smart_5G (smart devices)")
    
    print("\n3. Work From Home:")
    print("   • Regular: Personal_2G / Personal_5G (personal devices)")
    print("   • Guest: Family_Guest (family visitors)")
    print("   • Extra: IoT_2G / Work_5G (work equipment)")
    
    print("\n4. Multi-Tenant/Rental:")
    print("   • Regular: Owner_2G / Owner_5G (owner devices)")
    print("   • Guest: Tenant_WiFi (tenants)")
    print("   • Extra: Services_2G / Utilities_5G (utilities)")

if __name__ == "__main__":
    print("Comprehensive WiFi Management Example for KPN Box API")
    print("=" * 60)
    
    # Run main examples
    exit_code = main()
    
    # Show additional information
    wifi_best_practices()
    network_scenarios()
    
    print(f"\n{'✅ Examples completed successfully!' if exit_code == 0 else '❌ Examples failed!'}")
    exit(exit_code) 