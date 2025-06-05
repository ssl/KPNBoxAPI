#!/usr/bin/env python3
"""
Guest Network Configuration Example

This example demonstrates how to configure guest WiFi networks on KPN Box routers.
Shows how to enable guest networks, set credentials, configure bandwidth limits, 
and manage visibility settings.

Requirements:
- KPN Box router (tested with Box 14)
- Admin access to the router
- Guest network capability (available on most modern KPN Box models)
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
            
            # Check current guest network status
            print("📡 Current Guest Network Status:")
            guest_networks = api.get_guest_wifi_networks()
            if guest_networks:
                for network in guest_networks:
                    print(f"  {network['SSID']} ({network['VAPName']}) - {network['VAPStatus']}")
                    security = network.get('Security', {})
                    print(f"    Security: {security.get('ModeEnabled', 'Unknown')}")
                    print(f"    Connected devices: {network.get('AssociatedDeviceNumberOfEntries', 0)}")
            else:
                print("  No guest networks found (may be disabled)")
            print()
            
            # Example 1: Enable guest network
            print("🔧 Example 1: Enabling guest network...")
            success = api.enable_guest_network(enabled=True)
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  🏠 Guest network is now enabled on both bands")
            print()
            
            time.sleep(3)
            
            # Example 2: Configure guest WiFi credentials
            print("🔧 Example 2: Setting up guest WiFi credentials...")
            success = api.set_guest_wifi_config(
                ssid_2g="Guest_WiFi",
                ssid_5g="Guest_WiFi",
                password_2g="Welcome2024!",
                password_5g="Welcome2024!",
                security_mode_2g="WPA2-Personal",
                security_mode_5g="WPA2-Personal"
            )
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  📱 Guest networks configured with same credentials")
                print("  🔑 SSID: Guest_WiFi | Password: Welcome2024!")
            print()
            
            time.sleep(2)
            
            # Example 3: Set bandwidth limit for guests
            print("🔧 Example 3: Setting bandwidth limit for guests...")
            success = api.set_guest_bandwidth_limit(10)  # 10 Mbps
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  🚦 Guest bandwidth limited to 10 Mbps")
                print("  💡 This prevents guests from using all available bandwidth")
            print()
            
            time.sleep(2)
            
            # Example 4: Different configurations per band
            print("🔧 Example 4: Different guest settings per band...")
            success = api.set_guest_wifi_config(
                ssid_2g="Guest_Basic",      # 2.4GHz for basic devices
                ssid_5g="Guest_Fast",       # 5GHz for modern devices
                password_2g="BasicGuest123",
                password_5g="FastGuest456",
                security_mode_2g="WPA2-Personal",
                security_mode_5g="WPA2-Personal"
            )
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  📶 2.4GHz: Guest_Basic (for older devices)")
                print("  🚀 5GHz: Guest_Fast (for modern devices)")
            print()
            
            time.sleep(2)
            
            # Example 5: Hide guest networks
            print("🔧 Example 5: Hiding guest networks...")
            success = api.set_guest_wifi_visibility(visible_2g=False, visible_5g=False)
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  🕵️ Guest networks are now hidden")
                print("  📋 Guests will need manual network setup")
            print()
            
            time.sleep(3)
            
            # Example 6: Show guest networks again
            print("🔧 Example 6: Making guest networks visible...")
            success = api.set_guest_wifi_visibility(visible_2g=True, visible_5g=True)
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  👁️ Guest networks are now visible again")
            print()
            
            time.sleep(2)
            
            # Example 7: Adjust bandwidth limit
            print("🔧 Example 7: Adjusting bandwidth limit...")
            success = api.set_guest_bandwidth_limit(25)  # 25 Mbps
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  📈 Guest bandwidth increased to 25 Mbps")
            print()
            
            time.sleep(2)
            
            # Example 8: Remove bandwidth limit
            print("🔧 Example 8: Removing bandwidth limit...")
            success = api.set_guest_bandwidth_limit(0)  # Unlimited
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  🔓 Guest bandwidth is now unlimited")
                print("  ⚠️  Guests can use full available bandwidth")
            print()
            
            time.sleep(2)
            
            # Example 9: Setup secure guest network
            print("🔧 Example 9: Setting up secure guest network...")
            success = api.set_guest_wifi_config(
                ssid_2g="SecureGuest",
                ssid_5g="SecureGuest", 
                password_2g="Str0ngGu3stP@ss!",
                password_5g="Str0ngGu3stP@ss!",
                security_mode_2g="WPA2-Personal",
                security_mode_5g="WPA2-Personal"
            )
            if success:
                # Set reasonable bandwidth limit
                limit_success = api.set_guest_bandwidth_limit(15)
                print(f"  Config: {'✅ Success' if success else '❌ Failed'}")
                print(f"  Bandwidth: {'✅ 15 Mbps limit set' if limit_success else '❌ Limit failed'}")
                if success and limit_success:
                    print("  🛡️ Secure guest network with reasonable bandwidth limit")
            print()
            
            # Show final guest network configuration
            print("📋 Final Guest Network Configuration:")
            guest_networks = api.get_guest_wifi_networks()
            if guest_networks:
                for network in guest_networks:
                    ssid = network['SSID']
                    status = network['VAPStatus']
                    vap = network['VAPName']
                    security = network.get('Security', {}).get('ModeEnabled', 'Unknown')
                    
                    # Check if SSID broadcast is enabled
                    broadcast = network.get('SSIDAdvertisementEnabled', True)
                    visibility = "Visible" if broadcast else "Hidden"
                    
                    print(f"  📶 {ssid} ({vap})")
                    print(f"      Status: {status} | Security: {security} | {visibility}")
            else:
                print("  ❌ No guest networks available")
            
            # Option to disable guest network
            print("\n❓ Disable guest network? (y/N): ", end="")
            response = input().lower().strip()
            if response == 'y':
                print("\n🔧 Disabling guest network...")
                success = api.enable_guest_network(enabled=False)
                print(f"  Result: {'✅ Disabled' if success else '❌ Failed'}")
                if success:
                    print("  🔒 Guest network completely disabled")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

def guest_network_best_practices():
    """Print guest network best practices"""
    print("\n🏠 Guest Network Best Practices:")
    print("   • Use a separate, easily shareable password")
    print("   • Set reasonable bandwidth limits (10-25 Mbps is usually sufficient)")
    print("   • Use WPA2-Personal security minimum")
    print("   • Consider using time-based access restrictions")
    print("   • Regularly change guest network passwords")
    print("   • Monitor guest network usage")
    print("   • Keep guest networks visible for easy access")
    print("   • Use descriptive network names (e.g., 'YourName_Guest')")

def bandwidth_guidelines():
    """Print bandwidth limit guidelines"""
    print("\n📊 Bandwidth Limit Guidelines:")
    print("   • 0 Mbps = Unlimited (use with caution)")
    print("   • 5-10 Mbps = Basic browsing, email, light streaming")
    print("   • 10-25 Mbps = Standard use, video calls, streaming")
    print("   • 25-50 Mbps = Heavy usage, multiple devices")
    print("   • 50+ Mbps = High bandwidth applications")
    print("   • Consider your total internet speed when setting limits")

def advanced_guest_examples():
    """Show advanced guest network configurations"""
    print("\n🔧 Advanced Guest Network Examples:")
    
    print("\n1. Temporary Event Guest Network:")
    print("   # Enable for event")
    print("   api.enable_guest_network(enabled=True)")
    print("   api.set_guest_wifi_config(")
    print("       ssid_2g='Event_WiFi', ssid_5g='Event_WiFi',")
    print("       password_2g='Event2024!', password_5g='Event2024!'")
    print("   )")
    print("   api.set_guest_bandwidth_limit(20)  # 20 Mbps per guest")
    
    print("\n2. IoT Guest Network (2.4GHz only):")
    print("   api.set_guest_wifi_config(")
    print("       ssid_2g='IoT_Guest',")
    print("       password_2g='IoTPass123',")
    print("       security_mode_2g='WPA2-Personal'")
    print("   )")
    print("   api.set_guest_bandwidth_limit(5)  # Low bandwidth for IoT")
    
    print("\n3. High-Security Hidden Guest:")
    print("   api.set_guest_wifi_config(")
    print("       ssid_2g='SecretGuest', ssid_5g='SecretGuest',")
    print("       password_2g='VerySecureGuestPass2024!',")
    print("       password_5g='VerySecureGuestPass2024!'")
    print("   )")
    print("   api.set_guest_wifi_visibility(visible_2g=False, visible_5g=False)")
    print("   api.set_guest_bandwidth_limit(15)")

if __name__ == "__main__":
    print("Guest Network Configuration Example for KPN Box API")
    print("=" * 55)
    
    # Run main examples
    exit_code = main()
    
    # Show additional information
    guest_network_best_practices()
    bandwidth_guidelines() 
    advanced_guest_examples()
    
    print(f"\n{'✅ Examples completed successfully!' if exit_code == 0 else '❌ Examples failed!'}")
    exit(exit_code) 