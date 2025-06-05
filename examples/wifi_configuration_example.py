#!/usr/bin/env python3
"""
WiFi Configuration Example

This example demonstrates how to configure WiFi settings on KPN Box routers.
Shows how to change SSIDs, passwords, security modes, visibility, and WPS settings.

Requirements:
- KPN Box router (tested with Box 14)
- Admin access to the router
- Active WiFi networks to configure
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
            
            # Get current WiFi configuration
            print("📡 Current WiFi Networks:")
            wifi_networks = api.get_wifi_networks()
            for network in wifi_networks:
                print(f"  {network['SSID']} ({network['VAPName']}) - {network['VAPStatus']}")
                security = network.get('Security', {})
                print(f"    Security: {security.get('ModeEnabled', 'Unknown')}")
                print(f"    Connected devices: {network.get('AssociatedDeviceNumberOfEntries', 0)}")
            print()
            
            # Example 1: Change WiFi name and password for both bands
            print("🔧 Example 1: Changing WiFi name and password...")
            success = api.set_wifi_config(
                ssid_2g="MyHome_2G",
                ssid_5g="MyHome_5G",
                password_2g="MySecurePassword123!",
                password_5g="MySecurePassword123!",
                security_mode_2g="WPA2-Personal",
                security_mode_5g="WPA2-Personal"
            )
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  ⚠️  Devices will need to reconnect with new credentials!")
            print()
            
            # Wait a moment for changes to take effect
            time.sleep(2)
            
            # Example 2: Change only the SSID (keep existing password)
            print("🔧 Example 2: Changing only the network name...")
            success = api.set_wifi_config(
                ssid_2g="HomeNetwork_24G",
                ssid_5g="HomeNetwork_5G"
                # Note: password and security remain unchanged
            )
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            print()
            
            time.sleep(2)
            
            # Example 3: Hide WiFi networks (disable SSID broadcast)
            print("🔧 Example 3: Hiding WiFi networks...")
            success = api.set_wifi_visibility(visible_2g=False, visible_5g=False)
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  📵 Networks are now hidden - devices need manual connection")
            print()
            
            time.sleep(3)
            
            # Example 4: Show WiFi networks again
            print("🔧 Example 4: Making WiFi networks visible again...")
            success = api.set_wifi_visibility(visible_2g=True, visible_5g=True)
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  📶 Networks are now visible again")
            print()
            
            time.sleep(2)
            
            # Example 5: Disable WPS for security
            print("🔧 Example 5: Disabling WPS for better security...")
            results = api.set_wps_enabled(enabled_2g=False, enabled_5g=False)
            print(f"  2.4GHz WPS: {'✅ Disabled' if results.get('band_2g') else '❌ Failed'}")
            print(f"  5GHz WPS: {'✅ Disabled' if results.get('band_5g') else '❌ Failed'}")
            if results.get('band_2g') and results.get('band_5g'):
                print("  🔒 WPS disabled - more secure but requires manual setup")
            print()
            
            time.sleep(2)
            
            # Example 6: Enable WPS temporarily for easy device connection
            print("🔧 Example 6: Enabling WPS temporarily...")
            results = api.set_wps_enabled(enabled_2g=True, enabled_5g=True)
            print(f"  2.4GHz WPS: {'✅ Enabled' if results.get('band_2g') else '❌ Failed'}")
            print(f"  5GHz WPS: {'✅ Enabled' if results.get('band_5g') else '❌ Failed'}")
            if results.get('band_2g') and results.get('band_5g'):
                print("  📱 WPS enabled - you can now connect devices easily")
                print("  ⚠️  Remember to disable WPS again for security!")
            print()
            
            # Example 8: Separate band configuration
            print("🔧 Example 8: Different settings per band...")
            success = api.set_wifi_config(
                ssid_2g="MyHome_Guest",       # Use 2.4GHz for guest access
                ssid_5g="MyHome_Private",     # Use 5GHz for main devices
                password_2g="GuestPass123",   # Simpler guest password
                password_5g="PrivatePass456!",# Complex private password
                security_mode_2g="WPA2-Personal",  # Standard for guest
                security_mode_5g="WPA3-Personal"   # Latest for private
            )
            print(f"  Result: {'✅ Success' if success else '❌ Failed'}")
            if success:
                print("  🏠 2.4GHz configured as guest network")
                print("  🔐 5GHz configured as private network")
            print()
            
            # Show final configuration
            print("📋 Final WiFi Configuration:")
            wifi_networks = api.get_wifi_networks()
            for network in wifi_networks:
                ssid = network['SSID']
                status = network['VAPStatus']
                vap = network['VAPName']
                security = network.get('Security', {}).get('ModeEnabled', 'Unknown')
                
                # Check if SSID broadcast is enabled
                broadcast = network.get('SSIDAdvertisementEnabled', True)
                visibility = "Visible" if broadcast else "Hidden"
                
                print(f"  📶 {ssid} ({vap})")
                print(f"      Status: {status} | Security: {security} | {visibility}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

def security_recommendations():
    """Print WiFi security best practices"""
    print("\n🛡️  WiFi Security Best Practices:")
    print("   • Use WPA3-Personal if supported, otherwise WPA2-Personal")
    print("   • Use strong passwords (12+ characters, mixed case, numbers, symbols)")
    print("   • Disable WPS when not actively connecting devices")
    print("   • Consider hiding SSID for private networks")
    print("   • Enable Management Frame Protection (MFP) if available")
    print("   • Regularly update WiFi passwords")
    print("   • Use separate networks for guests and IoT devices")

def advanced_examples():
    """Show some advanced configuration patterns"""
    print("\n🔧 Advanced Configuration Examples:")
    print("\n1. Guest Network Setup:")
    print("   api.set_wifi_config(")
    print("       ssid_2g='Guest_2G', ssid_5g='Guest_5G',")
    print("       password_2g='TempPass123', password_5g='TempPass123',")
    print("       security_mode_2g='WPA2-Personal'")
    print("   )")
    
    print("\n2. IoT Device Network (2.4GHz only, simple security):")
    print("   api.set_wifi_config(")
    print("       ssid_2g='IoT_Devices',")
    print("       password_2g='SimpleIoTPass',")
    print("       security_mode_2g='WPA2-Personal'")
    print("   )")
    
    print("\n3. High Security Setup:")
    print("   api.set_wifi_config(")
    print("       ssid_2g='SecureHome', ssid_5g='SecureHome',")
    print("       password_2g='VeryStr0ngP@ssw0rd!2024',")
    print("       password_5g='VeryStr0ngP@ssw0rd!2024',")
    print("       security_mode_2g='WPA3-Personal',")
    print("       security_mode_5g='WPA3-Personal',")
    print("       mfp_config_2g='Benodigd', mfp_config_5g='Benodigd'")
    print("   )")
    print("   api.set_wifi_visibility(visible_2g=False, visible_5g=False)")
    print("   api.set_wps_enabled(enabled_2g=False, enabled_5g=False)")

if __name__ == "__main__":
    print("WiFi Configuration Example for KPN Box API")
    print("=" * 50)
    
    # Run main examples
    exit_code = main()
    
    # Show additional information
    security_recommendations()
    advanced_examples()
    
    print(f"\n{'✅ Examples completed successfully!' if exit_code == 0 else '❌ Examples failed!'}")
    exit(exit_code) 