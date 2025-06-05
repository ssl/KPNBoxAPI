#!/usr/bin/env python3
"""
IPv6 Prefix Delegation Configuration Example

This example demonstrates how to configure IPv6 prefix delegation
on your KPN Box router using the KPNBoxAPI library.

IPv6 prefix delegation allows the router to automatically obtain
IPv6 prefixes from your ISP and delegate sub-prefixes to your
LAN and guest networks.
"""

import sys
sys.path.insert(0, 'src')

from kpnboxapi import KPNBoxAPI

def main():
    # Initialize API client
    api = KPNBoxAPI()
    
    try:
        # Login to the router
        print("🔐 Logging into KPN Box...")
        if not api.login(password=input("Enter admin password: ")):
            print("❌ Failed to login")
            return
        
        print("✅ Successfully logged in")
        
        # Get current IPv6 status
        print("\n📋 Current IPv6 Configuration")
        print("-" * 40)
        
        # Get IPv6 configuration from NetMaster
        try:
            netmaster_config = api.get_netmaster_config()
            print(f"IPv6 Enabled: {netmaster_config.get('EnableIPv6', 'Unknown')}")
            print(f"IPv6 Prefix Mode: {netmaster_config.get('IPv6PrefixMode', 'Unknown')}")
        except Exception as e:
            print(f"Could not get IPv6 status: {e}")
        
        # Get IPv6 LAN configuration
        try:
            ipv6_config = api.get_lan_ipv6_config()
            print(f"LAN IPv6 Address: {ipv6_config.get('Address', 'Not configured')}")
            print(f"DHCPv6 Enabled: {ipv6_config.get('DHCPEnable', 'Unknown')}")
        except Exception as e:
            print(f"Could not get LAN IPv6 config: {e}")
        
        # Interactive menu
        while True:
            print("\n🔧 IPv6 Prefix Delegation Configuration")
            print("=" * 50)
            print("1. 🚫 Disable IPv6 prefix delegation")
            print("2. ✅ Enable IPv6 prefix delegation (RA mode)")
            print("3. ✅ Enable IPv6 prefix delegation (RA + DHCPv6 mode)")
            print("4. 🔧 Advanced configuration")
            print("5. 📊 Show current status")
            print("6. 🚪 Exit")
            
            choice = input("\nSelect an option (1-6): ").strip()
            
            if choice == "1":
                print("\n🚫 Disabling IPv6 prefix delegation...")
                success = api.disable_ipv6_prefix_delegation()
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                
                if success:
                    print("IPv6 prefix delegation has been disabled.")
                    print("The router will use DHCPv6 mode without prefix delegation.")
            
            elif choice == "2":
                print("\n✅ Enabling IPv6 prefix delegation (RA mode)...")
                success = api.enable_ipv6_prefix_delegation(use_dhcpv6=False)
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                
                if success:
                    print("IPv6 prefix delegation enabled with Router Advertisement (RA) mode.")
                    print("The router will delegate IPv6 prefixes using RA announcements.")
            
            elif choice == "3":
                print("\n✅ Enabling IPv6 prefix delegation (RA + DHCPv6 mode)...")
                success = api.enable_ipv6_prefix_delegation(use_dhcpv6=True)
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                
                if success:
                    print("IPv6 prefix delegation enabled with RA + DHCPv6 mode.")
                    print("The router will use both RA and DHCPv6 for IPv6 configuration.")
            
            elif choice == "4":
                print("\n🔧 Advanced IPv6 Prefix Delegation Configuration")
                print("-" * 45)
                
                # Get user preferences
                enabled = input("Enable prefix delegation? (y/n, default=y): ").strip().lower()
                enabled = enabled != 'n'
                
                if enabled:
                    use_dhcpv6 = input("Use DHCPv6 mode? (y/n, default=n for RA only): ").strip().lower()
                    use_dhcpv6 = use_dhcpv6 == 'y'
                    
                    print(f"\nConfiguring IPv6 prefix delegation:")
                    print(f"  - Enabled: {enabled}")
                    print(f"  - Mode: {'RA + DHCPv6' if use_dhcpv6 else 'RA only'}")
                    print(f"  - Prefix Length: 56 (fixed)")
                    
                    success = api.configure_ipv6_prefix_delegation(
                        enabled=enabled,
                        use_dhcpv6=use_dhcpv6,
                        prefix_length=56
                    )
                else:
                    print("\nDisabling IPv6 prefix delegation...")
                    success = api.configure_ipv6_prefix_delegation(enabled=False)
                
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
            
            elif choice == "5":
                print("\n📊 Current IPv6 Status")
                print("-" * 30)
                
                # NetMaster configuration
                try:
                    netmaster_config = api.get_netmaster_config()
                    ipv6_enabled = netmaster_config.get('EnableIPv6', False)
                    prefix_mode = netmaster_config.get('IPv6PrefixMode', 'Unknown')
                    
                    print(f"IPv6 Globally Enabled: {'✅ Yes' if ipv6_enabled else '❌ No'}")
                    print(f"IPv6 Prefix Mode: {prefix_mode}")
                    
                    if prefix_mode == "DHCPv6":
                        print("  📋 DHCPv6 mode - No prefix delegation")
                    elif prefix_mode == "RA":
                        print("  📡 Router Advertisement mode - Prefix delegation enabled")
                    elif prefix_mode == "RAandDHCPv6":
                        print("  🔄 RA + DHCPv6 mode - Prefix delegation with both methods")
                    
                except Exception as e:
                    print(f"Could not get NetMaster config: {e}")
                
                # LAN IPv6 configuration
                try:
                    ipv6_config = api.get_lan_ipv6_config()
                    print(f"\nLAN IPv6 Configuration:")
                    print(f"  Address: {ipv6_config.get('Address', 'Not set')}")
                    print(f"  Prefix Length: {ipv6_config.get('PrefixLength', 'Not set')}")
                    print(f"  DHCPv6 Enabled: {'✅ Yes' if ipv6_config.get('DHCPEnable') else '❌ No'}")
                    print(f"  IAPD Enabled: {'✅ Yes' if ipv6_config.get('DHCPIAPDEnable') else '❌ No'}")
                    print(f"  IANA Enabled: {'✅ Yes' if ipv6_config.get('DHCPIANAEnable') else '❌ No'}")
                    
                except Exception as e:
                    print(f"Could not get LAN IPv6 config: {e}")
                
                # DHCPv6 client status
                try:
                    dhcpv6_status = api.get_dhcpv6_client_status()
                    print(f"\nDHCPv6 Client Status:")
                    print(f"  Status: {dhcpv6_status.get('DHCPStatus', 'Unknown')}")
                    print(f"  Request Prefixes: {'✅ Yes' if dhcpv6_status.get('RequestPrefixes') else '❌ No'}")
                    print(f"  Request Addresses: {'✅ Yes' if dhcpv6_status.get('RequestAddresses') else '❌ No'}")
                    
                except Exception as e:
                    print(f"Could not get DHCPv6 client status: {e}")
            
            elif choice == "6":
                print("\n👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice. Please select 1-6.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        api.logout()

def demonstrate_prefix_delegation():
    """
    Demonstrate the different IPv6 prefix delegation modes.
    """
    print("IPv6 Prefix Delegation Modes:")
    print("=" * 40)
    
    print("\n🚫 OFF Mode:")
    print("  - Disables IPv6 prefix delegation")
    print("  - Sets IPv6PrefixMode to 'DHCPv6'")
    print("  - Router requests single IPv6 address from ISP")
    print("  - No automatic sub-prefix delegation to LAN/guest networks")
    
    print("\n✅ ON Mode (RA):")
    print("  - Enables IPv6 prefix delegation")
    print("  - Sets IPv6PrefixMode to 'RA' (Router Advertisement)")
    print("  - Router requests IPv6 prefix from ISP (typically /56)")
    print("  - Automatically delegates sub-prefixes to networks")
    print("  - Uses Router Advertisement for client configuration")
    
    print("\n🔄 ON with DHCPv6 Mode:")
    print("  - Enables IPv6 prefix delegation")
    print("  - Sets IPv6PrefixMode to 'RAandDHCPv6'")
    print("  - Combines Router Advertisement with DHCPv6")
    print("  - Provides both stateless (RA) and stateful (DHCPv6) configuration")
    print("  - More comprehensive IPv6 address management")
    
    print("\n💡 Benefits of Prefix Delegation:")
    print("  - Automatic IPv6 connectivity for all network segments")
    print("  - No manual IPv6 subnet configuration needed")
    print("  - Supports multiple networks (LAN, guest, etc.)")
    print("  - Dynamic prefix updates from ISP")
    print("  - Better IPv6 compliance and functionality")

if __name__ == "__main__":
    print("🌐 KPN Box IPv6 Prefix Delegation Configuration")
    print("=" * 50)
    
    # Show explanation first
    demonstrate_prefix_delegation()
    
    print("\n" + "=" * 50)
    proceed = input("Proceed with configuration? (y/n): ").strip().lower()
    
    if proceed == 'y':
        main()
    else:
        print("👋 Configuration cancelled.") 