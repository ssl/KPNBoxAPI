#!/usr/bin/env python3
"""
Ethernet Port Configuration Example

This example demonstrates how to configure Ethernet port settings
on your KPN Box router using the KPNBoxAPI library.

Features:
- Switch port 4 between home LAN and guest network
- Enable/disable STP (Spanning Tree Protocol)
- Configure interface settings (duplex, speed)
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
        
        # Get current network statistics to show port activity
        print("\n📊 Current Port Statistics")
        print("-" * 40)
        
        try:
            all_stats = api.get_all_network_stats()
            for port in ["ETH0", "ETH1", "ETH2", "ETH3"]:
                stats = all_stats.get(port, {})
                if stats.get('Available', True):
                    rx_bytes = api.format_bytes(stats.get('RxBytes', 0))
                    tx_bytes = api.format_bytes(stats.get('TxBytes', 0))
                    port_num = port.replace('ETH', '')
                    print(f"Port {port_num}: ↓{rx_bytes} ↑{tx_bytes}")
                    
                    if port == "ETH3":
                        print("  📌 Port 4 (ETH3) - This port can be configured for guest network")
        except Exception as e:
            print(f"Could not get port statistics: {e}")
        
        # Interactive menu
        while True:
            print("\n🔧 Ethernet Port Configuration")
            print("=" * 40)
            print("1. 🏠 Set port 4 to home LAN network")
            print("2. 👥 Set port 4 to guest network")
            print("3. 🔀 Toggle port 4 network assignment")
            print("4. 🌉 Enable STP (Spanning Tree Protocol)")
            print("5. 🚫 Disable STP (Spanning Tree Protocol)")
            print("6. ⚡ Configure interface speed/duplex")
            print("7. 📊 Show current statistics")
            print("8. 💡 Show configuration info")
            print("9. 🚪 Exit")
            
            choice = input("\nSelect an option (1-9): ").strip()
            
            if choice == "1":
                print("\n🏠 Setting port 4 to home LAN network...")
                success = api.disable_port4_guest_network()
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                
                if success:
                    print("Port 4 is now connected to the home LAN network.")
                    print("Devices connected to port 4 will get home network IP addresses.")
            
            elif choice == "2":
                print("\n👥 Setting port 4 to guest network...")
                success = api.enable_port4_guest_network()
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                
                if success:
                    print("Port 4 is now connected to the guest network.")
                    print("Devices connected to port 4 will get guest network IP addresses.")
            
            elif choice == "3":
                print("\n🔀 Configuring port 4 network assignment...")
                
                # Ask user for preference
                use_guest = input("Connect port 4 to guest network? (y/n): ").strip().lower()
                guest_enabled = use_guest == 'y'
                
                success = api.set_port4_guest_network(guest_enabled)
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                
                if success:
                    network = "guest network" if guest_enabled else "home LAN network"
                    print(f"Port 4 is now connected to the {network}.")
            
            elif choice == "4":
                print("\n🌉 Enabling STP (Spanning Tree Protocol)...")
                success = api.enable_stp()
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                
                if success:
                    print("STP has been enabled.")
                    print("This helps prevent network loops but may slightly increase latency.")
            
            elif choice == "5":
                print("\n🚫 Disabling STP (Spanning Tree Protocol)...")
                success = api.disable_stp()
                print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                
                if success:
                    print("STP has been disabled.")
                    print("⚠️  Warning: This may cause network loops if you have redundant connections.")
            
            elif choice == "6":
                print("\n⚡ Interface Speed/Duplex Configuration")
                print("-" * 40)
                
                # Show current options
                print("Available interfaces:")
                print("  - eth4 (WAN port)")
                print("  - ETH0-ETH3 (LAN ports 1-4)")
                
                interface = input("Enter interface name (default: eth4): ").strip()
                if not interface:
                    interface = "eth4"
                
                print("\nDuplex mode options: Auto, Half, Full")
                duplex = input("Enter duplex mode (default: Auto): ").strip()
                if not duplex:
                    duplex = "Auto"
                
                print("\nSpeed options: -1 (Auto) or speed in Mbps (e.g., 100, 1000)")
                speed_input = input("Enter max speed (default: -1 for Auto): ").strip()
                try:
                    speed = int(speed_input) if speed_input else -1
                except ValueError:
                    speed = -1
                
                print(f"\nConfiguring {interface}:")
                print(f"  - Duplex: {duplex}")
                print(f"  - Speed: {'Auto' if speed == -1 else f'{speed} Mbps'}")
                
                # Apply configuration
                success_duplex = api.set_interface_duplex(interface, duplex)
                success_speed = api.set_interface_speed(interface, speed)
                
                print(f"Duplex configured: {'✅ Success' if success_duplex else '❌ Failed'}")
                print(f"Speed configured: {'✅ Success' if success_speed else '❌ Failed'}")
            
            elif choice == "7":
                print("\n📊 Current Port Statistics")
                print("-" * 30)
                
                try:
                    all_stats = api.get_all_network_stats()
                    
                    print("Ethernet Ports:")
                    for port in ["ETH0", "ETH1", "ETH2", "ETH3"]:
                        stats = all_stats.get(port, {})
                        if stats.get('Available', True):
                            port_num = port.replace('ETH', '')
                            rx_bytes = api.format_bytes(stats.get('RxBytes', 0))
                            tx_bytes = api.format_bytes(stats.get('TxBytes', 0))
                            rx_packets = stats.get('RxPackets', 0)
                            tx_packets = stats.get('TxPackets', 0)
                            errors = stats.get('RxErrors', 0) + stats.get('TxErrors', 0)
                            
                            print(f"\n  Port {port_num} ({port}):")
                            print(f"    Data: ↓{rx_bytes} ↑{tx_bytes}")
                            print(f"    Packets: ↓{rx_packets:,} ↑{tx_packets:,}")
                            if errors > 0:
                                print(f"    ⚠️  Errors: {errors}")
                            
                            if port == "ETH3":
                                print(f"    📌 Configurable for guest network")
                    
                    print("\nWAN Port:")
                    wan_stats = all_stats.get("eth4", {})
                    if wan_stats.get('Available', True):
                        rx_bytes = api.format_bytes(wan_stats.get('RxBytes', 0))
                        tx_bytes = api.format_bytes(wan_stats.get('TxBytes', 0))
                        print(f"  WAN (eth4): ↓{rx_bytes} ↑{tx_bytes}")
                    
                except Exception as e:
                    print(f"Could not get statistics: {e}")
            
            elif choice == "8":
                print("\n💡 Ethernet Port Configuration Information")
                print("=" * 50)
                
                print("\n🔌 Port Layout:")
                print("  Port 1 (ETH0) - Always home LAN")
                print("  Port 2 (ETH1) - Always home LAN") 
                print("  Port 3 (ETH2) - Always home LAN")
                print("  Port 4 (ETH3) - Configurable (home LAN or guest)")
                print("  WAN (eth4)    - Internet connection")
                
                print("\n👥 Guest Network on Port 4:")
                print("  ✅ Benefits:")
                print("    - Physical isolation of guest devices")
                print("    - Easy guest access without WiFi password")
                print("    - Can apply different bandwidth limits")
                print("    - Separate from home network traffic")
                
                print("\n  ⚠️  Considerations:")
                print("    - Guest devices won't see home network")
                print("    - May need separate IP range configuration")
                print("    - Physical cable required for guest access")
                
                print("\n🌉 STP (Spanning Tree Protocol):")
                print("  ✅ Enable STP when:")
                print("    - Multiple network paths exist")
                print("    - Using network switches/hubs")
                print("    - Preventing network loops is critical")
                
                print("\n  ⚡ Disable STP when:")
                print("    - Simple single-path network")
                print("    - Maximum performance needed")
                print("    - No redundant connections exist")
                
                print("\n⚡ Interface Speed/Duplex:")
                print("  - Auto: Let devices negotiate best settings")
                print("  - Manual: Force specific speed/duplex for compatibility")
                print("  - Full duplex: Simultaneous send/receive (recommended)")
                print("  - Half duplex: One direction at a time (legacy)")
            
            elif choice == "9":
                print("\n👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice. Please select 1-9.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        api.logout()

def demonstrate_advanced_config():
    """
    Demonstrate advanced port configuration scenarios.
    """
    print("Advanced Ethernet Port Configuration Scenarios:")
    print("=" * 50)
    
    print("\n🏠 Home Office Setup:")
    print("  - Ports 1-3: Home network devices")
    print("  - Port 4: Guest network for visitors")
    print("  - Benefit: Physical separation of networks")
    
    print("\n🏢 Small Business Setup:")
    print("  - Ports 1-3: Employee devices")
    print("  - Port 4: Public/customer network")
    print("  - Add: Bandwidth limiting on guest network")
    
    print("\n🔧 Troubleshooting Setup:")
    print("  - Port 4 on home network: Test device connectivity")
    print("  - Port 4 on guest network: Isolate problematic device")
    print("  - STP disabled: Maximize performance for testing")
    
    print("\n🎮 Gaming Setup:")
    print("  - Gaming console on Port 1-3 (home network)")
    print("  - Port 4: Guest network for friends")
    print("  - STP disabled for lowest latency")

if __name__ == "__main__":
    print("🔌 KPN Box Ethernet Port Configuration")
    print("=" * 40)
    
    # Show explanation first
    demonstrate_advanced_config()
    
    print("\n" + "=" * 40)
    proceed = input("Proceed with configuration? (y/n): ").strip().lower()
    
    if proceed == 'y':
        main()
    else:
        print("👋 Configuration cancelled.") 