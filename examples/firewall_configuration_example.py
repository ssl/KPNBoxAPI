#!/usr/bin/env python3
"""
Firewall Configuration Example

This example demonstrates how to configure firewall settings
on your KPN Box router using the KPNBoxAPI library.

Features:
- Configure ping response settings
- Set firewall security levels (Low/Medium/High/Custom)
- Manage custom firewall rules (when in Custom mode)
- View current firewall status and rules
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
        
        # Get current firewall status
        print("\n🛡️ Current Firewall Status")
        print("-" * 40)
        
        try:
            firewall_level = api.get_firewall_level()
            firewall_config = api.get_firewall_config()
            ping_settings = api.get_ping_response_settings()
            
            print(f"Firewall Level: {firewall_level}")
            print(f"IPv4 Ping Response: {'Enabled' if ping_settings.get('enableIPv4') else 'Disabled'}")
            print(f"IPv6 Ping Response: {'Enabled' if ping_settings.get('enableIPv6') else 'Disabled'}")
            print(f"Firewall Status: {firewall_config.get('Status', 'Unknown')}")
            
            if firewall_level == "Custom":
                print("🔧 Custom mode - Custom rules available")
                custom_rules = api.get_custom_firewall_rules()
                print(f"Custom rules: {len(custom_rules)} defined")
            
        except Exception as e:
            print(f"Could not get firewall status: {e}")
        
        # Interactive menu
        while True:
            print("\n🛡️ Firewall Configuration")
            print("=" * 40)
            print("1. 🔒 Set firewall level to Low")
            print("2. 🔐 Set firewall level to Medium")
            print("3. 🔥 Set firewall level to High")
            print("4. ⚙️  Set firewall level to Custom")
            print("5. 🏓 Configure ping response")
            print("6. 📋 View current firewall status")
            print("7. 🔧 Manage custom firewall rules")
            print("8. 📊 Show firewall information")
            print("9. 🚪 Exit")
            
            choice = input("\nSelect an option (1-9): ").strip()
            
            if choice == "1":
                print("\n🔒 Setting firewall level to Low...")
                results = api.set_firewall_level("Low")
                print(f"IPv4: {'✅ Success' if results.get('ipv4') else '❌ Failed'}")
                print(f"IPv6: {'✅ Success' if results.get('ipv6') else '❌ Failed'}")
                
                if results.get('ipv4') and results.get('ipv6'):
                    print("Firewall set to Low level - minimal protection.")
            
            elif choice == "2":
                print("\n🔐 Setting firewall level to Medium...")
                results = api.set_firewall_level("Medium")
                print(f"IPv4: {'✅ Success' if results.get('ipv4') else '❌ Failed'}")
                print(f"IPv6: {'✅ Success' if results.get('ipv6') else '❌ Failed'}")
                
                if results.get('ipv4') and results.get('ipv6'):
                    print("Firewall set to Medium level - balanced protection.")
            
            elif choice == "3":
                print("\n🔥 Setting firewall level to High...")
                results = api.set_firewall_level("High")
                print(f"IPv4: {'✅ Success' if results.get('ipv4') else '❌ Failed'}")
                print(f"IPv6: {'✅ Success' if results.get('ipv6') else '❌ Failed'}")
                
                if results.get('ipv4') and results.get('ipv6'):
                    print("Firewall set to High level - maximum protection.")
            
            elif choice == "4":
                print("\n⚙️  Setting firewall level to Custom...")
                results = api.enable_custom_firewall()
                print(f"IPv4: {'✅ Success' if results.get('ipv4') else '❌ Failed'}")
                print(f"IPv6: {'✅ Success' if results.get('ipv6') else '❌ Failed'}")
                
                if results.get('ipv4') and results.get('ipv6'):
                    print("Firewall set to Custom level - custom rules now available.")
                    print("Use option 7 to manage custom firewall rules.")
            
            elif choice == "5":
                print("\n🏓 Configure Ping Response")
                print("-" * 30)
                
                current_settings = api.get_ping_response_settings()
                current_ipv4 = current_settings.get('enableIPv4', True)
                current_ipv6 = current_settings.get('enableIPv6', True)
                
                print(f"Current settings:")
                print(f"  IPv4 ping response: {'Enabled' if current_ipv4 else 'Disabled'}")
                print(f"  IPv6 ping response: {'Enabled' if current_ipv6 else 'Disabled'}")
                
                print("\nOptions:")
                print("1. Enable both IPv4 and IPv6 ping response")
                print("2. Disable both IPv4 and IPv6 ping response")
                print("3. Enable IPv4 only")
                print("4. Enable IPv6 only")
                print("5. Custom configuration")
                
                ping_choice = input("Select ping option (1-5): ").strip()
                
                if ping_choice == "1":
                    success = api.enable_ping_response(ipv4=True, ipv6=True)
                    print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                    if success:
                        print("Both IPv4 and IPv6 ping response enabled.")
                
                elif ping_choice == "2":
                    success = api.disable_ping_response()
                    print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                    if success:
                        print("Both IPv4 and IPv6 ping response disabled.")
                
                elif ping_choice == "3":
                    success = api.enable_ping_response(ipv4=True, ipv6=False)
                    print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                    if success:
                        print("IPv4 ping response enabled, IPv6 disabled.")
                
                elif ping_choice == "4":
                    success = api.enable_ping_response(ipv4=False, ipv6=True)
                    print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                    if success:
                        print("IPv6 ping response enabled, IPv4 disabled.")
                
                elif ping_choice == "5":
                    ipv4_enable = input("Enable IPv4 ping response? (y/n): ").strip().lower() == 'y'
                    ipv6_enable = input("Enable IPv6 ping response? (y/n): ").strip().lower() == 'y'
                    
                    success = api.set_ping_response(enable_ipv4=ipv4_enable, enable_ipv6=ipv6_enable)
                    print(f"Result: {'✅ Success' if success else '❌ Failed'}")
                    if success:
                        print(f"IPv4: {'Enabled' if ipv4_enable else 'Disabled'}")
                        print(f"IPv6: {'Enabled' if ipv6_enable else 'Disabled'}")
            
            elif choice == "6":
                print("\n📋 Current Firewall Status")
                print("-" * 30)
                
                try:
                    firewall_level = api.get_firewall_level()
                    firewall_config = api.get_firewall_config()
                    ping_settings = api.get_ping_response_settings()
                    
                    print(f"🛡️  Firewall Level: {firewall_level}")
                    print(f"📡 Status: {firewall_config.get('Status', 'Unknown')}")
                    print(f"🏓 IPv4 Ping: {'Enabled' if ping_settings.get('enableIPv4') else 'Disabled'}")
                    print(f"🏓 IPv6 Ping: {'Enabled' if ping_settings.get('enableIPv6') else 'Disabled'}")
                    
                    if firewall_config.get('UpnpPortForwardingEnable'):
                        print(f"🔌 UPnP Port Forwarding: Enabled")
                    
                    print(f"📊 Port Forwarding Rules: {firewall_config.get('ProtocolForwardingNumberOfEntries', 0)}")
                    print(f"📊 IPv6 Pinholes: {firewall_config.get('PinholeNumberOfEntries', 0)}")
                    
                    if firewall_level == "Custom":
                        custom_rules = api.get_custom_firewall_rules()
                        print(f"🔧 Custom Rules: {len(custom_rules)}")
                        
                        if custom_rules:
                            print("\nCustom Rules:")
                            for rule in custom_rules[:5]:  # Show first 5 rules
                                status = "🟢" if rule.get('Enable') else "🔴"
                                action = "✅" if rule.get('Target') == 'Accept' else "❌"
                                protocol_name = {"6": "TCP", "17": "UDP", "6,17": "TCP/UDP"}.get(
                                    rule.get('Protocol', ''), rule.get('Protocol', 'Unknown')
                                )
                                print(f"  {status} {action} {rule.get('Id')}: {protocol_name} port {rule.get('DestinationPort', 'any')}")
                            
                            if len(custom_rules) > 5:
                                print(f"  ... and {len(custom_rules) - 5} more rules")
                
                except Exception as e:
                    print(f"Could not get firewall status: {e}")
            
            elif choice == "7":
                # Check if custom mode is enabled
                current_level = api.get_firewall_level()
                if current_level != "Custom":
                    print("\n⚠️  Custom firewall rules require Custom firewall level.")
                    enable = input("Enable Custom firewall level? (y/n): ").strip().lower()
                    if enable == 'y':
                        results = api.enable_custom_firewall()
                        if not (results.get('ipv4') and results.get('ipv6')):
                            print("❌ Failed to enable Custom firewall level.")
                            continue
                        print("✅ Custom firewall level enabled.")
                    else:
                        continue
                
                # Custom rules management
                manage_custom_rules(api)
            
            elif choice == "8":
                show_firewall_info()
            
            elif choice == "9":
                print("\n👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice. Please select 1-9.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        api.logout()

def manage_custom_rules(api):
    """
    Manage custom firewall rules.
    """
    while True:
        print("\n🔧 Custom Firewall Rules Management")
        print("-" * 40)
        print("1. 📋 List current custom rules")
        print("2. ➕ Add new custom rule")
        print("3. ✏️  Edit existing rule")
        print("4. 🗑️  Delete rule")
        print("5. ✅ Enable rule")
        print("6. ❌ Disable rule")
        print("7. 📚 Rule examples")
        print("8. 🔙 Back to main menu")
        
        choice = input("\nSelect an option (1-8): ").strip()
        
        if choice == "1":
            print("\n📋 Current Custom Rules")
            print("-" * 30)
            
            try:
                rules = api.get_custom_firewall_rules()
                if not rules:
                    print("No custom rules defined.")
                else:
                    for i, rule in enumerate(rules, 1):
                        status = "🟢 Enabled" if rule.get('Enable') else "🔴 Disabled"
                        action = "✅ Accept" if rule.get('Target') == 'Accept' else "❌ Drop"
                        protocol = rule.get('Protocol', '')
                        protocol_name = {"6": "TCP", "17": "UDP", "6,17": "TCP/UDP"}.get(protocol, protocol)
                        
                        print(f"\n{i}. {rule.get('Id')} - {status}")
                        print(f"   Action: {action}")
                        print(f"   Protocol: {protocol_name} (IPv{rule.get('IPVersion', 4)})")
                        if rule.get('DestinationPort'):
                            print(f"   Port: {rule.get('DestinationPort')}")
                        if rule.get('DestinationPrefix'):
                            print(f"   Destination: {rule.get('DestinationPrefix')}")
                        if rule.get('SourcePrefix'):
                            print(f"   Source: {rule.get('SourcePrefix')}")
            
            except Exception as e:
                print(f"Could not get custom rules: {e}")
        
        elif choice == "2":
            print("\n➕ Add New Custom Rule")
            print("-" * 30)
            
            rule_id = input("Rule ID (e.g., 'ssh', 'myapp'): ").strip()
            if not rule_id:
                print("Rule ID is required.")
                continue
            
            print("Action: 1=Accept, 2=Drop")
            action_choice = input("Select action (1-2): ").strip()
            action = "Accept" if action_choice == "1" else "Drop"
            
            print("Protocol: 1=TCP, 2=UDP, 3=Both")
            proto_choice = input("Select protocol (1-3): ").strip()
            protocol = {"1": "6", "2": "17", "3": "6,17"}.get(proto_choice, "6")
            
            destination_port = input("Destination port (e.g., '22', '80-90', leave empty for any): ").strip()
            destination_ip = input("Destination IP (e.g., '192.168.2.100', leave empty for any): ").strip()
            source_ip = input("Source IP (leave empty for any): ").strip()
            
            print("IP version: 1=IPv4, 2=IPv6")
            ip_choice = input("Select IP version (1-2): ").strip()
            ip_version = 6 if ip_choice == "2" else 4
            
            enable_choice = input("Enable rule immediately? (y/n): ").strip().lower()
            enabled = enable_choice == 'y'
            
            try:
                result = api.add_custom_firewall_rule(
                    rule_id=rule_id,
                    action=action,
                    protocol=protocol,
                    destination_port=destination_port,
                    destination_prefix=destination_ip,
                    source_prefix=source_ip,
                    ip_version=ip_version,
                    enabled=enabled
                )
                
                if result:
                    print(f"✅ Rule '{rule_id}' added successfully.")
                else:
                    print(f"❌ Failed to add rule '{rule_id}'.")
            
            except Exception as e:
                print(f"Error adding rule: {e}")
        
        elif choice == "3":
            print("\n✏️  Edit Existing Rule")
            print("-" * 30)
            
            rules = api.get_custom_firewall_rules()
            if not rules:
                print("No custom rules to edit.")
                continue
            
            print("Current rules:")
            for i, rule in enumerate(rules):
                print(f"{i+1}. {rule.get('Id')} - {rule.get('Target')} - {rule.get('Protocol')}")
            
            try:
                rule_index = int(input("Select rule number to edit: ")) - 1
                if 0 <= rule_index < len(rules):
                    rule = rules[rule_index]
                    rule_id = rule.get('Id')
                    
                    print(f"Editing rule: {rule_id}")
                    print("Leave empty to keep current value:")
                    
                    destination_port = input(f"Destination port (current: {rule.get('DestinationPort', 'any')}): ").strip()
                    if not destination_port:
                        destination_port = rule.get('DestinationPort', '')
                    
                    destination_ip = input(f"Destination IP (current: {rule.get('DestinationPrefix', 'any')}): ").strip()
                    if not destination_ip:
                        destination_ip = rule.get('DestinationPrefix', '')
                    
                    result = api.update_custom_firewall_rule(
                        rule_id=rule_id,
                        destination_port=destination_port,
                        destination_prefix=destination_ip
                    )
                    
                    if result:
                        print(f"✅ Rule '{rule_id}' updated successfully.")
                    else:
                        print(f"❌ Failed to update rule '{rule_id}'.")
                else:
                    print("Invalid rule number.")
            
            except (ValueError, Exception) as e:
                print(f"Error: {e}")
        
        elif choice == "4":
            print("\n🗑️  Delete Rule")
            print("-" * 20)
            
            rules = api.get_custom_firewall_rules()
            if not rules:
                print("No custom rules to delete.")
                continue
            
            print("Current rules:")
            for i, rule in enumerate(rules):
                print(f"{i+1}. {rule.get('Id')}")
            
            try:
                rule_index = int(input("Select rule number to delete: ")) - 1
                if 0 <= rule_index < len(rules):
                    rule = rules[rule_index]
                    rule_id = rule.get('Id')
                    ip_version = rule.get('IPVersion', 4)
                    
                    confirm = input(f"Delete rule '{rule_id}'? (y/n): ").strip().lower()
                    if confirm == 'y':
                        success = api.delete_custom_firewall_rule(rule_id, ip_version)
                        if success:
                            print(f"✅ Rule '{rule_id}' deleted successfully.")
                        else:
                            print(f"❌ Failed to delete rule '{rule_id}'.")
                else:
                    print("Invalid rule number.")
            
            except (ValueError, Exception) as e:
                print(f"Error: {e}")
        
        elif choice == "5" or choice == "6":
            action = "enable" if choice == "5" else "disable"
            print(f"\n{'✅ Enable' if choice == '5' else '❌ Disable'} Rule")
            print("-" * 20)
            
            rules = api.get_custom_firewall_rules()
            if not rules:
                print("No custom rules found.")
                continue
            
            print("Current rules:")
            for i, rule in enumerate(rules):
                status = "🟢" if rule.get('Enable') else "🔴"
                print(f"{i+1}. {status} {rule.get('Id')}")
            
            try:
                rule_index = int(input("Select rule number: ")) - 1
                if 0 <= rule_index < len(rules):
                    rule = rules[rule_index]
                    rule_id = rule.get('Id')
                    
                    success = api.manage_custom_firewall_rule(action, rule_id)
                    if success:
                        print(f"✅ Rule '{rule_id}' {action}d successfully.")
                    else:
                        print(f"❌ Failed to {action} rule '{rule_id}'.")
                else:
                    print("Invalid rule number.")
            
            except (ValueError, Exception) as e:
                print(f"Error: {e}")
        
        elif choice == "7":
            show_rule_examples()
        
        elif choice == "8":
            break
        
        else:
            print("❌ Invalid choice. Please select 1-8.")

def show_rule_examples():
    """
    Show examples of custom firewall rules.
    """
    print("\n📚 Custom Firewall Rule Examples")
    print("=" * 50)
    
    print("\n🔒 Security Rules:")
    print("# Block SSH from internet (keep internal access)")
    print("api.add_custom_firewall_rule('block_ssh', 'Drop', '6', '22')")
    
    print("\n# Allow SSH only from specific IP")
    print("api.add_custom_firewall_rule('ssh_admin', 'Accept', '6', '22',")
    print("                           destination_prefix='192.168.2.100')")
    
    print("\n# Block IRC/P2P ports")
    print("api.add_custom_firewall_rule('block_irc', 'Drop', '6', '6660-6669')")
    
    print("\n🌐 Application Rules:")
    print("# Allow web server")
    print("api.add_custom_firewall_rule('webserver', 'Accept', '6', '80,443')")
    
    print("\n# Allow game server")
    print("api.add_custom_firewall_rule('gameserver', 'Accept', '6,17', '25565')")
    
    print("\n# Block BitTorrent")
    print("api.add_custom_firewall_rule('block_torrent', 'Drop', '6,17', '6881-6889')")
    
    print("\n📡 IPv6 Rules:")
    print("# Allow IPv6 web traffic")
    print("api.add_custom_firewall_rule('ipv6_web', 'Accept', '6', '80,443', ip_version=6)")
    
    print("\n# Block IPv6 Telnet")
    print("api.add_custom_firewall_rule('block_telnet_v6', 'Drop', '6', '23', ip_version=6)")
    
    print("\n🏠 Internal Network Rules:")
    print("# Allow specific device access to NAS")
    print("api.add_custom_firewall_rule('nas_access', 'Accept', '6', '5000',")
    print("                           destination_prefix='192.168.2.50',")
    print("                           source_prefix='192.168.2.100')")

def show_firewall_info():
    """
    Show firewall configuration information.
    """
    print("\n🛡️ Firewall Configuration Information")
    print("=" * 50)
    
    print("\n🔒 Firewall Levels:")
    print("  Low:    Minimal protection, allows most traffic")
    print("          - Basic port scanning protection")
    print("          - Allows most incoming connections")
    print("          - Good for testing/troubleshooting")
    
    print("\n  Medium: Balanced protection and functionality (recommended)")
    print("          - Blocks most unsolicited incoming traffic")
    print("          - Allows established connections")
    print("          - Good balance of security and usability")
    
    print("\n  High:   Maximum protection, blocks more traffic")
    print("          - Strict incoming traffic filtering")
    print("          - Enhanced protection against attacks")
    print("          - May block some legitimate services")
    
    print("\n  Custom: Allows custom firewall rules")
    print("          - Full control over firewall rules")
    print("          - Can create specific allow/deny rules")
    print("          - Requires networking knowledge")
    
    print("\n🏓 Ping Response:")
    print("  Enabled:  Router responds to ping requests")
    print("            - Allows connectivity testing")
    print("            - May reveal router presence")
    
    print("\n  Disabled: Router ignores ping requests")
    print("            - Improves stealth/security")
    print("            - Harder to test connectivity")
    
    print("\n🔧 Custom Rules (Custom mode only):")
    print("  Actions:")
    print("    Accept - Allow traffic")
    print("    Drop   - Block traffic silently")
    
    print("\n  Protocols:")
    print("    6      - TCP (web, email, SSH, etc.)")
    print("    17     - UDP (DNS, VPN, games, etc.)")
    print("    6,17   - Both TCP and UDP")
    print("    1      - ICMP (ping for IPv4)")
    print("    58     - ICMPv6 (ping for IPv6)")
    
    print("\n  Port Examples:")
    print("    22     - SSH")
    print("    80     - HTTP")
    print("    443    - HTTPS")
    print("    80,443 - Both HTTP and HTTPS")
    print("    8000-9000 - Port range")
    
    print("\n⚠️  Important Notes:")
    print("  • Custom rules require Custom firewall level")
    print("  • Rules are applied in addition to base level filtering")
    print("  • Be careful with Drop rules - they can block access")
    print("  • Test connectivity after making changes")
    print("  • IPv4 and IPv6 rules are managed separately")

if __name__ == "__main__":
    print("🛡️ KPN Box Firewall Configuration")
    print("=" * 40)
    
    # Show warning
    print("\n⚠️  Important Security Warning:")
    print("Firewall changes affect your network security.")
    print("Make sure you understand the implications before proceeding.")
    print("Always test connectivity after making changes.")
    
    print("\n" + "=" * 40)
    proceed = input("Proceed with firewall configuration? (y/n): ").strip().lower()
    
    if proceed == 'y':
        main()
    else:
        print("👋 Configuration cancelled.") 