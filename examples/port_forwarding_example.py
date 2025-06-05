#!/usr/bin/env python3
"""
KPN Box API - Port Forwarding Example

This example demonstrates how to configure port forwarding rules for both IPv4 and IPv6
on KPN Box routers. Includes common service templates, rule management, and security best practices.

Requirements:
- KPN Box router (tested with KPN Box 14)
- Python 3.8+
- kpnboxapi library

Features:
- IPv4 port forwarding rules management
- IPv6 pinhole configuration
- Common service templates (SSH, Web servers, Game servers, etc.)
- Rule status monitoring and management
- Security features and best practices
- Interactive examples

Author: Assistant
License: MIT
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kpnboxapi import KPNBoxAPI
import time
from typing import Dict, List, Any


# Common services configuration
COMMON_SERVICES = {
    "ssh": {"port": "22", "protocol": "6", "description": "SSH Server"},
    "web": {"port": "80", "protocol": "6", "description": "Web Server HTTP"},
    "https": {"port": "443", "protocol": "6", "description": "Web Server HTTPS"},
    "ftp": {"port": "21", "protocol": "6", "description": "FTP Server"},
    "smtp": {"port": "25", "protocol": "6", "description": "Mail Server SMTP"},
    "pop3": {"port": "110", "protocol": "6", "description": "Mail Server POP3"},
    "imap": {"port": "143", "protocol": "6", "description": "Mail Server IMAP"},
    "dns": {"port": "53", "protocol": "6,17", "description": "DNS Server"},
    "dhcp": {"port": "67", "protocol": "17", "description": "DHCP Server"},
    "minecraft": {"port": "25565", "protocol": "6", "description": "Minecraft Server"},
    "teamspeak": {"port": "9987", "protocol": "17", "description": "TeamSpeak Server"},
    "rdp": {"port": "3389", "protocol": "6", "description": "Remote Desktop"},
    "vnc": {"port": "5900", "protocol": "6", "description": "VNC Server"},
    "plex": {"port": "32400", "protocol": "6", "description": "Plex Media Server"},
    "homeassistant": {"port": "8123", "protocol": "6", "description": "Home Assistant"},
}


def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"{title:^60}")
    print(f"{'='*60}")


def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'-'*40}")
    print(f"📋 {title}")
    print(f"{'-'*40}")


def display_current_rules(api):
    """Display all current port forwarding rules."""
    print_section("Current Port Forwarding Rules")
    
    # IPv4 rules
    print("\n🌐 IPv4 Port Forwarding Rules:")
    ipv4_rules = api.get_port_forwarding("webui")
    
    if not ipv4_rules:
        print("   No IPv4 port forwarding rules found")
    else:
        for rule in ipv4_rules:
            status_icon = "🟢" if rule['Enable'] else "🔴"
            protocol = api.format_protocol(rule['Protocol'])
            description = rule.get('Description', 'No description')
            
            print(f"   {status_icon} {rule['Id']}")
            print(f"      Description: {description}")
            print(f"      Rule: {rule['ExternalPort']} → {rule['DestinationIPAddress']}:{rule['InternalPort']} ({protocol})")
            print(f"      Status: {rule['Status']}")
            print()
    
    # IPv6 rules
    print("🌐 IPv6 Pinholes:")
    ipv6_rules = api.get_ipv6_pinholes()
    
    if not ipv6_rules:
        print("   No IPv6 pinhole rules found")
    else:
        for rule in ipv6_rules:
            status_icon = "🟢" if rule['Enable'] else "🔴"
            protocol = api.format_protocol(rule['Protocol'])
            description = rule.get('Description', 'No description')
            
            print(f"   {status_icon} {rule['Id']}")
            print(f"      Description: {description}")
            print(f"      Rule: Port {rule['DestinationPort']} → {rule['DestinationIPAddress']} ({protocol})")
            print(f"      Status: {rule['Status']}")
            print()


def add_custom_ipv4_rule(api):
    """Interactive function to add a custom IPv4 port forwarding rule."""
    print_section("Add Custom IPv4 Port Forwarding Rule")
    
    print("Enter the details for your port forwarding rule:")
    
    rule_id = input("Rule ID (e.g., 'MyWebServer'): ").strip()
    if not rule_id:
        print("❌ Rule ID cannot be empty")
        return
    
    internal_port = input("Internal port (e.g., '80' or '8080-8090'): ").strip()
    if not internal_port:
        print("❌ Internal port cannot be empty")
        return
    
    external_port = input(f"External port (default: {internal_port}): ").strip() or internal_port
    
    destination_ip = input("Destination IP address (e.g., '192.168.2.100'): ").strip()
    if not destination_ip:
        print("❌ Destination IP cannot be empty")
        return
    
    print("\nProtocol options:")
    print("  6 = TCP")
    print("  17 = UDP")
    print("  6,17 = Both TCP and UDP")
    protocol = input("Protocol (default: 6): ").strip() or "6"
    
    description = input("Description (optional): ").strip()
    
    enabled_input = input("Enable rule immediately? (Y/n): ").strip().lower()
    enabled = enabled_input not in ['n', 'no', 'false']
    
    try:
        print(f"\n⏳ Creating rule '{rule_id}'...")
        
        created_rule_id = api.add_port_forwarding_rule(
            rule_id=rule_id,
            internal_port=internal_port,
            external_port=external_port,
            destination_ip=destination_ip,
            protocol=protocol,
            description=description,
            enabled=enabled
        )
        
        status_icon = "🟢" if enabled else "🔴"
        protocol_name = api.format_protocol(protocol)
        
        print(f"✅ Rule created successfully!")
        print(f"   {status_icon} Rule ID: {created_rule_id}")
        print(f"   Mapping: {external_port} → {destination_ip}:{internal_port} ({protocol_name})")
        print(f"   Description: {description or 'None'}")
        print(f"   Status: {'Enabled' if enabled else 'Disabled'}")
        
    except Exception as e:
        print(f"❌ Failed to create rule: {e}")


def add_custom_ipv6_rule(api):
    """Interactive function to add a custom IPv6 pinhole rule."""
    print_section("Add Custom IPv6 Pinhole Rule")
    
    print("Enter the details for your IPv6 pinhole rule:")
    
    destination_ip = input("IPv6 destination address (e.g., '2a02:a46f:ff52:0:f5a6:3bb7:c600:efc0'): ").strip()
    if not destination_ip:
        print("❌ Destination IPv6 address cannot be empty")
        return
    
    destination_port = input("Destination port (e.g., '22' or '8080-8090'): ").strip()
    if not destination_port:
        print("❌ Destination port cannot be empty")
        return
    
    print("\nProtocol options:")
    print("  6 = TCP")
    print("  17 = UDP")
    print("  6,17 = Both TCP and UDP")
    protocol = input("Protocol (default: 6): ").strip() or "6"
    
    source_port = input("Source port filter (optional, leave empty for any): ").strip()
    description = input("Description (optional): ").strip()
    
    enabled_input = input("Enable rule immediately? (Y/n): ").strip().lower()
    enabled = enabled_input not in ['n', 'no', 'false']
    
    try:
        print(f"\n⏳ Creating IPv6 pinhole rule...")
        
        created_rule_id = api.add_ipv6_pinhole(
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            description=description,
            enabled=enabled,
            source_port=source_port
        )
        
        status_icon = "🟢" if enabled else "🔴"
        protocol_name = api.format_protocol(protocol)
        
        print(f"✅ IPv6 pinhole created successfully!")
        print(f"   {status_icon} Rule ID: {created_rule_id}")
        print(f"   Target: {destination_ip}:{destination_port} ({protocol_name})")
        print(f"   Source port filter: {source_port or 'Any'}")
        print(f"   Description: {description or 'None'}")
        print(f"   Status: {'Enabled' if enabled else 'Disabled'}")
        
    except Exception as e:
        print(f"❌ Failed to create IPv6 pinhole: {e}")


def add_common_service(api):
    """Add a rule for a common service."""
    print_section("Add Common Service")
    
    print("Available common services:")
    for i, (key, service) in enumerate(COMMON_SERVICES.items(), 1):
        protocol_name = "TCP" if service["protocol"] == "6" else "UDP" if service["protocol"] == "17" else "TCP+UDP"
        print(f"  {i:2d}. {service['description']} (Port {service['port']}, {protocol_name})")
    
    try:
        choice = int(input("\nSelect service (number): ").strip())
        if not 1 <= choice <= len(COMMON_SERVICES):
            print("❌ Invalid choice")
            return
        
        service_key = list(COMMON_SERVICES.keys())[choice - 1]
        service = COMMON_SERVICES[service_key]
        
        print(f"\nSelected: {service['description']}")
        
        # Get destination details
        destination_ip = input("Destination IP address (e.g., '192.168.2.100'): ").strip()
        if not destination_ip:
            print("❌ Destination IP cannot be empty")
            return
        
        # Allow custom external port
        external_port = input(f"External port (default: {service['port']}): ").strip() or service['port']
        
        # Custom rule ID
        default_rule_id = service_key.upper()
        rule_id = input(f"Rule ID (default: {default_rule_id}): ").strip() or default_rule_id
        
        # IPv4 or IPv6?
        ip_version_input = input("IP version (4/6, default: 4): ").strip() or "4"
        
        if ip_version_input == "6":
            # IPv6 pinhole
            try:
                created_rule_id = api.add_ipv6_pinhole(
                    destination_ip=destination_ip,
                    destination_port=service['port'],
                    protocol=service['protocol'],
                    description=service['description'],
                    enabled=True
                )
                
                protocol_name = api.format_protocol(service['protocol'])
                print(f"✅ IPv6 {service['description']} rule created!")
                print(f"   🟢 Rule ID: {created_rule_id}")
                print(f"   Target: {destination_ip}:{service['port']} ({protocol_name})")
                
            except Exception as e:
                print(f"❌ Failed to create IPv6 pinhole: {e}")
        else:
            # IPv4 port forwarding
            try:
                created_rule_id = api.add_port_forwarding_rule(
                    rule_id=rule_id,
                    internal_port=service['port'],
                    external_port=external_port,
                    destination_ip=destination_ip,
                    protocol=service['protocol'],
                    description=service['description'],
                    enabled=True
                )
                
                protocol_name = api.format_protocol(service['protocol'])
                print(f"✅ {service['description']} rule created!")
                print(f"   🟢 Rule ID: {created_rule_id}")
                print(f"   Mapping: {external_port} → {destination_ip}:{service['port']} ({protocol_name})")
                
            except Exception as e:
                print(f"❌ Failed to create port forwarding rule: {e}")
                
    except ValueError:
        print("❌ Invalid choice, please enter a number")


def manage_existing_rules(api):
    """Manage existing port forwarding rules."""
    print_section("Manage Existing Rules")
    
    # Get all rules
    ipv4_rules = api.get_port_forwarding("webui")
    ipv6_rules = api.get_ipv6_pinholes()
    
    all_rules = []
    
    # Add IPv4 rules
    for rule in ipv4_rules:
        rule['type'] = 'ipv4'
        all_rules.append(rule)
    
    # Add IPv6 rules
    for rule in ipv6_rules:
        rule['type'] = 'ipv6'
        all_rules.append(rule)
    
    if not all_rules:
        print("No port forwarding rules found to manage.")
        return
    
    print("Current rules:")
    for i, rule in enumerate(all_rules, 1):
        status_icon = "🟢" if rule['Enable'] else "🔴"
        rule_type = "IPv4" if rule['type'] == 'ipv4' else "IPv6"
        description = rule.get('Description', 'No description')
        
        if rule['type'] == 'ipv4':
            mapping = f"{rule['ExternalPort']} → {rule['DestinationIPAddress']}:{rule['InternalPort']}"
        else:
            mapping = f"Port {rule['DestinationPort']} → {rule['DestinationIPAddress']}"
        
        print(f"  {i:2d}. {status_icon} [{rule_type}] {rule['Id']}")
        print(f"      {description}")
        print(f"      {mapping}")
    
    try:
        choice = int(input("\nSelect rule to manage (number): ").strip())
        if not 1 <= choice <= len(all_rules):
            print("❌ Invalid choice")
            return
        
        selected_rule = all_rules[choice - 1]
        
        print(f"\nSelected: {selected_rule['Id']}")
        print("\nActions:")
        print("  1. Enable rule")
        print("  2. Disable rule")
        print("  3. Delete rule")
        print("  4. View details")
        
        if selected_rule['type'] == 'ipv4':
            print("  5. Update rule")
        
        action = input("\nSelect action (number): ").strip()
        
        if action == "1":
            # Enable rule
            if selected_rule['type'] == 'ipv4':
                success = api.enable_port_forwarding_rule(selected_rule['Id'])
            else:
                success = api.enable_ipv6_pinhole(selected_rule['Id'])
            
            if success:
                print("✅ Rule enabled successfully!")
            else:
                print("❌ Failed to enable rule")
                
        elif action == "2":
            # Disable rule
            if selected_rule['type'] == 'ipv4':
                success = api.disable_port_forwarding_rule(selected_rule['Id'])
            else:
                success = api.disable_ipv6_pinhole(selected_rule['Id'])
            
            if success:
                print("✅ Rule disabled successfully!")
            else:
                print("❌ Failed to disable rule")
                
        elif action == "3":
            # Delete rule
            confirm = input(f"Are you sure you want to delete '{selected_rule['Id']}'? (y/N): ").strip().lower()
            if confirm in ['y', 'yes']:
                try:
                    if selected_rule['type'] == 'ipv4':
                        success = api.delete_port_forwarding_rule(
                            selected_rule['Id'], 
                            selected_rule['DestinationIPAddress']
                        )
                    else:
                        success = api.delete_ipv6_pinhole(selected_rule['Id'])
                    
                    if success:
                        print("✅ Rule deleted successfully!")
                    else:
                        print("❌ Failed to delete rule")
                except Exception as e:
                    print(f"❌ Error deleting rule: {e}")
            else:
                print("❌ Deletion cancelled")
                
        elif action == "4":
            # View details
            print(f"\n📋 Rule Details: {selected_rule['Id']}")
            for key, value in selected_rule.items():
                if key != 'type':
                    print(f"   {key}: {value}")
                    
        elif action == "5" and selected_rule['type'] == 'ipv4':
            # Update IPv4 rule
            print(f"\nUpdate rule: {selected_rule['Id']}")
            print("Leave empty to keep current value")
            
            new_internal_port = input(f"Internal port (current: {selected_rule['InternalPort']}): ").strip()
            new_external_port = input(f"External port (current: {selected_rule['ExternalPort']}): ").strip()
            new_destination_ip = input(f"Destination IP (current: {selected_rule['DestinationIPAddress']}): ").strip()
            new_description = input(f"Description (current: {selected_rule.get('Description', 'None')}): ").strip()
            
            update_params = {}
            if new_internal_port:
                update_params['internal_port'] = new_internal_port
            if new_external_port:
                update_params['external_port'] = new_external_port
            if new_destination_ip:
                update_params['destination_ip'] = new_destination_ip
            if new_description:
                update_params['description'] = new_description
            
            if update_params:
                try:
                    updated_rule_id = api.update_port_forwarding_rule(selected_rule['Id'], **update_params)
                    print(f"✅ Rule updated successfully! ID: {updated_rule_id}")
                except Exception as e:
                    print(f"❌ Failed to update rule: {e}")
            else:
                print("No changes made")
        
    except ValueError:
        print("❌ Invalid choice, please enter a number")
    except Exception as e:
        print(f"❌ Error managing rule: {e}")


def setup_home_server_scenario(api):
    """Set up a complete home server with multiple services."""
    print_section("Home Server Setup Scenario")
    
    print("This will set up a complete home server with common services.")
    
    server_ip = input("Enter server IP address (e.g., '192.168.2.100'): ").strip()
    if not server_ip:
        print("❌ Server IP cannot be empty")
        return
    
    print(f"\n🏠 Setting up home server at {server_ip}")
    
    # Services to set up
    services = [
        {"name": "SSH", "internal": "22", "external": "22", "protocol": "6", "desc": "SSH Access"},
        {"name": "HTTP", "internal": "80", "external": "80", "protocol": "6", "desc": "Web Server HTTP"},
        {"name": "HTTPS", "internal": "443", "external": "443", "protocol": "6", "desc": "Web Server HTTPS"},
        {"name": "Plex", "internal": "32400", "external": "32400", "protocol": "6", "desc": "Plex Media Server"},
    ]
    
    setup_all = input("Set up all services? (Y/n): ").strip().lower() not in ['n', 'no']
    
    created_rules = []
    
    for service in services:
        if not setup_all:
            setup_service = input(f"Set up {service['desc']}? (Y/n): ").strip().lower() not in ['n', 'no']
            if not setup_service:
                continue
        
        try:
            rule_id = api.add_port_forwarding_rule(
                rule_id=f"HomeServer_{service['name']}",
                internal_port=service['internal'],
                external_port=service['external'],
                destination_ip=server_ip,
                protocol=service['protocol'],
                description=f"Home Server - {service['desc']}",
                enabled=True
            )
            
            created_rules.append({
                'id': rule_id,
                'name': service['desc'],
                'port': service['external']
            })
            
            print(f"✅ {service['desc']}: Port {service['external']} → {server_ip}:{service['internal']}")
            
        except Exception as e:
            print(f"❌ Failed to create {service['desc']} rule: {e}")
    
    if created_rules:
        print(f"\n🎉 Home server setup complete!")
        print(f"Created {len(created_rules)} port forwarding rules:")
        for rule in created_rules:
            print(f"   • {rule['name']}: External port {rule['port']} (Rule ID: {rule['id']})")
        
        print(f"\n📝 Access information:")
        print(f"   SSH: ssh user@your-external-ip")
        print(f"   Web: http://your-external-ip or https://your-external-ip")
        print(f"   Plex: http://your-external-ip:32400/web")
        
        print(f"\n⚠️  Security reminders:")
        print(f"   • Use strong passwords for all services")
        print(f"   • Consider changing SSH to a non-standard port")
        print(f"   • Enable fail2ban or similar for SSH protection")
        print(f"   • Use HTTPS/SSL certificates for web services")
    else:
        print("❌ No rules were created")


def show_security_recommendations(api):
    """Show security recommendations for port forwarding."""
    print_section("Security Recommendations")
    
    print("📋 Port Forwarding Security Best Practices:")
    print()
    
    print("1. 🔒 Service Security:")
    print("   • Use strong, unique passwords for all exposed services")
    print("   • Enable two-factor authentication where possible")
    print("   • Keep all services updated with latest security patches")
    print("   • Disable unnecessary features and default accounts")
    print()
    
    print("2. 🛡️ Network Security:")
    print("   • Change default SSH port (22) to a non-standard port")
    print("   • Use fail2ban or similar tools to prevent brute force attacks")
    print("   • Consider using VPN access instead of direct port forwarding")
    print("   • Monitor logs for suspicious activity")
    print()
    
    print("3. 🚪 Port Management:")
    print("   • Only open ports that are absolutely necessary")
    print("   • Disable rules when services are not needed")
    print("   • Use custom external ports when possible")
    print("   • Document all port forwarding rules and their purposes")
    print()
    
    print("4. 🌐 External Access:")
    print("   • Use dynamic DNS services for consistent access")
    print("   • Consider using CloudFlare or similar CDN/proxy services")
    print("   • Implement rate limiting on web services")
    print("   • Use HTTPS/SSL for all web-based services")
    print()
    
    # Check current rules for security issues
    print("5. 🔍 Current Configuration Analysis:")
    ipv4_rules = api.get_active_port_forwarding("webui")
    ipv6_rules = api.get_active_ipv6_pinholes()
    
    security_issues = []
    
    # Check for common security issues
    for rule in ipv4_rules:
        external_port = rule.get('ExternalPort', '')
        description = rule.get('Description', '').lower()
        
        # Check for SSH on default port
        if external_port == "22":
            security_issues.append(f"SSH on default port 22 (Rule: {rule['Id']})")
        
        # Check for Telnet
        if external_port == "23":
            security_issues.append(f"Telnet exposed - highly insecure (Rule: {rule['Id']})")
        
        # Check for FTP
        if external_port == "21":
            security_issues.append(f"FTP on default port - consider SFTP instead (Rule: {rule['Id']})")
        
        # Check for missing descriptions
        if not rule.get('Description'):
            security_issues.append(f"Missing description for rule {rule['Id']}")
    
    if security_issues:
        print("   ⚠️  Potential security concerns found:")
        for issue in security_issues:
            print(f"      • {issue}")
    else:
        print("   ✅ No obvious security issues detected in current rules")
    
    print()
    print("6. 🔧 Recommended Tools:")
    print("   • fail2ban: Intrusion prevention system")
    print("   • UFW/iptables: Additional firewall rules")
    print("   • Let's Encrypt: Free SSL certificates")
    print("   • Nginx/Apache: Reverse proxy with security headers")
    print("   • Wireguard/OpenVPN: Secure VPN access")


def unified_management_demo(api):
    """Demonstrate the unified management interface."""
    print_section("Unified Management Interface Demo")
    
    print("The unified management interface allows you to manage both IPv4 and IPv6 rules")
    print("using a single API with consistent parameters.")
    print()
    
    # List all rules
    print("📋 Listing all rules using unified interface:")
    
    ipv4_rules = api.manage_port_forwarding("list")
    ipv6_rules = api.manage_port_forwarding("list", ip_version=6)
    
    print(f"   IPv4 rules: {len(ipv4_rules)}")
    print(f"   IPv6 rules: {len(ipv6_rules)}")
    print()
    
    # Demo adding rules
    demo_add = input("Demo adding rules? (Y/n): ").strip().lower() not in ['n', 'no']
    
    if demo_add:
        print("🔧 Adding demo rules...")
        
        # Add IPv4 rule
        try:
            ipv4_demo_id = api.manage_port_forwarding(
                "add", "DemoIPv4",
                internal_port="8080",
                external_port="8080",
                destination_ip="192.168.2.200",
                protocol="6",
                description="Demo IPv4 Rule"
            )
            print(f"✅ IPv4 demo rule created: {ipv4_demo_id}")
        except Exception as e:
            print(f"❌ Failed to create IPv4 demo rule: {e}")
        
        # Add IPv6 rule
        try:
            ipv6_demo_id = api.manage_port_forwarding(
                "add",
                ip_version=6,
                destination_ip="2a02:a46f:ff52:0:1234:5678:9abc:def0",
                destination_port="8080",
                protocol="6",
                description="Demo IPv6 Rule"
            )
            print(f"✅ IPv6 demo rule created: {ipv6_demo_id}")
            
            # Demo rule management
            print("\n🔧 Testing rule management...")
            
            # Disable IPv4 rule
            if api.manage_port_forwarding("disable", ipv4_demo_id):
                print("✅ IPv4 demo rule disabled")
            
            # Enable it back
            if api.manage_port_forwarding("enable", ipv4_demo_id):
                print("✅ IPv4 demo rule enabled")
            
            # Get rule details
            rule_details = api.manage_port_forwarding("get", ipv4_demo_id)
            if rule_details:
                print(f"✅ Retrieved rule details: {rule_details['Id']}")
            
            # Cleanup demo rules
            cleanup = input("\nCleanup demo rules? (Y/n): ").strip().lower() not in ['n', 'no']
            if cleanup:
                try:
                    if api.manage_port_forwarding("delete", ipv4_demo_id, destination_ip="192.168.2.200"):
                        print("✅ IPv4 demo rule deleted")
                    
                    if api.manage_port_forwarding("delete", ipv6_demo_id, ip_version=6):
                        print("✅ IPv6 demo rule deleted")
                    
                except Exception as e:
                    print(f"❌ Error during cleanup: {e}")
                    
        except Exception as e:
            print(f"❌ Failed to create IPv6 demo rule: {e}")


def main():
    """Main example function."""
    print_header("KPN Box API - Port Forwarding Example")
    
    print("This example demonstrates comprehensive port forwarding management")
    print("for KPN Box routers, including both IPv4 and IPv6 configurations.")
    
    # Get connection details
    host = input("\nEnter KPN Box IP address (default: 192.168.2.254): ").strip() or "192.168.2.254"
    password = input("Enter admin password: ").strip()
    
    if not password:
        print("❌ Password cannot be empty")
        return
    
    try:
        # Connect to KPN Box
        print(f"\n⏳ Connecting to KPN Box at {host}...")
        
        with KPNBoxAPI(host=host) as api:
            # Login
            if not api.login(password=password):
                print("❌ Failed to login to KPN Box")
                return
            
            print("✅ Successfully connected to KPN Box")
            
            # Show current configuration
            display_current_rules(api)
            
            # Main menu loop
            while True:
                print_section("Port Forwarding Management Menu")
                print("1. 📋 View current rules")
                print("2. ➕ Add custom IPv4 port forwarding rule")
                print("3. ➕ Add custom IPv6 pinhole rule")
                print("4. 🎯 Add common service rule")
                print("5. 🔧 Manage existing rules")
                print("6. 🏠 Setup home server scenario")
                print("7. 🔍 Unified management demo")
                print("8. 🛡️ Security recommendations")
                print("9. ❌ Exit")
                
                choice = input("\nSelect option (1-9): ").strip()
                
                if choice == "1":
                    display_current_rules(api)
                    
                elif choice == "2":
                    add_custom_ipv4_rule(api)
                    
                elif choice == "3":
                    add_custom_ipv6_rule(api)
                    
                elif choice == "4":
                    add_common_service(api)
                    
                elif choice == "5":
                    manage_existing_rules(api)
                    
                elif choice == "6":
                    setup_home_server_scenario(api)
                    
                elif choice == "7":
                    unified_management_demo(api)
                    
                elif choice == "8":
                    show_security_recommendations(api)
                    
                elif choice == "9":
                    print("\n👋 Goodbye!")
                    break
                    
                else:
                    print("❌ Invalid choice, please try again")
                
                # Pause before showing menu again
                input("\nPress Enter to continue...")
    
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main() 