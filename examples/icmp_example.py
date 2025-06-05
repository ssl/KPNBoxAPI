#!/usr/bin/env python3
"""
ICMP Diagnostics example for KPNBoxAPI.

This script demonstrates:
1. How to run ping diagnostics to test connectivity
2. How to run traceroute diagnostics to trace network paths
3. How to analyze and display network diagnostic results
4. How to test both IPv4 and IPv6 connectivity

Note: These tests send network packets and may take several seconds to complete.
"""

import ipaddress
from kpnboxapi import KPNBoxAPI, AuthenticationError, ConnectionError


def is_ipv6_address(address):
    """Check if the given address is an IPv6 address."""
    try:
        ip = ipaddress.ip_address(address)
        return isinstance(ip, ipaddress.IPv6Address)
    except ValueError:
        return False


def format_rtt_times(rtt_string):
    """Format RTT times string into readable format."""
    if not rtt_string or rtt_string == "0,0,0":
        return "* * * (no response)"
    
    times = rtt_string.split(',')
    formatted_times = []
    
    for time_str in times:
        try:
            time_ms = int(time_str)
            if time_ms > 0:
                formatted_times.append(f"{time_ms}ms")
            else:
                formatted_times.append("*")
        except ValueError:
            formatted_times.append("*")
    
    return " ".join(formatted_times)


def analyze_ping_result(result, host):
    """Analyze and display ping results."""
    if not result:
        print(f"❌ Ping to {host} failed - no results")
        return False
    
    state = result.get('DiagnosticsState', 'Unknown')
    target_ip = result.get('ipHost', 'Unknown')
    packets_sent = result.get('packetsSuccess', 0) + result.get('packetsFailed', 0)
    packets_success = result.get('packetsSuccess', 0)
    packets_failed = result.get('packetsFailed', 0)
    packet_size = result.get('packetSize', 0)
    avg_time = result.get('averageResponseTime', 0)
    min_time = result.get('minimumResponseTime', 0)
    max_time = result.get('maximumResponseTime', 0)
    
    print(f"🏓 Ping Results for {host}:")
    print("-" * 50)
    
    # Connection status
    if state == "Success" and packets_success > 0:
        success_rate = (packets_success / packets_sent) * 100 if packets_sent > 0 else 0
        status_icon = "🟢" if success_rate == 100 else "🟡" if success_rate > 0 else "🔴"
        print(f"{status_icon} Status: {state}")
        print(f"🎯 Target: {target_ip}")
        
        # Determine IP version
        if is_ipv6_address(target_ip):
            print(f"📡 Protocol: IPv6")
        else:
            print(f"📡 Protocol: IPv4")
        
        print(f"📦 Packet Size: {packet_size} bytes")
        print(f"📊 Success Rate: {success_rate:.1f}% ({packets_success}/{packets_sent})")
        
        if packets_success > 0:
            print(f"⏱️  Response Times:")
            print(f"   Average: {avg_time}ms")
            print(f"   Minimum: {min_time}ms")
            print(f"   Maximum: {max_time}ms")
            
            # Performance analysis
            if avg_time <= 10:
                perf_rating = "🟢 Excellent"
            elif avg_time <= 50:
                perf_rating = "🟢 Good"
            elif avg_time <= 100:
                perf_rating = "🟡 Moderate"
            elif avg_time <= 200:
                perf_rating = "🟠 Fair"
            else:
                perf_rating = "🔴 Poor"
            
            print(f"📈 Performance: {perf_rating}")
        
        if packets_failed > 0:
            print(f"⚠️  Packet Loss: {packets_failed} packets lost")
        
        return success_rate == 100
        
    else:
        print(f"🔴 Status: Failed ({state})")
        print(f"❌ No successful packets received")
        return False


def analyze_traceroute_result(result, host):
    """Analyze and display traceroute results."""
    if not result:
        print(f"❌ Traceroute to {host} failed - no results")
        return False
    
    state = result.get('DiagnosticState', 'Unknown')
    target_ip = result.get('IPAddressUsed', 'Unknown')
    protocol = result.get('ProtocolVersion', 'Unknown')
    total_time = result.get('ResponseTime', 0)
    max_hops = result.get('MaxHopCount', 30)
    hop_count = result.get('RouteHopsNumberOfEntries', 0)
    route_hops = result.get('RouteHops', {})
    
    print(f"🛤️  Traceroute Results for {host}:")
    print("-" * 60)
    
    if state == "Complete":
        print(f"🟢 Status: {state}")
        print(f"🎯 Target: {target_ip} ({protocol})")
        print(f"⏱️  Total Time: {total_time}ms")
        print(f"🔢 Hops Found: {hop_count}/{max_hops}")
        print()
        
        print("🛤️  Route Path:")
        print("Hop  IP Address           RTT Times         Host")
        print("-" * 60)
        
        # Display each hop
        for i in range(1, hop_count + 1):
            hop_key = str(i)
            if hop_key in route_hops:
                hop = route_hops[hop_key]
                hop_ip = hop.get('HostAddress', '')
                hop_host = hop.get('Host', '')
                hop_rtt = hop.get('RTTimes', '')
                error_code = hop.get('ErrorCode', 0)
                
                # Format RTT times
                rtt_formatted = format_rtt_times(hop_rtt)
                
                # Display hop information
                hop_display = hop_ip if hop_ip else "*"
                host_display = hop_host if hop_host else "(no reverse DNS)"
                
                # Color code based on response
                if error_code == 0:  # Success (final destination)
                    icon = "🎯"
                elif error_code == 11:  # TTL exceeded (normal hop)
                    icon = "🔸"
                elif error_code == 4294967295:  # No response
                    icon = "❌"
                    hop_display = "*"
                    host_display = "(no response)"
                else:
                    icon = "⚠️"
                
                print(f"{icon} {i:2d}  {hop_display:<17} {rtt_formatted:<17} {host_display}")
        
        print()
        
        # Analysis
        successful_hops = sum(1 for hop in route_hops.values() 
                            if hop.get('ErrorCode') in [0, 11])
        failed_hops = hop_count - successful_hops
        
        if failed_hops == 0:
            print("✅ Route trace completed successfully")
        else:
            print(f"⚠️  {failed_hops} hops did not respond")
        
        # Check for potential issues
        if hop_count >= max_hops:
            print("⚠️  Maximum hop count reached - route may be longer")
        
        return True
        
    else:
        print(f"🔴 Status: {state}")
        print(f"❌ Traceroute failed or incomplete")
        return False


def test_connectivity(api, targets, protocol_version="Any"):
    """Test ping connectivity to multiple targets."""
    print(f"🏓 Testing Connectivity ({protocol_version}):")
    print("=" * 50)
    
    results = {}
    
    for target in targets:
        print(f"\nTesting {target}...")
        try:
            result = api.run_ping(target, protocol_version)
            success = analyze_ping_result(result, target)
            results[target] = success
        except Exception as e:
            print(f"❌ Error testing {target}: {e}")
            results[target] = False
        print()
    
    # Summary
    successful = sum(1 for success in results.values() if success)
    total = len(results)
    
    print("📊 Connectivity Summary:")
    print("-" * 30)
    
    for target, success in results.items():
        status_icon = "🟢" if success else "🔴"
        print(f"{status_icon} {target}")
    
    print(f"\nOverall: {successful}/{total} targets reachable")
    
    return results


def trace_network_paths(api, targets, ip_version="IPv4"):
    """Trace network paths to multiple targets."""
    print(f"🛤️  Tracing Network Paths ({ip_version}):")
    print("=" * 50)
    
    results = {}
    
    for target in targets:
        print(f"\nTracing route to {target}...")
        try:
            result = api.run_traceroute(target, ip_version)
            success = analyze_traceroute_result(result, target)
            results[target] = success
        except Exception as e:
            print(f"❌ Error tracing {target}: {e}")
            results[target] = False
        print()
    
    # Summary
    successful = sum(1 for success in results.values() if success)
    total = len(results)
    
    print("📊 Traceroute Summary:")
    print("-" * 30)
    
    for target, success in results.items():
        status_icon = "🟢" if success else "🔴"
        print(f"{status_icon} {target}")
    
    print(f"\nOverall: {successful}/{total} traces completed")
    
    return results


def comprehensive_network_test():
    """Run comprehensive network diagnostics."""
    password = input("Enter your KPN Box password: ")
    
    try:
        api = KPNBoxAPI(host="192.168.2.254")
        print("Connecting and logging in...")
        api.login(username="admin", password=password)
        print("✅ Login successful!")
        
        # Check if internet is connected
        if not api.is_connected():
            print("❌ No internet connection available")
            return
        
        print("\n🌐 Internet connection confirmed")
        
        # Define test targets
        test_targets = [
            "8.8.8.8",          # Google DNS
            "1.1.1.1",          # Cloudflare DNS
            "www.google.com",   # Google website
            "www.nu.nl",        # Dutch news site
            "speedtest.kpn.com" # KPN's speedtest server
        ]
        
        ipv6_targets = [
            "2001:4860:4860::8888",  # Google DNS IPv6
            "2606:4700:4700::1111",  # Cloudflare DNS IPv6
            "www.google.com"         # Let it resolve to IPv6 if available
        ]
        
        # Test IPv4 connectivity
        print("\n" + "="*60)
        ipv4_results = test_connectivity(api, test_targets, "IPv4")
        
        # Test IPv6 connectivity
        print("\n" + "="*60)
        ipv6_results = test_connectivity(api, ipv6_targets, "IPv6")
        
        # Traceroute to key destinations
        traceroute_targets = ["8.8.8.8", "www.google.com"]
        
        print("\n" + "="*60)
        trace_results = trace_network_paths(api, traceroute_targets, "IPv4")
        
        # Overall summary
        print("\n" + "="*60)
        print("🌐 Overall Network Diagnostics Summary:")
        print("-" * 40)
        
        # IPv4 summary
        ipv4_success = sum(1 for success in ipv4_results.values() if success)
        ipv4_total = len(ipv4_results)
        ipv4_rate = (ipv4_success / ipv4_total * 100) if ipv4_total > 0 else 0
        
        ipv4_icon = "🟢" if ipv4_rate == 100 else "🟡" if ipv4_rate > 50 else "🔴"
        print(f"{ipv4_icon} IPv4 Connectivity: {ipv4_rate:.1f}% ({ipv4_success}/{ipv4_total})")
        
        # IPv6 summary
        ipv6_success = sum(1 for success in ipv6_results.values() if success)
        ipv6_total = len(ipv6_results)
        ipv6_rate = (ipv6_success / ipv6_total * 100) if ipv6_total > 0 else 0
        
        ipv6_icon = "🟢" if ipv6_rate == 100 else "🟡" if ipv6_rate > 50 else "🔴"
        print(f"{ipv6_icon} IPv6 Connectivity: {ipv6_rate:.1f}% ({ipv6_success}/{ipv6_total})")
        
        # Traceroute summary
        trace_success = sum(1 for success in trace_results.values() if success)
        trace_total = len(trace_results)
        trace_rate = (trace_success / trace_total * 100) if trace_total > 0 else 0
        
        trace_icon = "🟢" if trace_rate == 100 else "🟡" if trace_rate > 50 else "🔴"
        print(f"{trace_icon} Route Tracing: {trace_rate:.1f}% ({trace_success}/{trace_total})")
        
        # Recommendations
        print("\n💡 Recommendations:")
        if ipv4_rate < 100:
            print("   • Check IPv4 connectivity and DNS settings")
        if ipv6_rate < 50:
            print("   • IPv6 connectivity may be limited or disabled")
        if trace_rate < 100:
            print("   • Some network paths may have routing issues")
        
        if ipv4_rate == 100 and ipv6_rate >= 50 and trace_rate == 100:
            print("   ✅ Network connectivity appears healthy!")
        
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


def quick_connectivity_test():
    """Run a quick connectivity test to essential services."""
    password = input("Enter your KPN Box password: ")
    
    try:
        api = KPNBoxAPI(host="192.168.2.254")
        print("Connecting and logging in...")
        api.login(username="admin", password=password)
        print("✅ Login successful!")
        
        print("\n🚀 Quick Connectivity Test")
        print("=" * 30)
        
        # Test essential services
        essential_targets = ["8.8.8.8", "www.google.com"]
        
        all_good = True
        
        for target in essential_targets:
            print(f"\n🏓 Testing {target}...")
            
            result = api.run_ping(target, "Any")
            success = result.get('DiagnosticsState') == 'Success'
            packets_success = result.get('packetsSuccess', 0)
            avg_time = result.get('averageResponseTime', 0)
            target_ip = result.get('ipHost', 'Unknown')
            
            if success and packets_success > 0:
                protocol = "IPv6" if is_ipv6_address(target_ip) else "IPv4"
                status_icon = "🟢"
                print(f"{status_icon} {target} → {target_ip} ({protocol})")
                print(f"   Response: {avg_time}ms average")
            else:
                status_icon = "🔴"
                print(f"{status_icon} {target} → Failed")
                all_good = False
        
        print(f"\n{'🟢 Internet connectivity is working!' if all_good else '🔴 Connectivity issues detected'}")
        
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


def custom_diagnostic():
    """Run custom ping or traceroute to user-specified target."""
    password = input("Enter your KPN Box password: ")
    
    try:
        api = KPNBoxAPI(host="192.168.2.254")
        print("Connecting and logging in...")
        api.login(username="admin", password=password)
        print("✅ Login successful!")
        
        # Get target from user
        target = input("\nEnter target hostname or IP address: ").strip()
        if not target:
            print("❌ No target specified")
            return
        
        # Get test type
        while True:
            test_type = input("Choose test type (1=ping, 2=traceroute): ").strip()
            if test_type in ["1", "2"]:
                break
            print("Please enter 1 or 2")
        
        # Get IP version
        while True:
            ip_version = input("Choose IP version (1=IPv4, 2=IPv6, 3=Any): ").strip()
            if ip_version == "1":
                version = "IPv4"
                break
            elif ip_version == "2":
                version = "IPv6"
                break
            elif ip_version == "3":
                version = "Any"
                break
            print("Please enter 1, 2, or 3")
        
        print(f"\n🔍 Running {'ping' if test_type == '1' else 'traceroute'} to {target} ({version})...")
        
        if test_type == "1":
            # Run ping
            if version == "Any":
                result = api.run_ping(target, "Any")
            else:
                result = api.run_ping(target, version)
            analyze_ping_result(result, target)
        else:
            # Run traceroute  
            if version == "Any":
                version = "IPv4"  # Traceroute API uses different parameter name
            result = api.run_traceroute(target, version)
            analyze_traceroute_result(result, target)
        
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    """Main function with menu."""
    print("KPNBoxAPI - ICMP Diagnostics Example")
    print("=" * 40)
    print()
    
    while True:
        print("Choose an option:")
        print("1. Comprehensive network test (ping + traceroute)")
        print("2. Quick connectivity test")
        print("3. Custom diagnostic (specify target)")
        print("4. Exit")
        
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice == "1":
            comprehensive_network_test()
            break
        elif choice == "2":
            quick_connectivity_test()
            break
        elif choice == "3":
            custom_diagnostic()
            break
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main() 