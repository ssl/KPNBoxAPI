#!/usr/bin/env python3
"""
WiFi Spectrum Analysis Example

This script demonstrates how to use the KPNBoxAPI to analyze the WiFi environment,
including channel usage, interference, and optimization recommendations.

Features demonstrated:
- WiFi radio information for both bands
- Spectrum analysis with channel availability
- Network scanning and detection
- Best channel recommendations
- Comprehensive WiFi environment analysis
- Channel optimization suggestions
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kpnboxapi import KPNBoxAPI


def print_separator(title=""):
    """Print a section separator."""
    print("\n" + "="*60)
    if title:
        print(f" {title}")
        print("="*60)


def print_radio_info(api):
    """Display detailed WiFi radio information."""
    print_separator("WiFi Radio Information")
    
    radio_info = api.get_all_wifi_radio_info()
    
    for band_name, radio_data in radio_info.items():
        if not radio_data:
            continue
            
        print(f"\n📡 {band_name.upper().replace('_', ' ')} Radio:")
        print(f"   Name: {radio_data.get('Name', 'Unknown')}")
        print(f"   Status: {'🟢 Enabled' if radio_data.get('Enable') else '🔴 Disabled'}")
        print(f"   Frequency Band: {radio_data.get('OperatingFrequencyBand', 'Unknown')}")
        print(f"   Current Channel: {radio_data.get('Channel', 'Unknown')}")
        
        # For 80MHz/160MHz channels, show the full range
        channels_in_use = radio_data.get('ChannelsInUse', '')
        if channels_in_use and ',' in channels_in_use:
            print(f"   Channels in Use: {channels_in_use}")
        
        print(f"   Bandwidth: {radio_data.get('CurrentOperatingChannelBandwidth', 'Unknown')}")
        print(f"   Max Bandwidth: {radio_data.get('MaxChannelBandwidth', 'Unknown')}")
        print(f"   Standards: {radio_data.get('OperatingStandards', 'Unknown')}")
        print(f"   Auto Channel: {'🟢 Enabled' if radio_data.get('AutoChannelEnable') else '🔴 Disabled'}")
        print(f"   Channel Load: {radio_data.get('ChannelLoad', 0)}%")
        print(f"   Interference: {radio_data.get('Interference', 0)}%")
        print(f"   Noise Level: {radio_data.get('Noise', 'Unknown')} dBm")
        print(f"   Connected Devices: {radio_data.get('ActiveAssociatedDevices', 0)}/{radio_data.get('MaxAssociatedDevices', 0)}")


def print_spectrum_analysis(api):
    """Display WiFi spectrum analysis for both bands."""
    print_separator("WiFi Spectrum Analysis")
    
    spectrum_info = api.get_all_wifi_spectrum_info()
    
    for band_name, spectrum_data in spectrum_info.items():
        if not spectrum_data:
            continue
            
        print(f"\n📊 {band_name.upper().replace('_', ' ')} Spectrum Analysis:")
        print(f"{'Channel':<8} {'Bandwidth':<10} {'Availability':<12} {'Our Usage':<10} {'APs':<4} {'Noise':<8} {'Status'}")
        print("-" * 75)
        
        for channel in spectrum_data:
            ch = channel.get('channel', 0)
            bw = f"{channel.get('bandwidth', 0)}MHz"
            avail = f"{channel.get('availability', 0)}%"
            usage = f"{channel.get('ourUsage', 0)}%"
            aps = channel.get('accesspoints', 0)
            noise = f"{channel.get('noiselevel', 0)} dBm"
            
            # Status indicator
            availability = channel.get('availability', 0)
            our_usage = channel.get('ourUsage', 0)
            if our_usage > 0:
                status = "🔴 OURS"
            elif availability > 80:
                status = "🟢 GOOD"
            elif availability > 50:
                status = "🟡 OK"
            else:
                status = "🔴 BUSY"
            
            print(f"{ch:<8} {bw:<10} {avail:<12} {usage:<10} {aps:<4} {noise:<8} {status}")


def print_best_channels(api):
    """Display best channel recommendations."""
    print_separator("Best Channel Recommendations")
    
    for band in ["2g", "5g"]:
        best_channels = api.get_best_wifi_channels(band, top_n=5)
        
        if not best_channels:
            continue
            
        print(f"\n🏆 Best {band.upper()} Channels:")
        print(f"{'Rank':<5} {'Channel':<8} {'Score':<7} {'Congestion':<12} {'Availability':<12} {'Recommendation'}")
        print("-" * 85)
        
        for i, channel in enumerate(best_channels, 1):
            rank = f"#{i}"
            ch = channel.get('channel', 0)
            score = f"{channel.get('score', 0):.1f}"
            congestion = channel.get('congestion_level', 'Unknown')
            availability = f"{channel.get('availability', 0)}%"
            recommendation = channel.get('recommendation', '')
            
            # Emoji for congestion level
            if congestion == "Low":
                congestion_emoji = "🟢"
            elif congestion == "Medium":
                congestion_emoji = "🟡"
            else:
                congestion_emoji = "🔴"
            
            congestion_display = f"{congestion_emoji} {congestion}"
            
            print(f"{rank:<5} {ch:<8} {score:<7} {congestion_display:<12} {availability:<12} {recommendation}")


def print_network_scan(api, limit=10):
    """Display detected WiFi networks."""
    print_separator("Detected WiFi Networks")
    
    scan_results = api.get_all_wifi_scan_results()
    
    for band_name, networks in scan_results.items():
        if not networks:
            continue
            
        # Filter out hidden networks and sort by signal strength
        visible_networks = [n for n in networks if n.get('SSID', '').strip()]
        visible_networks.sort(key=lambda x: x.get('RSSI', -100), reverse=True)
        
        print(f"\n📡 {band_name.upper().replace('_', ' ')} Networks (Top {limit}):")
        print(f"{'SSID':<25} {'Channel':<8} {'Signal':<8} {'Security':<20} {'Bandwidth'}")
        print("-" * 85)
        
        for network in visible_networks[:limit]:
            ssid = network.get('SSID', 'Hidden')[:24]  # Truncate long SSIDs
            channel = network.get('Channel', 0)
            rssi = f"{network.get('RSSI', 0)} dBm"
            security = network.get('SecurityModeEnabled', 'Unknown')[:19]
            bandwidth = f"{network.get('Bandwidth', 0)}MHz"
            
            # Signal strength indicator
            signal_strength = network.get('RSSI', -100)
            if signal_strength > -50:
                signal_emoji = "📶"
            elif signal_strength > -70:
                signal_emoji = "📶"
            elif signal_strength > -80:
                signal_emoji = "📶"
            else:
                signal_emoji = "📶"
            
            print(f"{ssid:<25} {channel:<8} {rssi:<8} {security:<20} {bandwidth}")


def print_comprehensive_analysis(api):
    """Display comprehensive WiFi environment analysis."""
    print_separator("Comprehensive WiFi Environment Analysis")
    
    analysis = api.analyze_wifi_environment()
    
    print(f"\n🌐 Environment Summary:")
    print(f"   {analysis.get('summary', 'No summary available')}")
    print(f"   Total Networks Detected: {analysis.get('total_networks', 0)}")
    
    # Current channel status
    band_2g = analysis.get('band_2g', {})
    band_5g = analysis.get('band_5g', {})
    
    print(f"\n📊 Current Channel Status:")
    if band_2g.get('current_channel'):
        current_2g_info = band_2g.get('current_channel_info', {})
        availability_2g = current_2g_info.get('availability', 'Unknown')
        print(f"   2.4GHz: Channel {band_2g['current_channel']} ({availability_2g}% available)")
    
    if band_5g.get('current_channel'):
        current_5g_info = band_5g.get('current_channel_info', {})
        availability_5g = current_5g_info.get('availability', 'Unknown')
        print(f"   5GHz: Channel {band_5g['current_channel']} ({availability_5g}% available)")
    
    # Recommendations
    recommendations = analysis.get('recommendations', [])
    if recommendations:
        print(f"\n💡 Optimization Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"   {i}. {rec}")
    else:
        print(f"\n✅ No optimization recommendations - your WiFi setup looks good!")


def channel_interference_analysis(api):
    """Analyze channel interference patterns."""
    print_separator("Channel Interference Analysis")
    
    spectrum_2g = api.get_wifi_spectrum_info("2g")
    spectrum_5g = api.get_wifi_spectrum_info("5g")
    
    # Analyze 2.4GHz interference (overlapping channels)
    print("\n🔍 2.4GHz Interference Analysis:")
    print("   Note: Channels 1, 6, and 11 are non-overlapping and preferred")
    
    overlapping_channels = {}
    for channel in spectrum_2g:
        ch = channel.get('channel', 0)
        availability = channel.get('availability', 100)
        aps = channel.get('accesspoints', 0)
        
        # Check if this is one of the preferred non-overlapping channels
        if ch in [1, 6, 11]:
            status = "✅ Non-overlapping"
        else:
            status = "⚠️  Overlapping"
        
        congestion = "Low" if availability > 80 else "Medium" if availability > 50 else "High"
        print(f"   Channel {ch:2d}: {availability:3d}% available, {aps} APs, {status}, {congestion} congestion")
    
    # Analyze 5GHz DFS channels
    print("\n🔍 5GHz DFS Channel Analysis:")
    print("   DFS channels (52-144) require radar detection and may change automatically")
    
    for channel in spectrum_5g:
        ch = channel.get('channel', 0)
        availability = channel.get('availability', 100)
        
        if 52 <= ch <= 144:
            dfs_status = "📡 DFS (radar detection)"
        else:
            dfs_status = "🔒 Non-DFS"
        
        print(f"   Channel {ch:3d}: {availability:3d}% available, {dfs_status}")


def interactive_channel_optimizer(api):
    """Interactive channel optimization tool."""
    print_separator("Interactive Channel Optimizer")
    
    print("\n🔧 WiFi Channel Optimization Tool")
    print("This tool will analyze your current setup and suggest improvements.")
    
    # Get current radio info
    radio_info = api.get_all_wifi_radio_info()
    
    print(f"\n📊 Current Configuration:")
    for band_name, radio_data in radio_info.items():
        if radio_data:
            band = band_name.replace('band_', '').replace('_', '.')
            channel = radio_data.get('Channel', 'Unknown')
            bandwidth = radio_data.get('CurrentOperatingChannelBandwidth', 'Unknown')
            auto_channel = radio_data.get('AutoChannelEnable', False)
            
            print(f"   {band}GHz: Channel {channel}, {bandwidth} bandwidth, Auto: {'Yes' if auto_channel else 'No'}")
    
    # Get best channels
    best_2g = api.get_best_wifi_channels("2g", 3)
    best_5g = api.get_best_wifi_channels("5g", 3)
    
    print(f"\n🏆 Recommended Channels:")
    if best_2g:
        channels_2g = ', '.join([f"Channel {ch['channel']}" for ch in best_2g[:3]])
        print(f"   2.4GHz: {channels_2g}")
    if best_5g:
        channels_5g = ', '.join([f"Channel {ch['channel']}" for ch in best_5g[:3]])
        print(f"   5GHz: {channels_5g}")
    
    # Analysis and tips
    analysis = api.analyze_wifi_environment()
    total_networks = analysis.get('total_networks', 0)
    
    print(f"\n💡 Optimization Tips:")
    if total_networks > 20:
        print("   • High WiFi density detected - prioritize 5GHz for better performance")
    
    print("   • Use channels 1, 6, or 11 on 2.4GHz to avoid interference")
    print("   • Enable auto-channel selection for dynamic optimization")
    print("   • Consider 80MHz bandwidth on 5GHz for maximum speed")
    print("   • Regularly check for interference and adjust channels if needed")


def main():
    """Main function demonstrating WiFi spectrum analysis."""
    print("🌐 KPN Box WiFi Spectrum Analysis")
    print("Analyzing WiFi environment and providing optimization recommendations...")
    
    # Initialize API
    api = KPNBoxAPI()
    
    try:
        # Login
        print("\n🔐 Connecting to KPN Box...")
        password = input("Enter password: ")
        api.login("admin", password)
        print("✅ Connected successfully!")
        
        # Demonstrate spectrum analysis functions
        print_radio_info(api)
        print_spectrum_analysis(api)
        print_best_channels(api)
        print_network_scan(api)
        channel_interference_analysis(api)
        print_comprehensive_analysis(api)
        interactive_channel_optimizer(api)
        
        print_separator("Analysis Complete")
        print("✅ WiFi spectrum analysis completed successfully!")
        print("\nUse this information to optimize your WiFi channels for better performance.")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 