#!/usr/bin/env python3
"""
Speedtest example for KPNBoxAPI.

This script demonstrates:
1. How to run download and upload speed tests
2. How to interpret and display speed test results
3. How to format speeds in human-readable format
4. How to track test progress and analyze results

Note: Speed tests consume bandwidth and take several seconds to complete.
"""

import time
from datetime import datetime, timezone
from kpnboxapi import KPNBoxAPI, AuthenticationError, ConnectionError


def parse_timestamp(timestamp_str):
    """Parse ISO timestamp string to datetime object."""
    try:
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except:
        return None


def format_duration(milliseconds):
    """Format duration in human-readable format."""
    seconds = milliseconds / 1000
    if seconds >= 60:
        minutes = int(seconds // 60)
        seconds = seconds % 60
        return f"{minutes}m {seconds:.1f}s"
    else:
        return f"{seconds:.1f}s"


def analyze_speedtest_result(result, test_type):
    """Analyze and display speedtest results."""
    if not result:
        print(f"❌ {test_type} test failed - no results")
        return
    
    # Extract key metrics
    throughput = result.get('throughput', 0)
    latency = result.get('latency', 0)
    duration = result.get('duration', 0)
    bytes_transferred = result.get('rxbytes', 0)
    test_server = result.get('testserver', 'Unknown')
    suite = result.get('suite', 'Unknown')
    
    # Parse timestamps
    start_ts = parse_timestamp(result.get('RetrievedStartTS', ''))
    end_ts = parse_timestamp(result.get('RetrievedTS', ''))
    
    print(f"📊 {test_type} Speed Test Results:")
    print("-" * 50)
    
    # Speed and performance
    speed_formatted = format_speed_custom(throughput)
    print(f"🚀 Speed: {speed_formatted}")
    print(f"⚡ Latency: {latency} ms")
    print(f"⏱️  Duration: {format_duration(duration)}")
    print(f"📦 Data Transferred: {format_bytes_custom(bytes_transferred)}")
    
    # Test details
    print(f"\n🔧 Test Details:")
    print(f"   Server: {test_server}")
    print(f"   Suite: {suite}")
    print(f"   Interface: {result.get('interface', 'Unknown')}")
    
    # Timestamps
    if start_ts and end_ts:
        print(f"\n📅 Timing:")
        print(f"   Started: {start_ts.strftime('%H:%M:%S')}")
        print(f"   Ended: {end_ts.strftime('%H:%M:%S')}")
        actual_duration = (end_ts - start_ts).total_seconds()
        print(f"   Actual Duration: {actual_duration:.1f}s")
    
    # Performance analysis
    print(f"\n📈 Analysis:")
    
    # Speed categories (values now in kilobits per second)
    if throughput >= 1_000_000:  # 1 Gbps+ (1,000,000 Kbps)
        speed_rating = "🟢 Excellent"
    elif throughput >= 100_000:  # 100 Mbps+ (100,000 Kbps)
        speed_rating = "🟢 Very Good"
    elif throughput >= 50_000:   # 50 Mbps+ (50,000 Kbps)
        speed_rating = "🟡 Good"
    elif throughput >= 25_000:   # 25 Mbps+ (25,000 Kbps)
        speed_rating = "🟡 Moderate"
    elif throughput >= 10_000:   # 10 Mbps+ (10,000 Kbps)
        speed_rating = "🟠 Fair"
    else:
        speed_rating = "🔴 Poor"
    
    print(f"   Speed Rating: {speed_rating}")
    
    # Latency analysis
    if latency <= 20:
        latency_rating = "🟢 Excellent"
    elif latency <= 50:
        latency_rating = "🟢 Good"
    elif latency <= 100:
        latency_rating = "🟡 Moderate"
    elif latency <= 200:
        latency_rating = "🟠 Fair"
    else:
        latency_rating = "🔴 Poor"
    
    print(f"   Latency Rating: {latency_rating}")
    
    # Data efficiency
    if duration > 0:
        efficiency = (bytes_transferred / (duration / 1000)) / 1_000_000  # MB/s
        print(f"   Data Efficiency: {efficiency:.1f} MB/s")


def format_speed_custom(kilobits_per_second):
    """Format speed with custom logic."""
    if kilobits_per_second >= 1_000_000:  # Gbps
        return f"{kilobits_per_second / 1_000_000:.2f} Gbps"
    elif kilobits_per_second >= 1_000:  # Mbps
        return f"{kilobits_per_second / 1_000:.1f} Mbps"
    else:
        return f"{kilobits_per_second} Kbps"


def format_bytes_custom(bytes_count):
    """Format bytes with custom logic."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"


def run_individual_tests():
    """Run download and upload tests separately."""
    password = input("Enter your KPN Box password: ")
    
    try:
        api = KPNBoxAPI(host="192.168.2.254")
        print("Connecting and logging in...")
        api.login(username="admin", password=password)
        print("✅ Login successful!")
        
        # Check connection first
        if not api.is_connected():
            print("❌ No internet connection available")
            return
        
        print("\n🌐 Internet connection confirmed")
        
        # Run download test
        print("\n" + "="*60)
        print("🔽 Running Download Speed Test...")
        print("⏳ This will take several seconds and consume bandwidth...")
        
        start_time = time.time()
        download_result = api.run_download_speedtest()
        download_duration = time.time() - start_time
        
        if download_result:
            analyze_speedtest_result(download_result, "Download")
            print(f"\n⏱️  Test completed in {download_duration:.1f} seconds")
        else:
            print("❌ Download test failed")
        
        # Wait a moment between tests
        print("\n⏸️  Waiting 2 seconds before upload test...")
        time.sleep(2)
        
        # Run upload test
        print("\n" + "="*60)
        print("🔼 Running Upload Speed Test...")
        print("⏳ This will take several seconds and consume bandwidth...")
        
        start_time = time.time()
        upload_result = api.run_upload_speedtest()
        upload_duration = time.time() - start_time
        
        if upload_result:
            analyze_speedtest_result(upload_result, "Upload")
            print(f"\n⏱️  Test completed in {upload_duration:.1f} seconds")
        else:
            print("❌ Upload test failed")
        
        # Summary
        if download_result and upload_result:
            print("\n" + "="*60)
            print("📋 Speed Test Summary:")
            print("-" * 30)
            
            download_speed = format_speed_custom(download_result.get('throughput', 0))
            upload_speed = format_speed_custom(upload_result.get('throughput', 0))
            download_latency = download_result.get('latency', 0)
            upload_latency = upload_result.get('latency', 0)
            
            print(f"🔽 Download: {download_speed} (latency: {download_latency}ms)")
            print(f"🔼 Upload: {upload_speed} (latency: {upload_latency}ms)")
            
            # Speed ratio analysis
            if download_result.get('throughput', 0) > 0 and upload_result.get('throughput', 0) > 0:
                ratio = download_result['throughput'] / upload_result['throughput']
                print(f"📊 Download/Upload Ratio: {ratio:.1f}:1")
                
                if ratio > 10:
                    print("   ℹ️  Typical for ADSL/VDSL connections")
                elif ratio > 5:
                    print("   ℹ️  Common for cable connections")
                elif ratio < 2:
                    print("   ℹ️  Nearly symmetric (fiber-like)")
        
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


def run_full_speedtest():
    """Run both tests using the combined method."""
    password = input("Enter your KPN Box password: ")
    
    try:
        api = KPNBoxAPI(host="192.168.2.254")
        print("Connecting and logging in...")
        api.login(username="admin", password=password)
        print("✅ Login successful!")
        
        # Check connection first
        if not api.is_connected():
            print("❌ No internet connection available")
            return
        
        print("\n🌐 Internet connection confirmed")
        
        # Run full speed test
        print("\n" + "="*60)
        print("🚀 Running Full Speed Test (Download + Upload)...")
        print("⏳ This will take 10+ seconds and consume significant bandwidth...")
        
        start_time = time.time()
        results = api.run_full_speedtest()
        total_duration = time.time() - start_time
        
        # Analyze results
        if results.get('download'):
            print("\n")
            analyze_speedtest_result(results['download'], "Download")
        
        if results.get('upload'):
            print("\n")
            analyze_speedtest_result(results['upload'], "Upload")
        
        print(f"\n⏱️  Total test time: {total_duration:.1f} seconds")
        
        # Show bandwidth usage estimate
        download_bytes = results.get('download', {}).get('rxbytes', 0)
        upload_bytes = results.get('upload', {}).get('rxbytes', 0)
        total_bytes = download_bytes + upload_bytes
        
        print(f"📊 Total Bandwidth Used: {format_bytes_custom(total_bytes)}")
        
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    """Main function with menu."""
    print("KPNBoxAPI - Speed Test Example")
    print("=" * 40)
    print()
    print("⚠️  WARNING: Speed tests consume bandwidth and take time!")
    print("   • Download test: ~5 seconds, ~2.5 GB data")
    print("   • Upload test: ~5 seconds, ~2 GB data")
    print("   • Full test: ~10+ seconds, ~4.5 GB total")
    print()
    
    while True:
        print("Choose an option:")
        print("1. Run individual tests (download then upload)")
        print("2. Run full speed test (combined)")
        print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == "1":
            run_individual_tests()
            break
        elif choice == "2":
            run_full_speedtest()
            break
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main() 