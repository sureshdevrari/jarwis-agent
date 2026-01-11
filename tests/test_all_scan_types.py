#!/usr/bin/env python
"""Test all scan types - web, mobile, network, cloud"""
import requests
import time

BASE_URL = "http://localhost:8000"

def login():
    response = requests.post(f"{BASE_URL}/api/auth/login", json={"email": "user1@jarwis.ai", "password": "12341234"})
    return response.json()['access_token']

def test_web_scan(token):
    print("\n" + "="*60)
    print("TESTING WEB SCAN")
    print("="*60)
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{BASE_URL}/api/scans/", headers=headers, json={
        "target_url": "https://httpbin.org",
        "scan_type": "web"
    })
    if response.status_code == 201:
        scan_id = response.json()['scan_id']
        print(f"✅ Web scan created: {scan_id}")
        return True
    else:
        print(f"❌ Web scan failed: {response.status_code} - {response.text}")
        return False

def test_mobile_scan(token):
    print("\n" + "="*60)
    print("TESTING MOBILE SCAN")
    print("="*60)
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/scan/mobile", headers=headers)
    if response.status_code == 200:
        print(f"✅ Mobile scan endpoint accessible")
        data = response.json()
        if 'scans' in data and len(data['scans']) > 0:
            print(f"   Found {len(data['scans'])} mobile scan(s)")
        return True
    else:
        print(f"❌ Mobile scan: {response.status_code}")
        return False

def test_network_scan(token):
    print("\n" + "="*60)
    print("TESTING NETWORK SCAN")
    print("="*60)
    headers = {"Authorization": f"Bearer {token}"}
    # Check if network tools are available
    response = requests.get(f"{BASE_URL}/api/network/tools", headers=headers)
    if response.status_code == 200:
        print(f"✅ Network scan endpoint accessible")
        data = response.json()
        if 'total_available' in data:
            print(f"   {data['total_available']}/{data['total_tools']} network tools available")
        return True
    else:
        print(f"❌ Network scan: {response.status_code}")
        return False

def test_cloud_scan(token):
    print("\n" + "="*60)
    print("TESTING CLOUD SCAN")
    print("="*60)
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/scan/cloud", headers=headers)
    if response.status_code == 200:
        print(f"✅ Cloud scan endpoint accessible")
        data = response.json()
        if 'scans' in data and len(data['scans']) > 0:
            print(f"   Found {len(data['scans'])} cloud scan(s)")
        return True
    else:
        print(f"❌ Cloud scan: {response.status_code}")
        return False

def main():
    print("="*60)
    print("JARWIS ALL SCAN TYPES VERIFICATION")
    print("="*60)
    
    token = login()
    print("✅ Login successful\n")
    
    results = {
        "web": test_web_scan(token),
        "mobile": test_mobile_scan(token),
        "network": test_network_scan(token),
        "cloud": test_cloud_scan(token)
    }
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for scan_type, status in results.items():
        icon = "✅" if status else "❌"
        print(f"{icon} {scan_type.upper()}: {'Working' if status else 'Not Working'}")
    
    working = sum(results.values())
    total = len(results)
    print(f"\n{working}/{total} scan types operational")
    
    if working == total:
        print("\n🎉 ALL SCAN TYPES WORKING!")
    elif working > 0:
        print(f"\n⚠️  {total - working} scan type(s) need attention")
    else:
        print("\n❌ No scan types working")

if __name__ == "__main__":
    main()
