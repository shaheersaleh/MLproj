#!/usr/bin/env python3
"""
WAF Runner Script
Runs both the WAF proxy and the dashboard
"""

import subprocess
import sys
import time
import os
from threading import Thread

def run_waf():
    """Run the WAF proxy on port 5000"""
    print("Starting WAF Proxy on port 5000...")
    subprocess.run([sys.executable, "waf/app.py"])

def run_dashboard():
    """Run the dashboard on port 5001"""
    print("Starting WAF Dashboard on port 5001...")
    subprocess.run([sys.executable, "waf/dashboard.py"])

def main():
    print("🚀 Starting WAF System...")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists("waf/app.py"):
        print("❌ Error: Please run this script from the WAF directory")
        print("   Current directory:", os.getcwd())
        sys.exit(1)
    
    # Start both services in separate threads
    waf_thread = Thread(target=run_waf, daemon=True)
    dashboard_thread = Thread(target=run_dashboard, daemon=True)
    
    try:
        waf_thread.start()
        time.sleep(2)  # Give WAF a moment to start
        dashboard_thread.start()
        
        print("✅ WAF System started successfully!")
        print("📊 Dashboard: http://localhost:5001")
        print("🔒 WAF Proxy: http://localhost:5000")
        print("=" * 50)
        print("Press Ctrl+C to stop all services")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping WAF System...")
        print("✅ All services stopped")

if __name__ == "__main__":
    main() 