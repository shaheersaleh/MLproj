import time
from datetime import datetime, timedelta
from collections import defaultdict

class SimpleLogger:
    """Simple in-memory logger to replace MongoDB functionality"""
    
    def __init__(self):
        self.logs = []
        self.ip_blocks = {}  # IP -> block_until_timestamp
        self.request_counts = defaultdict(lambda: {"count": 0, "reset_time": time.time()})
    
    def log(self, request, blocked=False, reason="", ml_prediction=None, features=None, is_plugin_blocked=False):
        """Log a request"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": request.remote_addr,
            "path": request.path,
            "method": request.method,
            "user_agent": request.headers.get("User-Agent", ""),
            "blocked": blocked,
            "reason": reason,
            "ml_prediction": ml_prediction,
            "features": features,
            "is_plugin_blocked": is_plugin_blocked
        }
        self.logs.append(log_entry)
        
        # Keep only last 1000 logs to prevent memory issues
        if len(self.logs) > 1000:
            self.logs = self.logs[-1000:]
    
    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        if ip in self.ip_blocks:
            if time.time() < self.ip_blocks[ip]:
                return True
            else:
                # Block expired, remove it
                del self.ip_blocks[ip]
        return False
    
    def block_ip(self, ip, block_time_seconds):
        """Block an IP for the specified duration"""
        self.ip_blocks[ip] = time.time() + block_time_seconds
    
    def increment_request_count(self, ip, window_seconds):
        """Increment request count for an IP within a time window"""
        current_time = time.time()
        ip_data = self.request_counts[ip]
        
        # Reset count if window has passed
        if current_time - ip_data["reset_time"] > window_seconds:
            ip_data["count"] = 1
            ip_data["reset_time"] = current_time
        else:
            ip_data["count"] += 1
        
        return ip_data["count"]
    
    def get_logs(self, limit=100):
        """Get recent logs"""
        return self.logs[-limit:] if self.logs else []
    
    def get_blocked_ips(self):
        """Get currently blocked IPs"""
        current_time = time.time()
        active_blocks = {ip: block_until for ip, block_until in self.ip_blocks.items() 
                        if current_time < block_until}
        return active_blocks
