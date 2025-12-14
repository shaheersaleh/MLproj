# block_ip.py

# List of blocked IP addresses
BLOCKED_IPS = {
    "10.7.144.198",  # Example IP, replace with actual IPs to block
    # Add more IPs as needed
}

def run(request):
    if request.remote_addr in BLOCKED_IPS:
        return True
    return False 
