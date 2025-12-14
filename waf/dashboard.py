from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit
import json
import yaml
import os
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from bson import ObjectId
import threading
import time
from database.mongodb_logger import MongoLogger
from rules.rule_engine import RuleEngine
# EnhancedMLModelManager is no longer used; relying on text models only
import pandas as pd
import numpy as np

app = Flask(__name__)
app.config['SECRET_KEY'] = 'waf-dashboard-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize components
mongo_logger = MongoLogger()
rule_engine = RuleEngine("rules.yaml")
# No ML model manager; dashboard uses text models only (if present)

# Global settings
WAF_SETTINGS = {
    'rate_limiting': {
        'enabled': True,
        'max_requests': 2,
        'window_seconds': 60,
        'block_time': 60
    },
    'ml_model': {
        'enabled': True,
        'current_version': 'v1.0.0',
        'confidence_threshold': 0.7
    },
    'plugins': {
        'block_admin': True,
        'block_ip': True,
        'block_user_agent': True
    },
    'rules': {
        'enabled': True,
        'auto_update': False
    }
}

# Load settings from file if exists
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'waf_settings.json')
if os.path.exists(SETTINGS_FILE):
    with open(SETTINGS_FILE, 'r') as f:
        WAF_SETTINGS.update(json.load(f))

def save_settings():
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(WAF_SETTINGS, f, indent=2)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get real-time WAF statistics"""
    try:
        # Get all requests (not just recent ones for now)
        all_requests = list(mongo_logger.collection.find({}, {"_id": 0}))
        
        # Convert ObjectId to string for JSON serialization and handle timezone
        for req in all_requests:
            if 'timestamp' in req:
                # Handle timezone-naive timestamps
                if req['timestamp'].tzinfo is None:
                    req['timestamp'] = req['timestamp'].replace(tzinfo=timezone.utc)
                req['timestamp'] = req['timestamp'].isoformat()
        
        # Calculate statistics
        total_requests = len(all_requests)
        blocked_requests = len([r for r in all_requests if r.get('blocked', False)])
        allowed_requests = total_requests - blocked_requests
        
        # Get all blocked IPs (including expired ones)
        all_blocked_ips = list(mongo_logger.client['waf_logs']['blocked_ips'].find({}, {"_id": 0}))
        current_time = datetime.now(timezone.utc)
        
        # Separate currently blocked and expired IPs
        currently_blocked_ips = []
        expired_blocked_ips = []
        
        for ip in all_blocked_ips:
            unblock_time = ip.get('unblock_time')
            if unblock_time:
                # Handle timezone-naive timestamps
                if unblock_time.tzinfo is None:
                    unblock_time = unblock_time.replace(tzinfo=timezone.utc)
                
                if unblock_time > current_time:
                    currently_blocked_ips.append(ip)
                else:
                    expired_blocked_ips.append(ip)
        
        blocked_ips_count = len(currently_blocked_ips)
        
        # Get top attack types
        attack_reasons = {}
        for req in all_requests:
            if req.get('blocked'):
                reason = req.get('reason', 'Unknown')
                attack_reasons[reason] = attack_reasons.get(reason, 0) + 1
        
        # Get top attacking IPs
        attacking_ips = {}
        for req in all_requests:
            if req.get('blocked'):
                ip = req.get('remote_addr', 'Unknown')
                attacking_ips[ip] = attacking_ips.get(ip, 0) + 1
        
        # Sort by count and get top 5
        attacking_ips = dict(sorted(attacking_ips.items(), key=lambda x: x[1], reverse=True)[:5])
        
        stats = {
            'total_requests': total_requests,
            'blocked_requests': blocked_requests,
            'allowed_requests': allowed_requests,
            'block_rate': (blocked_requests / total_requests * 100) if total_requests > 0 else 0,
            'blocked_ips_count': blocked_ips_count,
            'total_blocked_ips': len(all_blocked_ips),
            'expired_blocked_ips': len(expired_blocked_ips),
            'attack_reasons': attack_reasons,
            'attacking_ips': attacking_ips,
            'recent_requests': all_requests[:20]  # Last 20 requests
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/requests')
def get_requests():
    """Get paginated requests with enhanced filtering"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        blocked_only = request.args.get('blocked_only', 'false').lower() == 'true'
        ip_filter = request.args.get('ip', '')
        method_filter = request.args.get('method', '')
        path_filter = request.args.get('path', '')
        
        # Build query
        query = {}
        if blocked_only:
            query['blocked'] = True
        if ip_filter:
            query['remote_addr'] = {'$regex': ip_filter, '$options': 'i'}
        if method_filter:
            query['method'] = {'$regex': method_filter, '$options': 'i'}
        if path_filter:
            query['path'] = {'$regex': path_filter, '$options': 'i'}
        
        skip = (page - 1) * per_page
        
        # Get total count first
        total = mongo_logger.collection.count_documents(query)
        
        # Get requests with error handling
        try:
            requests = list(mongo_logger.collection.find(query).sort("timestamp", -1).skip(skip).limit(per_page))
        except Exception as e:
            return jsonify({'error': f'Error fetching requests: {str(e)}'}), 500
        
        # Convert ObjectId to string and format timestamps
        for req in requests:
            try:
                if 'timestamp' in req:
                    # Handle timezone-naive timestamps
                    if req['timestamp'].tzinfo is None:
                        req['timestamp'] = req['timestamp'].replace(tzinfo=timezone.utc)
                    req['timestamp'] = req['timestamp'].isoformat()
                if '_id' in req:
                    req['_id'] = str(req['_id'])
            except Exception as e:
                print(f"Error processing request {req.get('_id', 'unknown')}: {e}")
                # Continue processing other requests
                continue
        
        return jsonify({
            'requests': requests,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        import traceback
        print(f"Error in get_requests: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
def manage_settings():
    """Get or update WAF settings"""
    if request.method == 'POST':
        data = request.json
        WAF_SETTINGS.update(data)
        save_settings()
        return jsonify({'success': True, 'message': 'Settings updated successfully'})
    
    return jsonify(WAF_SETTINGS)

@app.route('/api/blocked-ips')
def get_blocked_ips():
    """Get all blocked IPs with enhanced information (including expired ones)"""
    try:
        # Get all blocked IPs (including expired ones)
        all_blocked_ips = list(mongo_logger.client['waf_logs']['blocked_ips'].find({}, {"_id": 0}).sort("unblock_time", 1))
        current_time = datetime.now(timezone.utc)
        
        # Process each IP
        for ip in all_blocked_ips:
            unblock_time = ip.get('unblock_time')
            if unblock_time:
                # Handle timezone-naive timestamps
                if unblock_time.tzinfo is None:
                    unblock_time = unblock_time.replace(tzinfo=timezone.utc)
                
                ip['unblock_time'] = unblock_time.isoformat()
                
                # Calculate remaining time and status
                if unblock_time > current_time:
                    ip['remaining_time'] = (unblock_time - current_time).total_seconds()
                    ip['status'] = 'active'
                else:
                    ip['remaining_time'] = 0
                    ip['status'] = 'expired'
            
            # Get recent activity for this IP
            recent_activity = list(mongo_logger.collection.find(
                {"remote_addr": ip['ip']},
                {"timestamp": 1, "blocked": 1, "reason": 1, "_id": 0}  # Exclude _id to avoid ObjectId issues
            ).sort("timestamp", -1).limit(5))
            
            # Handle timezone for recent activity
            for activity in recent_activity:
                if 'timestamp' in activity and activity['timestamp'].tzinfo is None:
                    activity['timestamp'] = activity['timestamp'].replace(tzinfo=timezone.utc)
                if 'timestamp' in activity:
                    activity['timestamp'] = activity['timestamp'].isoformat()
            
            ip['recent_activity'] = recent_activity
            ip['total_requests'] = mongo_logger.collection.count_documents({"remote_addr": ip['ip']})
            ip['blocked_requests'] = mongo_logger.collection.count_documents({
                "remote_addr": ip['ip'], 
                "blocked": True
            })
        
        return jsonify(all_blocked_ips)
    except Exception as e:
        import traceback
        print(f"Error in get_blocked_ips: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    """Block an IP address with enhanced functionality"""
    try:
        data = request.json
        ip = data.get('ip')
        duration = data.get('duration', 3600)  # Default 1 hour
        reason = data.get('reason', 'Manually blocked')
        
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        # Validate IP format (basic validation)
        if not is_valid_ip(ip):
            return jsonify({'error': 'Invalid IP address format'}), 400
        
        # Check if IP is already blocked
        existing_block = mongo_logger.client['waf_logs']['blocked_ips'].find_one({"ip": ip})
        if existing_block and existing_block.get('unblock_time', datetime.now(timezone.utc)) > datetime.now(timezone.utc):
            return jsonify({'error': f'IP {ip} is already blocked'}), 400
        
        # Block the IP
        mongo_logger.block_ip(ip, duration)
        
        # Log the manual block action
        mongo_logger.collection.insert_one({
            "timestamp": datetime.now(timezone.utc),
            "remote_addr": ip,
            "method": "MANUAL",
            "path": "/dashboard",
            "blocked": True,
            "reason": reason,
            "is_manual_block": True
        })
        
        return jsonify({
            'success': True, 
            'message': f'IP {ip} blocked for {duration} seconds',
            'unblock_time': (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock-ip/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock an IP address"""
    try:
        result = mongo_logger.client['waf_logs']['blocked_ips'].delete_one({"ip": ip})
        if result.deleted_count > 0:
            return jsonify({'success': True, 'message': f'IP {ip} unblocked successfully'})
        else:
            return jsonify({'error': f'IP {ip} was not found in blocked list'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/remove-expired-ip/<ip>', methods=['POST'])
def remove_expired_ip(ip):
    """Remove an expired IP address from the blocked_ips collection"""
    try:
        result = mongo_logger.client['waf_logs']['blocked_ips'].delete_one({"ip": ip})
        if result.deleted_count > 0:
            return jsonify({'success': True, 'message': f'Expired IP {ip} removed successfully'})
        else:
            return jsonify({'error': f'IP {ip} was not found in blocked list'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules')
def get_rules():
    """Get current WAF rules with enhanced information"""
    try:
        # Fix the path to be relative to the dashboard.py file location
        rules_file_path = os.path.join(os.path.dirname(__file__), 'rules', 'rules.yaml')
        if not os.path.exists(rules_file_path):
            return jsonify({'error': 'Rules file not found'}), 404
        
        with open(rules_file_path, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        # Add metadata about rules
        rules_info = {
            'total_rules': len(rules_data.get('rules', [])),
            'block_rules': len([r for r in rules_data.get('rules', []) if r.get('action') == 'block']),
            'log_rules': len([r for r in rules_data.get('rules', []) if r.get('action') == 'log']),
            'rules': rules_data.get('rules', []),
            'last_modified': datetime.fromtimestamp(os.path.getmtime(rules_file_path)).isoformat(),
            'file_size': os.path.getsize(rules_file_path)
        }
        
        return jsonify(rules_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules', methods=['POST'])
def update_rules():
    """Update WAF rules with validation"""
    try:
        data = request.json
        rules = data.get('rules', [])
        
        # Validate rules structure
        for rule in rules:
            if not all(key in rule for key in ['id', 'pattern', 'action', 'description']):
                return jsonify({'error': 'Invalid rule structure'}), 400
            
            if rule['action'] not in ['block', 'log']:
                return jsonify({'error': f"Invalid action '{rule['action']}' for rule {rule['id']}"}), 400
        
        # Save rules
        rules_data = {'rules': rules}
        rules_file_path = os.path.join(os.path.dirname(__file__), 'rules', 'rules.yaml')
        with open(rules_file_path, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({
            'success': True, 
            'message': f'Rules updated successfully. Total rules: {len(rules)}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ml-models')
def get_ml_models():
    """Report presence of text models used by the WAF app."""
    try:
        models_dir = os.path.join(os.path.dirname(__file__), 'ml_model', 'waf_text')
        text_model = os.path.join(models_dir, 'final_model_pred.pkl')
        pt_model = os.path.join(models_dir, 'pt_final_model.pkl')

        available = []
        model_info = {}
        if os.path.exists(text_model):
            available.append('text_model')
            model_info['text_model'] = {
                'path': text_model,
                'type': 'text'
            }
        if os.path.exists(pt_model):
            available.append('param_tamper_model')
            model_info['param_tamper_model'] = {
                'path': pt_model,
                'type': 'parameter_tampering'
            }

        return jsonify({
            'available_models': available,
            'current_model': 'waf_text',
            'model_info': model_info
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/set-model/<version>', methods=['POST'])
def set_model(version):
    """Model switching via manager is not supported; using text models only."""
    return jsonify({'error': 'Model switching is not supported. Using text models only.'}), 400

@app.route('/api/analytics')
def get_analytics():
    """Get analytics data with enhanced metrics"""
    try:
        # Get data for last 7 days
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=7)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": start_date, "$lte": end_date}}},
            {"$group": {
                "_id": {
                    "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                    "blocked": "$blocked"
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.date": 1}}
        ]
        
        analytics = list(mongo_logger.collection.aggregate(pipeline))
        
        # Process analytics data
        daily_stats = {}
        for item in analytics:
            date = item['_id']['date']
            blocked = item['_id']['blocked']
            count = item['count']
            
            if date not in daily_stats:
                daily_stats[date] = {'allowed': 0, 'blocked': 0}
            
            if blocked:
                daily_stats[date]['blocked'] = count
            else:
                daily_stats[date]['allowed'] = count
        
        # Get additional metrics
        total_requests = sum(item['count'] for item in analytics)
        total_blocked = sum(item['count'] for item in analytics if item['_id']['blocked'])
        
        # Get top attack patterns (by reason)
        attack_patterns = list(mongo_logger.collection.aggregate([
            {"$match": {"blocked": True, "timestamp": {"$gte": start_date}}},
            {"$group": {"_id": "$reason", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))
        
        # Get top attacking IPs
        top_attackers = list(mongo_logger.collection.aggregate([
            {"$match": {"blocked": True, "timestamp": {"$gte": start_date}}},
            {"$group": {"_id": "$remote_addr", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))

        # ML attack types predicted by the model (exclude 'valid')
        ml_attack_types = list(mongo_logger.collection.aggregate([
            {"$match": {
                "blocked": True,
                "timestamp": {"$gte": start_date},
                "$or": [
                    {"reason": {"$regex": "^Blocked by ML model", "$options": "i"}},
                    {"reason": {"$regex": "^ML malicious", "$options": "i"}}
                ]
            }},
            {"$project": {
                "threats": {"$objectToArray": {"$ifNull": ["$ml_prediction.threats", {}]}}
            }},
            {"$unwind": "$threats"},
            {"$match": {"threats.k": {"$ne": "valid"}}},
            {"$group": {"_id": "$threats.k", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))

        # Rule-based blocks (group by rule id in reason)
        rule_block_counts = list(mongo_logger.collection.aggregate([
            {"$match": {
                "blocked": True,
                "timestamp": {"$gte": start_date},
                "reason": {"$regex": "^Rule: ", "$options": "i"}
            }},
            {"$group": {"_id": "$reason", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))

        # URLs blocked by different layers (ML / Rules / Plugins)
        urls_by_layer_raw = list(mongo_logger.collection.aggregate([
            {"$match": {"blocked": True, "timestamp": {"$gte": start_date}}},
            {"$addFields": {
                "layer": {
                    "$switch": {
                        "branches": [
                            {"case": {"$regexMatch": {"input": "$reason", "regex": "^Rule: ", "options": "i"}}, "then": "rules"},
                            {"case": {"$regexMatch": {"input": "$reason", "regex": "^Plugin: ", "options": "i"}}, "then": "plugins"},
                            {"case": {"$or": [
                                {"$regexMatch": {"input": "$reason", "regex": "^Blocked by ML model", "options": "i"}},
                                {"$regexMatch": {"input": "$reason", "regex": "^ML malicious", "options": "i"}}
                            ]}, "then": "ml"}
                        ],
                        "default": "other"
                    }
                }
            }},
            {"$group": {"_id": {"layer": "$layer", "path": "$path"}, "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 100}
        ]))

        urls_by_layer = {"ml": [], "rules": [], "plugins": [], "other": []}
        for item in urls_by_layer_raw:
            layer = item['_id'].get('layer', 'other')
            path = item['_id'].get('path', '/')
            count = item['count']
            if layer in urls_by_layer:
                urls_by_layer[layer].append({"path": path, "count": count})
            else:
                urls_by_layer['other'].append({"path": path, "count": count})

        # Limit to top 10 per layer for frontend simplicity
        for k in urls_by_layer.keys():
            urls_by_layer[k] = sorted(urls_by_layer[k], key=lambda x: x['count'], reverse=True)[:10]

        # Plugin-based blocks (group by plugin name in reason)
        plugin_block_counts = list(mongo_logger.collection.aggregate([
            {"$match": {
                "blocked": True,
                "timestamp": {"$gte": start_date},
                "reason": {"$regex": "^Plugin: ", "$options": "i"}
            }},
            {"$group": {"_id": "$reason", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))

        # Layer comparison totals (counts per layer)
        layer_comparison_raw = list(mongo_logger.collection.aggregate([
            {"$match": {"blocked": True, "timestamp": {"$gte": start_date}}},
            {"$addFields": {
                "layer": {
                    "$switch": {
                        "branches": [
                            {"case": {"$regexMatch": {"input": "$reason", "regex": "^Rule: ", "options": "i"}}, "then": "rules"},
                            {"case": {"$regexMatch": {"input": "$reason", "regex": "^Plugin: ", "options": "i"}}, "then": "plugins"},
                            {"case": {"$or": [
                                {"$regexMatch": {"input": "$reason", "regex": "^Blocked by ML model", "options": "i"}},
                                {"$regexMatch": {"input": "$reason", "regex": "^ML malicious", "options": "i"}}
                            ]}, "then": "ml"}
                        ],
                        "default": "other"
                    }
                }
            }},
            {"$group": {"_id": "$layer", "count": {"$sum": 1}}}
        ]))
        layer_comparison = {"ml": 0, "rules": 0, "plugins": 0, "other": 0}
        for item in layer_comparison_raw:
            layer = item.get('_id', 'other')
            layer_comparison[layer] = item.get('count', 0)
        
        return jsonify({
            'daily_stats': daily_stats,
            'total_requests': total_requests,
            'total_blocked': total_blocked,
            'attack_patterns': attack_patterns,
            'top_attackers': top_attackers,
            'ml_attack_types': ml_attack_types,
            'rule_block_counts': rule_block_counts,
            'plugin_block_counts': plugin_block_counts,
            'urls_by_layer': urls_by_layer,
            'layer_comparison': layer_comparison
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/network-flow-status')
def get_network_flow_status():
    """Get network flow analysis status"""
    try:
        # Check if Scapy is available
        try:
            import scapy
            scapy_available = True
        except ImportError:
            scapy_available = False
        
        # Get network interface info
        import psutil
        import socket
        network_interfaces = []
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                if interface != 'lo':  # Skip loopback
                    for addr in addrs:
                        if addr.family == socket.AF_INET:  # IPv4 only
                            network_interfaces.append({
                                'name': interface,
                                'ip': addr.address,
                                'netmask': addr.netmask
                            })
        except:
            network_interfaces = []
        
        # Get network interface names for display
        interface_names = [iface['name'] for iface in network_interfaces]
        
        # Get actual feature count if possible
        try:
            from feature_extractor import extract_live_features_from_request
            class MockRequest:
                def __init__(self):
                    self.remote_addr = '127.0.0.1'
                    self.method = 'GET'
                    self.path = '/test'
                    self.headers = {'User-Agent': 'Test'}
            
            features = extract_live_features_from_request(MockRequest())
            non_zero_count = sum(1 for v in features.values() if v != 0)
            total_features = len(features)
        except:
            non_zero_count = 0
            total_features = 15 if scapy_available else 0
        
        return jsonify({
            'scapy_available': scapy_available,
            'network_interfaces': network_interfaces,
            'interfaces': interface_names,
            'status': 'active' if scapy_available else 'disabled',
            'issue': 'Scapy not available' if not scapy_available else 'None',
            'active_features': f'{non_zero_count} active features' if scapy_available else 'None',
            'total_features': total_features,
            'message': 'Network flow analysis ready' if scapy_available else 'Scapy not available'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network-flow-settings', methods=['POST'])
def save_network_flow_settings():
    """Save network flow analysis settings"""
    try:
        data = request.json
        enabled = data.get('enabled', False)
        
        # Update settings
        WAF_SETTINGS['network_flow'] = {
            'enabled': enabled
        }
        save_settings()
        
        return jsonify({
            'success': True,
            'message': 'Network flow settings saved successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-network-flow', methods=['POST'])
def test_network_flow():
    """Test network flow analysis capabilities"""
    try:
        # Check if Scapy is available
        try:
            import scapy
            return jsonify({
                'success': True,
                'message': 'Scapy is ready for packet capture',
                'status': 'ready'
            })
        except ImportError:
            return jsonify({
                'success': False,
                'message': 'Scapy not available. Install with: pip install scapy',
                'status': 'not_available'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network-flow-features')
def get_network_flow_features():
    """Get current network flow features"""
    try:
        # Import the feature extractor
        from feature_extractor import extract_live_features_from_request
        
        # Create a mock request object to extract features
        class MockRequest:
            def __init__(self):
                self.remote_addr = '127.0.0.1'
                self.method = 'GET'
                self.path = '/test'
                self.headers = {'User-Agent': 'Test'}
        
        # Extract features
        features = extract_live_features_from_request(MockRequest())
        
        # Count non-zero features
        non_zero_count = sum(1 for v in features.values() if v != 0)
        
        return jsonify({
            'success': True,
            'features': features,
            'non_zero_count': non_zero_count,
            'total_features': len(features)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'features': {},
            'non_zero_count': 0,
            'total_features': 0
        })

@app.route('/api/rule', methods=['POST'])
def add_edit_rule():
    """Add a new rule or edit an existing one"""
    try:
        data = request.json
        rule_id = data.get('id')
        pattern = data.get('pattern')
        action = data.get('action')
        description = data.get('description')
        is_edit = data.get('is_edit', False)
        
        if not all([rule_id, pattern, action, description]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if action not in ['block', 'log']:
            return jsonify({'error': 'Invalid action. Must be "block" or "log"'}), 400
        
        # Load current rules
        rules_file_path = os.path.join(os.path.dirname(__file__), 'rules', 'rules.yaml')
        if not os.path.exists(rules_file_path):
            return jsonify({'error': 'Rules file not found'}), 404
        
        with open(rules_file_path, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        rules = rules_data.get('rules', [])
        
        if is_edit:
            # Update existing rule
            rule_index = next((i for i, r in enumerate(rules) if r.get('id') == rule_id), None)
            if rule_index is None:
                return jsonify({'error': f'Rule {rule_id} not found for editing'}), 404
            rules[rule_index] = {'id': rule_id, 'pattern': pattern, 'action': action, 'description': description}
            message = f'Rule {rule_id} updated successfully'
        else:
            # Check if rule ID already exists
            if any(r.get('id') == rule_id for r in rules):
                return jsonify({'error': f'Rule ID {rule_id} already exists'}), 400
            
            # Add new rule
            rules.append({'id': rule_id, 'pattern': pattern, 'action': action, 'description': description})
            message = f'Rule {rule_id} added successfully'
        
        # Save updated rules
        rules_data['rules'] = rules
        with open(rules_file_path, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({
            'success': True,
            'message': message
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-rule/<rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """Delete a specific rule by ID"""
    try:
        # Load current rules
        rules_file_path = os.path.join(os.path.dirname(__file__), 'rules', 'rules.yaml')
        if not os.path.exists(rules_file_path):
            return jsonify({'error': 'Rules file not found'}), 404
        
        with open(rules_file_path, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        # Find and remove the rule
        rules = rules_data.get('rules', [])
        original_count = len(rules)
        rules = [r for r in rules if r.get('id') != rule_id]
        
        if len(rules) == original_count:
            return jsonify({'error': f'Rule {rule_id} not found'}), 404
        
        # Save updated rules
        rules_data['rules'] = rules
        with open(rules_file_path, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({
            'success': True,
            'message': f'Rule {rule_id} deleted successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/request-details/<request_id>')
def get_request_details(request_id):
    """Get detailed information about a specific request"""
    try:
        # Convert string ID back to ObjectId
        obj_id = ObjectId(request_id)
        request_data = mongo_logger.collection.find_one({"_id": obj_id})
        
        if not request_data:
            return jsonify({'error': 'Request not found'}), 404
        
        # Convert ObjectId to string
        request_data['_id'] = str(request_data['_id'])
        if 'timestamp' in request_data:
            request_data['timestamp'] = request_data['timestamp'].isoformat()
        
        return jsonify(request_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def is_valid_ip(ip):
    """Basic IP address validation"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True
    except:
        return False

# WebSocket for real-time updates
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

def broadcast_stats():
    """Broadcast real-time stats to connected clients"""
    while True:
        try:
            with app.app_context():
                stats = get_stats().json
                socketio.emit('stats_update', stats)
        except Exception as e:
            print(f"Error broadcasting stats: {e}")
        time.sleep(5)  # Update every 5 seconds

# Start background thread for real-time updates
stats_thread = threading.Thread(target=broadcast_stats, daemon=True)
stats_thread.start()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5002, debug=False) 

