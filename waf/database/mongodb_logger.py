# mongo_logger.py
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import numpy as np


class MongoLogger:
    def __init__(self, uri="mongodb://localhost:27017", db_name="waf_logs", collection_name="requests"):
        self.client = MongoClient(uri)
        self.collection = self.client[db_name][collection_name]

    def _to_python_type(self, obj):
        if isinstance(obj, np.generic):
            return obj.item()
        elif isinstance(obj, dict):
            return {k: self._to_python_type(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._to_python_type(v) for v in obj]
        else:
            return obj

    def log(self, request, blocked, reason=None, ml_prediction=None, is_plugin_blocked=False, features=None, tags=None):
        log_entry = {
            "timestamp": datetime.now(timezone.utc),
            "path": request.path,
            "method": request.method,
            "user_agent": request.headers.get("User-Agent", ""),
            "query": request.query_string.decode(),
            "body": request.get_data(as_text=True),
            "remote_addr": request.remote_addr,
            "blocked": blocked,
            "reason": reason,
            "ml_prediction": ml_prediction,
            "is_plugin_blocked": is_plugin_blocked,
            "features_used": features,
            "tags": tags or []
        }

        
        log_entry = self._to_python_type(log_entry)
        self.collection.insert_one(log_entry)

    def is_ip_blocked(self, ip):
        now = datetime.now(timezone.utc)
        entry = self.client['waf_logs']['blocked_ips'].find_one({"ip": ip, "unblock_time": {"$gt": now}})
        return entry is not None

    def block_ip(self, ip, duration_seconds):
        unblock_time = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
        self.client['waf_logs']['blocked_ips'].update_one(
            {"ip": ip},
            {"$set": {"ip": ip, "unblock_time": unblock_time}},
            upsert=True
        )

    def increment_request_count(self, ip, window_seconds):
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window_seconds)
        req_coll = self.client['waf_logs']['ip_requests']
        # Remove old requests
        req_coll.delete_many({"ip": ip, "timestamp": {"$lt": window_start}})
        # Insert new request
        req_coll.insert_one({"ip": ip, "timestamp": now})
        # Count requests in window
        count = req_coll.count_documents({"ip": ip, "timestamp": {"$gte": window_start}})
        return count

