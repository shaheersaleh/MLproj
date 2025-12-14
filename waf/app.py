from flask import Flask, request, abort
import requests
import os
import pandas as pd
import importlib.util
import json
from rules.rule_engine import RuleEngine
from database.mongodb_logger import MongoLogger
from proxy import forward_to_backend
mongo_logger = MongoLogger()
from ml_model.waf_text.predictor import WafPredictor
import time

flow_stats = {}

rule_engine = RuleEngine("rules.yaml")
app = Flask(__name__)
MAX_REQUESTS = 2000      # requests
WINDOW = 60           # seconds
BLOCK_TIME = 10       # seconds

PLUGIN_FOLDER = os.path.join(os.path.dirname(__file__), "plugins")
plugins = []

# Load plugins
for fname in os.listdir(PLUGIN_FOLDER):
    if fname.endswith(".py"):
        path = os.path.join(PLUGIN_FOLDER, fname)
        spec = importlib.util.spec_from_file_location(fname[:-3], path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            plugins.append(mod)



# Initialize new text-based WAF predictor (if available)
_MODELS_DIR = os.path.join(os.path.dirname(__file__), "ml_model")
_TEXT_MODEL_PATH = os.path.join(_MODELS_DIR, "waf_text", "final_model_pred.pkl")
_PT_MODEL_PATH = os.path.join(_MODELS_DIR, "waf_text", "pt_final_model.pkl")
_text_predictor = None
try:
    if os.path.exists(_TEXT_MODEL_PATH) and os.path.exists(_PT_MODEL_PATH):
        _text_predictor = WafPredictor(_TEXT_MODEL_PATH, _PT_MODEL_PATH)
        pass  # WafPredictor initialized
    else:
        pass  # Using FeatureExtractor only
except Exception as e:
    pass  # WafPredictor initialization failed
def _init_current_model():
    # No longer needed since we're using FeatureExtractor
    print("Using FeatureExtractor for feature extraction")

_init_current_model()

# Settings handling (shared with dashboard)
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'waf_settings.json')

def load_waf_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    # Sensible defaults if settings are missing
    return {
        'rate_limiting': {
            'enabled': True,
            'max_requests': 2000,
            'window_seconds': 60,
            'block_time': 10
        },
        'ml_model': {
            'enabled': True,
            'confidence_threshold': 0.7
        },
        'plugins': {
            'enabled': True,
            'block_admin': True,
            'block_ip': True,
            'block_user_agent': True
        },
        'rules': {
            'enabled': True,
            'auto_update': False
        }
    }

def get_dynamic_settings():
    """
    Loads settings from the settings file and ensures plugins and rules are initialized.
    This function is called before each request to ensure the latest settings are used.
    """
    settings = load_waf_settings()
    
    # Reload plugins based on individual plugin settings
    global plugins
    plugins = []
    
    if settings.get('plugins', {}).get('block_admin', True):
        try:
            import plugins.block_admin as admin_plugin
            plugins.append(admin_plugin)
        except Exception as e:
            print(f"[WAF] Failed to load admin plugin: {e}")
    
    if settings.get('plugins', {}).get('block_ip', True):
        try:
            import plugins.block_ip as ip_plugin
            plugins.append(ip_plugin)
        except Exception as e:
            print(f"[WAF] Failed to load IP plugin: {e}")
    
    if settings.get('plugins', {}).get('block_user_agent', True):
        try:
            import plugins.block_user_agent as ua_plugin
            plugins.append(ua_plugin)
        except Exception as e:
            print(f"[WAF] Failed to load user agent plugin: {e}")
    
    return settings

@app.before_request
def waf_filter():
    # Get current settings (this will reload plugins and rules if needed)
    settings = get_dynamic_settings()
    
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    # 1. Check if IP is blocked
    if mongo_logger.is_ip_blocked(ip):
        print(f"This Ip is Blocked!!!")
        abort(429, "Too many requests. Try again later.")
    
    # 2. Rate limiting - only if enabled
    if settings.get('rate_limiting', {}).get('enabled', True):
        max_requests = settings.get('rate_limiting', {}).get('max_requests', 2000)
        window_seconds = settings.get('rate_limiting', {}).get('window_seconds', 60)
        block_time = settings.get('rate_limiting', {}).get('block_time', 10)
        
        req_count = mongo_logger.increment_request_count(ip, window_seconds)
        if req_count > max_requests:
            mongo_logger.block_ip(ip, block_time)
            print(f"Too many requests!!! Rate limit exceeded: {req_count}/{max_requests} in {window_seconds}s")
            abort(429, "Too many requests. Try again later.")
    else:
        print("[WAF] Rate limiting disabled")
        
    # Log request details
    print(f"[WAF] Request: {request.method} {request.path} from {ip}")
    print(f"[WAF] User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
    print(f"[WAF] Content-Type: {request.headers.get('Content-Type', 'None')}")
    
    blocked = False
    reason = "Allowed"
    ml_prediction = None
    is_plugin_blocked = False
    rule_id = None

    # 3. Evaluate rules first
    if settings.get('rules', {}).get('enabled', True):
        try:
            rule_id = rule_engine.evaluate()
            if rule_id:
                blocked = True
                reason = f"Rule: {rule_id}"
                print(f"[WAF] Rule Decision: BLOCKED by rule {rule_id}")
        except Exception as e:
            print(f"[WAF] Rule evaluation error: {e}")

    # 4. If not blocked by rules, evaluate plugins
    if not blocked:
        for plugin in plugins:
            try:
                if plugin.run(request):
                    blocked = True
                    reason = f"Plugin: {plugin.__name__}"
                    is_plugin_blocked = True
                    print(f"[WAF] Plugin Decision: BLOCKED by {plugin.__name__}")
                    break
            except Exception as e:
                print(f"[WAF] Plugin error: {e}")
                continue

    # 5. If still not blocked, evaluate ML last
    prediction_result = None
    if not blocked:
        ml_enabled = settings.get('ml_model', {}).get('enabled', True)
        confidence_threshold = settings.get('ml_model', {}).get('confidence_threshold', 0.7)
        if not ml_enabled:
            print("[WAF] ML is DISABLED - skipping ML evaluation")
        elif _text_predictor is None:
            print("[WAF] ML is ENABLED but model is unavailable - skipping ML evaluation")
        else:
            try:
                url_with_query = request.full_path if request.query_string else request.path
                body_params = []
                try:
                    if request.is_json:
                        body_params.append(request.get_data(as_text=True))
                    else:
                        body_params.append(request.get_data(as_text=True))
                except Exception:
                    pass
                threats, confidence_scores = _text_predictor.predict_request(url_with_query, body_params, dict(request.headers))
                class _TextPredictionResult:
                    def __init__(self, threats: dict, confidence_scores: dict):
                        self.threats = threats or {"valid": ""}
                        self.is_malicious = any(k != 'valid' for k in self.threats.keys())
                        if self.is_malicious:
                            malicious_confidences = [conf for threat, conf in confidence_scores.items() if threat != 'valid']
                            self.confidence = max(malicious_confidences) if malicious_confidences else 0.8
                        else:
                            self.confidence = confidence_scores.get('valid', 1.0)
                        self.features_used = {"mode": "text"}
                        self.confidence_scores = confidence_scores
                    def to_dict(self):
                        return {"threats": self.threats, "mode": "text", "confidence_scores": self.confidence_scores}
                prediction_result = _TextPredictionResult(threats, confidence_scores)
            except Exception as e:
                print(f"[WAF] ML evaluation error: {e}")

        if ml_enabled and prediction_result and prediction_result.is_malicious and (prediction_result.confidence >= confidence_threshold or getattr(prediction_result, 'features_used', {}).get('mode') == 'text'):
            blocked = True
            reason = "Blocked by ML model"
            print(f"[WAF] ML Decision: BLOCKED - Confidence: {prediction_result.confidence:.2f} (Threshold: {confidence_threshold})")
        else:
            if ml_enabled and prediction_result:
                print(f"[WAF] ML Decision: ALLOWED - Confidence: {prediction_result.confidence:.2f} (Threshold: {confidence_threshold})")

    # Log final decision with layer info
    decision = "BLOCKED" if blocked else "ALLOWED"
    layer = (
        "RULES" if str(reason).startswith("Rule: ") else
        "PLUGINS" if str(reason).startswith("Plugin: ") else
        "ML" if str(reason).startswith("Blocked by ML model") else
        "NONE"
    )
    print(f"[WAF] Final Decision: {decision} - Reason: {reason} (Layer: {layer})")
    print(f"[WAF] {'='*60}")
    
    mongo_logger.log(
        request,
        blocked=blocked,
        reason=reason,
        ml_prediction=prediction_result.to_dict() if prediction_result else None,
        is_plugin_blocked=is_plugin_blocked,
    
    )
    if blocked:
        abort(403)

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    return forward_to_backend(path)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)