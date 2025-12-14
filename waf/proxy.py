from flask import Flask, request, abort, Response
import requests
import os
import importlib.util
from pymongo import MongoClient
from datetime import datetime
import joblib
import numpy as np
from database.mongodb_logger import MongoLogger
from ml_model.waf_text.predictor import WafPredictor



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

# Load mongodb logger
mongo_logger = MongoLogger()


class _TextPredictionResult:
    def __init__(self, threats: dict, confidence_scores: dict):
        self.threats = threats or {"valid": ""}
        # malicious if any label other than 'valid' exists
        self.is_malicious = any(k != 'valid' for k in self.threats.keys())
        # Use real confidence scores instead of hardcoded values
        if self.is_malicious:
            # Get the highest confidence among malicious threats
            malicious_confidences = [conf for threat, conf in confidence_scores.items() if threat != 'valid']
            self.confidence = max(malicious_confidences) if malicious_confidences else 0.8
        else:
            self.confidence = confidence_scores.get('valid', 1.0)
        self.features_used = {"mode": "text"}
        self.confidence_scores = confidence_scores

    def to_dict(self):
        return {"threats": self.threats, "mode": "text", "confidence_scores": self.confidence_scores}

def forward_to_backend(path):
    backend_url = f"http://localhost:8000/{path}"
    try:
        resp = requests.request(
            method=request.method,
            url=backend_url,
            headers={k: v for k, v in request.headers if k != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        return resp.content, resp.status_code, resp.headers.items()
    except requests.RequestException as e:
        error_message = f"Backend unreachable or error: {str(e)}"
        return Response(error_message, status=502)

# Example endpoint for WAF analysis (add to your Flask app)
app = Flask(__name__)

# Settings handling (shared with dashboard)
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'waf_settings.json')

def load_waf_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            import json
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {
        'ml_model': {
            'enabled': True,
            'confidence_threshold': 0.7
        }
    }

@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def waf_proxy(path):
    # Log request details
    print(f"[WAF-PROXY] Request: {request.method} {request.path} from {request.remote_addr}")
    print(f"[WAF-PROXY] User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
    print(f"[WAF-PROXY] Content-Type: {request.headers.get('Content-Type', 'None')}")
    
    # Prefer new text-based predictor if available; fallback to flow-based model
    prediction = None
    if _text_predictor is not None:
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
            prediction = _TextPredictionResult(threats, confidence_scores)
        except Exception as e:
            pass  # Text predictor failed, using flow model

    if prediction is None:
        # Extract features using FeatureExtractor
        request_data = {
            "url": request.path,
            "method": request.method,
            "remote_addr": request.remote_addr,
            "headers": dict(request.headers),
            "body": request.get_data(as_text=True)
        }
       
        
        # Create a simple prediction result with extracted features
        class _FeaturePredictionResult:
            def __init__(self, features: dict):
                self.features_used = features
                # For now, use a simple heuristic based on flow duration
                # You can integrate with your predictor here
                self.is_malicious = features.get("Flow Duration", 1.0) > 10.0  # Simple heuristic
                self.confidence = 0.5 if self.is_malicious else 0.1
            def to_dict(self):
                return {"features": self.features_used, "mode": "flow"}
        
       

    # Apply ML settings: only block if ML is enabled and confidence >= threshold
    settings = load_waf_settings()
    ml_enabled = settings.get('ml_model', {}).get('enabled', True)
    confidence_threshold = settings.get('ml_model', {}).get('confidence_threshold', 0.7)

    # Log ML status and prediction result
    if not ml_enabled:
        print("[WAF-PROXY] ML is DISABLED - skipping ML evaluation")
    else:
        if prediction.is_malicious:
            print(f"[WAF-PROXY] ML Decision: BLOCKED - Confidence: {prediction.confidence:.2f} (Threshold: {confidence_threshold})")
        else:
            print(f"[WAF-PROXY] ML Decision: ALLOWED - Confidence: {prediction.confidence:.2f} (Threshold: {confidence_threshold})")

    if ml_enabled and prediction.is_malicious and (prediction.confidence >= confidence_threshold or isinstance(prediction, _TextPredictionResult)):
        print(f"[WAF-PROXY] Final Decision: BLOCKED - Reason: ML malicious (Layer: ML)")
        print(f"[WAF-PROXY] {'='*60}")
        mongo_logger.log(request, blocked=True, reason="ML malicious", ml_prediction=prediction.to_dict(), features=getattr(prediction, 'features_used', {}))
        return Response("Blocked by WAF (ML detected attack)", status=403)

    # Log allowed requests as well
    print(f"[WAF-PROXY] Final Decision: ALLOWED - Reason: Passed all checks (Layer: None)")
    print(f"[WAF-PROXY] {'='*60}")
    mongo_logger.log(request, blocked=False, ml_prediction=prediction.to_dict(), features=getattr(prediction, 'features_used', {}))
    # Forward to backend
    content, status, headers = forward_to_backend(path)
    return Response(content, status=status, headers=dict(headers))