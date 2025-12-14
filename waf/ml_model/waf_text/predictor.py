import json, urllib.parse, joblib

class WafPredictor:
    def __init__(self, text_model_path: str, pt_model_path: str):
        self.clf = joblib.load(text_model_path)
        self.pt_clf = joblib.load(pt_model_path)

    def _unquote(self, text: str) -> str:
        k, prev = 0, text or ""
        while k < 100:
            nxt = urllib.parse.unquote_plus(prev)
            if nxt == prev:
                break
            prev = nxt
            k += 1
        return prev

    def _clean(self, s: str) -> str:
        s = self._unquote(s)
        s = s.strip().lower()
        return ' '.join(s.split())

    def predict_request(self, url_with_query: str, body_params: list[str], headers: dict) -> dict:
        # text model inputs
        text_params, locations = [], []
        if url_with_query:
            text_params.append(self._clean(url_with_query)); locations.append('Request')
        for b in body_params or []:
            if b:
                text_params.append(self._clean(str(b))); locations.append('Body')
        if headers.get('Cookie'):
            text_params.append(self._clean(headers['Cookie'])); locations.append('Cookie')
        if headers.get('User-Agent'):
            text_params.append(self._clean(headers['User-Agent'])); locations.append('User Agent')
        if headers.get('Accept-Encoding'):
            text_params.append(self._clean(headers['Accept-Encoding'])); locations.append('Accept Encoding')
        if headers.get('Accept-Language'):
            text_params.append(self._clean(headers['Accept-Language'])); locations.append('Accept Language')

        threats = {}
        confidence_scores = {}
        
        if text_params:
            # Use predict_proba instead of predict for probability scores
            try:
                probas = self.clf.predict_proba(text_params)
                preds = self.clf.predict(text_params)
                
                for i, (pred, proba) in enumerate(zip(preds, probas)):
                    if pred != 'valid':
                        threats[pred] = locations[i]
                        # Get confidence for the predicted class
                        pred_idx = list(self.clf.classes_).index(pred)
                        confidence_scores[pred] = proba[pred_idx]
            except AttributeError:
                # Fallback to binary prediction if predict_proba not available
                preds = self.clf.predict(text_params)
                for i, p in enumerate(preds):
                    if p != 'valid':
                        threats[p] = locations[i]
                        confidence_scores[p] = 0.8  # Default confidence for binary models

        # parameter-tampering on parsed values
        req_params = urllib.parse.parse_qs(self._clean(url_with_query or ""))
        body_kv = {}
        for b in body_params or []:
            try:
                body_kv = urllib.parse.parse_qs(self._clean(str(b)))
                if not body_kv:
                    body_kv = json.loads(self._clean(str(b)))
            except Exception:
                pass

        pt_X, pt_loc = [], []
        for _, vals in req_params.items():
            for v in vals:
                pt_X.append([len(v)]); pt_loc.append('Request')
        if isinstance(body_kv, dict):
            for _, vals in body_kv.items():
                if isinstance(vals, list):
                    for v in vals:
                        pt_X.append([len(v)]); pt_loc.append('Body')
                else:
                    pt_X.append([len(vals)]); pt_loc.append('Body')

        if pt_X:
            try:
                # Use predict_proba for parameter tampering model too
                pt_probas = self.pt_clf.predict_proba(pt_X)
                pt_preds = self.pt_clf.predict(pt_X)
                
                for i, (pred, proba) in enumerate(zip(pt_preds, pt_probas)):
                    if pred != 'valid':
                        threats[pred] = pt_loc[i]
                        # Get confidence for the predicted class
                        pred_idx = list(self.pt_clf.classes_).index(pred)
                        confidence_scores[pred] = proba[pred_idx]
            except AttributeError:
                # Fallback to binary prediction
                pt_preds = self.pt_clf.predict(pt_X)
                for i, p in enumerate(pt_preds):
                    if p != 'valid':
                        threats[p] = pt_loc[i]
                        confidence_scores[p] = 0.8  # Default confidence

        if not threats:
            threats['valid'] = ''
            confidence_scores['valid'] = 1.0
            
        return threats, confidence_scores