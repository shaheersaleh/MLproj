import yaml
from flask import request
import os
import re
import urllib.parse

class RuleEngine:
    def __init__(self, rules_file="rules.yaml"):
        rules_path = os.path.join(os.path.dirname(__file__), rules_file)
        with open(rules_path, encoding='utf-8') as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict) and "rules" in loaded:
                self.rules = loaded["rules"]
            else:
                self.rules = loaded

    def evaluate(self):
        path_full = (request.full_path or request.path) or ""
        query_string = request.query_string.decode("utf-8", errors="ignore") if request.query_string else ""
        body = request.get_data(as_text=True) or ""

        def variants(text: str):
            if not text:
                return []
            lower = text.lower()
            unquoted = urllib.parse.unquote_plus(lower)
            return [lower, unquoted]

        # Exclude headers to avoid false positives; include raw and URL-decoded lowercase variants
        haystacks = []
        for piece in [path_full, query_string, body]:
            haystacks.extend(variants(piece))

        for rule in self.rules or []:
            action = (rule.get("action") or "").lower()
            pattern = rule.get("pattern")
            if not pattern:
                continue
            # Only enforce block actions here; log-only rules are ignored for blocking
            if action != "block":
                continue
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            except re.error:
                # Skip invalid regex patterns
                continue
            for text in haystacks:
                if text and regex.search(text):
                    return rule.get("id")
        return None