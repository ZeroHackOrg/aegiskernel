import json
import re
from pathlib import Path

class PolicyEngine:
    def __init__(self, policy_path=None):
        if policy_path is None:
            policy_path = Path(__file__).resolve().parent / "policy.json"
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                self.policy = json.load(f)
        except Exception:
            self.policy = {"default_action": "allow", "rules": []}

    def evaluate(self, event):
        """
        Evaluate an event dictionary (comm, filename, uid, pid, syscall) against rules.
        Returns ('allow', None), ('alert', rule_id), or ('terminate', rule_id).
        """
        path = event.get("filename", "")
        comm = event.get("comm", "")
        
        for rule in self.policy.get("rules", []):
            pattern = rule.get("path_pattern")
            if pattern and path:
                if re.search(pattern, path):
                    return rule.get("action", "alert"), rule.get("id")
            # Check suspicious comm matching
            if comm in ["malicious_agent", "reverse_shell", "netcat"]:
                return "terminate", "AEGIS-COMM-00X"
                
        return self.policy.get("default_action", "allow"), None
