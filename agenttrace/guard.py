"""The execution gate: judge an agent action BEFORE it runs.

A coding-agent PreToolUse hook calls Guard.evaluate() and honors the verdict
(allow / ask / block). The judgment is pure rules + taint state — no LLM — so
it still works when the model or network is down (success criterion 8).
"""
import os
import re
import yaml

_POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.yaml")
# 사용자가 대시보드 '막기'로 추가한 차단 목록(줄 단위 부분 문자열). 런타임마다 읽는다.
BLOCKLIST = os.path.join(os.path.expanduser("~"), "AgentTrace", "blocklist.txt")


def _user_blocked(content):
    try:
        for line in open(BLOCKLIST, encoding="utf-8"):
            s = line.strip()
            if s and s in (content or ""):
                return s
    except FileNotFoundError:
        pass
    return None


class Guard:
    def __init__(self, policy_path=_POLICY_PATH):
        with open(policy_path, encoding="utf-8") as f:
            p = yaml.safe_load(f)
        self.rules = p["rules"]
        self.escalate = set(p.get("tainted_escalate", []))

    def evaluate(self, action, content, tainted=False):
        """action: exec|write|send|autorun. content: command/path/body text.
        Returns (verdict, reason). verdict in {allow, ask, block}."""
        hit = _user_blocked(content)
        if hit:
            return "block", "user-blocklist"       # 사용자가 직접 막은 명령
        for rule in self.rules:
            if rule["action"] not in ("*", action):
                continue
            if re.search(rule["pattern"], content or "", re.I):
                verdict = rule["verdict"]
                if verdict != "block" and tainted and action in self.escalate:
                    return "ask", f"{rule['name']}, 오염 세션이라 확인으로 격상"
                return verdict, rule["name"]
        # no rule matched: escalate a tainted high-risk action, else allow
        if tainted and action in self.escalate:
            return "ask", "오염 세션의 고위험 행동이라 확인 요청"
        return "allow", "정책상 허용"
