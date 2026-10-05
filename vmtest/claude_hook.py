"""실제 에이전트 연동용 PreToolUse 훅 예제 (Claude Code).

Claude Code가 도구를 실행하기 직전에 이 훅을 부른다. 훅은 도구 호출을 AgentTrace
관문에 넘겨 allow/ask/block을 받고, block/ask면 종료코드 2로 실행을 막는다.
판정은 DB에 기록되므로 대시보드 행동 기록에서 바로 보인다.

settings.json 등록 예 (프로젝트 .claude/settings.json 또는 ~/.claude/settings.json):

  {
    "hooks": {
      "PreToolUse": [
        { "matcher": "Bash|Write|Edit",
          "hooks": [ { "type": "command",
                       "command": "python /경로/vmtest/claude_hook.py" } ] }
      ]
    }
  }

등록 후 에이전트에게 위험한 명령(예: 인코딩 PowerShell 실행)을 시키면 실행 전에 막힌다.
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agenttrace import Store, Monitor  # noqa: E402

DB = os.environ.get("AGENTTRACE_DB",
                    os.path.join(os.path.expanduser("~"), "AgentTrace", "agenttrace.db"))


def main():
    try:
        raw = sys.stdin.buffer.read().decode("utf-8-sig")   # BOM 허용
        data = json.loads(raw)
    except Exception:
        return 0
    tool = data.get("tool_name", "")
    ti = data.get("tool_input", {}) or {}

    if tool == "Bash":
        action, content = "exec", ti.get("command", "")
    elif tool in ("Write", "Edit"):
        action = "write"
        content = f"{ti.get('file_path','')} {ti.get('content', ti.get('new_string',''))}"
    else:
        return 0

    os.makedirs(os.path.dirname(DB), exist_ok=True)
    mon = Monitor(Store(DB))
    session = data.get("session_id", "claude-code")
    verdict, why = mon.guard_action(session, tool, action, content)
    mon.store.db.close()

    if verdict in ("block", "ask"):
        print(f"AgentTrace 관문: {verdict} ({why}). 실행을 막았습니다.", file=sys.stderr)
        return 2        # 종료코드 2 = 도구 실행 차단
    return 0


if __name__ == "__main__":
    sys.exit(main())
