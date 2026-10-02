# AgentTrace

내 PC의 AI 에이전트가 위험한 행동을 하기 전에 잡고(탐지·차단), 이미 퍼진 공격은 최초
감염원과 감염 범위까지 거슬러 올라가는(역추적) **개인용 로컬 보안 도구**의 시제품.

판정은 규칙·지문·그래프가 하고 LLM은 설명만 — **네트워크·LLM 없이 동작**합니다.

```bash
pip install -r requirements.txt
python demo.py          # 시나리오 S1~S5 재현
python -m pytest        # 자체 테스트 8종
```

- 기획 배경: [`에이전트_탐지_역추적_통합제안서.md`](에이전트_탐지_역추적_통합제안서.md)
- 사용 방법: [`docs/사용방법.md`](docs/사용방법.md)
- 기능 명세: [`docs/기능명세서.md`](docs/기능명세서.md)

## 구조

```
agenttrace/
  store.py        SQLite + 해시 체인 저장소 (변조 방지)
  fingerprint.py  정규화·SHA-256 지문·유사도·지시문 점수
  guard.py        실행 전 관문 (allow/ask/block)
  policy.yaml     판정 규칙
  engine.py       오염 추적·복제 탐지 (Monitor)
  trace.py        전파 그래프·역추적 (networkx)
  report.py       근거 기반 4단 보고
  collector.py    Sysmon 로그 수집 (wevtutil, ID 1·3·11·13)
  embedding.py    변형 웜 보완 유사도 (임베딩 선택 / stdlib 폴백)
  mcp_server.py   읽기 전용 MCP 서버 (공식 mcp SDK, stdio, 도구 4종)
demo.py           S1~S5 end-to-end
tests/            자체 테스트
```
