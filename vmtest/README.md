# VM에서 실제 탐지 기능 테스트

AgentTrace가 실제로 동작하는지 확인하는 키트입니다. 두 가지로 나뉩니다.

- **호스트/VM 어디서나 바로**: 실행 전 관문 차단, 웜 복제 탐지, 역추적
- **VM(또는 Sysmon 설치) 필요**: OS 행동 주기적 수집(폴링), 실제 에이전트 훅 연동

> 제안서 §A대로 격리된 Windows 11 VM에서 테스트하세요. 시작 전 **스냅샷**을 찍어두면
> 끝나고 원상 복구하기 쉽습니다. 모든 페이로드는 무해합니다(표식 파일 생성, 네트워크 없음).

---

## 준비

VM에 이 저장소를 복사하거나 clone 한 뒤:

```
pip install -r requirements.txt
```

(실행파일만 쓰려면 Releases의 zip을 풀어도 됩니다. 단, 자가 테스트 스크립트는 소스가 필요합니다.)

---

## 1. 바로 확인 (Sysmon 불필요)

```
python vmtest\detection_selftest.py
```

확인 항목:
- 인코딩 PowerShell이 **실제 실행되기 전에 차단**되는가 (표식 파일이 안 생겨야 통과)
- 정상 명령은 허용되어 실제로 실행되는가
- 자동 실행 등록은 확인 요청으로 격상되는가
- 실제 파일(메일, 메모, 답장) 흐름에서 **웜 복제 2건 탐지 + 최초 감염원 역추적**

이 부분은 호스트에서도 통과합니다(관리자 권한 불필요).

---

## 2. Sysmon 주기적 수집(폴링) (관리자 권한)

관리자 PowerShell에서:

```
powershell -ExecutionPolicy Bypass -File vmtest\install_sysmon.ps1
powershell -ExecutionPolicy Bypass -File vmtest\trigger_safe_events.ps1
python vmtest\detection_selftest.py
```

이제 3번 항목(Sysmon 수집)이 SKIP에서 PASS로 바뀌고, 방금 만든 무해한 이벤트
(파일 생성 ID 11, 인코딩 PowerShell ID 1, 자동 실행 레지스트리 ID 13)가 수집됩니다.

대시보드로 보려면:

```
python -m agenttrace.monitor_app      # 트레이 상주 + 10초마다 Sysmon 수집
```

제거: `%TEMP%\agenttrace_sysmon\Sysmon64.exe -u`

---

## 3. 실제 에이전트(Claude Code) 연동

`vmtest\claude_hook.py` 를 PreToolUse 훅으로 등록하면, 에이전트가 도구를 실행하기
직전에 AgentTrace 관문이 판정합니다. `.claude\settings.json` 예:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Write|Edit",
        "hooks": [ { "type": "command",
                     "command": "python <저장소경로>\\vmtest\\claude_hook.py" } ] }
    ]
  }
}
```

등록 후 에이전트에게 위험한 명령(예: 인코딩된 PowerShell 실행)을 시키면 **실행 전에
막히고**, 그 판정이 대시보드 행동 기록에 남습니다.

---

## 끝나고

VM 스냅샷으로 복원하거나, Sysmon을 `-u`로 제거하세요. 호스트에서 돌렸다면 임시 폴더
(`%TEMP%\agenttrace_*`)만 지우면 됩니다.
