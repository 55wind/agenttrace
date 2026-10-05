# AgentTrace VM 테스트: 무해한 OS 이벤트 생성 (Sysmon이 기록하도록)
# 실제 공격이 아니라, 탐지 파이프라인이 실제 OS 활동을 잡는지 보려는 안전한 표식이다.
# VM 안에서만 쓰세요.

$ErrorActionPreference = "Continue"
$tmp = Join-Path $env:TEMP "agenttrace_test"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

Write-Host "1) 파일 생성 이벤트(ID 11)"
New-Item -ItemType File -Force -Path (Join-Path $tmp "filecreate_test.txt") | Out-Null

Write-Host "2) 인코딩 PowerShell 프로세스(ID 1) - 무해한 Write-Host"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host AgentTraceTest"))
Start-Process -NoNewWindow -Wait powershell -ArgumentList "-EncodedCommand", $enc

Write-Host "3) 자동 실행 레지스트리(ID 13) - 추가 후 즉시 제거"
$run = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
New-ItemProperty -Path $run -Name "AgentTraceTest" -Value "C:\marker_not_real.exe" -PropertyType String -Force | Out-Null
Remove-ItemProperty -Path $run -Name "AgentTraceTest" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "완료. 이제 python vmtest\detection_selftest.py 를 실행하면 Sysmon 수집 항목이 PASS로 바뀝니다."
Write-Host "또는 python -c `"from agenttrace import Store, collector; s=Store('vm.db'); print('수집', collector.collect(s), '건')`""
