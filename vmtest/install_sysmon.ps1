# AgentTrace VM 테스트: Sysmon 설치 (관리자 PowerShell에서 실행)
# Sysinternals Sysmon을 받아 ID 1(프로세스) 3(네트워크) 11(파일 생성) 13(레지스트리)을
# 기록하도록 설치한다. VM 안에서만 쓰세요. 스냅샷을 먼저 찍어두면 되돌리기 쉽습니다.

$ErrorActionPreference = "Stop"
$work = Join-Path $env:TEMP "agenttrace_sysmon"
New-Item -ItemType Directory -Force -Path $work | Out-Null

# 모든 관심 이벤트를 기록하는 최소 설정 (테스트용, 다소 시끄러움)
$config = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <NetworkConnect onmatch="exclude" />
    <FileCreate onmatch="exclude" />
    <RegistryEvent onmatch="exclude" />
  </EventFiltering>
</Sysmon>
'@
$cfgPath = Join-Path $work "sysmonconfig.xml"
# BOM 없는 UTF-8로 써야 Sysmon 매니페스트 설치가 실패하지 않는다.
[System.IO.File]::WriteAllText($cfgPath, $config)

Write-Host "Sysmon 내려받는 중..."
$zip = Join-Path $work "Sysmon.zip"
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $work -Force

$sysmon = Join-Path $work "Sysmon64.exe"
if (-not (Test-Path $sysmon)) { $sysmon = Join-Path $work "Sysmon.exe" }

Write-Host "Sysmon 설치 중 (관리자 권한 필요)..."
& $sysmon -accepteula -i $cfgPath

Write-Host ""
Write-Host "완료. 이제 vmtest\trigger_safe_events.ps1 로 무해한 이벤트를 만들고,"
Write-Host "python vmtest\detection_selftest.py 로 Sysmon 수집까지 확인하세요."
Write-Host "제거하려면:  $sysmon -u"
