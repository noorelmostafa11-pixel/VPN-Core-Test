param([string]$Binary,[string]$Output)
$ErrorActionPreference='Stop'
$cases=Get-Content -LiteralPath (Join-Path $Output 'cases.json') -Raw|ConvertFrom-Json
$launcher=Join-Path (Split-Path $Binary -Parent) 'Run-Native-Tunnel.ps1'
if(!(Test-Path -LiteralPath $launcher)){throw 'Acceptance requires the packaged native launcher beside the binary.'}
foreach($case in $cases){
 if(Test-Path -LiteralPath (Join-Path $case.Directory 'stop')){continue}
 try{& $launcher -Config $case.Config -Binary $Binary -StateFile (Join-Path $case.Directory 'network-state.json') -Exchange $case.Directory}
 catch{$_|Out-File -LiteralPath (Join-Path $case.Directory 'worker-error.log') -Encoding UTF8;exit 1}
}
