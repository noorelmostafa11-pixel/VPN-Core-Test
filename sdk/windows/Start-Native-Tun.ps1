param([string]$ConfigPath='.\node.ini',[int]$UplinkIndex=0,[switch]$Recover)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run Windows PowerShell as Administrator.'}
$runtime=$PSScriptRoot
if(-not (Test-Path (Join-Path $runtime 'vpn-native-tun.exe'))){$runtime=Join-Path $PSScriptRoot '..\..'}
$exe=(Resolve-Path (Join-Path $runtime 'vpn-native-tun.exe')).Path
if($Recover){& $exe --recover-network;if($LASTEXITCODE){throw 'Owned network recovery failed.'};exit 0}
$manifest=Get-Content (Join-Path $runtime 'build-hashes.json') -Raw | ConvertFrom-Json
foreach($entry in $manifest){$file=Join-Path $runtime $entry.file;if(-not (Test-Path $file)){throw ('Missing package file: '+$entry.file)};if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256){throw ('Package hash mismatch: '+$entry.file)}}
$cfg=(Resolve-Path -LiteralPath $ConfigPath).Path
if($UplinkIndex -eq 0){
    $route=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceAlias -notlike 'VpnCore*'} | Sort-Object RouteMetric | Select-Object -First 1
    if(-not $route){$route=Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceAlias -notlike 'VpnCore*'} | Sort-Object RouteMetric | Select-Object -First 1}
    if(-not $route){throw 'No underlying route found. Specify -UplinkIndex.'};$UplinkIndex=[int]$route.InterfaceIndex
}
$wintun=(Resolve-Path (Join-Path $runtime 'wintun.dll')).Path
Write-Host 'Starting experimental Native TUN. Press Ctrl+C to disconnect and restore owned settings.'
& $exe --config $cfg --wintun $wintun --uplink-index $UplinkIndex
if($LASTEXITCODE -ne 0){throw 'Native TUN failed. The kill switch may remain active. Run this script with -Recover to disconnect.'}
