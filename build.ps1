param([ValidateSet('auto','windows','linux','darwin','android','freebsd','openbsd')][string]$Target='auto',
 [string]$Arch='amd64',[string]$Abi='arm64-v8a',[string]$Ndk=$env:ANDROID_NDK_HOME,[switch]$Shared,[switch]$Wintun)
$arguments=@((Join-Path $PSScriptRoot 'scripts/Build-Go.py'),'--target',$Target,'--arch',$Arch,'--abi',$Abi)
if($Ndk){$arguments+=@('--ndk',$Ndk)}
if($Shared){$arguments+='--shared'}
if($Wintun){$arguments+='--wintun'}
& python @arguments
if($LASTEXITCODE -ne 0){throw 'Go core build failed.'}
