param([ValidateSet('auto','windows','linux','android')][string]$Target='auto',
      [ValidateSet('arm64-v8a','armeabi-v7a','x86_64','x86')][string]$Abi='arm64-v8a',
      [string]$Ndk=$env:ANDROID_NDK_HOME)
$arguments=@((Join-Path $PSScriptRoot 'scripts/Build.py'),'--target',$Target,'--abi',$Abi)
if ($Ndk) { $arguments+=@('--ndk',$Ndk) }
& python @arguments
if ($LASTEXITCODE -ne 0) { throw 'Core build failed.' }
