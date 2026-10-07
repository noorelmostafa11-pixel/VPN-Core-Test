param([string]$Compiler='g++',[string]$CCompiler='gcc',[string]$Go='go')
$ErrorActionPreference='Stop'
$project=Split-Path $PSScriptRoot -Parent
& python (Join-Path $PSScriptRoot 'Build.py') --target windows --cxx $Compiler --cc $CCompiler --go $Go --output (Join-Path $project 'bin')
if ($LASTEXITCODE -ne 0) { throw 'Windows source build failed.' }
