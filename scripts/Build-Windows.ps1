param([string]$Compiler = 'g++',[string]$CCompiler = 'gcc',[string]$Go = 'go')
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
$goVersion = & $Go version
if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '^go version go1\.27\.1 windows/amd64$') { throw 'Use the pinned Go 1.27.1 Windows amd64 toolchain.' }
& (Join-Path $PSScriptRoot 'Apply-Component-Patches.ps1')
$bin = Join-Path $project 'bin'
$stage = Join-Path $bin ('build-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
$names = @('CGO_ENABLED','GOOS','GOARCH','CC','GOTOOLCHAIN','GOWORK')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
try {
    $env:CGO_ENABLED='1';$env:GOOS='windows';$env:GOARCH='amd64';$env:CC=$CCompiler;$env:GOTOOLCHAIN='local';$env:GOWORK='off'
    Push-Location (Join-Path $project 'tls-provider')
    try {
        & $Go build -mod=vendor -buildvcs=false -buildmode=c-shared -trimpath -ldflags=-s -o (Join-Path $stage 'vpn-tls.dll') .
        if ($LASTEXITCODE -ne 0) { throw 'TLS/HTTP component build failed.' }
    } finally { Pop-Location }
    & $Compiler -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror -Wno-misleading-indentation -D_WIN32_WINNT=0x0A00 -municode -static -static-libgcc -static-libstdc++ (Join-Path $project 'src/main.cpp') -o (Join-Path $stage 'vpn-core.exe') -lws2_32 -lsecur32 -lcrypt32 -lbcrypt -pthread
    if ($LASTEXITCODE -ne 0) { throw 'Core build failed.' }
    & (Join-Path $stage 'vpn-core.exe') --self-test
    if ($LASTEXITCODE -ne 0) { throw 'Protocol self-test failed.' }
    & (Join-Path $stage 'vpn-core.exe') --check-components
    if ($LASTEXITCODE -ne 0) { throw 'Component ABI validation failed.' }
    foreach ($file in @('vpn-tls.dll','vpn-tls.h','vpn-core.exe')) { Copy-Item -LiteralPath (Join-Path $stage $file) -Destination (Join-Path $bin $file) -Force }
    $hashes = @('vpn-core.exe','vpn-tls.dll') | ForEach-Object { [ordered]@{file=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $bin $_) -Algorithm SHA256).Hash.ToLowerInvariant()} }
    $hashes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $bin 'build-hashes.json') -Encoding UTF8
    Remove-Item -LiteralPath $stage -Recurse -Force
    Write-Host 'Built and checked: bin/vpn-core.exe + bin/vpn-tls.dll (0.4.2).'
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$previous[$name],'Process') }
}
