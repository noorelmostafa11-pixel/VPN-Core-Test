param([string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'node.ini'))
$ErrorActionPreference = 'Stop'
$path = [IO.Path]::GetFullPath($ConfigPath)
if (Test-Path -LiteralPath $path) { throw 'Config already exists. Edit it locally or choose a new ConfigPath.' }
if (-not (Test-Path -LiteralPath (Split-Path $path -Parent))) { throw 'Destination directory does not exist.' }

Write-Host 'Paste a VLESS, Trojan, VMess or Shadowsocks node URI. Input is hidden; it is saved in your local config.'
$secret = Read-Host 'Node URI' -AsSecureString
$pointer = [IntPtr]::Zero
$stream = $null
$created = $false
try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    $uri = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($uri) -or $uri.Length -gt 65536 -or $uri.Contains("`r") -or $uri.Contains("`n")) {
        throw 'Expected one node URI on one line.'
    }
    # Set permissions on an empty file before writing the credential.
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $created = $true
    $stream.Dispose()
    $stream = $null
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($identity.User, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl
    $text = "node_uri=$uri`r`nlisten_port=1080`r`nconnect_timeout_ms=10000`r`nidle_timeout_ms=60000`r`nmax_connections=32`r`n"
    [IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding -ArgumentList $false))
    Write-Host 'Config saved. The file contains your credential; keep it private.'
} catch {
    if ($stream) { $stream.Dispose(); $stream = $null }
    if ($created -and (Test-Path -LiteralPath $path)) { Remove-Item -LiteralPath $path -Force }
    throw
} finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $uri = $null
    $text = $null
    $secret.Dispose()
}

$binary = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\vpn-core.exe'
if (Test-Path -LiteralPath $binary) {
    & $binary --config $path --check-config
    if ($LASTEXITCODE -ne 0) { throw 'Config was saved, but this node uses options unsupported by this build. Review the displayed error.' }
}
