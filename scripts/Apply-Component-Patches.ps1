$ErrorActionPreference = 'Stop'
$root = Join-Path (Split-Path $PSScriptRoot -Parent) 'tls-provider'
foreach ($item in (Get-Content -Raw -LiteralPath (Join-Path $root 'component-patches/manifest.json') | ConvertFrom-Json)) {
    $target = Join-Path $root $item.path
    $digest = $null
    if (Test-Path -LiteralPath $target) { $digest = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() }
    if ($digest -eq $item.patched_sha256) { continue }
    if ($digest -ne $item.original_sha256) { throw ('Component source changed: '+$item.path) }
    $replacement = Join-Path (Join-Path $root 'component-patches') $item.replacement
    if ((Get-FileHash -LiteralPath $replacement -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.patched_sha256) { throw 'Component patch checksum mismatch.' }
    [IO.File]::WriteAllBytes($target,[IO.File]::ReadAllBytes($replacement))
}
Write-Host 'TLS/HTTP component patches verified.'
