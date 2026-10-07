param([string]$Destination = (Join-Path (Split-Path $PSScriptRoot -Parent) 'nodes/pre/protocols'))
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
$manifest = Get-Content -Raw -LiteralPath (Join-Path $project 'docs/pre-source-manifest.json') | ConvertFrom-Json
$destinationPath = [IO.Path]::GetFullPath($Destination)
[void][IO.Directory]::CreateDirectory($destinationPath)
$stage = Join-Path $destinationPath ('download-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
$previousProtocol = [Net.ServicePointManager]::SecurityProtocol
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    foreach ($item in $manifest.files) {
        $url = 'https://raw.githubusercontent.com/'+$manifest.repository+'/'+$manifest.commit+'/output/protocols/'+$item.name
        $file = Join-Path $stage $item.name
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file -TimeoutSec 120
        if ((Get-Item -LiteralPath $file).Length -ne $item.bytes -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.sha256) { throw ('Pinned inventory checksum failed: '+$item.name) }
    }
    foreach ($item in $manifest.files) {
        $target = Join-Path $destinationPath $item.name
        if (Test-Path -LiteralPath $target) {
            if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -eq $item.sha256) { continue }
            Move-Item -LiteralPath $target -Destination ($target+'.preserved-'+[guid]::NewGuid().ToString('N'))
        }
        Move-Item -LiteralPath (Join-Path $stage $item.name) -Destination $target
    }
    Write-Host ('Pinned Pre inventory: '+(($manifest.files | Measure-Object nodes -Sum).Sum)+' nodes; '+$manifest.commit)
    Write-Host ('Saved: '+$destinationPath)
} finally {
    [Net.ServicePointManager]::SecurityProtocol=$previousProtocol
    Remove-Item -LiteralPath $stage -Recurse -Force
}
