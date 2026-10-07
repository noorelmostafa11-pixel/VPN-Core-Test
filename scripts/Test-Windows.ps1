param(
    [string]$Nodes = (Join-Path (Split-Path $PSScriptRoot -Parent) 'nodes\pre\protocols'),
    [ValidateRange(1,32)][int]$Concurrency = 8,
    [ValidateRange(0,100000)][int]$Limit = 0,
    [ValidateRange(5,120)][int]$TimeoutSeconds = 20,
    [string]$Url = 'https://example.com/',
    [string]$OutputDirectory = '',
    [switch]$InspectOnly
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Test-Batch.ps1') @PSBoundParameters
