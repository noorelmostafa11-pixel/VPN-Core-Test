param(
    [string]$Nodes = (Join-Path (Split-Path $PSScriptRoot -Parent) 'nodes\pre\protocols'),
    [ValidateRange(1,32)][int]$Concurrency = 8,
    [ValidateRange(0,100000)][int]$Limit = 0,
    [ValidateRange(1,120)][int]$TimeoutSeconds = 10,
    [string]$Url = 'https://example.com/',
    [ValidateRange(1,120)][int]$OutputDrainSeconds = 10,
    [string]$OutputDirectory = '',
    [switch]$InspectOnly
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Test-Batch.ps1') @PSBoundParameters
