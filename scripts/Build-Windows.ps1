& python (Join-Path $PSScriptRoot 'Build-Go.py') --target windows @args
if($LASTEXITCODE -ne 0){throw 'Go build failed'}
