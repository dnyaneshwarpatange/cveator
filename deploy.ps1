param([switch]$Production, [switch]$NoBuild, [switch]$Demo)
$ErrorActionPreference = 'Stop'
$deployArgs = @((Join-Path $PSScriptRoot 'scripts/deploy.py'))
if ($Production) { $deployArgs += '--production' }
if ($NoBuild) { $deployArgs += '--no-build' }
if ($Demo) { $deployArgs += '--demo' }
& python @deployArgs
exit $LASTEXITCODE
