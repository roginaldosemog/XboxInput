[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ZigPath,
    [Parameter(Mandatory=$true)][string]$IdaxexRoot,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$zig = (Resolve-Path -LiteralPath $ZigPath).Path
$root = (Resolve-Path -LiteralPath $IdaxexRoot).Path
$mspack = Join-Path $root '3rdparty/mspack'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path 'lzx_bridge.dll'
if (Test-Path -LiteralPath $output) { throw 'Existing analysis DLL will not be overwritten.' }
& $zig cc -O2 -shared -Wall -Wextra -I $mspack `
    (Join-Path $PSScriptRoot 'lzx_bridge.c') (Join-Path $mspack 'lzxd.c') `
    (Join-Path $mspack 'system.c') -o $output
if ($LASTEXITCODE -ne 0) { throw 'Analysis DLL compilation failed.' }
Get-FileHash -LiteralPath $output -Algorithm SHA256
