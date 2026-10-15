[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ZigPath,
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][string]$XsdkRoot,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$zig = (Resolve-Path -LiteralPath $ZigPath).Path
$python = (Resolve-Path -LiteralPath $PythonPath).Path
$sdk = (Resolve-Path -LiteralPath $XsdkRoot).Path
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path
$elf = Join-Path $output 'compiler_parser_smoke.elf'
$xex = Join-Path $output 'compiler_parser_smoke.xex'
if ((Test-Path -LiteralPath $elf) -or (Test-Path -LiteralPath $xex)) {
    throw 'Use a new output directory: existing build artifacts will not be overwritten.'
}
$source = Join-Path $projectRoot 'source'
$smoke = Join-Path $PSScriptRoot 'compiler_smoke.cpp'
$parser = Join-Path $source 'gip_gamepad_parser.cpp'
$linker = Join-Path $sdk 'src/xsdk.ld'
$packer = Join-Path $sdk 'tools/elf2xex.py'
# This compiles portable C++ only. The generic freestanding ABI is NOT an Xbox
# kernel ABI. Do not extend this target to call imports without ABI adapters.
# Separate compilation/link avoids a crash in Zig 0.14.1's multi-source PPC
# C++ driver observed on this host. O0 is intentional for this build-only test.
$objects = @()
foreach ($inputSource in @($smoke,$parser)) {
    $object = Join-Path $output (([IO.Path]::GetFileNameWithoutExtension($inputSource)) + '.o')
    & $zig cc -x c++ -target powerpc-freestanding-none -mcpu=970 -std=c++11 -O0 `
        -ffreestanding -fno-exceptions -fno-rtti -fno-stack-protector `
        -I $source -c $inputSource -o $object
    if ($LASTEXITCODE -ne 0) { throw "Portable PPC object build failed ($LASTEXITCODE)." }
    $objects += $object
}
& $zig cc -target powerpc-freestanding-none -nostdlib "-Wl,-T,$linker" `
    '-Wl,-e,xsdk_start' @objects -o $elf
if ($LASTEXITCODE -ne 0) { throw "Portable PowerPC link failed ($LASTEXITCODE)." }
& $python $packer $elf $xex
if ($LASTEXITCODE -ne 0) { throw 'XEX packaging failed.' }
Write-Output 'BUILD-ONLY: compiled portable parser and packed a title, NOT a DashLaunch plugin.'
Write-Output 'No imports; no Xbox kernel ABI, loader, runtime or hardware validation performed.'
Get-FileHash -LiteralPath $elf,$xex -Algorithm SHA256
