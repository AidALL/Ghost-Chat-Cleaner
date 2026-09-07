[CmdletBinding()]
param(
    [string]$BinaryPath,
    [string]$OutputDirectory,
    [ValidateSet('x86_64', 'aarch64')]
    [string]$Architecture
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $BinaryPath) {
    $BinaryPath = Join-Path $ProjectRoot 'target/release/ghost-chat-cleaner.exe'
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $ProjectRoot 'dist'
}
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Release binary is missing: $BinaryPath. Run cargo build --locked --release first."
}
if (-not $Architecture) {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { $Architecture = 'x86_64' }
        'ARM64' { $Architecture = 'aarch64' }
        default { throw 'Specify -Architecture x86_64 or aarch64 for the built binary.' }
    }
}
$FontLicense = Join-Path $ProjectRoot 'assets/fonts/nanumgothic/OFL.txt'
$FontProvenance = Join-Path $ProjectRoot 'assets/fonts/nanumgothic/PROVENANCE.md'
foreach ($Document in @($FontLicense, $FontProvenance)) {
    if (-not (Test-Path -LiteralPath $Document -PathType Leaf)) {
        throw "Required font notice missing: $Document"
    }
}
$Manifest = Get-Content -LiteralPath (Join-Path $ProjectRoot 'Cargo.toml')
$VersionMatch = $Manifest | Select-String -Pattern '^version = "([0-9]+\.[0-9]+\.[0-9]+)"$' | Select-Object -First 1
if (-not $VersionMatch) {
    throw 'Expected a numeric release version in Cargo.toml.'
}
$Version = $VersionMatch.Matches[0].Groups[1].Value
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$Package = "ghost-chat-cleaner-$Version-windows-$Architecture"
$Archive = Join-Path $OutputDirectory "$Package.zip"
if (Test-Path -LiteralPath $Archive) {
    throw "Archive already exists: $Archive"
}
$Stage = Join-Path ([System.IO.Path]::GetTempPath()) ("ghost-chat-cleaner-" + [Guid]::NewGuid().ToString('N'))
try {
    $PackageDirectory = Join-Path $Stage $Package
    $null = New-Item -ItemType Directory -Path $PackageDirectory
    Copy-Item -LiteralPath $BinaryPath -Destination (Join-Path $PackageDirectory 'ghost-chat-cleaner.exe')
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'README.md'), (Join-Path $ProjectRoot 'README.ko.md'), (Join-Path $ProjectRoot 'LICENSE') -Destination $PackageDirectory
    & python (Join-Path $ProjectRoot 'scripts/generate-notices.py') --target "$Architecture-pc-windows-msvc" --output (Join-Path $PackageDirectory 'THIRD_PARTY_NOTICES.txt')
    if ($LASTEXITCODE -ne 0) {
        throw 'Third-party notice generation failed.'
    }
    $FontNoticeDirectory = Join-Path $PackageDirectory 'licenses/nanumgothic'
    $null = New-Item -ItemType Directory -Path $FontNoticeDirectory
    Copy-Item -LiteralPath $FontLicense, $FontProvenance -Destination $FontNoticeDirectory
    $StagingArchive = Join-Path $Stage 'package.zip'
    Compress-Archive -LiteralPath $PackageDirectory -DestinationPath $StagingArchive
    Move-Item -LiteralPath $StagingArchive -Destination $Archive
    Write-Output $Archive
}
finally {
    if (Test-Path -LiteralPath $Stage) {
        Remove-Item -LiteralPath $Stage -Recurse -Force
    }
}
