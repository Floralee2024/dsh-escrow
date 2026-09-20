Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$pkg = Get-Content -Raw -LiteralPath '.\package.json' | ConvertFrom-Json
$commit = (git rev-parse HEAD).Trim()
$branch = (git branch --show-current).Trim()

Write-Output "dsh-escrow paper artifact check"
Write-Output "version: $($pkg.version)"
Write-Output "branch: $branch"
Write-Output "commit: $commit"
Write-Output "node: $(& node --version)"
Write-Output "npm: $(& npm --version)"
Write-Output ""
Write-Output "Running npm run test:all ..."
npm run test:all

Write-Output ""
Write-Output "Artifact check complete."
