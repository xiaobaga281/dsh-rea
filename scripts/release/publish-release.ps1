# Publish dsh-rea from a machine that can reach github.com.
#
#   $env:GH_TOKEN = 'ghp_...'      # repo scope
#   pwsh -File scripts/release/publish-release.ps1 -Version 1.11.0
#
# Steps: push main, create the GitHub release for the tag, upload the tarball
# built by `npm run pack`. The token is only ever read from the environment and
# is never written into .git/config or printed.

param(
  [Parameter(Mandatory = $false)][string]$Version = ((Get-Content (Join-Path $PSScriptRoot '..' '..' 'package.json') -Raw | ConvertFrom-Json).version),
  [Parameter(Mandatory = $false)][string]$Token = $env:GH_TOKEN,
  [string]$Owner = 'xiaobaga281',
  [string]$Repo = 'dsh-rea'
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..' '..')
Set-Location $root

if (-not $Token) { throw 'set GH_TOKEN (or pass -Token) with a repo-scoped token' }
if ($Token -notmatch '^(ghp|github_pat)_') { throw 'GH_TOKEN does not look like a GitHub token' }

$tag = "v$Version"
$asset = Join-Path $root 'dist' "dsh-rea-$Version.tgz"
if (-not (Test-Path $asset)) { throw "missing $asset; run 'npm run pack' first" }

$sha = (Get-FileHash $asset -Algorithm SHA256).Hash.ToLower()
$manifest = Get-Content (Join-Path $root 'update.json') -Raw | ConvertFrom-Json
if ($manifest.version -ne $Version) { throw "update.json is $($manifest.version), expected $Version; run 'npm run manifest'" }
if ($manifest.sha256 -ne $sha) { throw 'update.json digest does not match the tarball; rerun npm run manifest' }

$safe = "https://x-access-token:$Token@github.com/$Owner/$Repo.git"
$env:GIT_TERMINAL_PROMPT = '0'
Write-Host "pushing main -> $Owner/$Repo"
git push $safe main
if ($LASTEXITCODE -ne 0) { throw 'git push failed' }

$headers = @{ Authorization = "token $Token"; 'User-Agent' = 'dsh-rea-release' }
$body = @{
  tag_name         = $tag
  target_commitish = 'main'
  name             = $tag
  body             = "dsh-rea $Version`n`nSee reports/duel-2026-11-06/RED-BLUE-REPORT.md for the changes in this release."
} | ConvertTo-Json

$release = $null
try {
  $release = Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$Owner/$Repo/releases" -Headers $headers -ContentType 'application/json' -Body $body
} catch {
  $status = $_.Exception.Response.StatusCode.value__
  if ($status -ne 422) { throw }
  # 422 = the tag already has a release; reuse it instead of failing the upload.
  $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases/tags/$tag" -Headers $headers
  Write-Host "release $tag already exists; uploading to it"
}
Write-Host "release $tag -> $($release.html_url)"

$upload = "https://uploads.github.com/repos/$Owner/$Repo/releases/$($release.id)/assets?name=dsh-rea-$Version.tgz"
$result = Invoke-RestMethod -Method Post -Uri $upload -Headers $headers -ContentType 'application/octet-stream' -InFile $asset
Write-Host "asset -> $($result.browser_download_url) ($([math]::Round($result.size / 1MB, 1)) MB)"
Write-Host "sha256 $sha"
