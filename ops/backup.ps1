param(
  [string]$Stamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
)
$ErrorActionPreference = 'Stop'
if ($Stamp -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw 'Stamp may contain only letters, digits, underscore, or hyphen.' }
$backupPath = Join-Path (Get-Location) 'backups'
New-Item -ItemType Directory -Force -Path $backupPath | Out-Null
$env:BACKUP_STAMP = $Stamp
docker compose -f compose.yml run --rm backup
if ($LASTEXITCODE -ne 0) { throw "Backup failed with exit code $LASTEXITCODE" }
Write-Output "Database and immutable object backup written under $backupPath with stamp $Stamp"

