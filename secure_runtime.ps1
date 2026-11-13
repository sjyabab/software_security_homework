param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { throw 'Expected a directory' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# Run on the newly created runtime root before creating any secrets.
& icacls.exe $resolved /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict runtime ACL' }
