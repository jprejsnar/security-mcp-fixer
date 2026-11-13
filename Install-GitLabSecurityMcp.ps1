[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string] $WheelPath,
    [string] $InstallDirectory = (Join-Path $env:USERPROFILE 'Tools\gitlab-security-mcp')
)

$ErrorActionPreference = 'Stop'
$wheelItem = Get-Item -LiteralPath $WheelPath
$wheel = $wheelItem.FullName
if ($wheelItem.PSIsContainer -or [IO.Path]::GetFileName($wheel) -notmatch '^gitlab_security_mcp-.+\.whl$') {
    throw 'Select a gitlab_security_mcp wheel file.'
}
$installRoot = [IO.Path]::GetFullPath($InstallDirectory)
$python = Join-Path $installRoot 'Scripts\python.exe'
$launcher = Join-Path $installRoot 'Scripts\gitlab-security-mcp.exe'

function Assert-LauncherAvailable {
    param([string] $LauncherPath)

    if (-not (Test-Path -LiteralPath $LauncherPath -PathType Leaf)) {
        return
    }
    try {
        $stream = [IO.File]::Open($LauncherPath, [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $stream.Dispose()
    }
    catch [IO.IOException] {
        $failure = $_.Exception
        while ($null -ne $failure.InnerException) {
            $failure = $failure.InnerException
        }
        if (($failure.HResult -band 0xFFFF) -in 32, 33) {
            Write-Host @"
Installation blocked: the GitLab security MCP server executable is in use.
Close ALL instances of VS Code and Cursor, including Agents/background windows.
Then rerun this installer from a standalone PowerShell window.
Locked file: $LauncherPath
No applications or servers were automatically terminated.
"@ -ForegroundColor Yellow
            throw 'Installation blocked. Close all VS Code/Cursor instances and retry.'
        }
        throw
    }
}

Assert-LauncherAvailable -LauncherPath $launcher
if (-not $PSCmdlet.ShouldProcess($installRoot, "Install or repair GitLab security MCP from $wheel")) {
    return
}

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    & py -3 -m venv $installRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Virtual environment creation failed (exit code $LASTEXITCODE)."
    }
}

& $python -m pip install --upgrade --force-reinstall $wheel
if ($LASTEXITCODE -ne 0) {
    $installExit = $LASTEXITCODE
    Assert-LauncherAvailable -LauncherPath $launcher
    throw "Installation failed (exit code $installExit). Review the pip error above. Close ALL VS Code and Cursor instances before retrying."
}
& $python -m pip check
if ($LASTEXITCODE -ne 0) {
    throw 'Installed dependencies failed pip check. Review the errors above; installation is not verified.'
}

$sitePackages = Join-Path $installRoot 'Lib\site-packages'
$leftovers = @(Get-ChildItem -LiteralPath $sitePackages -Directory |
    Where-Object { $_.Name -match '^~itlab[-_]security[-_]mcp(?:-.+\.dist-info)?$' })
if ($leftovers.Count -gt 0) {
    Write-Warning ("An interrupted earlier install left invalid distribution directories. " +
        "They were not deleted automatically: " + (($leftovers | ForEach-Object { $_.FullName }) -join ', '))
}
Write-Host 'Installation and dependency checks completed. Reopen VS Code/Cursor and start the MCP server.'
