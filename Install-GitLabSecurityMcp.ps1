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

function Assert-PowerShell7Installed {
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        return
    }
    $command = Get-Command -Name pwsh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command) {
        throw ('Installation blocked: PowerShell 7 (pwsh) is not installed. ' +
            'Install PowerShell 7, then rerun this installer. ' +
            'Windows PowerShell 5.1 can start this script, but it does not satisfy this prerequisite.')
    }
    $reported = @( & $command.Source -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()' )
    $versionText = [string]$reported[0]
    $parsed = [version]'0.0'
    if ($LASTEXITCODE -ne 0 -or
        -not [version]::TryParse($versionText.Trim(), [ref]$parsed) -or
        $parsed.Major -lt 7) {
        throw "Installation blocked: $($command.Source) is not PowerShell 7 or newer."
    }
}

function Get-PythonVersion {
    param(
        [string] $Executable,
        [string[]] $PrefixArguments
    )

    $output = @( & $Executable @PrefixArguments -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" )
    if ($LASTEXITCODE -ne 0 -or $output.Count -eq 0) {
        return $null
    }
    $parsed = [version]'0.0'
    if (-not [version]::TryParse(([string]$output[-1]).Trim(), [ref]$parsed)) {
        return $null
    }
    return $parsed
}

function Assert-Python311Installed {
    param([string] $ExistingPython)

    $missing = ('Installation blocked: Python 3.11 or newer is not installed. ' +
        'Install Python 3.11 or newer from python.org, including the py launcher and pip, ' +
        'then rerun this installer.')
    if (Test-Path -LiteralPath $ExistingPython -PathType Leaf) {
        $version = Get-PythonVersion -Executable $ExistingPython -PrefixArguments @()
        if ($null -eq $version -or $version -lt [version]'3.11.0') {
            throw "Installation blocked: $ExistingPython is not Python 3.11 or newer."
        }
        $null = & $ExistingPython -m pip --version
        if ($LASTEXITCODE -ne 0) {
            throw "Installation blocked: pip is not available in $ExistingPython."
        }
        return
    }
    $launcher = Get-Command -Name py -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $launcher) {
        throw $missing
    }
    $version = Get-PythonVersion -Executable $launcher.Source -PrefixArguments @('-3')
    if ($null -eq $version -or $version -lt [version]'3.11.0') {
        throw $missing
    }
    $null = & $launcher.Source -3 -c 'import venv, ensurepip'
    if ($LASTEXITCODE -ne 0) {
        throw ('Installation blocked: Python 3.11 or newer is installed, but venv or pip is unavailable. ' +
            'Reinstall Python with those features, then rerun this installer.')
    }
}

function Assert-GitInstalled {
    $command = Get-Command -Name git -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command) {
        throw ('Installation blocked: Git is not installed. ' +
            'Install Git, then rerun this installer.')
    }
    $null = & $command.Source --version
    if ($LASTEXITCODE -ne 0) {
        throw "Installation blocked: Git at $($command.Source) did not run."
    }
}

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

Assert-PowerShell7Installed
Assert-Python311Installed -ExistingPython $python
Assert-GitInstalled
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
