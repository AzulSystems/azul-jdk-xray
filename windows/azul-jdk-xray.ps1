# Azul JDK X-Ray Tool for Windows.
# Version 1.0.0
# Run:  powershell -ExecutionPolicy Bypass -File azul-jdk-xray.ps1
# Exit: 0 - no exposure found | 1 - outdated Java found | 2 - undetermined | 3 no Java found

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ---- VERSION TABLE ----
# Key = feature release, Value = minimum acceptable patch level.
# A patch level may carry a CSPU revision: '12.1' means 21.0.12.1, which ranks
# above 21.0.12. OpenJDK ships CSPUs between quarterly CPUs, so this table
# goes stale monthly, not quarterly.
$TableSource = 'August 2026 CSPU (2026-08-18); JDK 27 GA (2026-09-15)'
$TableDate   = '2026-09-15'   # newest date in TableSource; shown in the banner
$NextUpdate  = '2026-10-20 (October CPU)'
$MinPatch    = @{ 8 = '503'; 11 = '32.1'; 17 = '20.1'; 21 = '12.1'
                  25 = '4.1'; 26 = '2.1'; 27 = '0' }
# ------------------------------------------------------------

$NewestKnown  = ($MinPatch.Keys | Measure-Object -Maximum).Maximum
$KnownDepth   = 5        # depth limit for the standard-location pass
$MaxDirs      = 400000   # backstop against a pathological filesystem

$XRayVersion   = '1.0.0'   # keep in step with the Version line at the top
$AzulContact   = 'https://www.azul.com/contact/'
$AzulDownloads = 'https://www.azul.com/downloads/'

# Color only when writing to a console. NO_COLOR (https://no-color.org)
# turns it off, so redirected and logged output stays plain text.
$UseColor = (-not $env:NO_COLOR) -and (-not [Console]::IsOutputRedirected)

function Write-Out([string]$m, [string]$fg) {
    if ($UseColor -and $fg) { Write-Host $m -ForegroundColor $fg } else { Write-Host $m }
}
# A colored label, or [LABEL] when plain.
function Write-Badge([string]$bg, [string]$fg, [string]$label, [string]$headline) {
    if ($UseColor) {
        Write-Host " $label " -BackgroundColor $bg -ForegroundColor $fg -NoNewline
        Write-Host "  $headline"
    } else { Write-Host "[$label]  $headline" }
}
# One aligned line per next step.
function Write-Link([string]$label, [string]$url) {
    Write-Host ('  {0,-38} ' -f $label) -NoNewline
    Write-Out $url 'Cyan'
}

$script:Vuln     = $false  # set once an outdated JDK is found; stops the scan
$script:Problems = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
$script:Seen     = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
$script:DirCount = 0


# --- identifying Java --------------------------------------------------------

# True if the directory is a real Java home
function Test-JavaRoot([string]$Path) {
    if (Test-Path -LiteralPath (Join-Path $Path 'bin\java.exe') -PathType Leaf) { return $true }
    $rel = Join-Path $Path 'release'
    return ((Test-Path -LiteralPath $rel -PathType Leaf) -and
            (Select-String -LiteralPath $rel -Pattern '^JAVA_VERSION' -Quiet))
}

# True if the directory holds Java files at all, complete or not.
function Test-JavaDirectory([string]$Path) {
    if (Test-JavaRoot $Path) { return $true }
    foreach ($m in 'lib\rt.jar', 'lib\modules',
                   'bin\server\jvm.dll', 'bin\client\jvm.dll', 'bin\jvm.dll') {
        if (Test-Path -LiteralPath (Join-Path $Path $m) -PathType Leaf) { return $true }
    }
    return $false
}

# Read the version out of jvm.dll's embedded VM string.
function Read-JvmDllVersion([string]$JavaHome) {
    foreach ($rel in 'bin\server\jvm.dll', 'bin\client\jvm.dll',
                     'jre\bin\server\jvm.dll', 'jre\bin\client\jvm.dll') {
        $dll = Join-Path $JavaHome $rel
        if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) { continue }
        try {
            $text = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($dll))
        } catch { continue }
        if ($text -match '(?:OpenJDK|GraalVM|Java HotSpot)[^\(\r\n]*VM \(([^\)\r\n]+)\)') {
            $v = $Matches[1]
            # Legacy HotSpot numbering: 25.302-b08 is Java 8u302, 24.x is 7.
            if ($v -match '^25\.(\d+)-b') { return "1.8.0_$($Matches[1])" }
            if ($v -match '^24\.(\d+)-b') { return "1.7.0_$($Matches[1])" }
            return ($v -split '\+')[0]
        }
    }
    return $null
}

# Version from java.exe's PE resource.
function Read-PEVersion([string]$JavaHome) {
    $exe = Join-Path $JavaHome 'bin\java.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $null }
    try { $fv = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion } catch { return $null }
    if ($fv -match '^(\d+)\.(\d+)\.(\d+)' -and [int]$Matches[1] -ge 9) {
        return "$($Matches[1]).$($Matches[2]).$($Matches[3])"
    }
    return $null
}

# Get the Java version.
function Read-JavaVersion([string]$JavaHome) {
    $release = Join-Path $JavaHome 'release'
    if (Test-Path -LiteralPath $release -PathType Leaf) {
        $lines   = Get-Content -LiteralPath $release -ErrorAction SilentlyContinue
        $version = ($lines | Where-Object { $_ -match '^JAVA_VERSION\s*=' } |
                    Select-Object -First 1) -replace '^JAVA_VERSION\s*=\s*"?([^"]*)"?.*$', '$1'
        $vendor  = ($lines | Where-Object { $_ -match '^IMPLEMENTOR\s*=' } |
                    Select-Object -First 1) -replace '^IMPLEMENTOR\s*=\s*"?([^"]*)"?.*$', '$1'
        if ($version) {
            if (-not $vendor) { $vendor = 'unknown' }
            return @{ Version = $version.Trim(); Vendor = $vendor.Trim() }
        }
    }

    $v = Read-JvmDllVersion $JavaHome
    if ($v) { return @{ Version = $v; Vendor = 'unknown (read from jvm.dll)' } }

    $v = Read-PEVersion $JavaHome
    if ($v) { return @{ Version = $v; Vendor = 'unknown (read from PE resource)' } }

    # java writes -version output to stderr, so redirect and flatten to text.
    $exe = Join-Path $JavaHome 'bin\java.exe'
    if (Test-Path -LiteralPath $exe -PathType Leaf) {
        $out = (& $exe -version 2>&1 | Out-String)
        # Match the 'version "X"' line specifically: a set JAVA_TOOL_OPTIONS or
        # _JAVA_OPTIONS prints a "Picked up ..." banner ahead of it.
        if ($out -match 'version "([^"]+)"') {
            return @{ Version = $Matches[1]; Vendor = 'unknown (read from java -version)' }
        }
    }

    if ((Split-Path -Leaf $JavaHome) -match '(1\.[4-8]\.0_\d+)') {
        return @{ Version = $Matches[1]; Vendor = 'unknown (version inferred from path)' }
    }
    return $null
}

# Last resort: Major version from the directory name.
function Get-InferredFeature([string]$JavaHome) {
    $leaf = Split-Path -Leaf $JavaHome
    if ($leaf -match '1\.(\d)\.0')                   { return $Matches[1] }
    if ($leaf -match '[A-Za-z_-](\d{1,2})([.\-]|$)') { return $Matches[1] }
    if ($leaf -match '^(\d{1,2})([.\-]|$)')          { return $Matches[1] }
    return $null
}

# Split a version string into feature release and patch level.
# Handles: 1.8.0_502 | 21.0.12 | 21.0.12+7 | 21.0.12.11.1 | 25
# '12.1' -> 12001, '12' -> 12000, so a CSPU revision ranks above the CPU it
# patches.
function Get-VNum([string]$PatchLevel) {
    $parts = $PatchLevel -split '\.'
    $p = [int]$parts[0]
    $s = if ($parts.Count -gt 1) { [int]$parts[1] } else { 0 }
    return ($p * 1000 + $s)
}

function ConvertFrom-JavaVersion([string]$Version) {
    $v = ($Version -split '[+\-]')[0].Trim()
    if ($v -match '^1\.(\d)\.0_(\d+)$')   { return @{ Feature = [int]$Matches[1]; Patch = [int]$Matches[2]; Sub = 0 } }
    if ($v -match '^1\.(\d)(\.|$)')       { return @{ Feature = [int]$Matches[1]; Patch = 0; Sub = 0 } }
    # Five or more components are vendor build numbers appended to the OpenJDK
    # patch (Corretto 21.0.12.9.1), not a CSPU revision.
    if ($v -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)\.') { return @{ Feature = [int]$Matches[1]; Patch = [int]$Matches[3]; Sub = 0 } }
    if ($v -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)$')  { return @{ Feature = [int]$Matches[1]; Patch = [int]$Matches[3]; Sub = [int]$Matches[4] } }
    if ($v -match '^(\d+)\.(\d+)\.(\d+)') { return @{ Feature = [int]$Matches[1]; Patch = [int]$Matches[3]; Sub = 0 } }
    if ($v -match '^(\d+)\.(\d+)$')       { return @{ Feature = [int]$Matches[1]; Patch = 0; Sub = 0 } }
    if ($v -match '^(\d+)$')              { return @{ Feature = [int]$Matches[1]; Patch = 0; Sub = 0 } }
    return $null
}


# --- classification ----------------------------------------------------------

# Returns $true as soon as an outdated Java is identified.
function Test-Candidate([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.TrimEnd('\', '"', ' ')
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { return $false }
    # Common Files\Java\javapath is Oracle's shim directory - a set of
    # pointers to the real install, not an install of its own.
    if ($p -like '*Common Files*') { return $false }
    if (-not (Test-JavaDirectory $p)) { return $false }

    try { $p = Convert-Path -LiteralPath $p } catch { }
    if (-not $script:Seen.Add($p)) { return $false }

    $info = Read-JavaVersion $p
    if (-not $info) {
        $feat = Get-InferredFeature $p
        if ($feat) {
            [void]$script:Problems.Add("$p (Java $feat files present, no readable version)")
        } else {
            [void]$script:Problems.Add("$p (Java files present, version could not be determined)")
        }
        return $false
    }

    $parsed = ConvertFrom-JavaVersion $info.Version
    if (-not $parsed) {
        [void]$script:Problems.Add("$p (unparseable version string `"$($info.Version)`")")
        return $false
    }

    if ($MinPatch.ContainsKey($parsed.Feature)) {
        if ((Get-VNum "$($parsed.Patch).$($parsed.Sub)") -ge (Get-VNum $MinPatch[$parsed.Feature])) {
            return $false
        }
        $script:Vuln = $true
        return $true
    }
    if ($parsed.Feature -gt $NewestKnown) {
        [void]$script:Problems.Add("$p (Java $($info.Version) is newer than this script's data from $TableSource)")
        return $false
    }
    $script:Vuln = $true
    return $true
}


# --- the walker --------------------------------------------------------------
# An explicit stack rather than Get-ChildItem -Recurse, which can stall for a
# very long time on a large estate.
#
# MaxDepth 0 means unlimited. Reparse points are skipped: junction loops
# generate a fresh unique path on every traversal, so the visited set cannot
# catch them and only the directory cap would.

$PruneNames = @('node_modules', '.git', '.svn', 'WinSxS', '$Recycle.Bin',
                'System Volume Information', 'servicing', 'DriverStore',
                'assembly', 'Temp', 'Cache', 'cache2', 'INetCache')

function Invoke-JavaSweep([string]$Root, [int]$MaxDepth) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return }
    $visited = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $stack   = New-Object System.Collections.Stack
    $stack.Push(@{ P = $Root; D = 0 })

    while ($stack.Count -gt 0) {
        $n = $stack.Pop()
        if (-not $visited.Add($n.P)) { continue }
        if (++$script:DirCount -gt $MaxDirs) { return }

        if (Test-Candidate $n.P) { return }
        # Only a confirmed Java home stops the descent. Stopping at a weak
        # marker match would hide a runtime bundled further down, such as an
        # IDE's jbr\ directory.
        if (Test-JavaRoot $n.P) { continue }
        if ($MaxDepth -gt 0 -and $n.D -ge $MaxDepth) { continue }

        # Files and subdirectories in separate try/catch so that one
        # ACL-denied directory cannot abort the walk.
        try {
            $subs = (New-Object System.IO.DirectoryInfo $n.P).GetDirectories()
        } catch { continue }
        foreach ($d in $subs) {
            # .Attributes is already populated by the same OS call that listed
            # the directory, so this costs no extra syscall.
            if (($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($PruneNames -contains $d.Name) { continue }
            $stack.Push(@{ P = $d.FullName; D = $n.D + 1 })
        }
    }
}


# --- phase 1: standard install locations -------------------------------------

function Invoke-PhaseOne {
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        "$env:LOCALAPPDATA\Programs",
        "$env:USERPROFILE\.jdks",
        "$env:USERPROFILE\.gradle\jdks",
        "$env:USERPROFILE\scoop\apps",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        'C:\Java', 'C:\tools'
    ) | Where-Object { $_ } | Select-Object -Unique

    foreach ($r in $roots) {
        Invoke-JavaSweep $r $KnownDepth
        if ($script:Vuln) { return }
    }

    # JavaSoft keys - legacy Oracle layout, still written by some installers.
    foreach ($rk in 'HKLM:\SOFTWARE\JavaSoft', 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft',
                    'HKCU:\SOFTWARE\JavaSoft', 'HKLM:\SOFTWARE\AdoptOpenJDK',
                    'HKCU:\SOFTWARE\Eclipse Adoptium') {
        if (-not (Test-Path -LiteralPath $rk)) { continue }
        foreach ($k in (Get-ChildItem -LiteralPath $rk -Recurse -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            foreach ($vn in 'JavaHome', 'Path', 'InstallLocation') {
                $jh = $props.$vn
                if (-not $jh) { continue }
                if (Test-Path -LiteralPath $jh -PathType Container) {
                    if (Test-Candidate $jh) { return }
                } else {
                    [void]$script:Problems.Add("$jh (registry key $($k.PSChildName) points at a missing directory)")
                }
            }
        }
    }

    # Uninstall hive - catches installs outside the swept roots, and orphaned
    # registrations left behind by a partial uninstall.
    $pattern = 'java|jdk|jre|zulu|azul|temurin|adoptium|corretto|openjdk|semeru|liberica|sapmachine|graalvm|zing|dragonwell'
    foreach ($uk in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        foreach ($e in (Get-ItemProperty -Path $uk -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -and $_.DisplayName -match $pattern })) {
            $loc = $e.InstallLocation
            if (-not $loc) { continue }
            if (Test-Path -LiteralPath $loc.TrimEnd('\', '"', ' ') -PathType Container) {
                if (Test-Candidate $loc) { return }
            } else {
                [void]$script:Problems.Add("$($e.DisplayName): install location `"$loc`" is registered but missing (partial uninstall?)")
            }
        }
    }

    foreach ($scope in 'Process', 'User', 'Machine') {
        $jh = [Environment]::GetEnvironmentVariable('JAVA_HOME', $scope)
        if (-not $jh) { continue }
        if (Test-Path -LiteralPath $jh -PathType Container) {
            if (Test-Candidate $jh) { return }
        } else {
            [void]$script:Problems.Add("JAVA_HOME ($scope) is set to `"$jh`" but that directory does not exist")
        }
    }

    foreach ($c in (Get-Command java.exe -All -ErrorAction SilentlyContinue)) {
        if (Test-Candidate (Split-Path -Parent (Split-Path -Parent $c.Source))) { return }
    }
}


# --- phase 2: full disk ------------------------------------------------------
# Only reached when phase 1 found nothing outdated. Fixed drives only - network and
# removable drives are skipped.

function Invoke-PhaseTwo {
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -ne [System.IO.DriveType]::Fixed -or -not $d.IsReady) { continue }
        Invoke-JavaSweep $d.RootDirectory.FullName 0
        if ($script:Vuln) { return }
    }
}


# --- run ---------------------------------------------------------------------

Write-Host 'Checking for outdated Java, please wait...'

Invoke-PhaseOne
if (-not $script:Vuln) {
    Write-Host 'Nothing outdated in the usual places. Widening the search...'
    Invoke-PhaseTwo
}


# --- report ------------------------------------------------------------------

$Rule = '==============================================================='
Write-Host ''
Write-Out $Rule 'DarkGray'
Write-Out ' Azul JDK XRay' ''
Write-Host ' Checks this machine for outdated, unpatched JDK installations.'
Write-Host ' Local scan only: no network calls, nothing leaves this host.'
Write-Host ''
Write-Out " Version $XRayVersion | Reference data: $TableDate" 'DarkGray'
Write-Out $Rule 'DarkGray'
Write-Host ''

if ($script:Vuln) {
    Write-Badge 'DarkRed' 'White' 'OUTDATED' 'This host runs an outdated JDK. Update it now.'
    Write-Host ''
    Write-Host 'The security flaws fixed since this release are publicly disclosed.'
    Write-Host 'Their CVE details and the source code of the fixes are published, so'
    Write-Host 'attackers know exactly what to target. Every day without the update'
    Write-Host 'adds to the risk.'
    Write-Host ''
    Write-Out '  Secure Java across your enterprise:' ''
    Write-Host '    Azul has the solution, process and tools to do it at scale.'
    Write-Out "    $AzulContact" 'Cyan'
    Write-Host ''
    Write-Out '  Patch this machine right now:' ''
    Write-Host '    Download free Azul Zulu builds of OpenJDK (no commercial support).'
    Write-Out "    $AzulDownloads" 'Cyan'
    Write-Host ''
    exit 1
}

if ($script:Seen.Count -eq 0 -and $script:Problems.Count -eq 0) {
    Write-Badge 'DarkGreen' 'White' 'NO JAVA' 'No Java was detected.'
    Write-Host ''
    exit 3
}

if ($script:Problems.Count -gt 0) {
    Write-Badge 'Yellow' 'Black' 'UNKNOWN' 'Java was found, but its version could not be identified.'
    Write-Host ''
    Write-Host 'Treat this as a problem, not a pass. An unidentified runtime may be'
    Write-Host 'unpatched, and files left behind by a removed install still carry the'
    Write-Host 'vulnerabilities of the version they came from.'
    Write-Host ''
    Write-Link 'Review your enterprise Java estate:' $AzulContact
    Write-Host ''
    exit 2
}

Write-Badge 'DarkGreen' 'White' 'UP TO DATE' 'Your Java is up to date.'
Write-Host ''
Write-Link 'Long-term enterprise Java support:' $AzulContact
Write-Host ''
exit 0
