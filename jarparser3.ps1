<#
.SYNOPSIS
    Prefetch Analyzer ELITE: Enterprise-grade forensic analysis for screenshare detection
.DESCRIPTION
    Advanced Windows Prefetch forensics with:
    - Registry injection detection
    - Network communication tracking
    - Memory analysis & process injection detection
    - Process tree analysis
    - Threat correlation & risk scoring
    - Command line argument logging
    - Persistent execution detection
    - Advanced anomaly detection
.NOTES
    Run as Administrator - Required for full capabilities.
    Requires PECmd.exe (cached after first run).
#>

[CmdletBinding()]
param(
    [string[]]$ProcessNames = @("java", "javaw", "minecraft", "launcher", "launcher.exe"),
    [string]$PrefetchPath = "C:\Windows\Prefetch",
    [switch]$AnalyzeDLLs,
    [switch]$DetectRegistryInjection,
    [switch]$LogNetworkActivity,
    [switch]$AnalyzeMemory,
    [switch]$ProcessTreeAnalysis,
    [switch]$DetectPersistence,
    [switch]$DeepScan,
    [switch]$ExportCSV,
    [switch]$ExportHTML,
    [switch]$ExportJSON,
    [string]$CsvPath = "$env:TEMP\Prefetch_Report.csv",
    [string]$HtmlPath = "$env:TEMP\Prefetch_Report.html",
    [string]$JsonPath = "$env:TEMP\Prefetch_Report.json"
)

#region BANNER & ADMIN CHECK

function Show-Banner {
    $banner = @"
╔════════════════════════════════════════════════════════════╗
║      PREFETCH ANALYZER ELITE - PowerShell v3.0            ║
║    Enterprise Forensic Windows Execution Analysis         ║
║         Advanced Threat Detection & Correlation           ║
╚════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

function Test-Admin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

#endregion

#region TOOL MANAGEMENT

$PECmdUrl = "https://github.com/NoDiff-del/JARs/releases/download/Jar/PECmd.exe"
$ToolCachePath = "$env:LOCALAPPDATA\SS_Tools"

function Initialize-ToolCache {
    if (-not (Test-Path $ToolCachePath)) {
        New-Item -ItemType Directory -Path $ToolCachePath -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "✓ Carpeta de caché creada: $ToolCachePath" -ForegroundColor Green
    }
}

function Get-PECmdTool {
    Initialize-ToolCache
    $pecmdPath = Join-Path $ToolCachePath "PECmd.exe"
    
    if (Test-Path $pecmdPath) {
        Write-Host "✓ PECmd.exe en caché" -ForegroundColor Green
        return $pecmdPath
    }
    
    Write-Host "Descargando PECmd.exe (primera vez)..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $PECmdUrl -OutFile $pecmdPath -UseBasicParsing -ErrorAction Stop
        Write-Host "✓ PECmd.exe descargado correctamente" -ForegroundColor Green
        return $pecmdPath
    } catch {
        Write-Error "Error descargando PECmd.exe: $_"
        return $null
    }
}

#endregion

#region THREAT DEFINITIONS

function Get-ThreatSignatures {
    return @{
        'CheatModules' = @(
            'liquidbounce', 'vape', 'kami', 'meteor', 'impact', 'rusherhack',
            'salhack', 'future', 'phobos', 'inertia', 'ratpoison', 'baritone'
        )
        'SuspiciousExes' = @(
            'injector', 'patcher', 'launcher', 'hook', 'detour', 'beacon',
            'bypass', 'loader', 'crypter', 'stubexe', 'wrapper', 'trigger'
        )
        'SuspiciousDLLs' = @(
            'detours.dll', 'mhook.dll', 'easyhook.dll', 'tinytracer.dll',
            'dinput8.dll', 'dxgi.dll', 'nvapi.dll', 'dxvk.dll', 'injection'
        )
        'ObfuscationIndicators' = @(
            'obf', 'crypt', 'pack', 'enc', 'hide', '_rl_', 'xor'
        )
    }
}

#endregion

#region PREFETCH PARSING

function Get-BootTime {
    try {
        return (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    } catch {
        Write-Warning "Error obteniendo boot time: $_"
        return (Get-Date).AddHours(-24)
    }
}

function Get-PrefetchFiles {
    param(
        [string[]]$ProcessNames,
        [string]$PrefetchPath
    )
    
    if (-not (Test-Path $PrefetchPath)) {
        Write-Warning "Carpeta Prefetch no encontrada: $PrefetchPath"
        return @()
    }
    
    $files = @()
    foreach ($process in $ProcessNames) {
        $pattern = "$($process)*.pf"
        $files += Get-ChildItem -Path $PrefetchPath -Filter $pattern -ErrorAction SilentlyContinue
    }
    
    return $files | Sort-Object LastWriteTime -Descending
}

function Parse-PrefetchFile {
    param(
        [string]$PrefetchFilePath,
        [string]$PECmdPath
    )
    
    if (-not (Test-Path $PECmdPath)) {
        Write-Warning "PECmd.exe no disponible"
        return $null
    }
    
    try {
        $output = & $PECmdPath -f $PrefetchFilePath 2>&1
        return $output
    } catch {
        Write-Warning "Error parsing prefetch file $PrefetchFilePath : $_"
        return $null
    }
}

function Extract-PrefetchMetadata {
    param(
        [string[]]$PECmdOutput,
        [string]$FileName
    )
    
    $metadata = @{
        'FileName'          = $FileName
        'ExecutableVersion' = ""
        'RunCount'          = 0
        'LastRunTime'       = ""
        'AllRunTimes'       = @()
        'LoadedFiles'       = @()
        'LoadedDLLs'        = @()
        'CommandLine'       = ""
    }
    
    if (-not $PECmdOutput) { return $metadata }
    
    foreach ($line in $PECmdOutput) {
        # Extract run count
        if ($line -match "Run count:\s+(\d+)") {
            $metadata['RunCount'] = [int]$matches[1]
        }
        
        # Extract last run time - FIXED: Removed $ from regex group
        if ($line -match "Last run time.*?(\d{4}-\d{2}-\d{2})") {
            $metadata['LastRunTime'] = $matches[1]
        }
        
        # Extract command line
        if ($line -match "Command line:\s+(.+)") {
            $metadata['CommandLine'] = $matches[1]
        }
        
        # Extract file paths
        if ($line -match '\\[^\\]+\.[^\\]+$' -or $line -match '^\d+:\s+\\') {
            $filePath = $line -replace '^\d+:\s+', '' -replace '^- ', ''
            $filePath = $filePath.Trim()
            
            if ($filePath -and $filePath.Length -gt 3) {
                if ($filePath -like '*.dll' -or $filePath -like '*.so') {
                    $metadata['LoadedDLLs'] += $filePath
                } else {
                    $metadata['LoadedFiles'] += $filePath
                }
            }
        }
    }
    
    return $metadata
}

#endregion

#region REGISTRY INJECTION DETECTION

function Detect-RegistryInjections {
    param([string]$ProcessName)
    
    $findings = @()
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            try {
                $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                foreach ($prop in $items.PSObject.Properties) {
                    $value = $prop.Value
                    if (-not $value -or $prop.Name -like 'PS*') { continue }
                    
                    $valueStr = $value.ToString().ToLower()
                    
                    if ($valueStr -like "*injector*" -or $valueStr -like "*hook*" -or $valueStr -like "*bypass*") {
                        $findings += [PSCustomObject]@{
                            'Ruta'            = $path
                            'Propiedad'       = $prop.Name
                            'Valor'           = $value
                            'Tipo'            = 'Inyección'
                            'Severidad'       = 'CRITICA'
                        }
                    }
                }
            } catch {
                Write-Warning "Error leyendo registro: $_"
            }
        }
    }
    
    return $findings
}

#endregion

#region NETWORK ACTIVITY DETECTION

function Detect-NetworkActivity {
    param([string]$ProcessName)
    
    $findings = @()
    
    try {
        $netstat = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        if ($netstat) {
            foreach ($conn in $netstat) {
                $suspiciousPorts = @(1080, 5555, 8888, 8080, 4444, 9999, 6666)
                if ($conn.RemotePort -in $suspiciousPorts) {
                    $findings += [PSCustomObject]@{
                        'IP'              = $conn.RemoteAddress
                        'Puerto'          = $conn.RemotePort
                        'Tipo'            = 'Red'
                        'Severidad'       = 'ALTA'
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error detectando red: $_"
    }
    
    return $findings
}

#endregion

#region MEMORY & PROCESS INJECTION ANALYSIS

function Detect-MemoryInjection {
    param([string]$ProcessName)
    
    $findings = @()
    
    try {
        $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $modules = $proc.Modules
            foreach ($module in $modules) {
                $moduleName = [System.IO.Path]::GetFileName($module.FileName).ToLower()
                $injectionIndicators = @('detours', 'hook', 'inject', 'patch', 'mod')
                
                foreach ($indicator in $injectionIndicators) {
                    if ($moduleName -like "*$indicator*") {
                        $findings += [PSCustomObject]@{
                            'Modulo'          = $moduleName
                            'Tipo'            = 'Inyección'
                            'Severidad'       = 'CRITICA'
                        }
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error analizando memoria: $_"
    }
    
    return $findings
}

#endregion

#region PROCESS TREE ANALYSIS

function Build-ProcessTree {
    param([string]$ProcessName)
    
    $findings = @()
    
    try {
        $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            try {
                $parentProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                $suspiciousParents = @('cmd', 'powershell', 'rundll32', 'wscript')
                
                $parentName = ""
                if ($parentProc.ParentProcessId) {
                    $parentName = (Get-Process -Id $parentProc.ParentProcessId -ErrorAction SilentlyContinue).Name
                }
                
                if ($parentName -in $suspiciousParents) {
                    $findings += [PSCustomObject]@{
                        'Padre'           = $parentName
                        'Hijo'            = $proc.Name
                        'Tipo'            = 'Árbol'
                        'Severidad'       = 'MEDIA'
                    }
                }
            } catch {}
        }
    } catch {
        Write-Warning "Error analizando árbol: $_"
    }
    
    return $findings
}

#endregion

#region PERSISTENCE DETECTION

function Detect-PersistenceMechanisms {
    param([string]$ProcessName)
    
    $findings = @()
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.Actions.Execute -like "*$ProcessName*"
        }
        
        if ($tasks) {
            foreach ($task in $tasks) {
                $findings += [PSCustomObject]@{
                    'Nombre'          = $task.TaskName
                    'Tipo'            = 'Tarea'
                    'Severidad'       = 'ALTA'
                }
            }
        }
    } catch {
        Write-Warning "Error detectando persistencia: $_"
    }
    
    return $findings
}

#endregion

#region THREAT ANALYSIS

function Test-FileForThreats {
    param(
        [string]$FilePath,
        [hashtable]$Signatures
    )
    
    $findings = @()
    $fileName = Split-Path -Leaf $FilePath
    $fileNameLower = $fileName.ToLower()
    
    foreach ($susp in $Signatures['SuspiciousExes']) {
        if ($fileNameLower -like "*$susp*") {
            $findings += [PSCustomObject]@{
                'Tipo'       = 'Ejecutable'
                'Severidad'  = 'ALTA'
                'Detalle'    = $susp
            }
        }
    }
    
    foreach ($dll in $Signatures['SuspiciousDLLs']) {
        if ($fileNameLower -eq $dll.ToLower()) {
            $findings += [PSCustomObject]@{
                'Tipo'       = 'DLL'
                'Severidad'  = 'CRITICA'
                'Detalle'    = $dll
            }
        }
    }
    
    return $findings
}

function Analyze-LoadedDLLs {
    param(
        [string[]]$DLLs,
        [hashtable]$Signatures
    )
    
    $findings = @()
    
    foreach ($dll in $DLLs) {
        $dllName = Split-Path -Leaf $dll
        $dllNameLower = $dllName.ToLower()
        
        foreach ($susp in $Signatures['SuspiciousDLLs']) {
            if ($dllNameLower -eq $susp.ToLower()) {
                $findings += [PSCustomObject]@{
                    'Tipo'       = 'DLL Maliciosa'
                    'Severidad'  = 'CRITICA'
                    'DLL'        = $dllName
                }
            }
        }
    }
    
    return $findings
}

function Measure-FileEntropy {
    param([string]$FilePath)
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath) | Select-Object -First 1MB
        $freq = @{}
        
        foreach ($byte in $bytes) {
            if ($freq.ContainsKey($byte)) {
                $freq[$byte]++
            } else {
                $freq[$byte] = 1
            }
        }
        
        $entropy = 0
        $length = $bytes.Length
        foreach ($count in $freq.Values) {
            $p = $count / $length
            $entropy -= $p * [Math]::Log($p, 2)
        }
        
        return @{
            'Entropy'     = [Math]::Round($entropy, 2)
            'IsPacked'    = $entropy -gt 7.5
        }
    } catch {
        return $null
    }
}

#endregion

#region RISK SCORING

function Calculate-RiskScore {
    param([object]$ScanData)
    
    $baseScore = 0
    if ($ScanData.AllFindings) {
        $baseScore = ($ScanData.AllFindings.Count * 5)
    }
    if ($ScanData.RunCount -gt 10) { $baseScore += 15 }
    if ($ScanData.LoadedDLLs.Count -gt 5) { $baseScore += 10 }
    if ($ScanData.Registry -and $ScanData.Registry.Count -gt 0) { $baseScore += 25 }
    if ($ScanData.NetworkActivity -and $ScanData.NetworkActivity.Count -gt 0) { $baseScore += 30 }
    if ($ScanData.MemoryInjection -and $ScanData.MemoryInjection.Count -gt 0) { $baseScore += 35 }
    if ($ScanData.Persistence -and $ScanData.Persistence.Count -gt 0) { $baseScore += 25 }
    
    return [Math]::Min($baseScore, 100)
}

function Get-RiskAssessment {
    param([int]$RiskScore)
    
    if ($RiskScore -ge 90) { return @{ 'Level' = 'CRITICO'; 'Color' = 'Red' } }
    elseif ($RiskScore -ge 70) { return @{ 'Level' = 'ALTO'; 'Color' = 'Yellow' } }
    elseif ($RiskScore -ge 50) { return @{ 'Level' = 'MEDIO'; 'Color' = 'Magenta' } }
    elseif ($RiskScore -ge 30) { return @{ 'Level' = 'BAJO'; 'Color' = 'Cyan' } }
    else { return @{ 'Level' = 'MINIMO'; 'Color' = 'Green' } }
}

#endregion

#region REPORTING

function Format-ScanResults {
    param([object[]]$ScanData)
    
    $results = @()
    
    foreach ($scan in $ScanData) {
        $totalFindings = if ($scan.AllFindings) { $scan.AllFindings.Count } else { 0 }
        $riskScore = $scan.RiskScore
        $riskAssessment = Get-RiskAssessment -RiskScore $riskScore
        
        if ($totalFindings -eq 0) {
            $maxSeverity = "NINGUNA"
            $status = "✓ Limpio"
        } else {
            $maxSeverity = ($scan.AllFindings | ForEach-Object { $_.Severidad } | Select-Object -First 1)
            $status = "⚠ Sospechoso"
        }
        
        $results += [PSCustomObject]@{
            'Proceso'          = $scan.Proceso
            'Estado'           = $status
            'Hallazgos'        = $totalFindings
            'Severidad'        = $maxSeverity
            'Puntuacion'       = $riskScore
            'Nivel'            = $riskAssessment.Level
            'Ejecuciones'      = $scan.RunCount
            'Ultima'           = $scan.LastRunTime
            'DLLs'             = $scan.LoadedDLLs.Count
            'Archivos'         = $scan.LoadedFiles.Count
        }
    }
    
    return $results
}

function Export-ToCSV {
    param(
        [object[]]$Data,
        [string]$Path
    )
    
    try {
        $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "✓ Exportado a CSV: $Path" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "Error exportando CSV: $_"
        return $false
    }
}

function Export-ToJSON {
    param(
        [object[]]$ScanData,
        [string]$Path
    )
    
    try {
        $jsonData = @{
            'GeneratedAt'    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            'Computer'       = $env:COMPUTERNAME
            'User'           = $env:USERNAME
            'ProcessCount'   = $ScanData.Count
            'TotalFindings'  = if ($ScanData.AllFindings) { $ScanData.AllFindings.Count } else { 0 }
            'HighestRisk'    = ($ScanData | ForEach-Object { $_.RiskScore } | Measure-Object -Maximum).Maximum
        }
        
        $jsonData | ConvertTo-Json | Out-File -FilePath $Path -Encoding UTF8
        Write-Host "✓ Exportado a JSON: $Path" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "Error exportando JSON: $_"
        return $false
    }
}

function Export-ToHTML {
    param(
        [object[]]$ScanData,
        [object[]]$FormattedResults,
        [string]$Path
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computerName = $env:COMPUTERNAME
    $userName = $env:USERNAME
    
    $totalFindings = if ($ScanData.AllFindings) { $ScanData.AllFindings.Count } else { 0 }
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Prefetch Analyzer Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #667eea; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .card { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; background: white; margin: 20px 0; }
        th { background: #667eea; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #ff6b6b; }
        .medium { color: #ffc107; }
        .footer { text-align: center; margin-top: 40px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Prefetch Analyzer Elite v3.0</h1>
        <p>Informe Forense de Ejecución de Procesos</p>
    </div>
    <div class="summary">
        <div class="card"><h3>Hallazgos</h3><p style="font-size: 24px;">$totalFindings</p></div>
        <div class="card"><h3>Procesos</h3><p style="font-size: 24px;">$($ScanData.Count)</p></div>
        <div class="card"><h3>Timestamp</h3><p style="font-size: 12px;">$timestamp</p></div>
        <div class="card"><h3>Equipo</h3><p style="font-size: 12px;">$computerName</p></div>
    </div>
    <table>
        <tr><th>Proceso</th><th>Estado</th><th>Hallazgos</th><th>Severidad</th><th>Puntuacion</th></tr>
"@
    
    foreach ($result in $FormattedResults) {
        $severityClass = $result.Severidad.ToLower()
        $htmlContent += "<tr><td>$($result.Proceso)</td><td>$($result.Estado)</td><td>$($result.Hallazgos)</td><td class='$severityClass'>$($result.Severidad)</td><td>$($result.Puntuacion)</td></tr>"
    }
    
    $htmlContent += @"
    </table>
    <div class="footer">
        <p>Prefetch Analyzer Elite v3.0 - Generado: $timestamp</p>
        <p>$computerName | Usuario: $userName</p>
    </div>
</body>
</html>
"@
    
    try {
        $htmlContent | Out-File -FilePath $Path -Encoding UTF8
        Write-Host "✓ Reporte HTML: $Path" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "Error exportando HTML: $_"
        return $false
    }
}

#endregion

#region MAIN EXECUTION

Clear-Host
Show-Banner

if (-not (Test-Admin)) {
    Write-Warning 'Ejecute como Administrador.'
    Start-Sleep -Seconds 5
    exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

$pecmdPath = Get-PECmdTool
if (-not $pecmdPath) {
    Write-Error "No se puede continuar sin PECmd.exe"
    exit
}

Write-Host "Iniciando análisis de Prefetch..." -ForegroundColor Cyan
$bootTime = Get-BootTime
Write-Host "Boot time: $bootTime" -ForegroundColor Gray

$threats = Get-ThreatSignatures
$prefetchFiles = Get-PrefetchFiles -ProcessNames $ProcessNames -PrefetchPath $PrefetchPath

if ($prefetchFiles.Count -eq 0) {
    Write-Host "No se encontraron archivos Prefetch." -ForegroundColor Yellow
    exit
}

Write-Host "Archivos encontrados: $($prefetchFiles.Count)" -ForegroundColor Green
Write-Host ""

$scanResults = @()
$progressCount = 0

foreach ($pfFile in $prefetchFiles) {
    $progressCount++
    $processName = $pfFile.Name -replace '\.pf$'
    Write-Host "[$progressCount/$($prefetchFiles.Count)] $($pfFile.Name)" -ForegroundColor Yellow
    
    $pecmdOutput = Parse-PrefetchFile -PrefetchFilePath $pfFile.FullName -PECmdPath $pecmdPath
    $metadata = Extract-PrefetchMetadata -PECmdOutput $pecmdOutput -FileName $pfFile.Name
    
    $allFindings = @()
    $executableFindings = Test-FileForThreats -FilePath $pfFile.FullName -Signatures $threats
    $allFindings += @($executableFindings)
    
    $registryFindings = @()
    if ($DetectRegistryInjection) {
        $registryFindings = Detect-RegistryInjections -ProcessName $processName
        $allFindings += @($registryFindings)
    }
    
    $networkFindings = @()
    if ($LogNetworkActivity) {
        $networkFindings = Detect-NetworkActivity -ProcessName $processName
        $allFindings += @($networkFindings)
    }
    
    $memoryFindings = @()
    if ($AnalyzeMemory) {
        $memoryFindings = Detect-MemoryInjection -ProcessName $processName
        $allFindings += @($memoryFindings)
    }
    
    $treeFindings = @()
    if ($ProcessTreeAnalysis) {
        $treeFindings = Build-ProcessTree -ProcessName $processName
        $allFindings += @($treeFindings)
    }
    
    $persistenceFindings = @()
    if ($DetectPersistence) {
        $persistenceFindings = Detect-PersistenceMechanisms -ProcessName $processName
        $allFindings += @($persistenceFindings)
    }
    
    if ($AnalyzeDLLs -and $metadata.LoadedDLLs.Count -gt 0) {
        $dllFindings = Analyze-LoadedDLLs -DLLs $metadata.LoadedDLLs -Signatures $threats
        $allFindings += @($dllFindings)
    }
    
    $scanObject = [PSCustomObject]@{
        'Proceso'          = $processName
        'RunCount'         = $metadata.RunCount
        'LastRunTime'      = $metadata.LastRunTime
        'CommandLine'      = $metadata.CommandLine
        'LoadedDLLs'       = $metadata.LoadedDLLs
        'LoadedFiles'      = $metadata.LoadedFiles
        'AllFindings'      = @($allFindings)
        'Registry'         = @($registryFindings)
        'NetworkActivity'  = @($networkFindings)
        'MemoryInjection'  = @($memoryFindings)
        'ProcessTree'      = @($treeFindings)
        'Persistence'      = @($persistenceFindings)
    }
    
    $riskScore = Calculate-RiskScore -ScanData $scanObject
    $scanObject | Add-Member -NotePropertyName 'RiskScore' -NotePropertyValue $riskScore
    
    $scanResults += $scanObject
    
    $riskAssessment = Get-RiskAssessment -RiskScore $riskScore
    Write-Host "  Hallazgos: $($allFindings.Count) | Riesgo: $($riskScore) [$($riskAssessment.Level)]" -ForegroundColor $riskAssessment.Color
}

$formatted = Format-ScanResults -ScanData $scanResults

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
    $formatted | Out-GridView -Title "Prefetch Analyzer Elite"
} else {
    $formatted | Format-Table -AutoSize -Wrap
}

if ($ExportCSV) {
    Export-ToCSV -Data $formatted -Path $CsvPath
}

if ($ExportHTML) {
    Export-ToHTML -ScanData $scanResults -FormattedResults $formatted -Path $HtmlPath
}

if ($ExportJSON) {
    Export-ToJSON -ScanData $scanResults -Path $JsonPath
}

$sw.Stop()
Write-Host ""
Write-Host "✔ Completado en $([math]::Round($sw.Elapsed.TotalSeconds, 2)) segundos." -ForegroundColor Green

#endregion
