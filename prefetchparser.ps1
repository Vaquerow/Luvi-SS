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
    .NET 4.5+ required for advanced features.
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
    [switch]$AdvancedThreatCorrelation,
    [switch]$DeepScan,
    [switch]$ExportCSV,
    [switch]$ExportHTML,
    [switch]$ExportJSON,
    [string]$CsvPath = "$env:TEMP\Prefetch_Report.csv",
    [string]$HtmlPath = "$env:TEMP\Prefetch_Report.html",
    [string]$JsonPath = "$env:TEMP\Prefetch_Report.json",
    [string]$BaselineFile = ""
)

#region BANNER & ADMIN CHECK

function Show-Banner {
    $banner = @"
╔════════════════════════════════════════════════════════════╗
║      PREFETCH ANALYZER ELITE - PowerShell v3.0            ║
║    Enterprise Forensic Windows Execution Analysis         ║
║         🔍 Advanced Threat Detection & Correlation         ║
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
            'salhack', 'future', 'phobos', 'inertia', 'ratpoison', 'baritone',
            'opticaliware', 'novoline', 'flux', 'rise', 'hypixel'
        )
        'SuspiciousExes' = @(
            'injector', 'patcher', 'launcher', 'hook', 'detour', 'beacon',
            'bypass', 'loader', 'crypter', 'stubexe', 'wrapper', 'trigger',
            'payload', 'stub', 'exploit', 'shellcode', 'dropper'
        )
        'SuspiciousDLLs' = @(
            'detours.dll', 'mhook.dll', 'easyhook.dll', 'tinytracer.dll',
            'dinput8.dll', 'dxgi.dll', 'nvapi.dll', 'dxvk.dll', 'injection',
            'hook.dll', 'patch.dll', 'mod.dll', 'client.dll', 'bypass.dll'
        )
        'ObfuscationIndicators' = @(
            'obf', 'crypt', 'pack', 'enc', 'hide', '_rl_', 'xor', 'b64',
            'encoded', 'scrambl', 'confus'
        )
        'HighRiskAPIs' = @(
            'WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx',
            'SetWindowsHookEx', 'LoadLibrary', 'GetProcAddress',
            'SetWinEventHook', 'GetWindowLongPtr', 'SetWindowLong',
            'NtQueueApcThread', 'RtlCreateUserThread'
        )
        'MaliciousRegistryPaths' = @(
            'Run', 'RunOnce', 'Winlogon', 'Shell', 'UserInit',
            'Notify', 'AppInit_DLLs', 'CmdLine', 'Debugger'
        )
        'SuspiciousNetworkPatterns' = @(
            'http://', 'https://', 'ftp://', 'socket', 'connect',
            'SendData', 'ReceiveData', 'inet_addr', 'htons', 'CONNECT'
        )
        'DataExfiltrationPatterns' = @(
            'credentials', 'password', 'token', 'session', 'cookie',
            'auth', 'secret', 'private', 'confidential', 'key'
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
            $metadata.RunCount = [int]$matches[1]
        }
        
        # Extract last run time
        if ($line -match "Last run time.*?(\d{4}-\d{2}-\d{2}.*?)$") {
            $metadata.LastRunTime = $matches[1]
        }
        
        # Extract command line
        if ($line -match "Command line:\s+(.+)$") {
            $metadata.CommandLine = $matches[1]
        }
        
        # Extract file paths
        if ($line -match '\\[^\\]+\.[^\\]+$' -or $line -match '^\d+:\s+\\') {
            $filePath = $line -replace '^\d+:\s+', '' -replace '^- ', ''
            $filePath = $filePath.Trim()
            
            if ($filePath -and $filePath.Length -gt 3) {
                if ($filePath -like '*.dll' -or $filePath -like '*.so') {
                    $metadata.LoadedDLLs += $filePath
                } else {
                    $metadata.LoadedFiles += $filePath
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
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\System\CurrentControlSet\Services',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Scripts'
    )
    
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            try {
                $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                foreach ($prop in $items.PSObject.Properties) {
                    $value = $prop.Value
                    
                    # Skip null or system properties
                    if (-not $value -or $prop.Name -like 'PS*') { continue }
                    
                    $valueStr = $value.ToString().ToLower()
                    
                    # Check for suspicious patterns
                    if ($valueStr -like "*injector*" -or $valueStr -like "*hook*" -or 
                        $valueStr -like "*patch*" -or $valueStr -like "*bypass*" -or
                        $valueStr -like "*detour*" -or $valueStr -like "*beacon*" -or
                        $valueStr -like "*payload*" -or $valueStr -like "*exploit*") {
                        
                        $findings += [PSCustomObject]@{
                            'Ruta_registro'   = $path
                            'Propiedad'       = $prop.Name
                            'Valor'           = $value
                            'Tipo'            = 'Inyección de Registro'
                            'Severidad'       = 'CRITICA'
                            'Descripcion'     = "Referencia sospechosa detectada en registro"
                        }
                    }
                    
                    # Check for obfuscated or encoded patterns
                    if ($valueStr -match '[a-f0-9]{32,}|pow.*shell|cmd.*exe.*\/c') {
                        $findings += [PSCustomObject]@{
                            'Ruta_registro'   = $path
                            'Propiedad'       = $prop.Name
                            'Valor'           = $value.Substring(0, [Math]::Min(100, $value.Length)) + "..."
                            'Tipo'            = 'Ofuscación'
                            'Severidad'       = 'MEDIA'
                            'Descripcion'     = "Posible ofuscación en entrada de registro"
                        }
                    }
                }
            } catch {}
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
        # Get established connections
        $netstat = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
                   Where-Object { $_.OwningProcess -like "*$ProcessName*" -or 
                                 (Get-Process -PID $_.OwningProcess -ErrorAction SilentlyContinue).Name -like "*$ProcessName*" }
        
        if ($netstat) {
            foreach ($conn in $netstat) {
                $remoteIP = $conn.RemoteAddress
                $remotePort = $conn.RemotePort
                
                # Check for suspicious ports
                $suspiciousPorts = @(1080, 5555, 8888, 8080, 4444, 9999, 6666, 25, 587, 465)
                
                if ($remotePort -in $suspiciousPorts -or $remotePort -gt 60000) {
                    $findings += [PSCustomObject]@{
                        'Proceso'         = (Get-Process -PID $conn.OwningProcess -ErrorAction SilentlyContinue).Name
                        'IP_remota'       = $remoteIP
                        'Puerto_remoto'   = $remotePort
                        'Puerto_local'    = $conn.LocalPort
                        'Estado'          = $conn.State
                        'Tipo'            = 'Conexión Sospechosa'
                        'Severidad'       = 'ALTA'
                        'Descripcion'     = "Conexión a puerto sospechoso detectada"
                    }
                }
            }
        }
        
        # Check DNS queries
        $dnsEvents = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'dnsclient'
            StartTime    = (Get-Date).AddHours(-1)
        } -ErrorAction SilentlyContinue
        
        if ($dnsEvents) {
            foreach ($event in $dnsEvents) {
                if ($event.Message -like "*$ProcessName*") {
                    $findings += [PSCustomObject]@{
                        'Proceso'       = $ProcessName
                        'Tipo_evento'   = $event.LevelDisplayName
                        'Mensaje'       = $event.Message
                        'Tipo'          = 'Consulta DNS'
                        'Severidad'     = 'BAJA'
                        'Descripcion'   = "Actividad DNS detectada"
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error detectando actividad de red: $_"
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
            # Check for suspicious memory regions
            $memory = [System.Diagnostics.ProcessModule]::GetModules($proc.Handle)
            
            foreach ($module in $memory) {
                $moduleName = [System.IO.Path]::GetFileName($module.FileName).ToLower()
                
                # Check for DLL injection patterns
                $injectionIndicators = @(
                    'detours', 'hook', 'inject', 'patch', 'mod', 'bypass',
                    'beacon', 'shellcode', 'payload', 'exploit'
                )
                
                foreach ($indicator in $injectionIndicators) {
                    if ($moduleName -like "*$indicator*") {
                        $findings += [PSCustomObject]@{
                            'Proceso'         = $proc.Name
                            'PID'             = $proc.Id
                            'Modulo'          = $moduleName
                            'Ruta_completa'   = $module.FileName
                            'Tipo'            = 'DLL Inyectada'
                            'Severidad'       = 'CRITICA'
                            'Descripcion'     = "Módulo sospechoso cargado en proceso"
                        }
                    }
                }
            }
            
            # Check memory protection flags
            try {
                $memInfo = Get-WmiObject -Query "SELECT * FROM Win32_ProcessMemoryInfo WHERE ProcessHandle=$($proc.Id)" -ErrorAction SilentlyContinue
                if ($memInfo.WorkingSetSize -gt 500MB) {
                    $findings += [PSCustomObject]@{
                        'Proceso'         = $proc.Name
                        'PID'             = $proc.Id
                        'Memoria_MB'      = [Math]::Round($memInfo.WorkingSetSize / 1MB, 2)
                        'Tipo'            = 'Consumo Anómalo'
                        'Severidad'       = 'MEDIA'
                        'Descripcion'     = "Consumo de memoria inusualmente alto"
                    }
                }
            } catch {}
        }
    } catch {
        Write-Warning "Error analizando inyección de memoria: $_"
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
            # Get parent process
            try {
                $parentProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                $parentName = Get-Process -Id $parentProc.ParentProcessId -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                
                # Check for suspicious parent processes
                $suspiciousParents = @(
                    'cmd', 'powershell', 'rundll32', 'regsvcs', 'regasm',
                    'InstallUtil', 'cscript', 'wscript', 'explorer', 'svchost'
                )
                
                if ($parentName -in $suspiciousParents) {
                    $findings += [PSCustomObject]@{
                        'Proceso_hijo'    = $proc.Name
                        'Proceso_padre'   = $parentName
                        'PID_hijo'        = $proc.Id
                        'PID_padre'       = $parentProc.ParentProcessId
                        'Linea_comando'   = $parentProc.CommandLine
                        'Tipo'            = 'Árbol Sospechoso'
                        'Severidad'       = 'MEDIA'
                        'Descripcion'     = "Proceso iniciado desde parent sospechoso"
                    }
                }
            } catch {}
        }
    } catch {
        Write-Warning "Error analizando árbol de procesos: $_"
    }
    
    return $findings
}

#endregion

#region PERSISTENCE DETECTION

function Detect-PersistenceMechanisms {
    param([string]$ProcessName)
    
    $findings = @()
    
    # Check scheduled tasks
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.Actions.Execute -like "*$ProcessName*" -or
            $_.Triggers.Repetition -or
            $_.Author -like "*Minecraft*" -or $_.Author -like "*Java*"
        }
        
        if ($tasks) {
            foreach ($task in $tasks) {
                $findings += [PSCustomObject]@{
                    'Mecanismo'       = 'Tarea Programada'
                    'Nombre'          = $task.TaskName
                    'Ruta'            = $task.TaskPath
                    'Accion'          = $task.Actions.Execute
                    'Triggers'        = $task.Triggers.Count
                    'Tipo'            = 'Persistencia'
                    'Severidad'       = 'ALTA'
                    'Descripcion'     = "Tarea programada potencialmente maliciosa"
                }
            }
        }
    } catch {}
    
    # Check services
    try {
        $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -like "*$ProcessName*" -or
            $_.Name -like "*$ProcessName*" -or
            $_.Status -eq 'Running' -and $_.StartType -eq 'Automatic'
        }
        
        if ($services) {
            foreach ($svc in $services) {
                $findings += [PSCustomObject]@{
                    'Mecanismo'       = 'Servicio'
                    'Nombre'          = $svc.DisplayName
                    'Estado'          = $svc.Status
                    'Tipo_inicio'     = $svc.StartType
                    'Proceso'         = (Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE Name='$($svc.Name)'" -ErrorAction SilentlyContinue).PathName
                    'Tipo'            = 'Persistencia'
                    'Severidad'       = 'ALTA'
                    'Descripcion'     = "Servicio de persistencia detectado"
                }
            }
        }
    } catch {}
    
    # Check startup folder
    try {
        $startupFolders = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        
        foreach ($folder in $startupFolders) {
            if (Test-Path $folder) {
                $items = Get-ChildItem -Path $folder -ErrorAction SilentlyContinue
                
                foreach ($item in $items) {
                    if ($item.Name -like "*$ProcessName*" -or $item.Name -like "*hack*" -or $item.Name -like "*cheat*") {
                        $findings += [PSCustomObject]@{
                            'Mecanismo'       = 'Carpeta Startup'
                            'Archivo'         = $item.Name
                            'Ruta'            = $item.FullName
                            'Creado'          = $item.CreationTime
                            'Modificado'      = $item.LastWriteTime
                            'Tipo'            = 'Persistencia'
                            'Severidad'       = 'MEDIA'
                            'Descripcion'     = "Archivo en carpeta Startup"
                        }
                    }
                }
            }
        }
    } catch {}
    
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
    
    # Check against suspicious executables
    foreach ($susp in $Signatures['SuspiciousExes']) {
        if ($fileNameLower -like "*$susp*") {
            $findings += [PSCustomObject]@{
                'Tipo'       = 'Ejecutable Sospechoso'
                'Severidad'  = 'ALTA'
                'Detalle'    = "Nombre coincide con patrón: $susp"
                'Archivo'    = $fileName
            }
        }
    }
    
    # Check against suspicious DLLs
    foreach ($dll in $Signatures['SuspiciousDLLs']) {
        if ($fileNameLower -eq $dll.ToLower()) {
            $findings += [PSCustomObject]@{
                'Tipo'       = 'DLL Sospechosa'
                'Severidad'  = 'CRITICA'
                'Detalle'    = "DLL conocida de inyección: $dll"
                'Archivo'    = $fileName
            }
        }
    }
    
    # Check obfuscation
    foreach ($obf in $Signatures['ObfuscationIndicators']) {
        if ($fileNameLower -like "*$obf*" -and $fileNameLower -like '*.exe') {
            $findings += [PSCustomObject]@{
                'Tipo'       = 'Ofuscación'
                'Severidad'  = 'MEDIA'
                'Detalle'    = "Posible ofuscación detectada: $obf"
                'Archivo'    = $fileName
            }
        }
    }
    
    # Check digital signature
    if (Test-Path $FilePath) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
            if ($sig.Status -ne 'Valid' -and $sig.Status -ne 'NotSigned') {
                $findings += [PSCustomObject]@{
                    'Tipo'       = 'Firma Digital'
                    'Severidad'  = 'MEDIA'
                    'Detalle'    = "Firma inválida: $($sig.Status)"
                    'Archivo'    = $fileName
                }
            }
        } catch {}
    } else {
        $findings += [PSCustomObject]@{
            'Tipo'       = 'Archivo No Encontrado'
            'Severidad'  = 'BAJA'
            'Detalle'    = "Archivo no existe (posiblemente eliminado)"
            'Archivo'    = $fileName
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
        
        # Check against suspicious DLLs
        foreach ($susp in $Signatures['SuspiciousDLLs']) {
            if ($dllNameLower -eq $susp.ToLower()) {
                $findings += [PSCustomObject]@{
                    'Tipo'       = 'DLL Maliciosa'
                    'Severidad'  = 'CRITICA'
                    'DLL'        = $dllName
                    'Ruta'       = $dll
                    'Detalle'    = "DLL de inyección conocida detectada"
                }
            }
        }
        
        # Entropy check
        if (Test-Path $dll) {
            try {
                $entropy = Measure-FileEntropy -FilePath $dll
                if ($entropy -and $entropy.IsPacked) {
                    $findings += [PSCustomObject]@{
                        'Tipo'       = 'DLL Comprimida'
                        'Severidad'  = 'MEDIA'
                        'DLL'        = $dllName
                        'Ruta'       = $dll
                        'Detalle'    = "Entropía: $($entropy.Entropy) - Posible empaquetamiento"
                    }
                }
            } catch {}
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
            'Assessment'  = if ($entropy -gt 7.8) { "Muy alta" }
                           elseif ($entropy -gt 7.2) { "Alta" }
                           else { "Normal" }
        }
    } catch {
        return $null
    }
}

#endregion

#region ADVANCED THREAT CORRELATION

function Calculate-RiskScore {
    param([object]$ScanData)
    
    $baseScore = 0
    
    # Scoring by severity
    $criticalCount = ($ScanData.AllFindings | Where-Object { $_.Severidad -eq 'CRITICA' } | Measure-Object).Count
    $highCount = ($ScanData.AllFindings | Where-Object { $_.Severidad -eq 'ALTA' } | Measure-Object).Count
    $mediumCount = ($ScanData.AllFindings | Where-Object { $_.Severidad -eq 'MEDIA' } | Measure-Object).Count
    
    $baseScore = ($criticalCount * 40) + ($highCount * 20) + ($mediumCount * 10)
    
    # Additional factors
    if ($ScanData.RunCount -gt 10) { $baseScore += 15 }  # Frequent execution
    if ($ScanData.LoadedDLLs.Count -gt 5) { $baseScore += 10 }  # Many DLLs loaded
    if ($ScanData.Registry -and $ScanData.Registry.Count -gt 0) { $baseScore += 25 }  # Registry modifications
    if ($ScanData.NetworkActivity -and $ScanData.NetworkActivity.Count -gt 0) { $baseScore += 30 }  # Network activity
    if ($ScanData.MemoryInjection -and $ScanData.MemoryInjection.Count -gt 0) { $baseScore += 35 }  # Memory injection
    if ($ScanData.Persistence -and $ScanData.Persistence.Count -gt 0) { $baseScore += 25 }  # Persistence mechanisms
    
    # Cap at 100
    $finalScore = [Math]::Min($baseScore, 100)
    
    return $finalScore
}

function Get-RiskAssessment {
    param([int]$RiskScore)
    
    switch ($RiskScore) {
        { $_ -ge 90 } { return @{ 'Level' = 'CRITICO'; 'Color' = 'Red'; 'Action' = 'Acción inmediata requerida' } }
        { $_ -ge 70 } { return @{ 'Level' = 'ALTO'; 'Color' = 'Yellow'; 'Action' = 'Investigación urgente' } }
        { $_ -ge 50 } { return @{ 'Level' = 'MEDIO'; 'Color' = 'Magenta'; 'Action' = 'Monitoreo recomendado' } }
        { $_ -ge 30 } { return @{ 'Level' = 'BAJO'; 'Color' = 'Cyan'; 'Action' = 'Revisión aconsejable' } }
        default { return @{ 'Level' = 'MINIMO'; 'Color' = 'Green'; 'Action' = 'Sin riesgos detectados' } }
    }
}

#endregion

#region REPORTING

function Format-ScanResults {
    param([object[]]$ScanData)
    
    $results = @()
    
    foreach ($scan in $ScanData) {
        $totalFindings = $scan.AllFindings.Count
        $riskScore = $scan.RiskScore
        $riskAssessment = Get-RiskAssessment -RiskScore $riskScore
        
        if ($totalFindings -eq 0) {
            $maxSeverity = "NINGUNA"
            $status = "✓ Limpio"
        } else {
            $severities = $scan.AllFindings | ForEach-Object { $_.Severidad } | Sort-Object {
                switch ($_) {
                    'CRITICA' { 0 }
                    'ALTA' { 1 }
                    'MEDIA' { 2 }
                    'BAJA' { 3 }
                    default { 4 }
                }
            }
            $maxSeverity = $severities[0]
            $status = "⚠ Sospechoso"
        }
        
        $results += [PSCustomObject]@{
            'Proceso'             = $scan.Proceso
            'Estado'              = $status
            'Hallazgos'           = $totalFindings
            'Severidad'           = $maxSeverity
            'Puntuacion_riesgo'   = $riskScore
            'Nivel_riesgo'        = $riskAssessment.Level
            'Ejecuciones'         = $scan.RunCount
            'Ultima_ejecucion'    = $scan.LastRunTime
            'Dlls_cargadas'       = $scan.LoadedDLLs.Count
            'Archivos_cargados'   = $scan.LoadedFiles.Count
            'Inyecciones_memoria' = ($scan.MemoryInjection | Measure-Object).Count
            'Actividad_red'       = ($scan.NetworkActivity | Measure-Object).Count
            'Persistencia'        = ($scan.Persistence | Measure-Object).Count
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
            'GeneratedAt'       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            'ComputerName'      = $env:COMPUTERNAME
            'UserName'          = $env:USERNAME
            'TotalProcesses'    = $ScanData.Count
            'TotalFindings'     = ($ScanData | ForEach-Object { $_.AllFindings.Count } | Measure-Object -Sum).Sum
            'HighestRiskScore'  = ($ScanData | ForEach-Object { $_.RiskScore } | Measure-Object -Maximum).Maximum
            'Scans'             = $ScanData
        }
        
        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
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
    
    $totalFindings = ($ScanData | ForEach-Object { $_.AllFindings.Count } | Measure-Object -Sum).Sum
    $totalCritical = ($ScanData | ForEach-Object { $_.AllFindings | Where-Object { $_.Severidad -eq 'CRITICA' } } | Measure-Object).Count
    $totalHigh = ($ScanData | ForEach-Object { $_.AllFindings | Where-Object { $_.Severidad -eq 'ALTA' } } | Measure-Object).Count
    $avgRiskScore = [Math]::Round(($ScanData | ForEach-Object { $_.RiskScore } | Measure-Object -Average).Average, 2)
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Prefetch Analyzer Elite - Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .content {
            padding: 40px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-left: 5px solid #667eea;
            transition: transform 0.3s ease;
        }
        .summary-card:hover {
            transform: translateY(-5px);
        }
        .summary-card.critical {
            border-left-color: #dc3545;
            background: rgba(220, 53, 69, 0.05);
        }
        .summary-card.high {
            border-left-color: #ff6b6b;
            background: rgba(255, 107, 107, 0.05);
        }
        .summary-card.medium {
            border-left-color: #ffc107;
            background: rgba(255, 193, 7, 0.05);
        }
        .summary-card h3 {
            color: #333;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            opacity: 0.7;
        }
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .summary-card.critical .value {
            color: #dc3545;
        }
        .summary-card.high .value {
            color: #ff6b6b;
        }
        .summary-card.medium .value {
            color: #ffc107;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th {
            background-color: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        tr:last-child td {
            border-bottom: none;
        }
        .critical { 
            color: #dc3545; 
            font-weight: bold;
            background: rgba(220, 53, 69, 0.1);
        }
        .high { 
            color: #ff6b6b; 
            font-weight: bold;
            background: rgba(255, 107, 107, 0.1);
        }
        .medium { 
            color: #ffc107; 
            font-weight: bold;
        }
        .low { 
            color: #28a745;
        }
        .clean { 
            color: #28a745; 
            font-weight: bold;
        }
        .suspicious { 
            color: #dc3545; 
            font-weight: bold;
        }
        .finding {
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            transition: all 0.3s ease;
        }
        .finding.critical {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        .finding.high {
            background: #ffebee;
            border-left-color: #ff6b6b;
        }
        .finding:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .finding strong {
            display: block;
            margin-bottom: 5px;
        }
        .footer {
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e9ecef;
            color: #666;
        }
        .risk-meter {
            width: 100%;
            height: 10px;
            background: #e9ecef;
            border-radius: 5px;
            overflow: hidden;
            margin: 10px 0;
        }
        .risk-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #ffc107, #dc3545);
        }
        .process-detail {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Prefetch Analyzer Elite v3.0</h1>
            <p>Informe Forense Avanzado de Ejecución de Procesos</p>
        </div>
        
        <div class="content">
            <div class="summary-grid">
                <div class="summary-card critical">
                    <h3>Hallazgos Totales</h3>
                    <div class="value">$totalFindings</div>
                </div>
                <div class="summary-card critical">
                    <h3>Críticos</h3>
                    <div class="value">$totalCritical</div>
                </div>
                <div class="summary-card high">
                    <h3>Altos</h3>
                    <div class="value">$totalHigh</div>
                </div>
                <div class="summary-card medium">
                    <h3>Puntuación Promedio</h3>
                    <div class="value">$avgRiskScore</div>
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Resumen Ejecutivo</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Proceso</th>
                            <th>Estado</th>
                            <th>Hallazgos</th>
                            <th>Severidad</th>
                            <th>Puntuación</th>
                            <th>Ejecuciones</th>
                            <th>Inyecciones</th>
                            <th>Red</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    
    foreach ($result in $FormattedResults) {
        $statusClass = if ($result.Estado -like "*Sospechoso*") { "suspicious" } else { "clean" }
        $severityClass = $result.Severidad.ToLower()
        
        $htmlContent += @"
                        <tr>
                            <td><strong>$($result.Proceso)</strong></td>
                            <td class="$statusClass">$($result.Estado)</td>
                            <td>$($result.Hallazgos)</td>
                            <td class="$severityClass">$($result.Severidad)</td>
                            <td>
                                <div class="risk-meter">
                                    <div class="risk-fill" style="width: $($result.Puntuacion_riesgo)%"></div>
                                </div>
                                $($result.Puntuacion_riesgo)
                            </td>
                            <td>$($result.Ejecuciones)</td>
                            <td>$($result.Inyecciones_memoria)</td>
                            <td>$($result.Actividad_red)</td>
                        </tr>
"@
    }
    
    $htmlContent += @"
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🔎 Hallazgos Detallados</h2>
"@
    
    foreach ($scan in $ScanData) {
        if ($scan.AllFindings.Count -gt 0) {
            $htmlContent += @"
                <div class="process-detail">
                    <h3>$($scan.Proceso)</h3>
                    <p><strong>Ejecuciones:</strong> $($scan.RunCount) | <strong>Última:</strong> $($scan.LastRunTime)</p>
"@
            
            foreach ($finding in $scan.AllFindings) {
                $findingClass = $finding.Severidad.ToLower()
                $htmlContent += @"
                    <div class="finding $findingClass">
                        <strong>[$($finding.Severidad)]</strong> $($finding.Tipo)<br>
                        $($finding.Detalle)
                    </div>
"@
            }
            
            $htmlContent += "</div>"
        }
    }
    
    $htmlContent += @"
            </div>
            
            <div class="footer">
                <p><strong>Prefetch Analyzer Elite v3.0</strong></p>
                <p>Equipo: $computerName | Usuario: $userName</p>
                <p>Generado: $timestamp</p>
                <p style="margin-top: 20px; font-size: 0.9em; opacity: 0.7;">
                    Este informe contiene información clasificada y sensible. Está destinado únicamente para el uso autorizado.
                </p>
            </div>
        </div>
    </div>
</body>
</html>
"@
    
    try {
        $htmlContent | Out-File -FilePath $Path -Encoding UTF8 -ErrorAction Stop
        Write-Host "✓ Reporte HTML generado: $Path" -ForegroundColor Green
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
    Write-Warning 'Ejecute el script como Administrador.'
    Start-Sleep -Seconds 5
    exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

# Get PECmd tool
$pecmdPath = Get-PECmdTool
if (-not $pecmdPath) {
    Write-Error "No se puede continuar sin PECmd.exe"
    exit
}

Write-Host ""
Write-Host "Iniciando análisis avanzado de Prefetch..." -ForegroundColor Cyan

# Get boot time
$bootTime = Get-BootTime
Write-Host "Última vez de arranque: $bootTime" -ForegroundColor Gray

# Get threat signatures
$threats = Get-ThreatSignatures

# Get prefetch files
$prefetchFiles = Get-PrefetchFiles -ProcessNames $ProcessNames -PrefetchPath $PrefetchPath

if ($prefetchFiles.Count -eq 0) {
    Write-Host "No se encontraron archivos Prefetch para: $($ProcessNames -join ', ')" -ForegroundColor Yellow
    exit
}

Write-Host "Archivos Prefetch encontrados: $($prefetchFiles.Count)" -ForegroundColor Green
Write-Host ""

# Process each prefetch file
$scanResults = @()
$progressCount = 0

foreach ($pfFile in $prefetchFiles) {
    $progressCount++
    $processName = $pfFile.Name -replace '\.pf$'
    Write-Host "[$progressCount/$($prefetchFiles.Count)] Analizando: $($pfFile.Name)" -ForegroundColor Yellow
    
    # Parse prefetch
    $pecmdOutput = Parse-PrefetchFile -PrefetchFilePath $pfFile.FullName -PECmdPath $pecmdPath
    $metadata = Extract-PrefetchMetadata -PECmdOutput $pecmdOutput -FileName $pfFile.Name
    
    # Initialize findings array
    $allFindings = @()
    
    # Threat analysis on executable
    $executableFindings = Test-FileForThreats -FilePath $pfFile.FullName -Signatures $threats
    $allFindings += @($executableFindings)
    
    # Threat analysis on loaded DLLs
    if ($AnalyzeDLLs -and $metadata.LoadedDLLs.Count -gt 0) {
        Write-Host "  ├─ Analizando $($metadata.LoadedDLLs.Count) DLLs cargadas..." -ForegroundColor Gray
        $dllFindings = Analyze-LoadedDLLs -DLLs $metadata.LoadedDLLs -Signatures $threats
        $allFindings += @($dllFindings)
    }
    
    # Registry injection detection
    $registryFindings = @()
    if ($DetectRegistryInjection) {
        Write-Host "  ├─ Detectando inyecciones en registro..." -ForegroundColor Gray
        $registryFindings = Detect-RegistryInjections -ProcessName $processName
        $allFindings += @($registryFindings)
    }
    
    # Network activity detection
    $networkFindings = @()
    if ($LogNetworkActivity) {
        Write-Host "  ├─ Analizando actividad de red..." -ForegroundColor Gray
        $networkFindings = Detect-NetworkActivity -ProcessName $processName
        $allFindings += @($networkFindings)
    }
    
    # Memory injection detection
    $memoryFindings = @()
    if ($AnalyzeMemory) {
        Write-Host "  ├─ Detectando inyecciones de memoria..." -ForegroundColor Gray
        $memoryFindings = Detect-MemoryInjection -ProcessName $processName
        $allFindings += @($memoryFindings)
    }
    
    # Process tree analysis
    $treeFindings = @()
    if ($ProcessTreeAnalysis) {
        Write-Host "  ├─ Analizando árbol de procesos..." -ForegroundColor Gray
        $treeFindings = Build-ProcessTree -ProcessName $processName
        $allFindings += @($treeFindings)
    }
    
    # Persistence detection
    $persistenceFindings = @()
    if ($DetectPersistence) {
        Write-Host "  ├─ Detectando mecanismos de persistencia..." -ForegroundColor Gray
        $persistenceFindings = Detect-PersistenceMechanisms -ProcessName $processName
        $allFindings += @($persistenceFindings)
    }
    
    # Calculate risk score
    $scanObject = [PSCustomObject]@{
        'Proceso'           = $processName
        'RunCount'          = $metadata.RunCount
        'LastRunTime'       = $metadata.LastRunTime
        'CommandLine'       = $metadata.CommandLine
        'LoadedDLLs'        = $metadata.LoadedDLLs
        'LoadedFiles'       = $metadata.LoadedFiles
        'AllFindings'       = @($allFindings)
        'Registry'          = @($registryFindings)
        'NetworkActivity'   = @($networkFindings)
        'MemoryInjection'   = @($memoryFindings)
        'ProcessTree'       = @($treeFindings)
        'Persistence'       = @($persistenceFindings)
    }
    
    $scanObject | Add-Member -NotePropertyName 'RiskScore' -NotePropertyValue (Calculate-RiskScore -ScanData $scanObject)
    
    $scanResults += $scanObject
    
    # Display risk score
    $riskAssessment = Get-RiskAssessment -RiskScore $scanObject.RiskScore
    Write-Host "  └─ Hallazgos: $($allFindings.Count) | Puntuación: $($scanObject.RiskScore) [$($riskAssessment.Level)]" -ForegroundColor $riskAssessment.Color
}

# Format results
$formatted = Format-ScanResults -ScanData $scanResults

# Display results
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
    $formatted | Out-GridView -Title "Prefetch Analyzer Elite - Análisis Forense Avanzado"
} else {
    $formatted | Format-Table -AutoSize -Wrap
}

# Export options
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
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "✔ Análisis completado en $([math]::Round($sw.Elapsed.TotalSeconds, 2)) segundos." -ForegroundColor Green
Write-Host "Escaneo completado: $($scanResults.Count) procesos analizados" -ForegroundColor Green
Write-Host "Hallazgos totales: $(($scanResults | ForEach-Object { $_.AllFindings.Count } | Measure-Object -Sum).Sum)" -ForegroundColor Yellow
Write-Host ""

#endregion
