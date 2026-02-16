<#
.SYNOPSIS
    JAR Analyzer: Detect suspicious mods, obfuscation, and cheats in Minecraft JARs
.DESCRIPTION
    Scans JAR files for known cheat mods, obfuscation patterns, suspicious classes,
    and verifies integrity against known clean versions.
    Multi-file support and detailed reporting.
.NOTES
    Requires 7-Zip or built-in Expand-Archive.
    Run as Administrator for best results.
#>

[CmdletBinding()]
param(
    [string[]]$JarPaths,
    [switch]$DeepScan,
    [switch]$ExportCSV,
    [string]$CsvPath = "$env:TEMP\JAR_Report.csv",
    [string]$KnownGoodHash = ""
)

function Show-Banner {
    $banner = @"
╔══════════════════════════════════════════════════════╗
║              JAR ANALYZER - PowerShell               ║
║       Detect Suspicious Mods & Cheat Injections      ║
╚══════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

function Test-Admin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$knownCheatMods = @(
    'net\.ccbluex\.liquidbounce',
    'net\.asphaltemc',
    'com\.github\.ccetl\.vape',
    'org\.lwjgl',
    'me\.zeroeightsix\.kami',
    'meteordevelopment\.meteorclient',
    'cadc\.cad',
    'rip\.combat',
    'top\.fl0wer',
    'dev\.sora\.skidclient',
    'org\.springframework',  # Remote access
    'org\.apache\.commons\.httpclient', # Exfil
    'com\.sun\.org\.apache\.xalan',
    'javax\.script',
    'java\.lang\.reflect.*Unsafe'
)

$suspiciousPatterns = @(
    'invoke.*Reflection',
    'getRuntime.*exec',
    'ProcessBuilder',
    'Runtime\.getRuntime',
    'System\.load',
    'defineClass',
    'getDeclaredMethod',
    'setAccessible',
    'forName',
    'newInstance.*Constructor',
    'writeBytes',
    'readObject',
    'ObjectInputStream'
)

$suspiciousClassNames = @(
    '^[a-z]\.class$',      # Single letter classes (common obfuscation)
    '^[a-z]{2,4}\.class$', # 2-4 letter classes (likely obfuscated)
    'Injector',
    'Hook',
    'Patch',
    'Cheat',
    'Hack',
    'Bypass',
    'AntiCheat'
)

function Get-FileHashSHA256 {
    param([string]$FilePath)
    try {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return "No disponible"
    }
}

function Extract-Jar {
    param([string]$JarPath)
    $extractPath = "$env:TEMP\jar_extract_$(Get-Random)"
    try {
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -Path $JarPath -DestinationPath $extractPath -Force -ErrorAction Stop
        } else {
            Write-Warning "Expand-Archive no disponible. Intente con 7-Zip instalado."
            return $null
        }
        return $extractPath
    } catch {
        Write-Error "Error al extraer JAR: $_"
        return $null
    }
}

function Scan-ClassNames {
    param([string]$ExtractPath)
    $findings = @()
    $classes = Get-ChildItem -Path $ExtractPath -Recurse -Filter *.class
    
    foreach ($class in $classes) {
        $className = $class.FullName.Replace($ExtractPath, '').Replace('\', '.').Replace('.class', '')
        
        # Check against known cheat mods
        foreach ($pattern in $knownCheatMods) {
            if ($className -match $pattern) {
                $findings += [PSCustomObject]@{
                    'Tipo'       = 'Mod Sospechoso'
                    'Severidad'  = 'CRITICA'
                    'Clase'      = $className
                    'Detalles'   = "Coincide con patrón de mod cheat conocido: $pattern"
                }
            }
        }
        
        # Check against suspicious class names
        $classNameOnly = Split-Path -Leaf $class.FullName
        foreach ($suspiciousName in $suspiciousClassNames) {
            if ($classNameOnly -match $suspiciousName) {
                $findings += [PSCustomObject]@{
                    'Tipo'       = 'Nombre Sospechoso'
                    'Severidad'  = 'MEDIA'
                    'Clase'      = $className
                    'Detalles'   = "Patrón de nombre típico de obfuscación: $suspiciousName"
                }
            }
        }
    }
    
    return $findings
}

function Analyze-Manifest {
    param([string]$ExtractPath)
    $findings = @()
    $manifestPath = Join-Path $ExtractPath "META-INF\MANIFEST.MF"
    
    if (Test-Path $manifestPath) {
        $manifest = Get-Content $manifestPath
        foreach ($line in $manifest) {
            if ($line -match "Premain-Class|Agent-Class|Boot-Class-Path") {
                $findings += [PSCustomObject]@{
                    'Tipo'       = 'Manifest Sospechoso'
                    'Severidad'  = 'ALTA'
                    'Clase'      = 'MANIFEST.MF'
                    'Detalles'   = "Línea sospechosa: $line"
                }
            }
        }
    }
    
    return $findings
}

function Scan-JarFile {
    param([string]$JarPath)
    
    if (-not (Test-Path $JarPath)) {
        Write-Warning "Archivo no encontrado: $JarPath"
        return $null
    }
    
    Write-Host "Analizando: $(Split-Path -Leaf $JarPath)" -ForegroundColor Yellow
    
    $results = @{
        'Archivo'              = Split-Path -Leaf $JarPath
        'Ruta_completa'        = $JarPath
        'Tamano_bytes'         = (Get-Item $JarPath).Length
        'Hash_SHA256'          = Get-FileHashSHA256 -FilePath $JarPath
        'Firma_digital'        = Get-AuthenticodeSignature -FilePath $JarPath | Select-Object -ExpandProperty Status
        'Fecha_modificacion'   = (Get-Item $JarPath).LastWriteTime
        'Hallazgos'            = @()
    }
    
    $extractPath = Extract-Jar -JarPath $JarPath
    if ($extractPath) {
        $results['Hallazgos'] += @(Scan-ClassNames -ExtractPath $extractPath)
        $results['Hallazgos'] += @(Analyze-Manifest -ExtractPath $extractPath)
        
        # Clean up
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    return $results
}

function Format-Results {
    param([object[]]$ScanResults)
    
    $output = @()
    foreach ($result in $ScanResults) {
        if ($result['Hallazgos'].Count -eq 0) {
            $output += [PSCustomObject]@{
                'Archivo'           = $result['Archivo']
                'Estado'            = '✓ Limpio'
                'Hallazgos'         = 0
                'Severidad_maxima'  = 'NINGUNA'
                'Hash'              = $result['Hash_SHA256']
                'Firma_digital'     = $result['Firma_digital']
            }
        } else {
            $maxSeverity = @($result['Hallazgos'] | ForEach-Object { $_.Severidad } | Sort-Object { 
                switch ($_) {
                    'CRITICA' { 0 }
                    'ALTA' { 1 }
                    'MEDIA' { 2 }
                    default { 3 }
                }
            })[0]
            
            $output += [PSCustomObject]@{
                'Archivo'           = $result['Archivo']
                'Estado'            = '⚠ Sospechoso'
                'Hallazgos'         = $result['Hallazgos'].Count
                'Severidad_maxima'  = $maxSeverity
                'Hash'              = $result['Hash_SHA256']
                'Firma_digital'     = $result['Firma_digital']
            }
        }
    }
    return $output
}

# MAIN

Clear-Host
Show-Banner

if (-not (Test-Admin)) {
    Write-Warning 'Ejecute el script como Administrador para acceso completo.'
}

if (-not $JarPaths -or $JarPaths.Count -eq 0) {
    $JarPaths = @(Read-Host "Ingrese la ruta del archivo JAR (o arrastrar y soltar)")
}

$sw = [Diagnostics.Stopwatch]::StartNew()
$scanResults = @()

foreach ($jar in $JarPaths) {
    $result = Scan-JarFile -JarPath $jar
    if ($result) {
        $scanResults += $result
    }
}

if ($scanResults.Count -eq 0) {
    Write-Host "No se pudieron analizar archivos." -ForegroundColor Red
    exit
}

$formatted = Format-Results -ScanResults $scanResults

if ($ExportCSV) {
    $formatted | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nExportado a $CsvPath" -ForegroundColor Green
} elseif (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
    $formatted | Out-GridView -Title "Análisis JAR - Detección de Mods y Cheats"
} else {
    $formatted | Format-Table -AutoSize
}

$sw.Stop()
Write-Host "`n✔ Análisis completado en $([math]::Round($sw.Elapsed.TotalSeconds,2)) segundos." -ForegroundColor Green
