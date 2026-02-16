Clear-Host
$SS = @"

.____     ____ _______   ____.______________________    _____  ______________________
|    |   |    |   \   \ /   /|   \_   ___ \______   \  /  _  \ \_   _____/\__    ___/
|    |   |    |   /\   Y   / |   /    \  \/|       _/ /  /_\  \ |    __)    |    |   
|    |___|    |  /  \     /  |   \     \___|    |   \/    |    \|     \     |    |   
|_______ \______/    \___/   |___|\______  /____|_  /\____|__  /\___  /     |____|   
        \/                               \/       \/         \/     \/               
"@
Write-Host $SS -ForegroundColor Yellow

$pecmdUrl = "https://github.com/NoDiff-del/JARs/releases/download/Jar/PECmd.exe"
$pecmdPath = "$env:TEMP\PECmd.exe"

Invoke-WebRequest -Uri $pecmdUrl -OutFile $pecmdPath -UseBasicParsing

$logonTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$prefetchFolder = "C:\\Windows\\Prefetch"
$files = Get-ChildItem -Path $prefetchFolder -Filter *.pf | Where-Object {
    ($_.Name -match "java|javaw") -and ($_.LastWriteTime -gt $logonTime)
} | Sort-Object LastWriteTime -Descending

if ($files.Count -gt 0) {
    Write-Host "Archivos PF encontrados despues de login, ordenados por fecha de modificacion" -ForegroundColor DarkMagenta
    $files | ForEach-Object {
        Write-Host " "
        Write-Host "Analizando: $($_.Name)" -ForegroundColor DarkCyan
        Write-Host "Última modificación del .pf: $($_.LastWriteTime)" -ForegroundColor DarkCyan

        try {
            $pecmdOutput = & $pecmdPath -f $_.FullName
        } catch {
            Write-Warning "Error ejecutando PECmd.exe en $($_.Name): $_"
            return
        }

        $filteredImports = $pecmdOutput

        if ($filteredImports.Count -gt 0) {
            Write-Host "Imports encontrados:" -ForegroundColor White
            foreach ($lineRaw in $filteredImports) {
                if ($lineRaw -notmatch '\\VOLUME|:\\\\') {
                    continue
                }

                $line = $lineRaw
                if ($line -match '\\VOLUME{(.+?)}') {
                    $line = $line -replace '\\VOLUME{(.+?)}', 'C:'
                }
                $line = $line -replace '^\d+: ', ''
                $line = $line.Trim()

                if ($line -match '\\[^\\]+\.[^\\]+$' -and (Test-Path $line)) {
                    $sig = Get-AuthenticodeSignature -FilePath $line -ErrorAction SilentlyContinue
                    if ($sig.Status -ne 'Valid') {
                        Write-Host "[SIN FIRMA] $line" -ForegroundColor DarkRed
                    }
                } elseif ($line -match '\\[^\\]+\.[^\\]+$') {
                    Write-Host "[NO EXISTE] $line" -ForegroundColor White
                }
            }
        } else {
            Write-Host "No se encontraron imports para el archivo $($_.Name)." -ForegroundColor DarkRed
        }
    }
} else {
    Write-Host "No hay archivos PF modificados despues del login para java.exe o javaw.exe" -ForegroundColor DarkRed
}
