Clear-Host

function Mostrar-Menu {
    Write-Host ""
    Write-Host "======= MENÚ DE SCRIPTS ========" -ForegroundColor DarkGreen
    Write-Host "1. Prefetch analyzer"
    Write-Host "2. Bamparser"
    Write-Host "3. Prefetch analyzer 2"
    Write-Host "4. Jarparser 2"
    Write-Host "0. Salir"
    Write-Host "===============================" -ForegroundColor DarkGreen
}

function Ejecutar-Script($url) {
    try {
        $tempPath = "$env:TEMP\temp_script_$(Get-Random).ps1"
        Invoke-WebRequest -Uri $url -OutFile $tempPath -UseBasicParsing
        Write-Host ""
        Write-Host "--- Ejecutando script ---" -ForegroundColor DarkBlue
        Write-Host ""

        . $tempPath

        Remove-Item $tempPath -Force
    }
    catch {
        Write-Host "`n✖ Fallo al usar script:`n$($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

$seguir = $true

do {
    Mostrar-Menu
    $opcion = Read-Host "Selecciona una opción (0-4)"

    switch ($opcion) {
        '1' { Ejecutar-Script "https://raw.githubusercontent.com/Vaquerow/Luvi-SS/refs/heads/main/Jarparser.ps1" }
        '2' { Ejecutar-Script "https://raw.githubusercontent.com/Vaquerow/Luvi-SS/refs/heads/main/Bamparser.ps1" }
        '3' { Ejecutar-Script "https://raw.githubusercontent.com/Vaquerow/Luvi-SS/refs/heads/main/prefetchparser.ps1" }
        '4' { Ejecutar-Script "https://raw.githubusercontent.com/Vaquerow/Luvi-SS/refs/heads/main/jarparser2.ps1" }
        '0' {
            Write-Host "Saliendo, Adios!" -ForegroundColor DarkGreen
            $seguir = $false
        }
        default {
            Write-Host "Opción inválida. Intenta de nuevo." -ForegroundColor DarkRed
        }
    }

    if ($seguir) {
        Write-Host ""
        Write-Host "Pulsa Enter para seguir"
        [void][System.Console]::ReadLine()
    }

} while ($seguir)
