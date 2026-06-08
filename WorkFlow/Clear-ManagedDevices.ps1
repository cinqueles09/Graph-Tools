# ==============================================================================
# SCRIPT DE MANTENIMIENTO: INTUNE & ENTRA ID
# ==============================================================================
<#
.SYNOPSIS
    Script de mantenimiento avanzado para entornos Microsoft Intune y Entra ID.

.DESCRIPTION
    Conecta con Microsoft Graph API mediante credenciales de App Registration
    para ejecutar las siguientes tareas de limpieza y analisis:

      1. Cruce de inventarios entre Intune y Entra ID.
      2. Identificacion y borrado de dispositivos inactivos (por fecha limite).
      3. Deteccion y eliminacion de dispositivos "huerfanos" (Windows y Apple).
      4. Analisis de dispositivos Workplace y MDM Office 365 Mobile.
      5. Eliminacion de duplicados en Intune por numero de serie.
      6. Exportacion automatica de reportes CSV y fichero de log.

    Todas las operaciones destructivas requieren confirmacion explicita del
    operador. Cada accion queda registrada en el fichero de log de sesion.

.PARAMETER TenantId
    Directory (Tenant) ID del inquilino de Azure AD.

.PARAMETER AppId
    Application (Client) ID del registro de aplicacion en Azure AD.

.PARAMETER ClientSecret
    Secreto de cliente generado para el App Registration (SecureString).

.NOTES
    Autor:         Ismael Morilla / ST05
    Fecha:         2025-12-23
    Version:       7.0
    Requisitos:    App Registration en Azure con permisos de Aplicacion:
                     - Device.ReadWrite.All
                     - DeviceManagementManagedDevices.ReadWrite.All

.LINK
    https://github.com/cinqueles09/Graph-Tools
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ==============================================================================
# REGION: CONSTANTES Y CONFIGURACION GLOBAL
# ==============================================================================
$Script:VERSION        = "7.0"
$Script:GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
$Script:AUTH_URL_BASE  = "https://login.microsoftonline.com"
$Script:GRAPH_SCOPE    = "https://graph.microsoft.com/.default"

# Rutas de sesion (se asignan tras crear el directorio de trabajo)
$Script:LogPath  = $null
$Script:BasePath = $null

# Contadores de sesion
$Script:Stats = [ordered]@{
    EliminadosIntune  = 0
    EliminadosEntraID = 0
    ErroresEliminacion = 0
    Saltados          = 0
}

# ==============================================================================
# REGION: FUNCIONES AUXILIARES
# ==============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Escribe un mensaje formateado en consola y en el fichero de log.
    .PARAMETER Message
        Texto del mensaje.
    .PARAMETER Level
        Nivel del mensaje: INFO, OK, WARN, ERROR, SECTION, HEADER.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO","OK","WARN","ERROR","SECTION","HEADER","DEBUG")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $colorMap = @{
        INFO    = "Gray"
        OK      = "Green"
        WARN    = "Yellow"
        ERROR   = "Red"
        SECTION = "Cyan"
        HEADER  = "White"
        DEBUG   = "DarkGray"
    }

    $prefixMap = @{
        INFO    = " >> "
        OK      = " OK "
        WARN    = " !! "
        ERROR   = " XX "
        SECTION = " ** "
        HEADER  = "    "
        DEBUG   = " .. "
    }

    $prefix = $prefixMap[$Level]
    $color  = $colorMap[$Level]
    $line   = "$timestamp  $prefix  $Message"

    Write-Host -NoNewline "  "
    Write-Host -NoNewline "$timestamp " -ForegroundColor DarkGray
    Write-Host -NoNewline "[$prefix]" -ForegroundColor $color
    Write-Host "  $Message" -ForegroundColor $color

    if ($Script:LogPath) {
        Add-Content -Path $Script:LogPath -Value $line -Encoding UTF8
    }
}

function Write-Separator {
    <#
    .SYNOPSIS
        Escribe una linea separadora visual en consola y en el log.
    .PARAMETER Style
        'Double' para seccion principal, 'Single' para subseccion.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Double","Single")]
        [string]$Style = "Single"
    )

    if ($Style -eq "Double") {
        $line = "+" + ("=" * 70) + "+"
    } else {
        $line = "+" + ("-" * 70) + "+"
    }
    Write-Host $line -ForegroundColor DarkCyan
    if ($Script:LogPath) {
        Add-Content -Path $Script:LogPath -Value $line -Encoding UTF8
    }
}

function Write-SectionHeader {
    <#
    .SYNOPSIS
        Muestra un encabezado de seccion con formato destacado.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        [string]$Subtitle = "",
        [string]$Color = "Cyan"
    )

    Write-Host ""
    Write-Host ("  +" + ("=" * 68) + "+") -ForegroundColor $Color
    Write-Host ("  |  " + $Title.ToUpper().PadRight(66) + "|") -ForegroundColor White
    if ($Subtitle) {
        Write-Host ("  |  " + $Subtitle.PadRight(66) + "|") -ForegroundColor Gray
    }
    Write-Host ("  +" + ("=" * 68) + "+") -ForegroundColor $Color
    Write-Host ""
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Ejecuta una peticion a Microsoft Graph con reintentos automaticos
        ante errores transitorios y respeto de rate-limiting (HTTP 429).
    .PARAMETER Uri
        URL completa del endpoint de Graph.
    .PARAMETER Method
        Metodo HTTP: GET, DELETE, POST, PATCH.
    .PARAMETER Body
        Cuerpo opcional de la peticion (para POST/PATCH).
    .PARAMETER MaxRetries
        Numero maximo de reintentos (por defecto 3).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet("GET","DELETE","POST","PATCH")]
        [string]$Method = "GET",

        [hashtable]$Body = $null,

        [int]$MaxRetries = 3
    )

    $attempt = 0
    while ($attempt -le $MaxRetries) {
        try {
            $params = @{
                Uri     = $Uri
                Headers = $Script:Headers
                Method  = $Method
            }
            if ($Body) {
                $params.Body        = ($Body | ConvertTo-Json -Depth 10)
                $params.ContentType = "application/json"
            }

            $response = Invoke-RestMethod @params
            return $response
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) { $statusCode = $_.Exception.Response.StatusCode.value__ }

            if ($statusCode -eq 429) {
                # Rate limit: esperar el tiempo indicado por la API o 30s por defecto
                $retryAfter = 30
                try {
                    $retryHeader = $_.Exception.Response.Headers["Retry-After"]
                    if ($retryHeader) { $retryAfter = [int]$retryHeader }
                }
                catch {}

                Write-Log "Rate limit alcanzado. Esperando $retryAfter segundos..." -Level WARN
                Start-Sleep -Seconds $retryAfter
                $attempt++
                continue
            }
            elseif ($statusCode -in @(500, 502, 503, 504) -and $attempt -lt $MaxRetries) {
                # Error transitorio del servidor
                $waitSeconds = [math]::Pow(2, $attempt) * 2
                Write-Log "Error transitorio ($statusCode). Reintento $($attempt+1)/$MaxRetries en $waitSeconds s..." -Level WARN
                Start-Sleep -Seconds $waitSeconds
                $attempt++
                continue
            }
            else {
                throw
            }
        }
    }
    throw "Se superaron los $MaxRetries reintentos para: $Uri"
}

function Get-AllGraphPages {
    <#
    .SYNOPSIS
        Recupera de forma paginada todos los registros de un endpoint de Graph.
    .PARAMETER InitialUrl
        URL inicial del endpoint (puede incluir filtros y selectores OData).
    .PARAMETER EntityName
        Nombre descriptivo de la entidad (para el mensaje de progreso).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InitialUrl,

        [string]$EntityName = "registros"
    )

    $allItems = [System.Collections.Generic.List[object]]::new()
    $url      = $InitialUrl
    $page     = 1

    do {
        Write-Progress -Activity "Extrayendo $EntityName" `
                       -Status "Pagina $page -- $($allItems.Count) obtenidos..." `
                       -PercentComplete -1

        $response = Invoke-GraphRequest -Uri $url -Method GET
        if ($response.value) {
            $allItems.AddRange([object[]]$response.value)
        }

        # Acceso seguro: @odata.nextLink no existe en la ultima pagina
        $url = $null
        if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $url = $response.'@odata.nextLink'
        }
        $page++
    } while ($url)

    Write-Progress -Activity "Extrayendo $EntityName" -Completed
    return $allItems
}

function Remove-IntuneDevice {
    <#
    .SYNOPSIS
        Elimina un dispositivo de Microsoft Intune y opcionalmente de Entra ID.
    .PARAMETER Device
        Objeto de dispositivo de Intune (debe contener: id, deviceName, azureADDeviceId).
    .PARAMETER AlsoRemoveFromEntraID
        Si es $true, tambien elimina el objeto correspondiente en Entra ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Device,

        [bool]$AlsoRemoveFromEntraID = $true
    )

    $name = $Device.deviceName

    # Eliminar de Intune
    if ($Device.id) {
        try {
            Invoke-GraphRequest -Uri "$Script:GRAPH_BASE_URL/deviceManagement/managedDevices/$($Device.id)" -Method DELETE
            Write-Log "[$name] Eliminado de Intune correctamente." -Level OK
            $Script:Stats.EliminadosIntune++
        }
        catch {
            Write-Log "[$name] Error al eliminar de Intune: $($_.Exception.Message)" -Level ERROR
            $Script:Stats.ErroresEliminacion++
        }
    }

    # Eliminar de Entra ID
    if ($AlsoRemoveFromEntraID -and $Device.azureADDeviceId) {
        $aadDevice = $Script:AllDevicesAAD | Where-Object { $_.deviceId -eq $Device.azureADDeviceId }
        if ($aadDevice) {
            try {
                Invoke-GraphRequest -Uri "$Script:GRAPH_BASE_URL/devices/$($aadDevice.id)" -Method DELETE
                Write-Log "[$name] Eliminado de Entra ID correctamente." -Level OK
                $Script:Stats.EliminadosEntraID++
            }
            catch {
                Write-Log "[$name] Error al eliminar de Entra ID: $($_.Exception.Message)" -Level ERROR
                $Script:Stats.ErroresEliminacion++
            }
        }
        else {
            Write-Log "[$name] No encontrado en Entra ID (omitido)." -Level DEBUG
        }
    }
}

function Remove-EntraIDDevice {
    <#
    .SYNOPSIS
        Elimina un dispositivo unicamente de Entra ID.
    .PARAMETER Device
        Objeto de dispositivo de Entra ID (debe contener: id, displayName).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Device
    )

    $name = $Device.displayName
    try {
        Invoke-GraphRequest -Uri "$Script:GRAPH_BASE_URL/devices/$($Device.id)" -Method DELETE
        Write-Log "[$name] Eliminado de Entra ID correctamente." -Level OK
        $Script:Stats.EliminadosEntraID++
    }
    catch {
        Write-Log "[$name] Error al eliminar de Entra ID: $($_.Exception.Message)" -Level ERROR
        $Script:Stats.ErroresEliminacion++
    }
}

function Show-DeviceTable {
    <#
    .SYNOPSIS
        Muestra una lista de dispositivos en formato tabla en consola.
    .PARAMETER Devices
        Coleccion de objetos de dispositivo.
    .PARAMETER Columns
        Array con los nombres de propiedades a mostrar.
    .PARAMETER Headers
        Array con los encabezados de columna (mismo orden que Columns).
    .PARAMETER ColumnWidths
        Array con el ancho de cada columna.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Devices,

        [Parameter(Mandatory)]
        [string[]]$Columns,

        [Parameter(Mandatory)]
        [string[]]$Headers,

        [int[]]$ColumnWidths
    )

    if (-not $ColumnWidths) {
        $ColumnWidths = $Columns | ForEach-Object { 20 }
    }

    # Construir formato de encabezado
    $fmt = ""
    for ($i = 0; $i -lt $Headers.Count; $i++) {
        $fmt += "{$i,-$($ColumnWidths[$i])}"
        if ($i -lt $Headers.Count - 1) { $fmt += " | " }
    }

    $separator = "-" * ($ColumnWidths | Measure-Object -Sum).Sum + "-" * (($Headers.Count - 1) * 3)

    Write-Host ("  +" + ("-" * ($separator.Length)) + "+") -ForegroundColor DarkCyan
    Write-Host ("  | " + ($fmt -f $Headers) + " |") -ForegroundColor White
    Write-Host ("  +" + ("-" * ($separator.Length)) + "+") -ForegroundColor DarkCyan

    $rowIndex = 0
    foreach ($device in ($Devices | Sort-Object $Columns[0])) {
        $values = @()
        for ($i = 0; $i -lt $Columns.Count; $i++) {
            $val = $device.($Columns[$i])
            if ($val -is [datetime]) { $val = $val.ToString("yyyy-MM-dd") }
            elseif (-not $val)       { $val = "---" }
            $values += $val
        }
        $rowColor = if ($rowIndex % 2 -eq 0) { "White" } else { "Gray" }
        Write-Host ("  | " + ($fmt -f $values) + " |") -ForegroundColor $rowColor
        $rowIndex++
    }

    Write-Host ("  +" + ("-" * ($separator.Length)) + "+") -ForegroundColor DarkCyan
}

function Confirm-Action {
    <#
    .SYNOPSIS
        Solicita confirmacion al operador para una accion destructiva.
    .PARAMETER Message
        Descripcion de la accion a confirmar.
    .RETURNS
        $true si el operador confirma, $false en caso contrario.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host ""
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ("  |  CONFIRMACION REQUERIDA" + " " * 38 + "|") -ForegroundColor Yellow
    Write-Host ("  |  " + $Message.PadRight(58) + "|") -ForegroundColor White
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ""
    $answer = Read-Host "  Escribe S para confirmar o N para cancelar"
    Write-Host ""
    return ($answer -match "^[sS]$")
}

# ==============================================================================
# REGION: MENU INTERACTIVO
# ==============================================================================

function Show-InteractiveMenu {
    <#
    .SYNOPSIS
        Muestra un menu de seleccion multiple navegable con teclado.
        Usa las flechas ARRIBA/ABAJO para mover el cursor,
        ESPACIO para marcar/desmarcar opciones y ENTER para confirmar.
    .PARAMETER Options
        Array de strings con los textos de cada opcion.
    .RETURNS
        Array de indices (base 0) de las opciones seleccionadas.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Options
    )

    $selected   = @($false) * $Options.Count
    $cursor     = 0
    $checkOn    = "[X]"
    $checkOff   = "[ ]"

    # Ocultar cursor para experiencia mas limpia
    [Console]::CursorVisible = $false

    # Guardar posicion de inicio del menu
    $menuTop = [Console]::CursorTop

    function Render-Menu {
        [Console]::SetCursorPosition(0, $menuTop)
        for ($i = 0; $i -lt $Options.Count; $i++) {
            $mark  = if ($selected[$i]) { $checkOn } else { $checkOff }
            $line  = "    $mark  $($Options[$i])"
            if ($i -eq $cursor) {
                Write-Host ("  > " + $mark + "  " + $Options[$i].PadRight(60)) -ForegroundColor Black -BackgroundColor Cyan -NoNewline
                Write-Host ""
            } else {
                $markColor = if ($selected[$i]) { "Green" } else { "DarkGray" }
                Write-Host -NoNewline "    "
                Write-Host -NoNewline $mark -ForegroundColor $markColor
                Write-Host ("  " + $Options[$i])
            }
        }
        Write-Host ""
        Write-Host "  Flechas: mover  |  Espacio: seleccionar  |  Enter: confirmar  |  A: todo  |  N: ninguno" -ForegroundColor DarkGray
    }

    # Reservar lineas para el menu
    for ($i = 0; $i -lt ($Options.Count + 2); $i++) { Write-Host "" }
    $menuTop = [Console]::CursorTop - $Options.Count - 2

    Render-Menu

    while ($true) {
        $key = [Console]::ReadKey($true)

        switch ($key.Key) {
            "UpArrow"   { if ($cursor -gt 0) { $cursor-- } }
            "DownArrow" { if ($cursor -lt ($Options.Count - 1)) { $cursor++ } }
            "Spacebar"  { $selected[$cursor] = -not $selected[$cursor] }
            "Enter"     {
                [Console]::CursorVisible = $true
                Write-Host ""
                $result = @()
                for ($i = 0; $i -lt $Options.Count; $i++) {
                    if ($selected[$i]) { $result += $i }
                }
                return $result
            }
            default {
                $ch = $key.KeyChar.ToString().ToUpper()
                if ($ch -eq "A") { for ($i = 0; $i -lt $Options.Count; $i++) { $selected[$i] = $true  } }
                if ($ch -eq "N") { for ($i = 0; $i -lt $Options.Count; $i++) { $selected[$i] = $false } }
            }
        }
        Render-Menu
    }
}

# ==============================================================================
# REGION: FUNCIONES DE ANALISIS (sin efectos secundarios, solo cuentan)
# ==============================================================================

function Get-AnalysisData {
    <#
    .SYNOPSIS
        Ejecuta todos los filtros de analisis y devuelve un objeto con
        los conjuntos de dispositivos y sus conteos. No realiza ninguna
        operacion destructiva ni exporta ficheros.
    #>

    $O365_MDM_APP_ID = "7add3ecd-5b01-452e-b4bf-cdaf9df1d097"

    # --- Cruce ---
    $aadIds = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($Script:AllDevicesAAD | ForEach-Object { $_.deviceId } | Where-Object { $_ }),
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $intuneAADIds = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($Script:AllManagedDevices | ForEach-Object { $_.azureADDeviceId } | Where-Object { $_ }),
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $coincidentes = @($Script:AllManagedDevices | Where-Object { $aadIds.Contains($_.azureADDeviceId) })
    $soloIntune   = @($Script:AllManagedDevices | Where-Object { -not $aadIds.Contains($_.azureADDeviceId) })
    $soloAAD      = @($Script:AllDevicesAAD     | Where-Object { -not $intuneAADIds.Contains($_.deviceId) })

    # --- Inactivos Intune ---
    $inactivosIntune = @($Script:AllManagedDevices | Where-Object {
        $_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime -lt $Script:FechaLimite)
    })

    # --- Inactivos solo Entra ID ---
    $inactivosAAD = @($Script:AllDevicesAAD | Where-Object {
        $_.approximateLastSignInDateTime -and
        ([datetime]$_.approximateLastSignInDateTime -lt $Script:FechaLimite) -and
        $_.operatingSystem -notlike "*Server*"
    })
    $inactivosIntune_ids = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($inactivosIntune | ForEach-Object { $_.azureADDeviceId } | Where-Object { $_ }),
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $inactivosSoloAAD = @($inactivosAAD | Where-Object { -not $inactivosIntune_ids.Contains($_.deviceId) })

    # --- Huerfanos ---
    $intuneIds   = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($Script:AllManagedDevices | ForEach-Object { $_.azureADDeviceId } | Where-Object { $_ } | ForEach-Object { $_.ToLower() }),
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $intuneNames = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($Script:AllManagedDevices | ForEach-Object { $_.deviceName } | Where-Object { $_ } | ForEach-Object { $_.ToLower() }),
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $isOrphan = {
        param($dev)
        (-not $dev.deviceId   -or -not $intuneIds.Contains($dev.deviceId.ToLower())) -and
        (-not $dev.displayName -or -not $intuneNames.Contains($dev.displayName.ToLower())) -and
        $dev.registrationDateTime -eq $null
    }
    $huerfanosWindows = @($Script:AllDevicesAAD | Where-Object {
        $_.operatingSystem -like "*Windows*" -and
        $_.operatingSystem -notlike "*Server*" -and
        $_.managementType  -ne "MicrosoftSense" -and
        (& $isOrphan $_)
    })
    $huerfanosApple = @($Script:AllDevicesAAD | Where-Object {
        ($_.operatingSystem -like "*iPhone*" -or $_.operatingSystem -like "*iPad*" -or $_.operatingSystem -like "*Mac*") -and
        (& $isOrphan $_)
    })

    # --- Workplace ---
    $workplaceDevices = @($Script:AllDevicesAAD | Where-Object {
        $_.trustType       -eq "Workplace" -and
        $_.operatingSystem -like "Windows*" -and
        $_.operatingSystem -notlike "*Server*" -and
        $_.managementType  -ne "MDM"
    })

    # --- Registered MDM (solo revision, no destructivo) ---
    $registeredMDMDevices = @($Script:AllDevicesAAD | Where-Object {
        $_.trustType       -eq "Workplace" -and
        $_.managementType  -eq "MDM" -and
        $_.operatingSystem -like "Windows*" -and
        $_.operatingSystem -notlike "*Server*"
    })

    # --- MDM Office 365 Mobile ---
    $mdmOfficeDevices = @($Script:AllDevicesAAD | Where-Object { $_.mdmAppId -eq $O365_MDM_APP_ID })

    # --- Duplicados Intune ---
    $devicesConSerie = @($Script:AllManagedDevices | Where-Object {
        $_.serialNumber -and $_.serialNumber.Trim() -ne "" -and $_.serialNumber -ne "Unknown"
    })
    $duplicados = @($devicesConSerie | Group-Object serialNumber | Where-Object { $_.Count -gt 1 })
    $duplicadosCount = ($duplicados | ForEach-Object { $_.Count - 1 } | Measure-Object -Sum).Sum
    if (-not $duplicadosCount) { $duplicadosCount = 0 }

    return [PSCustomObject]@{
        # Cruce
        Coincidentes        = $coincidentes
        SoloIntune          = $soloIntune
        SoloAAD             = $soloAAD
        # Limpiezas
        InactivosIntune     = $inactivosIntune
        InactivosSoloAAD    = $inactivosSoloAAD
        HuerfanosWindows    = $huerfanosWindows
        HuerfanosApple      = $huerfanosApple
        WorkplaceDevices    = $workplaceDevices
        RegisteredMDM       = $registeredMDMDevices
        MdmOffice365        = $mdmOfficeDevices
        Duplicados          = $duplicados
        DuplicadosCount     = $duplicadosCount
        # HashSets para reutilizar en bloques de accion
        IntuneIds           = $intuneIds
        IntuneNames         = $intuneNames
        InactivosIntune_ids = $inactivosIntune_ids
    }
}

# ==============================================================================
# REGION: FUNCIONES DE ACCION (bloques de limpieza individuales)
# ==============================================================================

function Invoke-LimpiezaInactivosIntune {
    param([object[]]$Devices)

    Write-SectionHeader -Title "LIMPIEZA -- INACTIVOS EN INTUNE" `
        -Subtitle "Ultima sincronizacion anterior a $($Script:FechaLimite.ToString('yyyy-MM-dd'))." `
        -Color "Yellow"

    $exportPath = "$Script:BasePath\Inactivos_Intune.csv"
    $Devices | Select-Object deviceName, operatingSystem, lastSyncDateTime, azureADDeviceId, id |
        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Log "Listado exportado: $exportPath" -Level INFO

    Show-DeviceTable -Devices $Devices `
        -Columns @("deviceName","operatingSystem","lastSyncDateTime") `
        -Headers @("Dispositivo","Sistema Operativo","Ultima Sync") `
        -ColumnWidths @(30,20,22)

    if (Confirm-Action "Eliminar estos $($Devices.Count) dispositivos de Intune y Entra ID?") {
        Write-Log "Iniciando eliminacion..." -Level WARN
        $i = 0
        foreach ($device in ($Devices | Sort-Object deviceName)) {
            $i++
            Write-Progress -Activity "Eliminando inactivos Intune" -Status $device.deviceName `
                           -PercentComplete (($i / $Devices.Count) * 100)
            Remove-IntuneDevice -Device $device -AlsoRemoveFromEntraID $true
        }
        Write-Progress -Activity "Eliminando inactivos Intune" -Completed
        Write-Log "Completado." -Level OK
    } else {
        Write-Log "Cancelado por el operador." -Level WARN
        $Script:Stats.Saltados += $Devices.Count
    }
}

function Invoke-LimpiezaInactivosEntraID {
    param([object[]]$Devices)

    Write-SectionHeader -Title "LIMPIEZA -- INACTIVOS SOLO EN ENTRA ID" `
        -Subtitle "Actividad anterior a $($Script:FechaLimite.ToString('yyyy-MM-dd')). Excluye Windows Server." `
        -Color "Yellow"

    $exportPath = "$Script:BasePath\Inactivos_Solo_EntraID.csv"
    $Devices | Select-Object displayName, operatingSystem, trustType, managementType,
        registrationDateTime, approximateLastSignInDateTime, deviceId, id |
        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Log "Listado exportado: $exportPath" -Level INFO

    Show-DeviceTable -Devices $Devices `
        -Columns @("displayName","operatingSystem","approximateLastSignInDateTime") `
        -Headers @("Dispositivo","Sistema Operativo","Ultimo Inicio Sesion") `
        -ColumnWidths @(30,20,22)

    if (Confirm-Action "Eliminar estos $($Devices.Count) dispositivos de Entra ID?") {
        Write-Log "Iniciando eliminacion..." -Level WARN
        $i = 0
        foreach ($device in ($Devices | Sort-Object displayName)) {
            $i++
            Write-Progress -Activity "Eliminando inactivos Entra ID" -Status $device.displayName `
                           -PercentComplete (($i / $Devices.Count) * 100)
            Remove-EntraIDDevice -Device $device
        }
        Write-Progress -Activity "Eliminando inactivos Entra ID" -Completed
        Write-Log "Completado." -Level OK
    } else {
        Write-Log "Cancelado por el operador." -Level WARN
        $Script:Stats.Saltados += $Devices.Count
    }
}

function Invoke-LimpiezaHuerfanos {
    param([object[]]$Windows, [object[]]$Apple)

    Write-SectionHeader -Title "LIMPIEZA -- DISPOSITIVOS HUERFANOS EN ENTRA ID" `
        -Subtitle "Sin objeto en Intune, sin fecha de registro, sin gestion MicrosoftSense." `
        -Color "Yellow"

    # Windows
    if ($Windows.Count -gt 0) {
        Write-Log "Huerfanos Windows: $($Windows.Count)" -Level WARN
        Show-DeviceTable -Devices $Windows `
            -Columns @("displayName","operatingSystem") `
            -Headers @("Dispositivo","Sistema Operativo") `
            -ColumnWidths @(35,25)

        if (Confirm-Action "Eliminar $($Windows.Count) dispositivos Windows huerfanos?") {
            $i = 0
            foreach ($device in $Windows) {
                $i++
                Write-Progress -Activity "Eliminando Windows huerfanos" -Status $device.displayName `
                               -PercentComplete (($i / $Windows.Count) * 100)
                Remove-EntraIDDevice -Device $device
            }
            Write-Progress -Activity "Eliminando Windows huerfanos" -Completed
        } else {
            Write-Log "Cancelado (Windows)." -Level WARN
            $Script:Stats.Saltados += $Windows.Count
        }
    } else {
        Write-Log "No hay huerfanos Windows." -Level OK
    }

    # Apple
    if ($Apple.Count -gt 0) {
        Write-Log "Huerfanos Apple (iPhone/iPad/Mac): $($Apple.Count)" -Level WARN
        Write-Log "AVISO: Pueden ser registros de pre-inscripcion o ADE." -Level WARN
        Show-DeviceTable -Devices $Apple `
            -Columns @("displayName","operatingSystem") `
            -Headers @("Dispositivo","Sistema Operativo") `
            -ColumnWidths @(35,25)

        if (Confirm-Action "Eliminar $($Apple.Count) dispositivos Apple huerfanos?") {
            $i = 0
            foreach ($device in $Apple) {
                $i++
                Write-Progress -Activity "Eliminando Apple huerfanos" -Status $device.displayName `
                               -PercentComplete (($i / $Apple.Count) * 100)
                Remove-EntraIDDevice -Device $device
            }
            Write-Progress -Activity "Eliminando Apple huerfanos" -Completed
        } else {
            Write-Log "Cancelado (Apple)." -Level WARN
            $Script:Stats.Saltados += $Apple.Count
        }
    } else {
        Write-Log "No hay huerfanos Apple." -Level OK
    }
}

function Invoke-LimpiezaWorkplace {
    param([object[]]$Devices)

    Write-SectionHeader -Title "LIMPIEZA -- DISPOSITIVOS REGISTERED (WORKPLACE)" `
        -Subtitle "Windows, TrustType Workplace, sin gestion MDM, excluye Servers." `
        -Color "Yellow"

    $exportPath = "$Script:BasePath\Dispositivos_Workplace.csv"
    $Devices | Select-Object displayName, operatingSystem, trustType, managementType,
        registrationDateTime, approximateLastSignInDateTime, mdmAppId, deviceId |
        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Log "Listado exportado: $exportPath" -Level INFO

    Show-DeviceTable -Devices $Devices `
        -Columns @("displayName","operatingSystem","approximateLastSignInDateTime") `
        -Headers @("Dispositivo","S.O.","Ultimo Inicio (Entra ID)") `
        -ColumnWidths @(30,18,22)

    if (Confirm-Action "Eliminar estos $($Devices.Count) dispositivos Workplace de Entra ID?") {
        Write-Log "Iniciando eliminacion..." -Level WARN
        $i = 0
        foreach ($device in ($Devices | Sort-Object displayName)) {
            $i++
            Write-Progress -Activity "Eliminando Workplace" -Status $device.displayName `
                           -PercentComplete (($i / $Devices.Count) * 100)

            $enIntune = $Script:AllManagedDevices | Where-Object {
                ($_.azureADDeviceId -eq $device.deviceId) -or ($_.deviceName -eq $device.displayName)
            }
            if ($enIntune) {
                Write-Log "[$($device.displayName)] SALTADO -- encontrado en Intune." -Level WARN
                $Script:Stats.Saltados++
                continue
            }
            Remove-EntraIDDevice -Device $device
        }
        Write-Progress -Activity "Eliminando Workplace" -Completed
        Write-Log "Completado." -Level OK
    } else {
        Write-Log "Cancelado por el operador." -Level WARN
        $Script:Stats.Saltados += $Devices.Count
    }
}

function Invoke-RevisionRegisteredMDM {
    param([object[]]$Devices)

    Write-SectionHeader -Title "REVISION -- REGISTERED CON GESTION MDM" `
        -Subtitle "Solo informativo. Estos dispositivos estan en Intune y no se eliminan automaticamente." `
        -Color "Cyan"

    $exportPath = "$Script:BasePath\Registered_MDM_Revision.csv"
    $Devices | Select-Object displayName, operatingSystem, trustType, managementType,
        registrationDateTime, approximateLastSignInDateTime, mdmAppId, deviceId |
        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Log "Reporte exportado: $exportPath" -Level INFO

    Show-DeviceTable -Devices $Devices `
        -Columns @("displayName","operatingSystem","managementType") `
        -Headers @("Dispositivo","S.O.","Tipo Gestion") `
        -ColumnWidths @(30,18,15)
}

function Invoke-RevisionMdmOffice365 {
    param([object[]]$Devices)

    Write-SectionHeader -Title "REVISION -- DISPOSITIVOS MDM OFFICE 365 MOBILE" `
        -Subtitle "Requieren revision manual de licencia si estan activos." `
        -Color "Cyan"

    $pathOfficeMDM = "$Script:BasePath\Dispositivos_MDM_Office365Mobile.csv"
    $Devices | Export-Csv -Path $pathOfficeMDM -NoTypeInformation -Encoding UTF8
    Write-Log "Listado exportado: $pathOfficeMDM" -Level OK

    Show-DeviceTable -Devices $Devices `
        -Columns @("displayName","operatingSystem","managementType") `
        -Headers @("Dispositivo","S.O.","Tipo Gestion") `
        -ColumnWidths @(30,18,15)
}

function Invoke-LimpiezaDuplicados {
    param([object[]]$GruposDuplicados)

    Write-SectionHeader -Title "LIMPIEZA -- DUPLICADOS EN INTUNE (POR SERIE)" `
        -Subtitle "Se conserva el registro con ultima sincronizacion mas reciente." `
        -Color "Yellow"

    $duplicadosParaEliminar = [System.Collections.Generic.List[object]]::new()

    Write-Host ""
    foreach ($grupo in $GruposDuplicados) {
        $serial    = $grupo.Name
        $ordenados = $grupo.Group | Sort-Object -Property { [datetime]$_.lastSyncDateTime } -Descending
        $aConservar = $ordenados[0]
        $aEliminar  = $ordenados | Select-Object -Skip 1

        Write-Host ("  +-- Serie: " + $serial) -ForegroundColor Cyan
        Write-Host ("  |   [KEEP] " + "$($aConservar.deviceName)".PadRight(30) + " Sync: $($aConservar.lastSyncDateTime)") -ForegroundColor Green
        foreach ($d in $aEliminar) {
            Write-Host ("  |   [DEL]  " + "$($d.deviceName)".PadRight(30) + " Sync: $($d.lastSyncDateTime)") -ForegroundColor Red
            $duplicadosParaEliminar.Add($d)
        }
        Write-Host ""
    }

    $exportPath = "$Script:BasePath\Duplicados_Intune.csv"
    $duplicadosParaEliminar | Select-Object deviceName, serialNumber, lastSyncDateTime, azureADDeviceId, id |
        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Log "Registro exportado: $exportPath" -Level INFO

    if (Confirm-Action "Eliminar $($duplicadosParaEliminar.Count) registros duplicados?") {
        Write-Log "Iniciando eliminacion..." -Level WARN
        $i = 0
        foreach ($device in $duplicadosParaEliminar) {
            $i++
            Write-Progress -Activity "Eliminando duplicados" -Status $device.deviceName `
                           -PercentComplete (($i / $duplicadosParaEliminar.Count) * 100)
            try {
                Invoke-GraphRequest -Uri "$Script:GRAPH_BASE_URL/deviceManagement/managedDevices/$($device.id)" -Method DELETE
                Write-Log "[$($device.deviceName)] Duplicado eliminado." -Level OK
                $Script:Stats.EliminadosIntune++
            } catch {
                Write-Log "[$($device.deviceName)] Error: $($_.Exception.Message)" -Level ERROR
                $Script:Stats.ErroresEliminacion++
            }
        }
        Write-Progress -Activity "Eliminando duplicados" -Completed
        Write-Log "Completado." -Level OK
    } else {
        Write-Log "Cancelado por el operador." -Level WARN
        $Script:Stats.Saltados += $duplicadosParaEliminar.Count
    }
}

# ==============================================================================
# REGION: INICIO Y ENCABEZADO
# ==============================================================================
Clear-Host

Write-Host ""
Write-Host "  +======================================================================+" -ForegroundColor Cyan
Write-Host "  |                                                                      |" -ForegroundColor Cyan
Write-Host "  |      GESTION DE DISPOSITIVOS   //   MICROSOFT GRAPH                 |" -ForegroundColor White
Write-Host "  |      Intune & Entra ID Maintenance Tool                             |" -ForegroundColor Gray
Write-Host ("  |      v" + $Script:VERSION + " " * (63 - $Script:VERSION.Length) + "|") -ForegroundColor DarkGray
Write-Host "  |                                                                      |" -ForegroundColor Cyan
Write-Host "  +======================================================================+" -ForegroundColor Cyan
Write-Host ""

# Inicializar log de sesion
$fechaLog        = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:BasePath = "C:\Temp\Comparativa_Dispositivos_$fechaLog"
if (-not (Test-Path $Script:BasePath)) {
    New-Item -ItemType Directory -Path $Script:BasePath -Force | Out-Null
}
$Script:LogPath = Join-Path $Script:BasePath "Sesion_$fechaLog.log"
Add-Content -Path $Script:LogPath -Value ("=" * 80) -Encoding UTF8
Add-Content -Path $Script:LogPath -Value "  LOG DE SESION -- Clear-Devices v$Script:VERSION  |  $fechaLog" -Encoding UTF8
Add-Content -Path $Script:LogPath -Value ("=" * 80) -Encoding UTF8

Write-Log "Log de sesion iniciado: $Script:LogPath" -Level INFO

# ==============================================================================
# REGION: AUTENTICACION
# ==============================================================================
Write-SectionHeader -Title "AUTENTICACION" -Subtitle "Introduce los datos del App Registration de Azure." -Color "Cyan"

$tenantId    = Read-Host "  1. Directory (Tenant) ID"
$appId       = Read-Host "  2. Application (Client) ID"
$secretInput = Read-Host "  3. Client Secret" -AsSecureString

$credential   = New-Object System.Management.Automation.PSCredential("user", $secretInput)
$clientSecret = $credential.GetNetworkCredential().Password

Write-Log "Conectando con Microsoft Identity Platform..." -Level INFO

try {
    $authBody = @{
        client_id     = $appId
        scope         = $Script:GRAPH_SCOPE
        grant_type    = "client_credentials"
        client_secret = $clientSecret
    }
    $authResponse = Invoke-RestMethod -Method Post `
        -Uri "$Script:AUTH_URL_BASE/$tenantId/oauth2/v2.0/token" `
        -Body $authBody -ErrorAction Stop

    $token = $authResponse.access_token
    if (-not $token) { throw "El token devuelto esta vacio." }

    Write-Log "Autenticacion completada. Token de acceso generado." -Level OK
    $expiresAt = (Get-Date).AddSeconds($authResponse.expires_in)
    Write-Log "Token valido hasta: $($expiresAt.ToString('HH:mm:ss'))" -Level DEBUG
}
catch {
    Write-Log "Fallo de autenticacion: $($_.Exception.Message)" -Level ERROR
    Write-Log "Comprueba el TenantId, AppId y ClientSecret." -Level WARN
    exit 1
}

$Script:Headers = @{
    Authorization  = "Bearer $token"
    "Content-Type" = "application/json"
}

# ==============================================================================
# REGION: EXTRACCION DE INVENTARIOS
# ==============================================================================
Write-SectionHeader -Title "EXTRACCION DE INVENTARIOS" -Subtitle "Consultando Microsoft Graph API..." -Color "Cyan"

Write-Log "Extrayendo dispositivos de Microsoft Intune..." -Level INFO
$intuneUrl = "$Script:GRAPH_BASE_URL/deviceManagement/managedDevices" +
             "?`$select=id,deviceName,operatingSystem,osVersion,managementAgent," +
             "managementState,lastSyncDateTime,userPrincipalName,azureADDeviceId,serialNumber" +
             "&`$top=999"
$Script:AllManagedDevices = Get-AllGraphPages -InitialUrl $intuneUrl -EntityName "dispositivos Intune"
Write-Log "Intune: $($Script:AllManagedDevices.Count) dispositivos encontrados." -Level OK

Write-Log "Extrayendo dispositivos de Entra ID..." -Level INFO
$entraUrl = "$Script:GRAPH_BASE_URL/devices" +
            "?`$select=id,deviceId,displayName,trustType,operatingSystem,managementType," +
            "registrationDateTime,approximateLastSignInDateTime,mdmAppId" +
            "&`$top=999"
$Script:AllDevicesAAD = Get-AllGraphPages -InitialUrl $entraUrl -EntityName "dispositivos Entra ID"
Write-Log "Entra ID: $($Script:AllDevicesAAD.Count) dispositivos encontrados." -Level OK

# ==============================================================================
# REGION: FECHA LIMITE
# ==============================================================================
Write-SectionHeader -Title "FECHA LIMITE DE INACTIVIDAD" -Subtitle "Define el umbral para considerar un dispositivo inactivo." -Color "Cyan"

$fechaValida = $false
do {
    $inputFecha = Read-Host "`n  Introduce la fecha limite (YYYY-MM-DD)"
    try {
        $Script:FechaLimite = [datetime]::ParseExact(
            $inputFecha, "yyyy-MM-dd",
            [System.Globalization.CultureInfo]::InvariantCulture
        )
        $fechaValida = $true
        Write-Log "Fecha limite establecida: $($Script:FechaLimite.ToString('yyyy-MM-dd'))" -Level OK
    }
    catch {
        Write-Log "Formato de fecha invalido. Ejemplo correcto: 2024-12-31" -Level WARN
    }
} until ($fechaValida)

# ==============================================================================
# REGION: ANALISIS COMPLETO
# ==============================================================================
Write-SectionHeader -Title "ANALIZANDO INVENTARIO..." -Subtitle "Por favor espera, calculando todas las categorias." -Color "Cyan"

Write-Log "Ejecutando analisis completo del entorno..." -Level INFO
$data = Get-AnalysisData
Write-Log "Analisis completado." -Level OK

# Exportar CSVs de cruce siempre
$data.Coincidentes | Select-Object deviceName, operatingSystem, osVersion, userPrincipalName,
    managementAgent, lastSyncDateTime, azureADDeviceId |
    Export-Csv -Path "$Script:BasePath\Cruce_Coincidentes.csv" -NoTypeInformation -Encoding UTF8
$data.SoloIntune | Select-Object deviceName, operatingSystem, osVersion, userPrincipalName,
    managementAgent, lastSyncDateTime, azureADDeviceId |
    Export-Csv -Path "$Script:BasePath\Cruce_Solo_Intune.csv" -NoTypeInformation -Encoding UTF8
$data.SoloAAD | Select-Object displayName, operatingSystem, trustType, managementType,
    registrationDateTime, approximateLastSignInDateTime, mdmAppId, deviceId |
    Export-Csv -Path "$Script:BasePath\Cruce_Solo_EntraID.csv" -NoTypeInformation -Encoding UTF8
Write-Log "Reportes de cruce exportados." -Level OK

# ==============================================================================
# REGION: DASHBOARD DE RESULTADOS
# ==============================================================================
Write-Host ""
Write-Host "  +======================================================================+" -ForegroundColor Cyan
Write-Host "  |                   RESUMEN DEL ENTORNO                               |" -ForegroundColor White
Write-Host "  +------------------------------------+----------+----------------------+" -ForegroundColor Cyan
Write-Host "  | Categoria                          |  Devices | Estado               |" -ForegroundColor White
Write-Host "  +------------------------------------+----------+----------------------+" -ForegroundColor Cyan

function Write-DashboardRow {
    param([string]$Label, [int]$Count, [string]$Note = "", [string]$Color = "White")
    $statusIcon = if ($Count -gt 0) { "(!)" } else { "(OK)" }
    $statusColor = if ($Count -gt 0) { "Yellow" } else { "Green" }
    Write-Host -NoNewline ("  | " + $Label.PadRight(34) + " | " + "$Count".PadLeft(8) + " | ") -ForegroundColor $Color
    Write-Host -NoNewline $statusIcon.PadRight(6) -ForegroundColor $statusColor
    Write-Host (" " + $Note.PadRight(14) + "|") -ForegroundColor DarkGray
}

Write-DashboardRow "Intune total"                  $Script:AllManagedDevices.Count  "inventario"   "Gray"
Write-DashboardRow "Entra ID total"                $Script:AllDevicesAAD.Count      "inventario"   "Gray"
Write-Host "  +------------------------------------+----------+----------------------+" -ForegroundColor DarkCyan
Write-DashboardRow "En ambas plataformas"          $data.Coincidentes.Count         "coincidentes" "White"
Write-DashboardRow "Solo en Intune"                $data.SoloIntune.Count           "sin EntraID"  "Yellow"
Write-DashboardRow "Solo en Entra ID"              $data.SoloAAD.Count              "sin Intune"   "Yellow"
Write-Host "  +------------------------------------+----------+----------------------+" -ForegroundColor DarkCyan
Write-DashboardRow "Inactivos en Intune"           $data.InactivosIntune.Count      "limpieza"     "Yellow"
Write-DashboardRow "Inactivos solo Entra ID"       $data.InactivosSoloAAD.Count     "limpieza"     "Yellow"
Write-DashboardRow "Huerfanos Windows"             $data.HuerfanosWindows.Count     "limpieza"     "Yellow"
Write-DashboardRow "Huerfanos Apple"               $data.HuerfanosApple.Count       "limpieza"     "Yellow"
Write-DashboardRow "Workplace (sin MDM)"           $data.WorkplaceDevices.Count     "limpieza"     "Yellow"
Write-DashboardRow "Registered con MDM"            $data.RegisteredMDM.Count        "revision"     "Cyan"
Write-DashboardRow "MDM Office 365 Mobile"         $data.MdmOffice365.Count         "revision"     "Cyan"
Write-DashboardRow "Series duplicadas (Intune)"    $data.Duplicados.Count           "limpieza"     "Yellow"
Write-Host "  +------------------------------------+----------+----------------------+" -ForegroundColor Cyan
Write-Host ""

# ==============================================================================
# REGION: FUNCION DE PREVISUALIZACION
# ==============================================================================

function Show-PreviewDevices {
    <#
    .SYNOPSIS
        Muestra una tabla previa de los dispositivos afectados antes de ejecutar
        una tarea. El operador puede continuar o cancelar desde aqui.
    .PARAMETER Devices
        Array de dispositivos a previsualizar.
    .PARAMETER Title
        Titulo de la seccion de previsualizacion.
    .PARAMETER Columns
        Columnas a mostrar en la tabla.
    .PARAMETER Headers
        Encabezados de las columnas.
    .PARAMETER ColumnWidths
        Anchos de cada columna.
    .RETURNS
        $true si el operador desea continuar, $false para cancelar.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Devices,

        [Parameter(Mandatory)]
        [string]$Title,

        [string[]]$Columns      = @("displayName","operatingSystem","trustType"),
        [string[]]$Headers      = @("Dispositivo","Sistema Operativo","Tipo"),
        [int[]]$ColumnWidths    = @(30, 22, 15)
    )

    Write-Host ""
    Write-Host ("  +=================================================================+") -ForegroundColor Magenta
    Write-Host ("  |  PREVISUALIZACION: " + $Title.ToUpper().PadRight(46) + "|") -ForegroundColor White
    Write-Host ("  |  Total dispositivos afectados: " + "$($Devices.Count)".PadRight(34) + "|") -ForegroundColor Yellow
    Write-Host ("  +=================================================================+") -ForegroundColor Magenta
    Write-Host ""

    if ($Devices.Count -eq 0) {
        Write-Host "  (sin dispositivos en esta categoria)" -ForegroundColor DarkGray
        Write-Host ""
        return $true
    }

    # Limitar vista previa a 50 filas para no saturar la consola
    $preview = if ($Devices.Count -gt 50) { $Devices | Select-Object -First 50 } else { $Devices }

    Show-DeviceTable -Devices $preview -Columns $Columns -Headers $Headers -ColumnWidths $ColumnWidths

    if ($Devices.Count -gt 50) {
        Write-Host ""
        Write-Host ("  >> Mostrando 50 de $($Devices.Count) dispositivos. Consulta el CSV para el listado completo.") -ForegroundColor DarkGray
    }

    Write-Host ""
    $answer = Read-Host "  Continuar con esta tarea? (S para continuar / N para cancelar)"
    Write-Host ""
    return ($answer -match "^[sS]$")
}

# ==============================================================================
# REGION: MENU DE SELECCION
# ==============================================================================
Write-SectionHeader -Title "SELECCION DE TAREAS" `
    -Subtitle "Usa flechas + Espacio para marcar. Enter para ejecutar. A=todo N=ninguno." `
    -Color "White"

# Construir opciones del menu con conteos inline
$menuOptions = @(
    "Inactivos en Intune              [$($data.InactivosIntune.Count) dispositivos]"
    "Inactivos solo en Entra ID       [$($data.InactivosSoloAAD.Count) dispositivos]"
    "Huerfanos (Windows + Apple)      [$($data.HuerfanosWindows.Count + $data.HuerfanosApple.Count) dispositivos]"
    "Workplace sin MDM (Entra ID)     [$($data.WorkplaceDevices.Count) dispositivos]"
    "Duplicados en Intune             [$($data.Duplicados.Count) series / $($data.DuplicadosCount) a eliminar]"
    "Registered con MDM               [$($data.RegisteredMDM.Count) dispositivos] (solo revision)"
    "MDM Office 365 Mobile            [$($data.MdmOffice365.Count) dispositivos] (solo revision)"
)

$seleccion = @(Show-InteractiveMenu -Options $menuOptions)

if ($seleccion.Count -eq 0) {
    Write-Log "No se selecciono ninguna tarea. Saliendo." -Level WARN
}
else {
    Write-Log "Tareas seleccionadas: $($seleccion.Count)" -Level INFO

    # Ejecutar solo los bloques seleccionados
    foreach ($idx in $seleccion) {
        switch ($idx) {
            0 {
                if ($data.InactivosIntune.Count -gt 0) {
                    $continuar = Show-PreviewDevices `
                        -Devices      $data.InactivosIntune `
                        -Title        "Inactivos en Intune" `
                        -Columns      @("deviceName","operatingSystem","lastSyncDateTime") `
                        -Headers      @("Dispositivo","S.O.","Ultima Sync") `
                        -ColumnWidths @(30,20,22)
                    if ($continuar) {
                        Invoke-LimpiezaInactivosIntune -Devices $data.InactivosIntune
                    } else {
                        Write-Log "Tarea cancelada en la previsualizacion." -Level WARN
                        $Script:Stats.Saltados += $data.InactivosIntune.Count
                    }
                } else { Write-Log "No hay inactivos en Intune." -Level OK }
            }
            1 {
                if ($data.InactivosSoloAAD.Count -gt 0) {
                    $continuar = Show-PreviewDevices `
                        -Devices      $data.InactivosSoloAAD `
                        -Title        "Inactivos solo en Entra ID" `
                        -Columns      @("displayName","operatingSystem","approximateLastSignInDateTime") `
                        -Headers      @("Dispositivo","S.O.","Ultimo Inicio Sesion") `
                        -ColumnWidths @(30,20,22)
                    if ($continuar) {
                        Invoke-LimpiezaInactivosEntraID -Devices $data.InactivosSoloAAD
                    } else {
                        Write-Log "Tarea cancelada en la previsualizacion." -Level WARN
                        $Script:Stats.Saltados += $data.InactivosSoloAAD.Count
                    }
                } else { Write-Log "No hay inactivos exclusivos en Entra ID." -Level OK }
            }
            2 {
                $huerfanosAll = @($data.HuerfanosWindows) + @($data.HuerfanosApple)
                if ($huerfanosAll.Count -gt 0) {
                    $continuar = Show-PreviewDevices `
                        -Devices      $huerfanosAll `
                        -Title        "Huerfanos Windows + Apple" `
                        -Columns      @("displayName","operatingSystem","trustType") `
                        -Headers      @("Dispositivo","S.O.","Tipo") `
                        -ColumnWidths @(30,22,15)
                    if ($continuar) {
                        Invoke-LimpiezaHuerfanos -Windows $data.HuerfanosWindows -Apple $data.HuerfanosApple
                    } else {
                        Write-Log "Tarea cancelada en la previsualizacion." -Level WARN
                        $Script:Stats.Saltados += $huerfanosAll.Count
                    }
                } else {
                    Write-Log "No hay dispositivos huerfanos." -Level OK
                }
            }
            3 {
                if ($data.WorkplaceDevices.Count -gt 0) {
                    $continuar = Show-PreviewDevices `
                        -Devices      $data.WorkplaceDevices `
                        -Title        "Workplace sin MDM (Entra ID)" `
                        -Columns      @("displayName","operatingSystem","approximateLastSignInDateTime") `
                        -Headers      @("Dispositivo","S.O.","Ultimo Inicio (Entra ID)") `
                        -ColumnWidths @(30,18,22)
                    if ($continuar) {
                        Invoke-LimpiezaWorkplace -Devices $data.WorkplaceDevices
                    } else {
                        Write-Log "Tarea cancelada en la previsualizacion." -Level WARN
                        $Script:Stats.Saltados += $data.WorkplaceDevices.Count
                    }
                } else { Write-Log "No hay dispositivos Workplace sin MDM." -Level OK }
            }
            4 {
                if ($data.Duplicados.Count -gt 0) {
                    # Para duplicados mostramos los dispositivos que se van a eliminar
                    $dupsFlat = @($data.Duplicados | ForEach-Object {
                        $ord = $_.Group | Sort-Object { [datetime]$_.lastSyncDateTime } -Descending
                        $ord | Select-Object -Skip 1
                    })
                    $continuar = Show-PreviewDevices `
                        -Devices      $dupsFlat `
                        -Title        "Duplicados en Intune (a eliminar)" `
                        -Columns      @("deviceName","serialNumber","lastSyncDateTime") `
                        -Headers      @("Dispositivo","Numero Serie","Ultima Sync") `
                        -ColumnWidths @(30,22,22)
                    if ($continuar) {
                        Invoke-LimpiezaDuplicados -GruposDuplicados $data.Duplicados
                    } else {
                        Write-Log "Tarea cancelada en la previsualizacion." -Level WARN
                        $Script:Stats.Saltados += $dupsFlat.Count
                    }
                } else { Write-Log "No hay duplicados en Intune." -Level OK }
            }
            5 {
                if ($data.RegisteredMDM.Count -gt 0) {
                    $continuar = Show-PreviewDevices `
                        -Devices      $data.RegisteredMDM `
                        -Title        "Registered con MDM (solo revision)" `
                        -Columns      @("displayName","operatingSystem","managementType") `
                        -Headers      @("Dispositivo","S.O.","Tipo Gestion") `
                        -ColumnWidths @(30,18,15)
                    if ($continuar) {
                        Invoke-RevisionRegisteredMDM -Devices $data.RegisteredMDM
                    } else {
                        Write-Log "Revision cancelada en la previsualizacion." -Level WARN
                    }
                } else { Write-Log "No hay dispositivos Registered con MDM." -Level OK }
            }
            6 {
                if ($data.MdmOffice365.Count -gt 0) {
                    $continuar = Show-PreviewDevices `
                        -Devices      $data.MdmOffice365 `
                        -Title        "MDM Office 365 Mobile (solo revision)" `
                        -Columns      @("displayName","operatingSystem","managementType") `
                        -Headers      @("Dispositivo","S.O.","Tipo Gestion") `
                        -ColumnWidths @(30,18,15)
                    if ($continuar) {
                        Invoke-RevisionMdmOffice365 -Devices $data.MdmOffice365
                    } else {
                        Write-Log "Revision cancelada en la previsualizacion." -Level WARN
                    }
                } else { Write-Log "No hay dispositivos MDM Office 365 Mobile." -Level OK }
            }
        }
        Write-Separator
    }
}

# ==============================================================================
# REGION: GENERACION DE README
# ==============================================================================
$readmeContent = @"
================================================================================
  README -- Descripcion de ficheros de la sesion
  Generado: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Script:   Clear-Devices v$Script:VERSION
  Fecha limite analizada: $($Script:FechaLimite.ToString("yyyy-MM-dd"))
================================================================================

FICHEROS CSV GENERADOS
----------------------

Cruce_Coincidentes.csv        Dispositivos en Entra ID e Intune.
Cruce_Solo_Intune.csv         Dispositivos en Intune sin objeto en Entra ID.
Cruce_Solo_EntraID.csv        Dispositivos en Entra ID sin inscripcion en Intune.
Inactivos_Intune.csv          Inactivos en Intune segun fecha limite.
Inactivos_Solo_EntraID.csv    Inactivos en Entra ID que no existen en Intune.
Dispositivos_Workplace.csv    Windows Registered sin MDM (Workplace).
Registered_MDM_Revision.csv   Workplace con MDM activo. Requieren revision.
Dispositivos_MDM_Office365.csv MDM Office 365 Mobile. Revision de licencia.
Duplicados_Intune.csv         Duplicados eliminados en Intune por numero de serie.
Sesion_*.log                  Log completo de la sesion con marcas de tiempo.
================================================================================
"@

$readmePath = Join-Path $Script:BasePath "README.txt"
$readmeContent | Out-File -FilePath $readmePath -Encoding UTF8 -Force
Write-Log "README generado: $readmePath" -Level OK

# ==============================================================================
# REGION: RESUMEN FINAL
# ==============================================================================
Write-Host ""
Write-Host "  +======================================================================+" -ForegroundColor Cyan
Write-Host "  |                      RESUMEN DE LA SESION                           |" -ForegroundColor White
Write-Host "  +======================================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  |  {0,-44} {1,5}  |" -f "Dispositivos eliminados de Intune:",    $Script:Stats.EliminadosIntune)  -ForegroundColor Cyan
Write-Host ("  |  {0,-44} {1,5}  |" -f "Dispositivos eliminados de Entra ID:",  $Script:Stats.EliminadosEntraID) -ForegroundColor Cyan
$errColor = if ($Script:Stats.ErroresEliminacion -gt 0) { "Red" } else { "Green" }
Write-Host ("  |  {0,-44} {1,5}  |" -f "Errores durante la eliminacion:", $Script:Stats.ErroresEliminacion) -ForegroundColor $errColor
Write-Host ("  |  {0,-44} {1,5}  |" -f "Dispositivos saltados (sin accion):",   $Script:Stats.Saltados) -ForegroundColor Yellow
Write-Host ""
Write-Host "  +----------------------------------------------------------------------+" -ForegroundColor DarkCyan
Write-Host ""
Write-Log "Sesion finalizada -- Eliminados Intune: $($Script:Stats.EliminadosIntune) | Eliminados EntraID: $($Script:Stats.EliminadosEntraID) | Errores: $($Script:Stats.ErroresEliminacion) | Saltados: $($Script:Stats.Saltados)" -Level INFO
Write-Log "Todos los reportes disponibles en: $Script:BasePath" -Level OK

Write-Host ""
Write-Host "  +======================================================================+" -ForegroundColor DarkCyan
Write-Host "  |    FIN DEL SCRIPT DE MANTENIMIENTO                                  |" -ForegroundColor White
Write-Host ("  |    Clear-Devices v" + $Script:VERSION + " -- " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "                    |") -ForegroundColor Gray
Write-Host "  +======================================================================+" -ForegroundColor DarkCyan
Write-Host ""
