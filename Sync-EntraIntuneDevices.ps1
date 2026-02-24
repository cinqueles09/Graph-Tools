# ==============================================================================
# SCRIPT DE MANTENIMIENTO: INTUNE & ENTRA ID
# ==============================================================================
<#
.SYNOPSIS
    Script de mantenimiento avanzado para entornos Microsoft Intune y Entra ID.
    
.DESCRIPTION
    Este script conecta con Microsoft Graph API para realizar tareas de limpieza:
    1. Cruce de inventarios entre Intune y Entra ID.
    2. Identificacion y borrado de dispositivos inactivos (por fecha).
    3. Deteccion de dispositivos "huerfanos" y registros Workplace.
    4. Eliminacion de duplicados en Intune basados en el numero de serie.
    5. Exportacion automatica de reportes CSV.

.NOTES
    Autor:         Ismael Morilla
    Fecha:         2025-12-23
    Version:       5.5
    Requisitos:    App Registration en Azure con permisos (Aplicacion):
                   - Device.ReadWrite.All
                   - DeviceManagementManagedDevices.ReadWrite.All

.LINK
    https://github.com/cinqueles09/Graph-Tools
#>

Clear-Host
$lineaVisual = "================================================================"
Write-Host $lineaVisual -ForegroundColor Cyan
Write-Host "   SISTEMA DE GESTION DE DISPOSITIVOS - MICROSOFT GRAPH" -ForegroundColor White
Write-Host $lineaVisual -ForegroundColor Cyan

# ==========================
# CONFIGURACIÓN DE ACCESO
# ==========================
# Solicitar datos por pantalla
Write-Host "`n[?] Introduce los datos de la aplicacion registrada:" -ForegroundColor Yellow

$tenantId     = Read-Host "1. Introduce el Directory (tenant) ID"
$appId        = Read-Host "2. Introduce el Application (client) ID"

# Solicitamos el secreto de forma segura
$secretInput  = Read-Host "3. Introduce el Client Secret" -AsSecureString

# MÉTODO COMPATIBLE: Convierte el SecureString a texto plano de forma segura
$credential   = New-Object System.Management.Automation.PSCredential("user", $secretInput)
$clientSecret = $credential.GetNetworkCredential().Password

$scopes       = "https://graph.microsoft.com/.default"

# ==========================
# OBTENCION DE TOKEN
# ==========================
Write-Host "`n[i] Conectando con Microsoft Identity..." -ForegroundColor Gray

try {
    $authBody = @{
        client_id     = $appId
        scope         = $scopes
        grant_type    = "client_credentials"
        client_secret = $clientSecret
    }

    $authResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $authBody
    $token = $authResponse.access_token

    if ($token) {
        Write-Host "  [OK] Autenticacion exitosa. Token generado." -ForegroundColor Green
    }
}
catch {
    Write-Host "  [!] ERROR: No se pudo obtener el token de acceso." -ForegroundColor Red
    Write-Host "      Detalle: $($_.Exception.Message)" -ForegroundColor Red
    return # Detiene la ejecucion si falla la autenticacion
}

# ==========================
# CABECERAS PARA GRAPH
# ==========================
$headers = @{ 
    Authorization  = "Bearer $token"
    "Content-Type" = "application/json"
}

Write-Host "  [i] Cabeceras de sesion configuradas." -ForegroundColor Gray
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan

# ==============================================================================
# EXTRACCION DE DISPOSITIVOS
# ==============================================================================
Write-Host "[i] Iniciando consulta de inventarios en Microsoft Graph..." -ForegroundColor Gray

# --- Obtener Dispositivos de Intune ---
Write-Host "  > Extrayendo dispositivos de Intune..." -NoNewline
$devicesUrlIntune = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,operatingSystem,osVersion,managementAgent,managementState,lastSyncDateTime,userPrincipalName,azureADDeviceId,serialNumber&`$top=999"
$allManagedDevices = @()

do {
    $response = Invoke-RestMethod -Uri $devicesUrlIntune -Headers $headers -Method GET
    $allManagedDevices += $response.value
    $devicesUrlIntune = $response.'@odata.nextLink'
} while ($devicesUrlIntune -ne $null)
Write-Host " [OK] ($($allManagedDevices.Count) encontrados)" -ForegroundColor Green

# --- Obtener Dispositivos de Entra ID ---
Write-Host "  > Extrayendo dispositivos de Entra ID..." -NoNewline
$devicesUrlAAD = "https://graph.microsoft.com/v1.0/devices?`$select=id,deviceId,displayName,trustType,operatingSystem,managementType,registrationDateTime,approximateLastSignInDateTime,mdmAppId&`$top=999"
$allDevicesAAD = @()

do {
    $response = Invoke-RestMethod -Uri $devicesUrlAAD -Headers $headers -Method GET
    $allDevicesAAD += $response.value
    $devicesUrlAAD = $response.'@odata.nextLink'
} while ($devicesUrlAAD -ne $null)
Write-Host " [OK] ($($allDevicesAAD.Count) encontrados)" -ForegroundColor Green

# ==============================================================================
# COMPARACION DE REGISTROS
# ==============================================================================
Write-Host "`n[i] Cruzando datos entre plataformas..." -ForegroundColor Gray

$coincidentes = $allManagedDevices | Where-Object {
    $id = $_.azureADDeviceId
    $allDevicesAAD.deviceId -contains $id
}

$soloIntune = $allManagedDevices | Where-Object {
    $id = $_.azureADDeviceId
    $allDevicesAAD.deviceId -notcontains $id
}

$soloAAD = $allDevicesAAD | Where-Object {
    $id = $_.deviceId
    $allManagedDevices.azureADDeviceId -notcontains $id
}

Write-Host "  - Dispositivos en ambos:      $($coincidentes.Count)" 
Write-Host "  - Solo en Intune:             $($soloIntune.Count)" 
Write-Host "  - Solo en Entra ID:           $($soloAAD.Count)" 

# ==============================================================================
# EXPORTACION DE RESULTADOS
# ==============================================================================
$fecha = Get-Date -Format "yyyyMMdd_HHmmss"
$basePath = "C:\Temp\Comparativa_Dispositivos_$fecha"

Write-Host "`n[i] Generando reportes CSV..." -ForegroundColor Gray
if (!(Test-Path $basePath)) { 
    New-Item -ItemType Directory -Path $basePath -Force | Out-Null 
}

# Exportacion de archivos
$coincidentes | Select-Object deviceName, operatingSystem, osVersion, userPrincipalName, managementAgent, lastSyncDateTime, azureADDeviceId |
    Export-Csv -Path "$basePath\Coincidentes.csv" -NoTypeInformation -Encoding UTF8

$soloIntune | Select-Object deviceName, operatingSystem, osVersion, userPrincipalName, managementAgent, lastSyncDateTime, azureADDeviceId |
    Export-Csv -Path "$basePath\Solo_Intune.csv" -NoTypeInformation -Encoding UTF8

$soloAAD | Select-Object displayName, operatingSystem, trustType, managementType, registrationDateTime, approximateLastSignInDateTime, mdmAppId, deviceId |
    Export-Csv -Path "$basePath\Solo_AzureAD.csv" -NoTypeInformation -Encoding UTF8

Write-Host "  [OK] Archivos guardados en: $basePath" -ForegroundColor Green
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan

# ==========================
# DETECTAR DISPOSITIVOS INACTIVOS
# ==========================

#$fechaLimite = Get-Date "2024-12-31"

do {
    $inputFecha = Read-Host "Introduce la fecha limite (formato YYYY-MM-DD). Se analizaran dispositivos anteriores a esta fecha"

    try {
        $fechaLimite = [datetime]::ParseExact(
            $inputFecha,
            "yyyy-MM-dd",
            [System.Globalization.CultureInfo]::InvariantCulture
        )
        $fechaValida = $true
    }
    catch {
        Write-Host "Formato de fecha incorrecto. Ejemplo valido: 2024-12-31" -ForegroundColor Red
        $fechaValida = $false
    }

} until ($fechaValida)

Write-Host "Fecha limite establecida: $($fechaLimite.ToString('yyyy-MM-dd'))" -ForegroundColor Green

Write-Host "`nAnalizando dispositivos inactivos (ultima actividad antes de $FechaLimite)..." 



$inactivosIntune = $allManagedDevices | Where-Object {
    $_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime -lt $fechaLimite)
}

$inactivosAAD = $allDevicesAAD | Where-Object {
    $_.approximateLastSignInDateTime -and ([datetime]$_.approximateLastSignInDateTime -lt $fechaLimite)
}

Write-Host " - Intune inactivos: $($inactivosIntune.Count)" 
Write-Host " - Entra ID inactivos: $($inactivosAAD.Count)" 

$inactivosIntune | Export-Csv -Path "$basePath\Inactivos_Intune.csv" -NoTypeInformation -Encoding UTF8
$inactivosAAD | Export-Csv -Path "$basePath\Inactivos_AzureAD.csv" -NoTypeInformation -Encoding UTF8

# ==============================================================================
# MDM OFFICE 365 MOBILE
# ==============================================================================
Write-Host "[i] Identificando dispositivos con MDM Office 365 Mobile..." -ForegroundColor Gray
$office365MobileMDMAppId = "7add3ecd-5b01-452e-b4bf-cdaf9df1d097"

$mdmOfficeDevices = $allDevicesAAD | Where-Object {
    $_.mdmAppId -eq $office365MobileMDMAppId
}

Write-Host "  - Total dispositivos detectados: $($mdmOfficeDevices.Count)" 

# Exportacion
$pathOfficeMDM = "$basePath\Dispositivos_MDM_Office365Mobile_$fecha.csv"
$mdmOfficeDevices | Export-Csv -Path $pathOfficeMDM -NoTypeInformation -Encoding UTF8

Write-Host "  [OK] Listado exportado correctamente." -ForegroundColor Green
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan

# ==============================================================================
# BLOQUE 1: ELIMINACION DE INACTIVOS (INTUNE + ENTRA ID)
# ==============================================================================
Write-Host "[!] PROCESO DE ELIMINACION DE DISPOSITIVOS INACTIVOS EN INTUNE" -ForegroundColor Yellow
Write-Host "    Filtro: Ultima sincronizacion anterior a $($fechaLimite.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

# Buscar inactivos en Intune
$inactivosIntune = $allManagedDevices | Where-Object {
    $_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime -lt $fechaLimite)
}

# --- VALIDACION DE DISPOSITIVOS EXISTENTES ---
if ($inactivosIntune.Count -eq 0) {
    Write-Host "`n  [i] No se detectaron dispositivos inactivos en Intune." -ForegroundColor Green
    Write-Host "      Saltando bloque de eliminacion..." -ForegroundColor Gray
} 
else {
    Write-Host "`n[i] Dispositivos inactivos en Intune detectados: $($inactivosIntune.Count)" -ForegroundColor Gray

    # Exportar lista para revision
    $exportPathMDM = "$basePath\Dispositivos_Inactivos_Intune_$fecha.csv"
    $inactivosIntune | Select-Object deviceName, operatingSystem, lastSyncDateTime, azureADDeviceId, id |
        Export-Csv -Path $exportPathMDM -NoTypeInformation -Encoding UTF8

    Write-Host "  > Revision exportada en: $exportPathMDM" -ForegroundColor Gray

    # Mostrar lista ordenada
    $inactivosIntune_Ordenados = $inactivosIntune | Sort-Object deviceName
    Write-Host "`nListado para procesar:" -ForegroundColor White
    Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
    foreach ($device in $inactivosIntune_Ordenados) {
        $lastSync = if ($device.lastSyncDateTime) { [datetime]$device.lastSyncDateTime } else { "Sin datos" }
        Write-Host " - $($device.deviceName.PadRight(25)) | $($device.operatingSystem.PadRight(15)) | Sync: $lastSync"
    }
    Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan

    # Confirmar eliminacion
    Write-Host ""
    $confirm = Read-Host "[?] Deseas eliminar TODOS estos dispositivos de Intune y Entra ID? (S/N)"

    if ($confirm -match "^[sS]$") {
        Write-Host "`n[!] Iniciando ciclo de eliminacion..." -ForegroundColor Yellow

        foreach ($device in $inactivosIntune_Ordenados) {
            Write-Host "`n>>> Procesando: $($device.deviceName)" -ForegroundColor White
            $eliminadoIntune = $false
            $eliminadoAAD    = $false

            # --- Eliminar de Intune ---
            if ($device.id) {
                try {
                    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($device.id)" -Headers $headers -Method DELETE
                    Write-Host "    [OK] Eliminado de Intune" -ForegroundColor Cyan
                    $eliminadoIntune = $true
                } catch {
                    Write-Host "    [X] Error en Intune: $($_.Exception.Message)" -ForegroundColor Red
                }
            }

            # --- Buscar y eliminar de Entra ID ---
            if ($device.azureADDeviceId) {
                $aadDevice = $allDevicesAAD | Where-Object { $_.deviceId -eq $device.azureADDeviceId }
                if ($aadDevice) {
                    try {
                        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/devices/$($aadDevice.id)" -Headers $headers -Method DELETE
                        Write-Host "    [OK] Eliminado de Entra ID" -ForegroundColor Cyan
                        $eliminadoAAD = $true
                    } catch {
                        Write-Host "    [X] Error en Entra ID: $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "    [-] No se encontro en Entra ID (saltando)" -ForegroundColor Gray
                }
            }

            if (-not $eliminadoIntune -and -not $eliminadoAAD) {
                Write-Host "    [!] Atencion: No se pudo completar ninguna accion." -ForegroundColor Yellow
            }
        }
        Write-Host "`n[OK] Proceso completado." -ForegroundColor Green
    } else {
        Write-Host "`n[!] Operacion cancelada por el usuario." -ForegroundColor Red
    }
}
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan

# ==============================================================================
# BLOQUE 1.1: ELIMINAR INACTIVOS SOLO EN ENTRA ID (EXCLUYENDO SERVERS)
# ==============================================================================
Write-Host "[!] PROCESO DE DISPOSITIVOS OBSOLETOS EN ENTRA ID" -ForegroundColor Yellow
Write-Host "    Filtro: Actividad anterior a $($fechaLimite.ToString('yyyy-MM-dd')), excluir Windows Server" -ForegroundColor Gray

# Buscar inactivos en Entra ID (Filtrando por fecha y excluyendo Servers)
$inactivosAAD = $allDevicesAAD | Where-Object {
    $_.approximateLastSignInDateTime -and 
    ([datetime]$_.approximateLastSignInDateTime -lt $fechaLimite) -and
    $_.operatingSystem -notlike "*Server*"
}

# Excluir los que ya se procesaron en el Bloque 1 (los que estaban en Intune)
$inactivosSoloAAD = $inactivosAAD | Where-Object {
    $id = $_.deviceId
    -not ($inactivosIntune | Where-Object { $_.azureADDeviceId -eq $id })
}

# --- VALIDACION DE DISPOSITIVOS EXISTENTES ---
if ($inactivosSoloAAD.Count -eq 0) {
    Write-Host "`n  [i] No se encontraron dispositivos inactivos exclusivos de Entra ID (o son Servers)." -ForegroundColor Green
    Write-Host "      Saltando bloque de eliminacion..." -ForegroundColor Gray
} 
else {
    Write-Host "`n[i] Dispositivos inactivos detectados solo en Entra ID: $($inactivosSoloAAD.Count)" -ForegroundColor Gray

    # Exportar lista para revision
    $exportPathSoloAAD = "$basePath\Dispositivos_Inactivos_Solo_EntraID_$fecha.csv"
    $inactivosSoloAAD | Select-Object displayName, operatingSystem, trustType, managementType, 
                                registrationDateTime, approximateLastSignInDateTime, deviceId, id |
        Export-Csv -Path $exportPathSoloAAD -NoTypeInformation -Encoding UTF8

    Write-Host "  > Revision exportada en: $exportPathSoloAAD" -ForegroundColor Gray

    # Mostrar lista ordenada con formato tabular
    $inactivosSoloAAD_Ordenados = $inactivosSoloAAD | Sort-Object displayName
    Write-Host "`nListado para procesar (Solo Entra ID):" -ForegroundColor White
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ("{0,-25} | {1,-15} | {2}" -f "Dispositivo", "S.O.", "Ultimo Inicio (Entra ID)")
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan

    foreach ($device in $inactivosSoloAAD_Ordenados) {
        $lastSeen = if ($device.approximateLastSignInDateTime) { [datetime]$device.approximateLastSignInDateTime } else { "Sin datos" }
        Write-Host (" - {0,-25} | {1,-15} | {2}" -f $device.displayName, $device.operatingSystem, $lastSeen)
    }
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan

    # Confirmar eliminacion
    Write-Host ""
    $confirm = Read-Host "[?] Deseas eliminar estos dispositivos de Entra ID? (S/N)"

    if ($confirm -match "^[sS]$") {
        Write-Host "`n[!] Iniciando ciclo de eliminacion..." -ForegroundColor Yellow

        foreach ($device in $inactivosSoloAAD_Ordenados) {
            Write-Host "  > Eliminando: $($device.displayName.PadRight(25)) " -NoNewline
            try {
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/devices/$($device.id)" -Headers $headers -Method DELETE
                Write-Host "[OK]" -ForegroundColor Cyan
            } catch {
                Write-Host "[X] ERROR" -ForegroundColor Red
                Write-Host "      Motivo: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Write-Host "`n[OK] Proceso completado en Entra ID." -ForegroundColor Green
    } else {
        Write-Host "`n[!] Operacion cancelada por el usuario." -ForegroundColor Red
    }
}
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan

# ==============================================================================
# BLOQUE 2: ELIMINAR HUERFANOS (POR CATEGORÍAS)
# ==============================================================================
Write-Host "[!] PROCESO DE DISPOSITIVOS HUERFANOS REALES" -ForegroundColor Yellow

# 1. Crear listas de exclusión de Intune
$intuneIds = $allManagedDevices.azureADDeviceId | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
$intuneNames = $allManagedDevices.deviceName | Where-Object { $_ } | ForEach-Object { $_.ToLower() }

# --- FILTRADO POR CATEGORÍAS ---

# Grupo A: Solo Windows (No servidores)
$huerfanosWindows = $allDevicesAAD | Where-Object {
    $_.operatingSystem -like "*Windows*" -and
    $_.operatingSystem -notlike "*Server*" -and
    $_.registrationDateTime -eq $null -and
    $_.managementType -ne "MicrosoftSense" -and
    (
        ( -not $_.deviceId -or ($_.deviceId.ToLower() -notin $intuneIds) ) -and
        ( -not $_.displayName -or ($_.displayName.ToLower() -notin $intuneNames) )
    )
}

# Grupo B: Apple (iPad, iPhone, Mac)
$huerfanosApple = $allDevicesAAD | Where-Object {
    ($_.operatingSystem -like "*iPhone*" -or $_.operatingSystem -like "*iPad*" -or $_.operatingSystem -like "*Mac*") -and
    $_.registrationDateTime -eq $null -and
    (
        ( -not $_.deviceId -or ($_.deviceId.ToLower() -notin $intuneIds) ) -and
        ( -not $_.displayName -or ($_.displayName.ToLower() -notin $intuneNames) )
    )
}

# --- PROCESAMIENTO: WINDOWS ---
if ($huerfanosWindows.Count -gt 0) {
    Write-Host "`n[i] Windows detectados para revision: $($huerfanosWindows.Count)" -ForegroundColor Cyan
    foreach ($dev in ($huerfanosWindows | Sort-Object displayName)) {
        Write-Host " - $($dev.displayName.PadRight(25)) | $($dev.operatingSystem.PadRight(15))"
    }

    $confirmWin = Read-Host "`n[?] Deseas eliminar los dispositivos WINDOWS detectados? (S/N)"
    if ($confirmWin -match "^[sS]$") {
        foreach ($device in $huerfanosWindows) {
            Write-Host "  > Eliminando Windows: $($device.displayName)... " -NoNewline
            try {
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/devices/$($device.id)" -Headers $headers -Method DELETE
                Write-Host "[OK]" -ForegroundColor Cyan
            } catch { Write-Host "[ERROR]" -ForegroundColor Red }
        }
    } else { Write-Host "Operacion Windows cancelada." -ForegroundColor Red }
} else {
    Write-Host "`n[i] No se detectaron Windows huerfanos." -ForegroundColor Green
}

# --- PROCESAMIENTO: APPLE ---
if ($huerfanosApple.Count -gt 0) {
    Write-Host "`n[!] Apple (iPad/Mac) detectados: $($huerfanosApple.Count)" -ForegroundColor Magenta
    Write-Host "    Nota: Estos suelen ser registros de pre-inscripcion o ADE." -ForegroundColor Gray
    
    foreach ($dev in ($huerfanosApple | Sort-Object displayName)) {
        Write-Host " - $($dev.displayName.PadRight(25)) | $($dev.operatingSystem.PadRight(15))"
    }

    $confirmApple = Read-Host "`n[?] Deseas eliminar los dispositivos APPLE detectados? (S/N)"
    if ($confirmApple -match "^[sS]$") {
        foreach ($device in $huerfanosApple) {
            Write-Host "  > Eliminando Apple: $($device.displayName)... " -NoNewline
            try {
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/devices/$($device.id)" -Headers $headers -Method DELETE
                Write-Host "[OK]" -ForegroundColor Cyan
            } catch { Write-Host "[ERROR]" -ForegroundColor Red }
        }
    } else { Write-Host "Operacion Apple cancelada." -ForegroundColor Red }
} else {
    Write-Host "`n[i] No se detectaron Apple huerfanos." -ForegroundColor Green
}

Write-Host "`n----------------------------------------------------------------" -ForegroundColor Cyan

# ==============================================================================
# BLOQUE 3: DISPOSITIVOS CON TRUSTTYPE = WORKPLACE
# ==============================================================================
Write-Host "[!] ANALISIS DE DISPOSITIVOS REGISTERED (WORKPLACE)" -ForegroundColor Yellow
Write-Host "    Filtro: Windows, TrustType Workplace y no gestionados por MDM" -ForegroundColor Gray

$workplaceDevices = $allDevicesAAD | Where-Object {
    $_.trustType -eq "Workplace" -and
    $_.operatingSystem -notlike "*Server*" -and
    $_.operatingSystem -like "Windows*" -and
    $_.managementType -ne "MDM"
}

# --- VALIDACION DE DISPOSITIVOS EXISTENTES ---
if ($workplaceDevices.Count -eq 0) {
    Write-Host "`n  [i] No se detectaron dispositivos con trustType Workplace." -ForegroundColor Green
    Write-Host "      Saltando bloque de eliminacion..." -ForegroundColor Gray
} 
else {
    Write-Host "`n[i] Total dispositivos con trustType Workplace: $($workplaceDevices.Count)" -ForegroundColor Gray

    # Exportar a CSV
    $exportPathWorkplace = "$basePath\Dispositivos_TrustType_Workplace_$fecha.csv"
    $workplaceDevices | Select-Object displayName, operatingSystem, trustType, managementType,
                                registrationDateTime, approximateLastSignInDateTime, mdmAppId, deviceId, azureADDeviceId |
        Export-Csv -Path $exportPathWorkplace -NoTypeInformation -Encoding UTF8

    Write-Host "  > Lista exportada para revision: $exportPathWorkplace" -ForegroundColor Gray
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ("{0,-25} | {1,-15} | {2}" -f "Dispositivo", "S.O.", "Ultimo Inicio (Entra ID)")
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan

    # Ordenar alfabeticamente por nombre
    $workplaceDevices_Ordenados = $workplaceDevices | Sort-Object displayName

    foreach ($device in $workplaceDevices_Ordenados) {
        $lastLogon = if ($device.approximateLastSignInDateTime) { [datetime]$device.approximateLastSignInDateTime } else { "Sin datos" }
        Write-Host (" - {0,-25} | {1,-15} | {2}" -f $device.displayName, $device.operatingSystem, $lastLogon)
    }

    # Confirmacion del bloque
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    $confirmWorkplace = Read-Host "[?] Deseas eliminar estos dispositivos Registered? (S/N)"

    if ($confirmWorkplace -match "^[sS]$") {
        Write-Host "`n[!] Iniciando eliminacion de dispositivos Workplace..." -ForegroundColor Yellow

        foreach ($device in $workplaceDevices) {
            Write-Host "  > Eliminando: $($device.displayName.PadRight(25)) " -NoNewline

            # Comprobar si esta en Intune para evitar borrar activos
            $intuneDevice = $allManagedDevices | Where-Object {
                ($_.azureADDeviceId -eq $device.deviceId) -or ($_.deviceName -eq $device.displayName)
            }

            if ($intuneDevice) {
                Write-Host "[SALTADO]" -ForegroundColor Yellow
                Write-Host "      Motivo: Se encontro en Intune, abortando borrado." -ForegroundColor Gray
                continue
            }

            # Eliminar de Entra ID
            try {
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/devices/$($device.id)" -Headers $headers -Method DELETE
                Write-Host "[OK]" -ForegroundColor Cyan
            } catch {
                Write-Host "[X] ERROR" -ForegroundColor Red
                Write-Host "      Motivo: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Write-Host "`n[OK] Eliminacion completada para dispositivos Workplace." -ForegroundColor Green
    } else {
        Write-Host "`n[!] Operacion cancelada: no se eliminaron los dispositivos Workplace." -ForegroundColor Red
    }
}
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan

# ==============================================================================
# BLOQUE 4: DISPOSITIVOS REGISTERED GESTIONADOS POR INTUNE (MDM)
# ==============================================================================
Write-Host "[i] ANALISIS DE DISPOSITIVOS REGISTERED CON GESTION MDM" -ForegroundColor Cyan
Write-Host "    Nota: Estos dispositivos Windows estan en Intune y no se deben borrar sin revision." -ForegroundColor Gray

$registeredMDMDevices = $allDevicesAAD | Where-Object {
    $_.trustType -eq "Workplace" -and
    $_.managementType -eq "MDM" -and
    $_.operatingSystem -notlike "*Server*" -and
    $_.operatingSystem -like "Windows*"
}

# --- VALIDACION DE DISPOSITIVOS EXISTENTES ---
if ($registeredMDMDevices.Count -eq 0) {
    Write-Host "`n  [OK] No se detectaron dispositivos Registered con gestion MDM activa." -ForegroundColor Green
} 
else {
    Write-Host "`n[!] Detectados $($registeredMDMDevices.Count) dispositivos que requieren atencion." -ForegroundColor Yellow

    # Exportar a CSV
    $exportPathRegistered = "$basePath\Dispositivos_TrustType_Registered_MDM_$fecha.csv"
    $registeredMDMDevices | Select-Object displayName, operatingSystem, trustType, managementType,
                                registrationDateTime, approximateLastSignInDateTime, mdmAppId, deviceId, azureADDeviceId |
        Export-Csv -Path $exportPathRegistered -NoTypeInformation -Encoding UTF8

    Write-Host "  > Reporte detallado generado en: $exportPathRegistered" -ForegroundColor Gray

    # Mostrar lista ordenada para revision visual
    $registeredMDMDevices_Ordenados = $registeredMDMDevices | Sort-Object displayName
    Write-Host "`nListado de dispositivos (Revision Recomendada):" -ForegroundColor White
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ("{0,-25} | {1,-15} | {2}" -f "Dispositivo", "S.O.", "Tipo de Gestion")
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan

    foreach ($device in $registeredMDMDevices_Ordenados) {
        Write-Host (" - {0,-25} | {1,-15} | {2}" -f $device.displayName, $device.operatingSystem, $device.managementType)
    }
}

Write-Host "`n----------------------------------------------------------------" -ForegroundColor Cyan

# ==============================================================================
# BLOQUE 5: ELIMINAR DUPLICADOS EN INTUNE (POR NUMERO DE SERIE)
# ==============================================================================
Write-Host "[!] PROCESO DE DISPOSITIVOS DUPLICADOS EN INTUNE" -ForegroundColor Yellow
Write-Host "    Criterio: Mismo Numero de Serie (se conserva el mas reciente)" -ForegroundColor Gray

# Filtrar los dispositivos que tienen numero de serie valido
$devicesConSerie = $allManagedDevices | Where-Object { 
    $_.serialNumber -and $_.serialNumber -ne "" 
}

# Agrupar por numero de serie y quedarnos con los que aparecen mas de una vez
$duplicados = $devicesConSerie | Group-Object serialNumber | Where-Object { $_.Count -gt 1 }

if ($duplicados.Count -eq 0) {
    Write-Host "`n  [OK] No se encontraron dispositivos duplicados por numero de serie." -ForegroundColor Green
} 
else {
    Write-Host "`n[i] Numeros de serie duplicados detectados: $($duplicados.Count)" -ForegroundColor Gray
    $duplicadosParaEliminar = @()

    Write-Host "`nAnalisis de registros:" -ForegroundColor White
    Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Cyan
    
    foreach ($grupo in $duplicados) {
        $serial = $grupo.Name
        $dispositivos = $grupo.Group

        # Ordenar por fecha de sincronizacion descendente (mas reciente primero)
        $ordenados = $dispositivos | Sort-Object -Property {[datetime]$_.lastSyncDateTime} -Descending

        # El primero es el mas reciente, se conserva
        $aConservar = $ordenados[0]
        $aEliminar = $ordenados | Select-Object -Skip 1

        Write-Host "Serie: $($serial.PadRight(20))" -ForegroundColor Cyan
        Write-Host "  [KEEP] -> $($aConservar.deviceName.PadRight(25)) | Sync: $($aConservar.lastSyncDateTime)" -ForegroundColor Green
        
        foreach ($d in $aEliminar) {
            Write-Host "  [DEL]  -> $($d.deviceName.PadRight(25)) | Sync: $($d.lastSyncDateTime)" -ForegroundColor Red
            $duplicadosParaEliminar += $d
        }
        Write-Host "--------------------------------------------------------------------------------------------" -ForegroundColor Gray
    }

    # Exportar a CSV para registro
    $exportPathDuplicados = "$basePath\Dispositivos_Duplicados_Intune_$fecha.csv"
    $duplicadosParaEliminar | Select-Object deviceName, serialNumber, lastSyncDateTime, azureADDeviceId, id |
        Export-Csv -Path $exportPathDuplicados -NoTypeInformation -Encoding UTF8

    Write-Host "`n  > Registro de duplicados exportado en: $exportPathDuplicados" -ForegroundColor Gray

    # Confirmacion de eliminacion
    Write-Host ""
    $confirm = Read-Host "[?] Deseas eliminar estos $($duplicadosParaEliminar.Count) duplicados (manteniendo el mas reciente)? (S/N)"

    if ($confirm -match "^[sS]$") {
        Write-Host "`n[!] Iniciando ciclo de eliminacion en Intune..." -ForegroundColor Yellow

        foreach ($device in $duplicadosParaEliminar) {
            Write-Host "  > Eliminando duplicado: $($device.deviceName.PadRight(25)) " -NoNewline
            try {
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($device.id)" -Headers $headers -Method DELETE
                Write-Host "[OK]" -ForegroundColor Cyan
            } catch {
                Write-Host "[X] ERROR" -ForegroundColor Red
            }
        }
        Write-Host "`n[OK] Proceso de duplicados completado." -ForegroundColor Green
    } else {
        Write-Host "`n[!] Operacion cancelada por el usuario." -ForegroundColor Red
    }
}

# ==============================================================================
# CREACION AUTOMATICA DEL README EN LA CARPETA DE EXPORTACION
# ==============================================================================

$ReadmeContent = @"
README - Descripcion de ficheros CSV

Los ficheros contenidos en esta carpeta tienen el siguiente significado:

- Coincidentes
Dispositivos que tienen objeto tanto en Entra ID como en Intune.
No implica que los objetos esten correctamente configurados; solo que existen en ambas plataformas.

- Dispositivos Duplicados Intune
Dispositivos con mas de un objeto asociado al mismo numero de serie en Intune.
El CSV muestra los que seran eliminados por duplicidad.

- Dispositivos Inactivos Intune
Dispositivos inactivos en Intune segun la fecha indicada durante la ejecucion del script.

- Dispositivos Inactivos solo Entra ID
Dispositivos inactivos en Entra ID segun la fecha indicada y que no existen en Intune.

- Dispositivo MDM Office365Mobile
Dispositivos registrados con MDM Office365Mobile.
Requieren revision manual de licencia si estan activos.

- TrustType - Registered MDM
Dispositivos Registered inscritos en MDM.
Requieren cambio de tipo de inscripcion.

- TrustType Workplace
Dispositivos Windows Registered que no estan en Intune.
Requieren revision por posible registro personal.

- Solo Azure AD
Dispositivos existentes unicamente en Azure AD. Informativo.

- Solo Intune
Dispositivos existentes unicamente en Intune. Informativo.

Fecha de generacion: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Fecha limite analizada: $($fechaLimite.ToString("yyyy-MM-dd"))
Version Script: 5.5
"@

$ReadmePath = Join-Path $basePath "README.txt"

$ReadmeContent | Out-File -FilePath $ReadmePath -Encoding UTF8 -Force

Write-Host "`n[OK] README generado correctamente en: $ReadmePath" -ForegroundColor Green
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "         FIN DEL SCRIPT DE MANTENIMIENTO" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
