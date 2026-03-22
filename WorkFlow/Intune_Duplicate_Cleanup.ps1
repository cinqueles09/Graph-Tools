<#
.SYNOPSIS
    Script de mantenimiento para Microsoft Intune: Eliminacion de dispositivos duplicados.

.DESCRIPTION
    Identifica dispositivos duplicados basandose en el Numero de Serie. 
    Conserva el registro con sincronización mas reciente y permite la confirmacion individual para la eliminacion de los antiguos.

.PARAMETER TenantId
    ID del Tenant de Azure AD.
.PARAMETER AppId
    ID de la aplicacion registrada con permisos DeviceManagementManagedDevices.ReadWrite.All.
.PARAMETER ClientSecret
    Secreto de la aplicacion (Client Secret).

.NOTES
    Version: 2.0
    Autor: Ismael Morilla Orellana
    Fecha modificacion: 2026-03-10
    Fecha creacion: 2026-01-28
#>

# ==============================================================================
# CABECERA DE EJECUCION
# ==============================================================================
Clear-Host
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   MANTENIMIENTO DE DISPOSITIVOS INTUNE - ELIMINACION DE DUPLICADOS" -ForegroundColor White
Write-Host "   Autor: Ismael Morilla Orellana" -ForegroundColor Gray
Write-Host "   Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# ==========================
# CONFIGURACION DE ACCESO
# ==========================
Write-Host "`n[?] Introduce los datos de la aplicacion para Microsoft Graph API:" -ForegroundColor Cyan

$tenantId     = Read-Host "1. Directory (tenant) ID"
$appId        = Read-Host "2. Application (client) ID"
$secretInput  = Read-Host "3. Client Secret" -AsSecureString

$credential   = New-Object System.Management.Automation.PSCredential("user", $secretInput)
$clientSecret = $credential.GetNetworkCredential().Password
$scopes       = "https://graph.microsoft.com/.default"

# ==========================
# OBTENCION DE TOKEN
# ==========================
Write-Host "`nConectando con Microsoft Graph..." -ForegroundColor Yellow
try {
    $token = (Invoke-RestMethod -Method Post -uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body @{
        client_id     = $appId
        scope         = $scopes
        grant_type    = "client_credentials"
        client_secret = $clientSecret
    }).access_token
} catch {
    Write-Error "No se pudo obtener el token. Revisa tus credenciales."
    return
}

$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

# ==========================
# PROCESAMIENTO DE DISPOSITIVOS
# ==========================
Write-Host "Obteniendo dispositivos de Intune..." -ForegroundColor Yellow
$devicesurl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,lastSyncDateTime,serialNumber&`$top=999"
$allManagedDevices = @()

do {
    $response = Invoke-RestMethod -uri $devicesurl -Headers $headers -Method GET
    $allManagedDevices += $response.value
    $devicesurl = $response.'@odata.nextLink'
} while ($devicesurl -ne $null)

$duplicados = ($allManagedDevices | Where-Object { $_.serialNumber } | Group-Object serialNumber | Where-Object { $_.Count -gt 1 })

if ($duplicados.Count -eq 0) {
    Write-Host "No se encontraron dispositivos duplicados." -ForegroundColor Green
} else {
    $eliminados = 0
    $omitidos = 0

    foreach ($grupo in $duplicados) {
        $ordenados = $grupo.Group | Sort-Object -Property {[datetime]$_.lastSyncDateTime} -Descending
        $principal = $ordenados[0]
        $aEliminar = $ordenados | Select-Object -Skip 1

        Write-Host "`n-----------------------------------------------------------" -ForegroundColor Gray
        Write-Host "N. Serie: $($grupo.Name)" -ForegroundColor Cyan
        Write-Host "  [CONSERVAR] $($principal.deviceName) (Ult. Sinc: $($principal.lastSyncDateTime))" -ForegroundColor Green

        foreach ($dev in $aEliminar) {
            Write-Host "  [ELIMINAR]  $($dev.deviceName) (Ult. Sinc: $($dev.lastSyncDateTime))" -ForegroundColor Red
            Write-Host "  Confirmar eliminacion de este dispositivo? (S/N): " -NoNewline -ForegroundColor Yellow
            
            $confirm = Read-Host
            if ($confirm -match "^[sS]$") {
                try {
                    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($dev.id)" -Headers $headers -Method DELETE
                    Write-Host "  -> Eliminado correctamente." -ForegroundColor Green
                    $eliminados++
                } catch {
                    Write-Host "  -> Error al eliminar." -ForegroundColor Red
                }
            } else {
                Write-Host "  -> Accion omitida." -ForegroundColor Gray
                $omitidos++
            }
        }
    }

    Write-Host "`n===========================================================" -ForegroundColor Cyan
    Write-Host "RESUMEN FINAL" -ForegroundColor Cyan
    Write-Host "Dispositivos eliminados: $eliminados" -ForegroundColor Green
    Write-Host "Dispositivos omitidos:   $omitidos" -ForegroundColor Gray
    Write-Host "===========================================================" -ForegroundColor Cyan
}
