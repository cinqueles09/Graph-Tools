<#
.SYNOPSIS
    Script de consulta para Microsoft Graph: Comprobacion de contactos de usuario.
.DESCRIPTION
    Busca un contacto por direccion de correo dentro de la libreta de contactos
    de un usuario de Microsoft 365 y muestra sus datos (nombre, empresa,
    departamento, telefonos y metadatos) por consola.
.PARAMETER TenantId
    ID del Tenant de Azure AD. Se solicita en tiempo de ejecucion para permitir
    el uso del script contra cualquier tenant.
.PARAMETER AppId
    ID de la aplicacion registrada con permisos de aplicacion Contacts.Read
    (o Contacts.ReadWrite) en Microsoft Graph, con consentimiento de
    administrador concedido.
.PARAMETER ClientSecret
    Secreto de la aplicacion (Client Secret).
.NOTES
    Version: 2.0
    Autor: Ismael Morilla Orellana
    Fecha creacion: 2026-04-17
#>

# ==========================================================
# 1. Autenticación contra Microsoft Graph (cualquier tenant)
# ==========================================================
$tenantId     = Read-Host "Introduce el Tenant ID"
$clientId     = Read-Host "Introduce el Client ID (App Registration)"
$clientSecretSecure = Read-Host "Introduce el Client Secret" -AsSecureString

# Convertimos el SecureString a texto plano solo para el body de la petición
$clientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecretSecure)
)

$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

$body = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body

    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-Type"  = "application/json"
    }

    Write-Host "`n[OK] Autenticación correcta contra el tenant $tenantId`n" -ForegroundColor Green
}
catch {
    Write-Error "Error al autenticar: $_"
    return
}

# ==========================================================
# 2. Datos de busqueda
# ==========================================================
$targetUserUPN = Read-Host "Introduce el email del usuario (ej: aariza@contoso.com)"
$contactEmail  = Read-Host "Introduce el correo del contacto para extraer sus datos"

# ==========================================================
# 3. Consulta y volcado de datos reales
# ==========================================================
$searchUrl = "https://graph.microsoft.com/v1.0/users/$targetUserUPN/contacts?`$filter=emailAddresses/any(a:a/address eq '$contactEmail')"

try {
    $resultado = Invoke-RestMethod -Uri $searchUrl -Headers $headers -Method GET

    if ($resultado.value.Count -gt 0) {

        foreach ($contacto in $resultado.value) {

            Write-Host "`n========================================================" -ForegroundColor Cyan
            Write-Host "  CONTACTO ENCONTRADO" -ForegroundColor Cyan
            Write-Host "========================================================" -ForegroundColor Cyan

            Write-Host "`n  Nombre completo : " -NoNewline -ForegroundColor Gray
            Write-Host "$($contacto.displayName)" -ForegroundColor White

            Write-Host "  Empresa         : " -NoNewline -ForegroundColor Gray
            Write-Host "$(if ($contacto.companyName) { $contacto.companyName } else { '-' })"

            Write-Host "  Departamento    : " -NoNewline -ForegroundColor Gray
            Write-Host "$(if ($contacto.department) { $contacto.department } else { '-' })"

            Write-Host "  Puesto          : " -NoNewline -ForegroundColor Gray
            Write-Host "$(if ($contacto.jobTitle) { $contacto.jobTitle } else { '-' })"

            Write-Host "`n  --- Contacto ---" -ForegroundColor DarkGray
            Write-Host "  Email principal : " -NoNewline -ForegroundColor Gray
            Write-Host "$($contacto.primaryEmailAddress.address)" -ForegroundColor Yellow

            Write-Host "  Telefono móvil  : " -NoNewline -ForegroundColor Gray
            Write-Host "$(if ($contacto.mobilePhone) { $contacto.mobilePhone } else { '-' })"

            Write-Host "  Telefono trabajo: " -NoNewline -ForegroundColor Gray
            $businessPhone = if ($contacto.businessPhones -and $contacto.businessPhones.Count -gt 0) { $contacto.businessPhones -join ", " } else { "-" }
            Write-Host "$businessPhone"

            Write-Host "`n  --- Metadatos ---" -ForegroundColor DarkGray
            Write-Host "  Creado          : " -NoNewline -ForegroundColor Gray
            Write-Host "$($contacto.createdDateTime)"

            Write-Host "  Última modif.   : " -NoNewline -ForegroundColor Gray
            Write-Host "$($contacto.lastModifiedDateTime)"

            Write-Host "  ID Contacto     : " -NoNewline -ForegroundColor Gray
            Write-Host "$($contacto.id)" -ForegroundColor DarkGray

            Write-Host "========================================================`n" -ForegroundColor Cyan
        }

    } else {
        Write-Host "`n[!] No hay datos para el email: $contactEmail" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Error al extraer datos: $_"
}