<#
.SYNOPSIS
Intune & Entra ID Baseline Assessment Dashboard.

.DESCRIPTION
This script performs an initial (baseline) assessment of a Microsoft tenant,
focusing on Microsoft Intune and Entra ID (Azure AD).

```
It authenticates against Microsoft Graph using application credentials
(client credentials flow), retrieves relevant information (devices,
configurations, compliance, risky users, and policies), and generates
a structured dashboard for audit and analysis.

The objective is to provide visibility into the tenant’s security posture,
device management state, and potential risks.
```

.AUTHOR
Ismael Morilla Orellana

.VERSION
1.0.0

.LASTUPDATED
2026-04-18

.TAGS
Intune, EntraID, AzureAD, MicrosoftGraph, Audit, Assessment, Security, Compliance, Dashboard

.AUTHENTICATION
This script uses Microsoft Graph API with Application Permissions (App Registration).

.REQUIREMENTS
- PowerShell 5.1 or higher
- Internet connectivity
- Azure App Registration with the following Microsoft Graph API permissions:

```
    Application Permissions:
    - Device.Read.All
    - DeviceManagementConfiguration.Read.All
    - DeviceManagementManagedDevices.Read.All
    - IdentityRiskyUser.Read.All
    - Policy.Read.All

- Admin consent must be granted for the above permissions.

- Required credentials:
    * Tenant ID
    * Client ID
    * Client Secret
```

.PARAMETER tenantId
Azure tenant identifier used for authentication.

.PARAMETER clientId
Application (client) ID from Azure App Registration.

.PARAMETER clientSecret
Client secret associated with the application.

.PARAMETER nombreCliente
Customer display name used in the dashboard.

.PARAMETER logoCliente
URL of the customer logo. Defaults to Microsoft logo if not provided.

.OUTPUTS
Dashboard output (HTML or structured report).

.EXAMPLE
.\AuditBaseline.ps1

.NOTES
- Designed for audit and assessment scenarios.
- Supports large datasets via Microsoft Graph pagination (@odata.nextLink).
- Ensure secure handling of credentials (avoid hardcoding secrets).
- Execution time may vary depending on tenant size.

.DISCLAIMER
This script is provided "as is" without warranty of any kind.
Use at your own risk.

#>

# ==============================================================================
# DASHBOARD PROFESIONAL â€” INTUNE + ENTRA ID ASSESSMENT
# ==============================================================================

Clear-Host
Write-Host ""
Write-Host "  ===============================================================" -ForegroundColor Cyan
Write-Host "              INTUNE + ENTRA ID ASSESSMENT DASHBOARD" -ForegroundColor Cyan
Write-Host "  ===============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Assessment Dashboard - Intune + Entra ID" -ForegroundColor White
Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray

# ==============================
# 1. PARAMETROS DE ENTRADA
# ==============================
$tenantId     = Read-Host "  Tenant ID"
$clientId     = Read-Host "  Client ID (Application)"
$clientSecret = Read-Host "  Client Secret" -AsSecureString

$nombreCliente = Read-Host "  Nombre del Cliente"
$logoCliente   = Read-Host "  URL Logo Cliente (Enter para logo generico)"
if ([string]::IsNullOrWhiteSpace($logoCliente)) {
    $logoCliente = "https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/200px-Microsoft_logo.svg.png"
}

# ==============================
# 2. AUTENTICACION GRAPH
# ==============================
try {
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecret)
    $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)

    $authBody = @{
        grant_type    = "client_credentials"
        scope         = "https://graph.microsoft.com/.default"
        client_id     = $clientId
        client_secret = $plainSecret
    }

    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $authBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    $headers = @{ 
        Authorization = "Bearer $($tokenResponse.access_token)" 
        "Content-Type" = "application/json"
    }
    $plainSecret = $null
    Write-Host "  [+] Autenticado correctamente" -ForegroundColor Green
}
catch {
    Write-Host "  [-] Error de autenticacion: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ==============================
# 3. FUNCION AUXILIAR (REPARADA)
# ==============================
function Get-GraphPagedData {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][hashtable]$Headers,
        [string]$Label
    )

    $result = New-Object System.Collections.Generic.List[PSObject]
    $nextUri = $Uri
    Write-Host "  -> $Label" -ForegroundColor Gray

    while ($null -ne $nextUri) {
        try {
            $response = Invoke-RestMethod -Uri $nextUri -Headers $Headers -Method Get -ErrorAction Stop
            if ($null -ne $response.value) {
                foreach ($item in $response.value) { $result.Add($item) }
            }
            $nextUri = $response.'@odata.nextLink'
        }
        catch {
            Write-Host "    ! Error obteniendo datos: $($_.Exception.Message)" -ForegroundColor DarkYellow
            $nextUri = $null
        }
    }
    Write-Host "    Total: $($result.Count) registros" -ForegroundColor DarkGray
    return $result
}

# ==============================
# 4. OBTENCION DE DATOS
# ==============================
Write-Host ""
Write-Host "  Obteniendo datos de Microsoft Graph..." -ForegroundColor Yellow

# Intune Devices
$intuneUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,model,manufacturer,serialNumber,lastSyncDateTime,enrolledDateTime,managementAgent"
$intuneDevices = Get-GraphPagedData -Uri $intuneUri -Headers $headers -Label "Dispositivos Intune"

# Entra Devices
$entraUri = "https://graph.microsoft.com/v1.0/devices?`$select=displayName,operatingSystem,operatingSystemVersion,isCompliant,isManaged,trustType,approximateLastSignInDateTime"
$entraDevices = Get-GraphPagedData -Uri $entraUri -Headers $headers -Label "Dispositivos Entra ID"

# Risky Users
$riskyUsers = @()
try {
    $riskyUri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel ne 'none'"
    $riskyUsers = (Invoke-RestMethod -Uri $riskyUri -Headers $headers -Method Get).value
    Write-Host "  -> Riesgos: $($riskyUsers.Count) detectados" -ForegroundColor Gray
} catch {
    Write-Host "  ! Riesgos: Sin acceso o sin licencia P2" -ForegroundColor DarkYellow
}

# Conditional Access Policies
$conditionalPolicies = @()
try {
    $caUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=displayName,state,createdDateTime,modifiedDateTime"
    $conditionalPolicies = Get-GraphPagedData -Uri $caUri -Headers $headers -Label "Politicas de Acceso Condicional"
} catch {
    Write-Host "  ! Acceso Condicional: Sin acceso suficiente para leer politicas" -ForegroundColor DarkYellow
}

# MFA Registration (requiere Reports.Read.All)
$mfaRegistered = 0
$mfaTotal      = 0
try {
    $mfaData = Get-GraphPagedData -Uri "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails" -Headers $headers -Label "Registro MFA usuarios"
    $mfaTotal      = @($mfaData).Count
    $mfaRegistered = @($mfaData | Where-Object { $_.isMfaRegistered -eq $true }).Count
    Write-Host "  -> MFA: $mfaRegistered de $mfaTotal usuarios registrados" -ForegroundColor Gray
} catch {
    Write-Host "  ! MFA: Sin acceso (requiere Reports.Read.All)" -ForegroundColor DarkYellow
}
$pctMFA = if ($mfaTotal -gt 0) { [math]::Round(($mfaRegistered / $mfaTotal) * 100) } else { 0 }
# ==============================
# 5. CALCULO DE KPIs - INTUNE
# ==============================
Write-Host ""
Write-Host "  Calculando KPIs..." -ForegroundColor Yellow

function Test-IsMacDevice {
    param($Device)

    $os = [string]$Device.operatingSystem
    $manufacturer = [string]$Device.manufacturer
    $model = [string]$Device.model

    return (
        $os -match "(?i)mac|osx|os x|apple" -or
        $manufacturer -match "(?i)apple" -or
        $model -match "(?i)macbook|imac|mac mini|mac pro"
    )
}

$allIntune     = $intuneDevices
$winDevices    = $allIntune | Where-Object { $_.operatingSystem -match "Windows" }
$androidDevices= $allIntune | Where-Object { $_.operatingSystem -match "Android" }
$iosDevices    = $allIntune | Where-Object { $_.operatingSystem -match "iOS" }
$macDevices    = $allIntune | Where-Object { Test-IsMacDevice -Device $_ }

$cntWin     = @($winDevices).Count
$cntAndroid = @($androidDevices).Count
$cntiOS     = @($iosDevices).Count
$cntMac     = @($macDevices).Count
$cntTotal   = @($allIntune).Count

# Cumplimiento
function Get-CompliancePct {
    param($devices)
    $deviceCount = @($devices).Count
    if ($deviceCount -eq 0) { return 0 }
    $compliant = @($devices | Where-Object { $_.complianceState -eq "compliant" }).Count
    return [math]::Round(($compliant / $deviceCount) * 100)
}

$compWin     = Get-CompliancePct -devices $winDevices
$compAndroid = Get-CompliancePct -devices $androidDevices
$compiOS     = Get-CompliancePct -devices $iosDevices
$compMac     = Get-CompliancePct -devices $macDevices

$compGlobal  = if ($cntTotal -gt 0) { 
    [math]::Round((($allIntune | Where-Object {$_.complianceState -eq "compliant"}).Count / $cntTotal) * 100) 
} else { 0 }

# Entra ID KPIs
$cntEntra   = @($entraDevices).Count
$cntHAADJ   = @($entraDevices | Where-Object { $_.trustType -eq "ServerAd" }).Count
$cntEntraAD = @($entraDevices | Where-Object { $_.trustType -eq "AzureAd" }).Count
$cntRiskyU  = @($riskyUsers).Count
$cntCAPol   = @($conditionalPolicies).Count
$cntCAPol_En= @($conditionalPolicies | Where-Object { $_.state -eq "enabled" }).Count

# ==============================
# 6. SERIALIZACION JSON (SEGURA)
# ==============================
function NullSafe {
    param($Value, $Default = "")
    if ($null -eq $Value) { return $Default }
    return [string]$Value
}

function ConvertTo-SafeJson {
    param($Data)
    if ($null -eq $Data -or $Data.Count -eq 0) { return "[]" }
    $arr = @()
    foreach ($item in $Data) {
        $compliance = NullSafe $item.complianceState "unknown"
        $arr += [PSCustomObject]@{
            deviceName        = NullSafe $item.deviceName
            userPrincipalName = NullSafe $item.userPrincipalName
            operatingSystem   = NullSafe $item.operatingSystem
            osVersion         = NullSafe $item.osVersion
            complianceState   = $compliance
            lastSyncDateTime  = NullSafe $item.lastSyncDateTime
            manufacturer      = NullSafe $item.manufacturer
            model             = NullSafe $item.model
            serialNumber      = NullSafe $item.serialNumber
            enrolledDateTime  = NullSafe $item.enrolledDateTime
            managementAgent   = NullSafe $item.managementAgent
        }
    }
    return (ConvertTo-Json -InputObject @($arr) -Depth 3 -Compress)
}

function ConvertTo-SafeJsonEntra {
    param($Data)
    if ($null -eq $Data -or $Data.Count -eq 0) { return "[]" }
    $arr = @()
    foreach ($item in $Data) {
        $compliant = if ($null -ne $item.isCompliant) { [bool]$item.isCompliant } else { $false }
        $managed   = if ($null -ne $item.isManaged)   { [bool]$item.isManaged   } else { $false }
        $arr += [PSCustomObject]@{
            displayName     = NullSafe $item.displayName
            operatingSystem = NullSafe $item.operatingSystem
            osVersion       = NullSafe $item.operatingSystemVersion
            trustType       = NullSafe $item.trustType
            isCompliant     = $compliant
            isManaged       = $managed
            lastSignIn      = NullSafe $item.approximateLastSignInDateTime
        }
    }
    return (ConvertTo-Json -InputObject @($arr) -Depth 3 -Compress)
}

function ConvertTo-SafeJsonRisky {
    param($Data)
    if ($null -eq $Data -or $Data.Count -eq 0) { return "[]" }
    $arr = @()
    foreach ($item in $Data) {
        $arr += [PSCustomObject]@{
            displayName       = NullSafe $item.userDisplayName
            userPrincipalName = NullSafe $item.userPrincipalName
            riskLevel         = NullSafe $item.riskLevel
            riskDetail        = NullSafe $item.riskDetail
            lastUpdated       = NullSafe $item.riskLastUpdatedDateTime
        }
    }
    return (ConvertTo-Json -InputObject @($arr) -Depth 3 -Compress)
}

function ConvertTo-SafeJsonCA {
    param($Data)
    if ($null -eq $Data -or $Data.Count -eq 0) { return "[]" }
    $arr = @()
    foreach ($item in $Data) {
        $arr += [PSCustomObject]@{
            displayName = NullSafe $item.displayName
            state       = NullSafe $item.state
            created     = NullSafe $item.createdDateTime
            modified    = NullSafe $item.modifiedDateTime
        }
    }
    return (ConvertTo-Json -InputObject @($arr) -Depth 3 -Compress)
}

$jsonWin     = ConvertTo-SafeJson -Data $winDevices
$jsonAndroid = ConvertTo-SafeJson -Data $androidDevices
$jsoniOS     = ConvertTo-SafeJson -Data $iosDevices
$jsonMac     = ConvertTo-SafeJson -Data $macDevices
$jsonEntra   = ConvertTo-SafeJsonEntra  -Data $entraDevices
$jsonRisky   = ConvertTo-SafeJsonRisky  -Data $riskyUsers
$jsonCA      = ConvertTo-SafeJsonCA     -Data $conditionalPolicies

# ==============================
# 7. CALCULO DONUT (porcentajes -> dasharray con circunf. 289px)
# ==============================
$circunf = 289
function Get-DashArray {
    param([int]$Count, [int]$Total)
    if ($Total -eq 0) { return "0 $circunf" }
    $filled = [math]::Round(($Count / $Total) * $circunf)
    $gap    = $circunf - $filled
    return "$filled $gap"
}

$pctWin     = if ($cntTotal -gt 0) { [math]::Round(($cntWin     / $cntTotal) * 100) } else { 0 }
$pctAndroid = if ($cntTotal -gt 0) { [math]::Round(($cntAndroid / $cntTotal) * 100) } else { 0 }
$pctiOS     = if ($cntTotal -gt 0) { [math]::Round(($cntiOS     / $cntTotal) * 100) } else { 0 }
$pctMac     = if ($cntTotal -gt 0) { [math]::Round(($cntMac     / $cntTotal) * 100) } else { 0 }

$dashWin     = Get-DashArray -Count $cntWin     -Total $cntTotal
$dashAndroid = Get-DashArray -Count $cntAndroid -Total $cntTotal
$dashiOS     = Get-DashArray -Count $cntiOS     -Total $cntTotal
$dashMac     = Get-DashArray -Count $cntMac     -Total $cntTotal

# Offset acumulado del donut
$offsetWin     = 0
$offsetAndroid = [math]::Round(($cntWin     / [math]::Max($cntTotal,1)) * 360)
$offsetiOS     = $offsetAndroid + [math]::Round(($cntAndroid / [math]::Max($cntTotal,1)) * 360)
$offsetMac     = $offsetiOS     + [math]::Round(($cntiOS     / [math]::Max($cntTotal,1)) * 360)

# Fecha y nombre de fichero
$fechaReporte  = Get-Date -Format "dd/MM/yyyy HH:mm"
$fechaFichero  = Get-Date -Format "yyyyMMdd_HHmm"
$clienteSlug   = ($nombreCliente -replace '[^a-zA-Z0-9]', '')

# ==============================
# 8. GENERACION HTML
# ==============================
Write-Host "  Generando HTML..." -ForegroundColor Yellow

$html = @'
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Assessment - $nombreCliente</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Syne:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #0a0f1e; --surface: #111827; --surface2: #1a2235;
  --border: rgba(99,179,237,0.15); --border2: rgba(99,179,237,0.4);
  --text: #e2e8f0; --muted: #64748b;
  --blue: #63b3ed; --cyan: #4fd1c5; --purple: #a78bfa;
  --green: #68d391; --orange: #f6ad55; --red: #fc8181;
  --font: 'Syne', sans-serif; --mono: 'IBM Plex Mono', monospace;
}
body { font-family: var(--font); background: var(--bg); color: var(--text); font-size: 14px; }
.header { background: #0d1b35; border-bottom: 1px solid var(--border); padding: 0 32px;
  display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 24px;
  min-height: 72px; position: relative; }
.header::after { content:''; position:absolute; bottom:0; left:0; right:0; height:1px;
  background: linear-gradient(90deg, transparent, var(--blue), var(--cyan), transparent); }
.logo-area { display:flex; align-items:center; gap:12px; }
.logo-icon { width:36px; height:36px; border-radius:8px; display:flex; align-items:center;
  justify-content:center; overflow:hidden; background:rgba(99,179,237,0.1); }
.logo-icon img { max-width:100%; max-height:100%; object-fit:contain; }
.logo-text { font-size:16px; font-weight:700; }
.logo-sub { font-family:var(--mono); font-size:10px; color:var(--muted); margin-top:1px; }
.header-center { text-align:center; }
.header-title { font-size:20px; font-weight:700; letter-spacing:-0.5px; }
.header-subtitle { font-family:var(--mono); font-size:11px; color:var(--muted); margin-top:2px; }
.header-meta { text-align:right; }
.meta-date { font-family:var(--mono); font-size:11px; color:var(--cyan); }
.status-dot { display:inline-flex; align-items:center; gap:6px; font-family:var(--mono);
  font-size:10px; color:var(--green); margin-top:4px; }
.status-dot::before { content:''; width:7px; height:7px; border-radius:50%;
  background:var(--green); animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
.tabs-bar { background:var(--surface); border-bottom:1px solid var(--border); padding:0 32px; display:flex; }
.tab { padding:14px 22px; font-size:12px; font-weight:600; letter-spacing:0.8px;
  text-transform:uppercase; color:var(--muted); cursor:pointer;
  border-bottom:2px solid transparent; transition:all .2s; display:flex; align-items:center; gap:8px; }
.tab:hover { color:var(--text); }
.tab.active { color:var(--blue); border-bottom-color:var(--blue); }
.tab-badge { font-family:var(--mono); font-size:9px; padding:2px 5px; border-radius:4px;
  background:rgba(99,179,237,0.12); color:var(--blue); }
.main { padding:28px 32px; }
.section-label { font-family:var(--mono); font-size:10px; letter-spacing:2px; color:var(--muted);
  text-transform:uppercase; margin-bottom:16px; display:flex; align-items:center; gap:10px; }
.section-label::after { content:''; flex:1; height:1px; background:var(--border); }
.kpi-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:32px; }
.kpi-card { background:var(--surface); border:1px solid var(--border); border-radius:12px;
  padding:20px; position:relative; overflow:hidden; cursor:pointer; transition:border-color .2s, transform .1s; }
.kpi-card:hover { border-color:var(--border2); transform:translateY(-1px); }
.kpi-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px;
  background:var(--card-accent, var(--blue)); opacity:0.7; }
.kpi-header { display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:14px; }
.kpi-platform { font-family:var(--mono); font-size:10px; letter-spacing:1.5px; text-transform:uppercase; color:var(--muted); }
.kpi-icon { width:32px; height:32px; border-radius:8px; display:flex; align-items:center;
  justify-content:center; font-size:16px; background:var(--icon-bg, rgba(99,179,237,0.1)); }
.kpi-count { font-size:36px; font-weight:700; letter-spacing:-1px; color:var(--text); line-height:1; margin-bottom:6px; }
.kpi-pct { font-family:var(--mono); font-size:11px; color:var(--muted); }
.kpi-footer { display:flex; align-items:center; justify-content:space-between; margin-top:12px;
  padding-top:12px; border-top:1px solid var(--border); }
.kpi-label { font-family:var(--mono); font-size:10px; color:var(--muted); }
.two-col { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:24px; }
.panel { background:var(--surface); border:1px solid var(--border); border-radius:12px; overflow:hidden; margin-bottom:24px; }
.panel-header { padding:16px 20px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; }
.panel-title { font-size:13px; font-weight:600; }
.panel-tag { font-family:var(--mono); font-size:9px; letter-spacing:1px; text-transform:uppercase;
  padding:3px 8px; border-radius:4px; background:rgba(99,179,237,0.08); color:var(--blue);
  border:1px solid rgba(99,179,237,0.2); }
.panel-body { padding:20px; }
.chart-donut-wrap { display:flex; align-items:center; gap:24px; }
.donut-legend { flex:1; }
.legend-row { display:flex; align-items:center; justify-content:space-between; padding:7px 0;
  border-bottom:1px solid var(--border); font-size:12px; }
.legend-row:last-child { border-bottom:none; }
.legend-left { display:flex; align-items:center; color:var(--muted); font-family:var(--mono); font-size:11px; }
.legend-dot { width:8px; height:8px; border-radius:50%; margin-right:8px; flex-shrink:0; }
.legend-count { font-weight:600; color:var(--text); font-family:var(--mono); font-size:12px; }
.legend-pct { font-size:10px; color:var(--muted); font-family:var(--mono); margin-left:4px; }
.compliance-bar-wrap { display:flex; flex-direction:column; gap:14px; }
.compliance-meta { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:6px; }
.compliance-name { font-size:12px; color:var(--text); font-family:var(--mono); }
.bar-track { height:6px; background:rgba(255,255,255,0.06); border-radius:6px; overflow:hidden; }
.bar-fill { height:100%; border-radius:6px; }
.device-table { width:100%; border-collapse:collapse; font-size:12px; }
.device-table th { font-family:var(--mono); font-size:9px; letter-spacing:1.5px; text-transform:uppercase;
  color:var(--muted); text-align:left; padding:0 12px 12px; border-bottom:1px solid var(--border); font-weight:500; }
.device-table td { padding:11px 12px; border-bottom:1px solid rgba(255,255,255,0.04); color:var(--text); vertical-align:middle; }
.device-table tr:last-child td { border-bottom:none; }
.device-table tr:hover td { background:rgba(99,179,237,0.03); }
.device-name { font-weight:600; font-size:12px; }
.device-user { color:var(--muted); font-size:11px; font-family:var(--mono); }
.badge { display:inline-flex; align-items:center; gap:4px; font-family:var(--mono); font-size:10px;
  padding:3px 7px; border-radius:4px; font-weight:500; }
.badge-compliant { background:rgba(104,211,145,0.12); color:var(--green); }
.badge-warning   { background:rgba(246,173,85,0.12);  color:var(--orange); }
.badge-error     { background:rgba(252,129,129,0.12); color:var(--red); }
.badge-info      { background:rgba(99,179,237,0.12);  color:var(--blue); }
.badge-muted     { background:rgba(100,116,139,0.12); color:var(--muted); }
.search-wrap { position:relative; margin-bottom:16px; }
.search-input { width:100%; background:var(--surface2); border:1px solid var(--border); border-radius:8px;
  padding:9px 12px 9px 36px; font-family:var(--mono); font-size:12px; color:var(--text); outline:none; transition:border-color .15s; }
.search-input:focus { border-color:var(--border2); }
.search-input::placeholder { color:var(--muted); }
.search-icon { position:absolute; left:11px; top:50%; transform:translateY(-50%); color:var(--muted); font-size:13px; pointer-events:none; }
.close-btn { background:rgba(252,129,129,0.1); border:1px solid rgba(252,129,129,0.3);
  color:var(--red); border-radius:5px; padding:4px 10px; cursor:pointer;
  font-family:var(--mono); font-size:10px; }
.close-btn:hover { background:rgba(252,129,129,0.2); }
.export-btn { display:inline-flex; align-items:center; gap:8px; font-family:var(--mono); font-size:11px;
  padding:9px 16px; border:1px solid var(--blue); border-radius:6px; background:rgba(99,179,237,0.08);
  color:var(--blue); cursor:pointer; transition:all .15s; }
.export-btn:hover { background:rgba(99,179,237,0.16); }
/* ENTRA GRID - FIX: grid forzado inline para compatibilidad */
.entra-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin-bottom:24px; }
/* ENTRA STAT - interactivo */
.entra-stat { background:var(--surface2); border:1px solid var(--border); border-radius:10px; padding:16px;
  cursor:pointer; transition:border-color .2s, transform .1s; }
.entra-stat:hover { border-color:var(--border2); transform:translateY(-1px); }
.entra-stat-label { font-family:var(--mono); font-size:9px; letter-spacing:1.5px; text-transform:uppercase; color:var(--muted); margin-bottom:8px; }
.entra-stat-value { font-size:28px; font-weight:700; letter-spacing:-0.5px; }
.risk-table { width:100%; border-collapse:collapse; font-size:12px; }
.risk-table th { font-family:var(--mono); font-size:9px; letter-spacing:1.5px; text-transform:uppercase;
  color:var(--muted); text-align:left; padding:0 12px 12px; border-bottom:1px solid var(--border); }
.risk-table td { padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.04); color:var(--text); }
.risk-table tr:last-child td { border-bottom:none; }
.risk-table tr:hover td { background:rgba(99,179,237,0.03); }
.ca-table { width:100%; border-collapse:collapse; font-size:12px; }
.ca-table th { font-family:var(--mono); font-size:9px; letter-spacing:1.5px; text-transform:uppercase;
  color:var(--muted); text-align:left; padding:0 12px 12px; border-bottom:1px solid var(--border); }
.ca-table td { padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.04); color:var(--text); }
.ca-table tr:last-child td { border-bottom:none; }
.ca-table tr:hover td { background:rgba(99,179,237,0.03); }
.tab-content { display:none; }
.tab-content.visible { display:block; }
.report-kpi-row { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:20px; }
.report-kpi { background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:14px; text-align:center; }
.report-kpi-val { font-size:28px; font-weight:700; }
.report-kpi-lbl { font-family:var(--mono); font-size:9px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-top:4px; }
.footer { background:var(--surface); border-top:1px solid var(--border); padding:14px 32px;
  display:flex; justify-content:space-between; align-items:center; }
.footer-text { font-family:var(--mono); font-size:10px; color:var(--muted); }
.footer-link { font-family:var(--mono); font-size:10px; color:var(--blue); cursor:pointer; margin-left:16px; }
/* DONUTS ENTRA */
.donuts-row { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:24px; }
.donut-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; overflow:hidden; }
.donut-card-header { padding:14px 18px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; }
.donut-card-title { font-size:12px; font-weight:600; }
.donut-card-body { padding:18px; display:flex; align-items:center; gap:20px; }
.donut-legend-scroll { flex:1; max-height:180px; overflow-y:auto; }
.donut-legend-scroll::-webkit-scrollbar { width:3px; }
.donut-legend-scroll::-webkit-scrollbar-thumb { background:var(--border2); border-radius:2px; }
.ver-plat-btn { font-family:var(--mono); font-size:9px; letter-spacing:1px; text-transform:uppercase;
  padding:3px 9px; border-radius:4px; border:1px solid var(--border); background:transparent;
  color:var(--muted); cursor:pointer; transition:all .15s; }
.ver-plat-btn:hover { border-color:var(--border2); color:var(--text); }
.ver-plat-btn.active { background:rgba(99,179,237,0.12); border-color:rgba(99,179,237,0.4); color:var(--blue); }
/* OBSOLESCENCIA */
.obs-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:24px; }
.obs-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; overflow:hidden; }
.obs-card-header { padding:14px 18px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; }
.obs-summary { display:flex; gap:0; }
.obs-half { flex:1; padding:16px 18px; text-align:center; }
.obs-half:first-child { border-right:1px solid var(--border); }
.obs-half-val { font-size:30px; font-weight:700; letter-spacing:-1px; }
.obs-half-lbl { font-family:var(--mono); font-size:9px; text-transform:uppercase; letter-spacing:1.5px; color:var(--muted); margin-top:4px; }
.obs-bar-wrap { padding:0 18px 16px; }
.obs-bar-track { height:8px; background:rgba(255,255,255,0.06); border-radius:8px; overflow:hidden; margin-top:6px; display:flex; }
.obs-bar-seg { height:100%; transition:width .4s; }
.obs-bar-labels { display:flex; justify-content:space-between; font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:4px; }
.obs-table { width:100%; border-collapse:collapse; font-size:12px; }
.obs-table th { font-family:var(--mono); font-size:9px; letter-spacing:1.5px; text-transform:uppercase; color:var(--muted); text-align:left; padding:0 12px 10px; border-bottom:1px solid var(--border); font-weight:500; }
.obs-table td { padding:9px 12px; border-bottom:1px solid rgba(255,255,255,0.04); color:var(--text); vertical-align:middle; }
.obs-table tr:last-child td { border-bottom:none; }
.obs-table tr:hover td { background:rgba(99,179,237,0.03); }
@media print {
  .tabs-bar { display:none; }
  .tab-content { display:block !important; }
  body { background:#fff; color:#000; }
}
</style>
</head>
<body>

<header class="header">
  <div class="logo-area">
    <div class="logo-icon">
      <img src="$logoCliente" alt="Logo $nombreCliente" onerror="this.parentElement.innerHTML='IT'">
    </div>
    <div>
      <div class="logo-text">$nombreCliente</div>
      <div class="logo-sub">Endpoint Management</div>
    </div>
  </div>
  <div class="header-center">
    <div class="header-title">Dashboard de auditoria de dispositivos</div>
    <div class="header-subtitle">Microsoft Intune + Entra ID - Assessment Report</div>
  </div>
  <div class="header-meta">
    <div class="meta-date">$fechaReporte</div>
    <div class="status-dot">Graph API Connected</div>
  </div>
</header>

<nav class="tabs-bar">
  <div class="tab active" onclick="switchTab('intune', this)">Intune <span class="tab-badge">$cntTotal</span></div>
  <div class="tab" onclick="switchTab('entra', this)">Entra ID <span class="tab-badge">$cntEntraNum</span></div>
  <div class="tab" onclick="switchTab('actividad', this)">Acceso Cond. <span class="tab-badge">$cntCAPolNum</span></div>
  <div class="tab" onclick="switchTab('reporte', this)">Reporte Ejecutivo</div>
</nav>

<!-- TAB INTUNE -->
<div class="tab-content visible" id="tab-intune">
  <div class="main">
    <div class="section-label">Resumen de Plataformas</div>
    <div class="kpi-grid">
      <div class="kpi-card" style="--card-accent:#63b3ed; --icon-bg:rgba(99,179,237,0.12);" onclick="showPanel('windows')">
        <div class="kpi-header">
          <div class="kpi-platform">Windows</div>
          <div class="kpi-icon">&#x1FA9F;</div>
        </div>
        <div class="kpi-count">$cntWin</div>
        <div class="kpi-pct">Cumplimiento: $compWin%</div>
        <div class="kpi-footer">
          <span class="kpi-label">$pctWin% del total</span>
          <span class="badge badge-compliant">$compWin% OK</span>
        </div>
      </div>
      <div class="kpi-card" style="--card-accent:#68d391; --icon-bg:rgba(104,211,145,0.12);" onclick="showPanel('android')">
        <div class="kpi-header">
          <div class="kpi-platform">Android</div>
          <div class="kpi-icon">&#x1F916;</div>
        </div>
        <div class="kpi-count">$cntAndroid</div>
        <div class="kpi-pct">Cumplimiento: $compAndroid%</div>
        <div class="kpi-footer">
          <span class="kpi-label">$pctAndroid% del total</span>
          <span class="badge badge-compliant">$compAndroid% OK</span>
        </div>
      </div>
      <div class="kpi-card" style="--card-accent:#a78bfa; --icon-bg:rgba(167,139,250,0.12);" onclick="showPanel('ios')">
        <div class="kpi-header">
          <div class="kpi-platform">iOS / iPadOS</div>
          <div class="kpi-icon">&#x1F4F1;</div>
        </div>
        <div class="kpi-count">$cntiOS</div>
        <div class="kpi-pct">Cumplimiento: $compiOS%</div>
        <div class="kpi-footer">
          <span class="kpi-label">$pctiOS% del total</span>
          <span class="badge badge-compliant">$compiOS% OK</span>
        </div>
      </div>
      <div class="kpi-card" style="--card-accent:#f6ad55; --icon-bg:rgba(246,173,85,0.12);" onclick="showPanel('macos')">
        <div class="kpi-header">
          <div class="kpi-platform">macOS</div>
          <div class="kpi-icon">&#x1F34E;</div>
        </div>
        <div class="kpi-count">$cntMac</div>
        <div class="kpi-pct">Cumplimiento: $compMac%</div>
        <div class="kpi-footer">
          <span class="kpi-label">$pctMac% del total</span>
          <span class="badge badge-compliant">$compMac% OK</span>
        </div>
      </div>
    </div>

    <div class="two-col">
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Distribucion por Plataforma</span>
          <span class="panel-tag">$cntTotal dispositivos</span>
        </div>
        <div class="panel-body">
          <div class="chart-donut-wrap">
            <svg width="130" height="130" viewBox="0 0 130 130" style="flex-shrink:0">
              <circle cx="65" cy="65" r="46" fill="none" stroke="#1a2235" stroke-width="22"/>
              <circle cx="65" cy="65" r="46" fill="none" stroke="#63b3ed" stroke-width="22"
                stroke-dasharray="$dashWin" transform="rotate(-90 65 65)"/>
              <circle cx="65" cy="65" r="46" fill="none" stroke="#68d391" stroke-width="22"
                stroke-dasharray="$dashAndroid" transform="rotate($rotAndroid 65 65)"/>
              <circle cx="65" cy="65" r="46" fill="none" stroke="#a78bfa" stroke-width="22"
                stroke-dasharray="$dashiOS" transform="rotate($rotiOS 65 65)"/>
              <circle cx="65" cy="65" r="46" fill="none" stroke="#f6ad55" stroke-width="22"
                stroke-dasharray="$dashMac" transform="rotate($rotMac 65 65)"/>
              <text x="65" y="60" text-anchor="middle" fill="#e2e8f0" font-size="20" font-weight="700" font-family="Syne,sans-serif">$cntTotal</text>
              <text x="65" y="76" text-anchor="middle" fill="#64748b" font-size="9" font-family="IBM Plex Mono,monospace">TOTAL</text>
            </svg>
            <div class="donut-legend">
              <div class="legend-row">
                <div class="legend-left"><span class="legend-dot" style="background:#63b3ed"></span>Windows</div>
                <div><span class="legend-count">$cntWin</span><span class="legend-pct">$pctWin%</span></div>
              </div>
              <div class="legend-row">
                <div class="legend-left"><span class="legend-dot" style="background:#68d391"></span>Android</div>
                <div><span class="legend-count">$cntAndroid</span><span class="legend-pct">$pctAndroid%</span></div>
              </div>
              <div class="legend-row">
                <div class="legend-left"><span class="legend-dot" style="background:#a78bfa"></span>iOS / iPadOS</div>
                <div><span class="legend-count">$cntiOS</span><span class="legend-pct">$pctiOS%</span></div>
              </div>
              <div class="legend-row">
                <div class="legend-left"><span class="legend-dot" style="background:#f6ad55"></span>macOS</div>
                <div><span class="legend-count">$cntMac</span><span class="legend-pct">$pctMac%</span></div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Cumplimiento por Plataforma</span>
          <span class="panel-tag">Global: $compGlobal%</span>
        </div>
        <div class="panel-body">
          <div class="compliance-bar-wrap">
            <div>
              <div class="compliance-meta">
                <span class="compliance-name">Windows</span>
                <span style="font-family:var(--mono); font-size:11px; color:var(--green)">$compWin%</span>
              </div>
              <div class="bar-track"><div class="bar-fill" style="width:$compWin%; background:#63b3ed"></div></div>
            </div>
            <div>
              <div class="compliance-meta">
                <span class="compliance-name">Android</span>
                <span style="font-family:var(--mono); font-size:11px; color:var(--green)">$compAndroid%</span>
              </div>
              <div class="bar-track"><div class="bar-fill" style="width:$compAndroid%; background:#68d391"></div></div>
            </div>
            <div>
              <div class="compliance-meta">
                <span class="compliance-name">iOS / iPadOS</span>
                <span style="font-family:var(--mono); font-size:11px; color:var(--green)">$compiOS%</span>
              </div>
              <div class="bar-track"><div class="bar-fill" style="width:$compiOS%; background:#a78bfa"></div></div>
            </div>
            <div>
              <div class="compliance-meta">
                <span class="compliance-name">macOS</span>
                <span style="font-family:var(--mono); font-size:11px; color:var(--green)">$compMac%</span>
              </div>
              <div class="bar-track"><div class="bar-fill" style="width:$compMac%; background:#f6ad55"></div></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TARJETA ACTUALIZACION / OBSOLESCENCIA -->
    <div class="obs-grid" id="obsGrid">
      <!-- Resumen global -->
      <div class="obs-card">
        <div class="obs-card-header">
          <span style="font-size:12px; font-weight:600;">Estado de Actualizacion</span>
          <span class="panel-tag" id="obsTag">-</span>
        </div>
        <div class="obs-summary">
          <div class="obs-half">
            <div class="obs-half-val" style="color:var(--green)" id="obsCurrentVal">-</div>
            <div class="obs-half-lbl">Actualizados</div>
          </div>
          <div class="obs-half">
            <div class="obs-half-val" style="color:var(--red)" id="obsOldVal">-</div>
            <div class="obs-half-lbl">Obsoletos</div>
          </div>
        </div>
        <div class="obs-bar-wrap">
          <div class="obs-bar-track">
            <div class="obs-bar-seg" id="obsBarCurrent" style="background:var(--green); width:0%"></div>
            <div class="obs-bar-seg" id="obsBarWarn"    style="background:var(--orange); width:0%"></div>
            <div class="obs-bar-seg" id="obsBarOld"     style="background:var(--red); width:0%"></div>
          </div>
          <div class="obs-bar-labels">
            <span id="obsLblCurrent" style="color:var(--green)">Actualizado</span>
            <span id="obsLblWarn"    style="color:var(--orange)">En riesgo</span>
            <span id="obsLblOld"     style="color:var(--red)">Obsoleto</span>
          </div>
        </div>
        <div style="padding:0 18px 14px; display:flex; gap:8px; flex-wrap:wrap;">
          <button class="export-btn" style="font-size:10px; padding:5px 10px;" onclick="showObsPanel('current')">Ver actualizados</button>
          <button class="export-btn" style="font-size:10px; padding:5px 10px; border-color:var(--orange); color:var(--orange); background:rgba(246,173,85,0.08);" onclick="showObsPanel('warn')">Ver en riesgo</button>
          <button class="export-btn" style="font-size:10px; padding:5px 10px; border-color:var(--red); color:var(--red); background:rgba(252,129,129,0.08);" onclick="showObsPanel('old')">Ver obsoletos</button>
        </div>
      </div>
      <!-- Detalle por tipo de gestion -->
      <div class="obs-card">
        <div class="obs-card-header">
          <span style="font-size:12px; font-weight:600;">Tipo de Gestion</span>
          <span class="panel-tag">MDM &middot; MDE &middot; SCCM</span>
        </div>
        <div style="padding:14px 18px; display:flex; flex-direction:column; gap:10px;" id="obsByMgmt"></div>
      </div>
    </div>

    <!-- PANEL DETALLE OBSOLESCENCIA (oculto) -->
    <div class="panel" id="obsDetailPanel" style="display:none; margin-bottom:24px;">
      <div class="panel-header">
        <span class="panel-title" id="obsDetailTitle">Dispositivos</span>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="panel-tag" id="obsDetailCount">-</span>
          <button class="close-btn" onclick="document.getElementById('obsDetailPanel').style.display='none'">Cerrar X</button>
        </div>
      </div>
      <div class="panel-body">
        <table class="obs-table">
          <thead><tr>
            <th>Dispositivo</th><th>Usuario</th><th>OS</th><th>Version</th><th>Estado</th><th>Gestion</th><th>Ultima Sync</th>
          </tr></thead>
          <tbody id="obsDetailBody"></tbody>
        </table>
        <div style="display:flex; justify-content:center; align-items:center; gap:15px; margin-top:15px; padding-top:15px; border-top:1px solid var(--border);">
          <button class="export-btn" id="obsPrevPage" onclick="changeObsPage(-1)" style="padding:5px 12px;">&laquo; Anterior</button>
          <span id="obsPageIndicator" style="font-family:var(--mono); font-size:12px; color:var(--muted);">Pagina 1 de 1</span>
          <button class="export-btn" id="obsNextPage" onclick="changeObsPage(1)" style="padding:5px 12px;">Siguiente &raquo;</button>
        </div>
      </div>
    </div>

    <!-- PANEL DISPOSITIVOS INTUNE -->
    <div class="panel" id="devicePanel" style="display:none;">
      <div class="panel-header">
        <span class="panel-title" id="panelTitle">Dispositivos</span>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="panel-tag" id="panelCount">-</span>
          <button class="close-btn" onclick="closePanel()">Cerrar X</button>
        </div>
      </div>
      <div class="panel-body">
        <div class="search-wrap">
          <span class="search-icon">&#x1F50D;</span>
          <input class="search-input" id="searchInput" placeholder="Buscar por nombre, usuario, OS..." oninput="filterDevices()">
        </div>
        <table class="device-table">
          <thead>
            <tr>
              <th>Dispositivo</th>
              <th>Usuario</th>
              <th>OS</th>
              <th>Version</th>
              <th>Cumplimiento</th>
              <th>Fabricante / Modelo</th>
              <th>Ultima Sync</th>
            </tr>
          </thead>
          <tbody id="deviceTableBody"></tbody>
        </table>
        <div style="display:flex; justify-content:center; align-items:center; gap:15px; margin-top:15px; padding-top:15px; border-top:1px solid var(--border);">
          <button class="export-btn" id="intunePrevPage" onclick="changeIntunePage(-1)" style="padding:5px 12px;">&laquo; Anterior</button>
          <span id="intunePageIndicator" style="font-family:var(--mono); font-size:12px; color:var(--muted);">Pagina 1 de 1</span>
          <button class="export-btn" id="intuneNextPage" onclick="changeIntunePage(1)" style="padding:5px 12px;">Siguiente &raquo;</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- TAB ENTRA ID -->
<div class="tab-content" id="tab-entra">
  <div class="main">
    <div class="section-label">Resumen Entra ID</div>

    <!-- GRID 3x2 con onclick en cada recuadro -->
    <div class="entra-grid" style="display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin-bottom:24px;">
      <div class="entra-stat" onclick="showEntraPanel('all')">
        <div class="entra-stat-label">Total Dispositivos Registrados</div>
        <div class="entra-stat-value" style="color:var(--blue)">$cntEntraNum</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('haadj')">
        <div class="entra-stat-label">Union Hibrida (HAADJ)</div>
        <div class="entra-stat-value" style="color:var(--cyan)">$cntHAADJ</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('aadj')">
        <div class="entra-stat-label">Union Pura Entra (AADJ)</div>
        <div class="entra-stat-value" style="color:var(--purple)">$cntEntraAD</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('risky')">
        <div class="entra-stat-label">Usuarios con MFA Activo</div>
        <div class="entra-stat-value" style="color:var(--green)">$pctMFAVal%</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('ca')">
        <div class="entra-stat-label">Politicas Acc. Condicional</div>
        <div class="entra-stat-value" style="color:var(--orange)">$cntCAPolNum</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('ca-enabled')">
        <div class="entra-stat-label">Pol. Acc. Condicional (Activas)</div>
        <div class="entra-stat-value" style="color:var(--green)">$cntCAPol_En</div>
      </div>
    </div>

    <!-- DONUTS: PLATAFORMAS Y VERSIONES DE SO -->
    <div class="donuts-row">
      <div class="donut-card">
        <div class="donut-card-header">
          <span class="donut-card-title">Distribucion por Plataforma</span>
          <span class="panel-tag" id="entraDonutPlatTag">-</span>
        </div>
        <div class="donut-card-body">
          <svg id="entraDonutPlat" width="120" height="120" viewBox="0 0 120 120" style="flex-shrink:0">
            <circle cx="60" cy="60" r="42" fill="none" stroke="#1a2235" stroke-width="20"/>
            <text x="60" y="56" text-anchor="middle" fill="#e2e8f0" font-size="18" font-weight="700" font-family="Syne,sans-serif" id="entraDonutPlatTotal">0</text>
            <text x="60" y="70" text-anchor="middle" fill="#64748b" font-size="8" font-family="IBM Plex Mono,monospace">TOTAL</text>
          </svg>
          <div class="donut-legend-scroll" id="entraLegendPlat"></div>
        </div>
      </div>
      <div class="donut-card">
        <div class="donut-card-header">
          <span class="donut-card-title">Versiones de Sistema Operativo</span>
          <span class="panel-tag" id="entraDonutVerTag">-</span>
        </div>
        <div style="padding:10px 18px 0; display:flex; gap:6px; flex-wrap:wrap;" id="verPlatBtns">
          <button class="ver-plat-btn active" data-plat="all"     onclick="selectVerPlat(this,'all')">Todos</button>
          <button class="ver-plat-btn"        data-plat="windows" onclick="selectVerPlat(this,'windows')">Windows</button>
          <button class="ver-plat-btn"        data-plat="android" onclick="selectVerPlat(this,'android')">Android</button>
          <button class="ver-plat-btn"        data-plat="ios"     onclick="selectVerPlat(this,'ios')">iOS</button>
          <button class="ver-plat-btn"        data-plat="macos"   onclick="selectVerPlat(this,'macos')">macOS</button>
        </div>
        <div class="donut-card-body">
          <svg id="entraDonutVer" width="120" height="120" viewBox="0 0 120 120" style="flex-shrink:0">
            <circle cx="60" cy="60" r="42" fill="none" stroke="#1a2235" stroke-width="20"/>
            <text x="60" y="56" text-anchor="middle" fill="#e2e8f0" font-size="18" font-weight="700" font-family="Syne,sans-serif" id="entraDonutVerTotal">0</text>
            <text x="60" y="70" text-anchor="middle" fill="#64748b" font-size="8" font-family="IBM Plex Mono,monospace">VERSIONES</text>
          </svg>
          <div class="donut-legend-scroll" id="entraLegendVer"></div>
        </div>
      </div>
    </div>

    <!-- PANEL DISPOSITIVOS ENTRA (oculto, se muestra al hacer clic) -->
    <div class="panel" id="entraDevPanel" style="display:none;">
      <div class="panel-header">
        <span class="panel-title" id="entraDevTitle">Dispositivos Entra ID</span>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="panel-tag" id="entraDevCount">-</span>
          <button class="close-btn" onclick="document.getElementById('entraDevPanel').style.display='none'">Cerrar X</button>
        </div>
      </div>
      <div class="panel-body">
        <div class="search-wrap">
          <span class="search-icon">&#x1F50D;</span>
          <input class="search-input" id="searchEntra" placeholder="Buscar dispositivo Entra ID..." oninput="filterEntra()">
        </div>
        <table class="device-table">
          <thead>
            <tr>
              <th>Nombre</th>
              <th>OS</th>
              <th>Version</th>
              <th>Tipo de Union</th>
              <th>Gestionado</th>
              <th>Conforme</th>
              <th>Ultimo Inicio de Sesion</th>
            </tr>
          </thead>
          <tbody id="entraTableBody"></tbody>
        </table>
        <div class="pagination-controls" id="entraPagination" style="display:flex; justify-content:center; align-items:center; gap:15px; margin-top:15px; padding-top:15px; border-top:1px solid var(--border);">
            <button class="export-btn" id="prevPage" onclick="changePage(-1)" style="padding: 5px 12px;">&laquo; Anterior</button>
            <span id="pageIndicator" style="font-family:var(--mono); font-size:12px; color:var(--muted);">Pagina 1 de 1</span>
            <button class="export-btn" id="nextPage" onclick="changePage(1)" style="padding: 5px 12px;">Siguiente &raquo;</button>
        </div>
      </div>
    </div>

    <!-- PANEL RISKY USERS (siempre visible en Entra) -->
    <div class="panel" id="riskyPanel">
      <div class="panel-header">
        <span class="panel-title">Identidades en Riesgo</span>
        <span class="panel-tag">Entra ID Protection - $cntRiskyU detectadas</span>
      </div>
      <div class="panel-body" style="padding:0 20px 20px;">
        <table class="risk-table" id="riskyTable">
          <thead>
            <tr>
              <th>Usuario</th>
              <th>UPN</th>
              <th>Nivel Riesgo</th>
              <th>Detalle</th>
              <th>Ultima Actualizacion</th>
            </tr>
          </thead>
          <tbody id="riskyTableBody"></tbody>
        </table>
      </div>
    </div>

  </div>
</div>

<!-- TAB ACCESO CONDICIONAL -->
<div class="tab-content" id="tab-actividad">
  <div class="main">
    <div class="section-label">Politicas de Acceso Condicional</div>
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title" id="caTitle">Politicas de Acceso Condicional</span>
        <span class="panel-tag" id="caCount">$cntCAPolNum total - $cntCAPol_En habilitadas</span>
      </div>
      <div class="panel-body" style="padding:0 20px 20px;">
        <table class="ca-table">
          <thead>
            <tr>
              <th>Nombre de Politica</th>
              <th>Estado</th>
              <th>Creada</th>
              <th>Modificada</th>
            </tr>
          </thead>
          <tbody id="caTableBody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- TAB REPORTE -->
<div class="tab-content" id="tab-reporte">
  <div class="main">
    <div class="section-label">Resumen Ejecutivo</div>
    <div class="report-kpi-row">
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--green)">$compGlobal%</div>
        <div class="report-kpi-lbl">Cumplimiento Global Intune</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--blue)">$cntTotal</div>
        <div class="report-kpi-lbl">Dispositivos Intune</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--orange)">$cntRiskyU</div>
        <div class="report-kpi-lbl">Identidades en Riesgo</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--cyan)">$cntEntraNum</div>
        <div class="report-kpi-lbl">Dispositivos Entra ID</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--purple)">$cntCAPolNum</div>
        <div class="report-kpi-lbl">Politicas Acc. Condicional</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--red)">$cntNoCompliant</div>
        <div class="report-kpi-lbl">Dispositivos No Conformes</div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Exportar Assessment</span>
        <span class="panel-tag">$fechaReporte</span>
      </div>
      <div class="panel-body" style="display:flex; gap:12px; flex-wrap:wrap;">
        <button class="export-btn" onclick="window.print()">Imprimir / PDF</button>
        <button class="export-btn" onclick="exportCSV()">Exportar CSV</button>
        <button class="export-btn" onclick="copyReport()">Copiar Resumen</button>
      </div>
    </div>
  </div>
</div>

<footer class="footer">
  <div class="footer-text">Microsoft Graph API v1.0 - $nombreCliente - Assessment: $fechaReporte</div>
  <div>
    <a href="https://endpoint.microsoft.com" target="_blank" class="footer-link">Intune Portal</a>
    <a href="https://entra.microsoft.com" target="_blank" class="footer-link">Entra Portal</a>
    <a href="https://portal.azure.com" target="_blank" class="footer-link">Azure Portal</a>
  </div>
</footer>

<script>
function ensureArray(v) {
  if (Array.isArray(v)) return v;
  if (v === null || v === undefined || v === '') return [];
  return [v];
}

const DATA = {
  windows: ensureArray($jsonWin),
  android: ensureArray($jsonAndroid),
  ios:     ensureArray($jsoniOS),
  macos:   ensureArray($jsonMac),
  entra:   ensureArray($jsonEntra),
  risky:   ensureArray($jsonRisky),
  ca:      ensureArray($jsonCA)
};

const platformNames = { windows:'Windows', android:'Android', ios:'iOS / iPadOS', macos:'macOS' };
let currentPlatform = null;
let currentEntraData = [];

function switchTab(id, el) {
  document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('visible'); });
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  document.getElementById('tab-' + id).classList.add('visible');
  el.classList.add('active');
}

function badge(state) {
  var map = {
    compliant:     '<span class="badge badge-compliant">Conforme</span>',
    noncompliant:  '<span class="badge badge-error">No Conforme</span>',
    unknown:       '<span class="badge badge-muted">Desconocido</span>',
    error:         '<span class="badge badge-error">Error</span>',
    inGracePeriod: '<span class="badge badge-warning">Periodo de Gracia</span>',
    configManager: '<span class="badge badge-info">ConfigMgr</span>'
  };
  return map[state] || '<span class="badge badge-muted">' + state + '</span>';
}

function riskBadge(level) {
  var map = {
    high:   '<span class="badge badge-error">ALTO</span>',
    medium: '<span class="badge badge-warning">MEDIO</span>',
    low:    '<span class="badge badge-info">BAJO</span>',
    none:   '<span class="badge badge-muted">NINGUNO</span>'
  };
  return map[level] || '<span class="badge badge-muted">' + level + '</span>';
}

function caBadge(state) {
  var map = {
    enabled:    '<span class="badge badge-compliant">Habilitada</span>',
    disabled:   '<span class="badge badge-muted">Deshabilitada</span>',
    enabledForReportingButNotEnforced: '<span class="badge badge-warning">Solo Informe</span>'
  };
  return map[state] || '<span class="badge badge-muted">' + state + '</span>';
}

function fmtDate(iso) {
  if (!iso) return '-';
  try { return new Date(iso).toLocaleString('es-ES', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' }); }
  catch(e) { return iso; }
}

// =====================================================================
// PAGINACION COMPARTIDA
// =====================================================================
var PAGE_SIZE = 25;

// --- INTUNE ---
var intunePage = 1;
var filteredIntuneData = [];

function showPanel(platform) {
  currentPlatform = platform;
  var devs = DATA[platform] || [];
  document.getElementById('panelTitle').textContent = 'Dispositivos - ' + platformNames[platform];
  document.getElementById('panelCount').textContent = devs.length + ' dispositivos';
  document.getElementById('searchInput').value = '';
  updateIntuneView(devs);
  var panel = document.getElementById('devicePanel');
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior:'smooth', block:'start' });
}

function updateIntuneView(data) {
  filteredIntuneData = data;
  intunePage = 1;
  renderIntunePage();
}

function renderIntunePage() {
  var tbody = document.getElementById('deviceTableBody');
  var totalPages = Math.ceil(filteredIntuneData.length / PAGE_SIZE) || 1;
  var start = (intunePage - 1) * PAGE_SIZE;
  var pageData = filteredIntuneData.slice(start, start + PAGE_SIZE);

  document.getElementById('intunePageIndicator').textContent = 'Pagina ' + intunePage + ' de ' + totalPages;
  document.getElementById('intunePrevPage').disabled = (intunePage === 1);
  document.getElementById('intuneNextPage').disabled = (intunePage === totalPages);
  document.getElementById('intunePrevPage').style.opacity = (intunePage === 1) ? '0.4' : '1';
  document.getElementById('intuneNextPage').style.opacity = (intunePage === totalPages) ? '0.4' : '1';

  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:24px; font-family:var(--mono)">Sin dispositivos</td></tr>';
    return;
  }
  tbody.innerHTML = pageData.map(function(d) {
    return '<tr>' +
      '<td><div class="device-name">' + (d.deviceName || '-') + '</div></td>' +
      '<td><div class="device-user">' + (d.userPrincipalName || '-') + '</div></td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.operatingSystem || '-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.osVersion || '-') + '</td>' +
      '<td>' + badge(d.complianceState) + '</td>' +
      '<td style="font-size:11px; color:var(--muted)">' + ([d.manufacturer, d.model].filter(Boolean).join(' / ') || '-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + fmtDate(d.lastSyncDateTime) + '</td>' +
      '</tr>';
  }).join('');
}

function changeIntunePage(step) {
  var totalPages = Math.ceil(filteredIntuneData.length / PAGE_SIZE) || 1;
  var newPage = intunePage + step;
  if (newPage >= 1 && newPage <= totalPages) {
    intunePage = newPage;
    renderIntunePage();
    document.getElementById('devicePanel').scrollIntoView({ behavior:'smooth', block:'start' });
  }
}

function filterDevices() {
  var q = document.getElementById('searchInput').value.toLowerCase();
  var devs = (DATA[currentPlatform] || []).filter(function(d) {
    return (d.deviceName||'').toLowerCase().indexOf(q) >= 0 ||
           (d.userPrincipalName||'').toLowerCase().indexOf(q) >= 0 ||
           (d.operatingSystem||'').toLowerCase().indexOf(q) >= 0;
  });
  updateIntuneView(devs);
}

// --- ENTRA ---
var entraPage = 1;
var filteredEntraData = [];

function updateEntraView(data) {
  filteredEntraData = data;
  entraPage = 1;
  renderEntraPage();
}

function renderEntraPage() {
  var tbody = document.getElementById('entraTableBody');
  var totalPages = Math.ceil(filteredEntraData.length / PAGE_SIZE) || 1;
  var start = (entraPage - 1) * PAGE_SIZE;
  var pageData = filteredEntraData.slice(start, start + PAGE_SIZE);
  var trustMap = { 'ServerAd':'Hibrida (HAADJ)', 'AzureAd':'Entra (AADJ)', 'Workplace':'Registrado' };

  document.getElementById('pageIndicator').textContent = 'Pagina ' + entraPage + ' de ' + totalPages;
  document.getElementById('prevPage').disabled = (entraPage === 1);
  document.getElementById('nextPage').disabled = (entraPage === totalPages);
  document.getElementById('prevPage').style.opacity = (entraPage === 1) ? '0.4' : '1';
  document.getElementById('nextPage').style.opacity = (entraPage === totalPages) ? '0.4' : '1';

  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:24px; font-family:var(--mono)">Sin datos de Entra ID</td></tr>';
    return;
  }
  tbody.innerHTML = pageData.map(function(d) {
    return '<tr>' +
      '<td style="font-weight:600">' + (d.displayName || '-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.operatingSystem || '-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.osVersion || '-') + '</td>' +
      '<td style="font-size:11px; color:var(--muted)">' + (trustMap[d.trustType] || d.trustType || '-') + '</td>' +
      '<td>' + (d.isManaged ? '<span class="badge badge-compliant">Si</span>' : '<span class="badge badge-muted">No</span>') + '</td>' +
      '<td>' + (d.isCompliant ? '<span class="badge badge-compliant">Si</span>' : '<span class="badge badge-muted">No</span>') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + fmtDate(d.lastSignIn) + '</td>' +
      '</tr>';
  }).join('');
}

function changePage(step) {
  var totalPages = Math.ceil(filteredEntraData.length / PAGE_SIZE) || 1;
  var newPage = entraPage + step;
  if (newPage >= 1 && newPage <= totalPages) {
    entraPage = newPage;
    renderEntraPage();
    document.getElementById('entraDevPanel').scrollIntoView({ behavior:'smooth', block:'start' });
  }
}

function filterEntra() {
  var q = document.getElementById('searchEntra').value.toLowerCase();
  var results = currentEntraData.filter(function(d) {
    return (d.displayName||'').toLowerCase().indexOf(q) >= 0 ||
           (d.operatingSystem||'').toLowerCase().indexOf(q) >= 0;
  });
  updateEntraView(results);
}

function closePanel() {
  document.getElementById('devicePanel').style.display = 'none';
}

// ---- ENTRA ----
function showEntraPanel(tipo) {
  var titles = {
    'all':        'Todos los Dispositivos Entra ID',
    'haadj':      'Dispositivos Hibridos (HAADJ)',
    'aadj':       'Dispositivos Entra puro (AADJ)',
    'risky':      'Identidades en Riesgo',
    'ca':         'Todas las Politicas de Acceso Condicional',
    'ca-enabled': 'Politicas de Acceso Condicional Activas'
  };

  // Ocultar panel de dispositivos Entra
  document.getElementById('entraDevPanel').style.display = 'none';

  if (tipo === 'risky') {
    // Scroll al panel de riesgos que ya esta visible
    document.getElementById('riskyPanel').scrollIntoView({ behavior:'smooth', block:'start' });

  } else if (tipo === 'ca' || tipo === 'ca-enabled') {
    // Ir a la pestana de acceso condicional y filtrar
    var tabEl = document.querySelector('.tab:nth-child(3)');
    switchTab('actividad', tabEl);
    var filtered = tipo === 'ca-enabled'
      ? DATA.ca.filter(function(p) { return p.state === 'enabled'; })
      : DATA.ca;
    document.getElementById('caTitle').textContent = titles[tipo];
    document.getElementById('caCount').textContent = filtered.length + ' politicas';
    renderCA(filtered);

  } else {
    var filtered;
    if (tipo === 'haadj') {
      filtered = DATA.entra.filter(function(d) { return d.trustType === 'ServerAd'; });
    } else if (tipo === 'aadj') {
      filtered = DATA.entra.filter(function(d) { return d.trustType === 'AzureAd'; });
    } else {
      filtered = DATA.entra;
    }
    currentEntraData = filtered;
    document.getElementById('entraDevTitle').textContent = titles[tipo];
    document.getElementById('entraDevCount').textContent = filtered.length + ' dispositivos';
    document.getElementById('searchEntra').value = '';
    updateEntraView(filtered);
    var panel = document.getElementById('entraDevPanel');
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior:'smooth', block:'start' });
  }
}


// ---- RISKY USERS ----
function renderRiskyUsers() {
  var tbody = document.getElementById('riskyTableBody');
  if (!DATA.risky || DATA.risky.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--muted); padding:24px; font-family:var(--mono)">Sin identidades en riesgo detectadas</td></tr>';
    return;
  }
  tbody.innerHTML = DATA.risky.map(function(u) {
    return '<tr>' +
      '<td style="font-weight:600">' + (u.displayName || '-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (u.userPrincipalName || '-') + '</td>' +
      '<td>' + riskBadge(u.riskLevel) + '</td>' +
      '<td style="font-size:11px; color:var(--muted)">' + ((u.riskDetail||'').replace(/([A-Z])/g, ' $1').trim() || '-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + fmtDate(u.lastUpdated) + '</td>' +
      '</tr>';
  }).join('');
}

// ---- ACCESO CONDICIONAL ----
function renderCA(data) {
  var tbody = document.getElementById('caTableBody');
  var src = data || DATA.ca;
  if (!src || src.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--muted); padding:24px; font-family:var(--mono)">Sin politicas de acceso condicional</td></tr>';
    return;
  }
  tbody.innerHTML = src.map(function(p) {
    return '<tr>' +
      '<td style="font-weight:600">' + (p.displayName || '-') + '</td>' +
      '<td>' + caBadge(p.state) + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + fmtDate(p.created) + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + fmtDate(p.modified) + '</td>' +
      '</tr>';
  }).join('');
}

// ---- CSV ----
function exportCSV() {
  var all = [].concat(DATA.windows||[], DATA.android||[], DATA.ios||[], DATA.macos||[]);
  var cols = ['deviceName','userPrincipalName','operatingSystem','osVersion','complianceState','manufacturer','model','serialNumber','enrolledDateTime','lastSyncDateTime'];
  var csv = [cols.join(';')].concat(all.map(function(d) {
    return cols.map(function(k) { return '"' + (d[k]||'') + '"'; }).join(';');
  })).join('\n');
  var blob = new Blob(['\uFEFF' + csv], { type:'text/csv;charset=utf-8;' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'intune_assessment_' + new Date().toISOString().slice(0,10) + '.csv';
  a.click();
}

function copyReport() {
  var txt = 'ASSESSMENT - $nombreCliente\nFecha: $fechaReporte\n--------------------------\nINTUNE\n  Total: $cntTotal dispositivos\n  Windows: $cntWin ($compWin% cumplimiento)\n  Android: $cntAndroid ($compAndroid% cumplimiento)\n  iOS: $cntiOS ($compiOS% cumplimiento)\n  macOS: $cntMac ($compMac% cumplimiento)\n  Cumplimiento Global: $compGlobal%\n\nENTRA ID\n  Total registrados: $cntEntraNum\n  Hibrida (HAADJ): $cntHAADJ\n  Entra puro (AADJ): $cntEntraAD\n  Identidades en riesgo: $cntRiskyU\n  Pol. Acceso Cond.: $cntCAPolNum ($cntCAPol_En habilitadas)';
  navigator.clipboard.writeText(txt).catch(function() { alert(txt); });
}

// =====================================================================
// DONUTS ENTRA ID
// =====================================================================
var DONUT_COLORS = ['#63b3ed','#68d391','#a78bfa','#f6ad55','#fc8181','#4fd1c5','#f687b3','#fbd38d','#90cdf4','#b794f4'];
var CIRC = 2 * Math.PI * 42; // circunferencia r=42

function buildDonut(svgId, legendId, tagId, totalId, groups, labelKey, countKey) {
  var svg = document.getElementById(svgId);
  var legend = document.getElementById(legendId);

  // Ordenar por cantidad desc, "Otros"/"Desconocida" siempre al final
  var sorted = groups.slice().sort(function(a, b) {
    var aOtros = /^(otros|desconocid)/i.test(a[labelKey]);
    var bOtros = /^(otros|desconocid)/i.test(b[labelKey]);
    if (aOtros && !bOtros) return 1;
    if (!aOtros && bOtros) return -1;
    return b[countKey] - a[countKey];
  });

  var total = sorted.reduce(function(s, g) { return s + g[countKey]; }, 0);
  document.getElementById(totalId).textContent = total;
  document.getElementById(tagId).textContent = sorted.length + ' grupos';

  // Quitar segmentos previos (mantener base + textos)
  var segs = svg.querySelectorAll('.dseg');
  segs.forEach(function(s) { s.parentNode.removeChild(s); });

  var offset = -CIRC / 4; // empezar arriba (-90 deg = -CIRC/4)
  var legendHtml = '';
  sorted.forEach(function(g, i) {
    var pct = total > 0 ? g[countKey] / total : 0;
    var dash = pct * CIRC;
    var gap  = CIRC - dash;
    var color = DONUT_COLORS[i % DONUT_COLORS.length];
    var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('class', 'dseg');
    circle.setAttribute('cx', 60);
    circle.setAttribute('cy', 60);
    circle.setAttribute('r', 42);
    circle.setAttribute('fill', 'none');
    circle.setAttribute('stroke', color);
    circle.setAttribute('stroke-width', 20);
    circle.setAttribute('stroke-dasharray', dash + ' ' + gap);
    circle.setAttribute('stroke-dashoffset', -offset);
    svg.insertBefore(circle, svg.querySelector('text'));
    offset += dash;
    var pctLbl = total > 0 ? Math.round(pct * 100) : 0;
    legendHtml += '<div class="legend-row">' +
      '<div class="legend-left"><span class="legend-dot" style="background:' + color + '"></span>' +
      '<span style="max-width:120px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + g[labelKey] + '">' + g[labelKey] + '</span></div>' +
      '<div><span class="legend-count">' + g[countKey] + '</span><span class="legend-pct"> ' + pctLbl + '%</span></div>' +
      '</div>';
  });
  legend.innerHTML = legendHtml || '<span style="font-family:var(--mono);font-size:11px;color:var(--muted)">Sin datos</span>';
}

function initEntraDonuts() {
  // -- Donut plataformas --
  var platMap = {};
  DATA.entra.forEach(function(d) {
    var os = d.operatingSystem || 'Desconocido';
    platMap[os] = (platMap[os] || 0) + 1;
  });
  var platGroups = Object.keys(platMap).map(function(k) { return { name: k, cnt: platMap[k] }; });
  platGroups.sort(function(a, b) { return b.cnt - a.cnt; });
  buildDonut('entraDonutPlat', 'entraLegendPlat', 'entraDonutPlatTag', 'entraDonutPlatTotal', platGroups, 'name', 'cnt');

  // -- Donut versiones: iniciar con "Todos" --
  buildVerDonut('all');
}

// Mapa de clave interna -> patron de busqueda en operatingSystem
var VER_PLAT_MAP = {
  windows: /windows/i,
  android: /android/i,
  ios:     /ios|ipad/i,
  macos:   /mac/i
};

function buildVerDonut(platKey) {
  var devs = DATA.entra;
  if (platKey !== 'all' && VER_PLAT_MAP[platKey]) {
    var re = VER_PLAT_MAP[platKey];
    devs = devs.filter(function(d) { return re.test(d.operatingSystem || ''); });
  }
  var verMap = {};
  devs.forEach(function(d) {
    var ver = (d.osVersion || 'Desconocida').trim();
    verMap[ver] = (verMap[ver] || 0) + 1;
  });
  var verGroups = Object.keys(verMap).map(function(k) { return { name: k, cnt: verMap[k] }; });
  verGroups.sort(function(a, b) { return b.cnt - a.cnt; });
  if (verGroups.length > 8) {
    var otros = verGroups.slice(8).reduce(function(s, g) { return s + g.cnt; }, 0);
    verGroups = verGroups.slice(0, 8);
    if (otros > 0) verGroups.push({ name: 'Otros', cnt: otros });
  }
  buildDonut('entraDonutVer', 'entraLegendVer', 'entraDonutVerTag', 'entraDonutVerTotal', verGroups, 'name', 'cnt');
}

function selectVerPlat(btn, platKey) {
  document.querySelectorAll('.ver-plat-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  buildVerDonut(platKey);
}

// =====================================================================
// OBSOLESCENCIA INTUNE
// =====================================================================

// --- Builds B oficiales de Microsoft (Patch Tuesday) por rama ---
// Fuente: support.microsoft.com/windows-release-health  (actualizado abril 2026)
// Formato: prefijo de 3 segmentos -> ultima build B publicada (sin OOB ni Preview)
var WIN_LATEST = {
  // Windows 11 25H2 / 24H2  (rama compartida 26100)
  '10.0.26100': { build: '10.0.26100.8246', label: 'W11 24H2/25H2', eol: false,
                  url: 'https://support.microsoft.com/topic/windows-11-version-24h2-update-history-0929c747-1815-4543-8461-0160d16f15e5' },
  // Windows 11 26H1 / 25H2  (rama 26200 - misma KB que 26100)
  '10.0.26200': { build: '10.0.26200.8246', label: 'W11 26H1',      eol: false,
                  url: 'https://support.microsoft.com/topic/windows-11-version-26h1-update-history-253c73cd-cab1-4bfd-94dc-76c452273fc9' },
  // Windows 11 23H2 / 22H2  (rama 22631/22621) - EoS junio 2025
  '10.0.22631': { build: '10.0.22631.5189', label: 'W11 23H2 (EoS)', eol: true,
                  url: 'https://support.microsoft.com/topic/windows-11-version-23h2-update-history-59875222-b990-4bd9-932f-91a5954de434' },
  '10.0.22621': { build: '10.0.22621.5189', label: 'W11 22H2 (EoS)', eol: true,
                  url: 'https://support.microsoft.com/topic/windows-11-version-22h2-update-history-ec4229c3-9184-4bd8-b4d1-97f83765a053' },
  // Windows 10 22H2 - EoS octubre 2025 (ultima build B: octubre 2025)
  '10.0.19045': { build: '10.0.19045.6456', label: 'W10 22H2 (EoS)', eol: true,
                  url: 'https://support.microsoft.com/topic/windows-10-update-history-8127c2c6-6edf-4fdf-8b9f-0f7be1ef3562' },
  '10.0.19044': { build: '10.0.19044.6456', label: 'W10 21H2 (EoS)', eol: true,
                  url: 'https://support.microsoft.com/topic/windows-10-update-history-8127c2c6-6edf-4fdf-8b9f-0f7be1ef3562' },
};

// Umbrales para Android/iOS/macOS
var MIN_VERSIONS = {
  android: { current: '14', warn: '12' },
  ios:     { current: '18', warn: '16' },
  macos:   { current: '15', warn: '13' }
};

function parseVer(v) {
  return String(v || '0').split('.').map(function(n) { return parseInt(n, 10) || 0; });
}
function cmpVer(a, b) {
  var va = parseVer(a), vb = parseVer(b);
  var len = Math.max(va.length, vb.length);
  for (var i = 0; i < len; i++) { var d = (va[i]||0)-(vb[i]||0); if (d!==0) return d; }
  return 0;
}

function getWinBuildPrefix(ver) {
  // Extrae los tres primeros segmentos: 10.0.22631.xxxx -> 10.0.22631
  var parts = String(ver || '').split('.');
  return parts.slice(0, 3).join('.');
}

function classifyWindows(ver) {
  if (!ver) return 'warn';
  var prefix = getWinBuildPrefix(ver);
  var entry  = WIN_LATEST[prefix];

  // Rama desconocida (anterior a W10 22H2) -> directamente obsoleto
  if (!entry) return 'old';

  // Rama EoS: si ademas le falta la ultima build B -> obsoleto; si esta al dia -> en riesgo
  if (entry.eol) {
    return cmpVer(ver, entry.build) >= 0 ? 'warn' : 'old';
  }

  // Rama activa: comparar build completa contra la ultima B publicada
  if (cmpVer(ver, entry.build) >= 0) return 'current';
  var verParts    = parseVer(ver);
  var latestParts = parseVer(entry.build);
  var revDiff = (latestParts[3] || 0) - (verParts[3] || 0);
  // Margen de 1 ciclo mensual (~500-800 puntos de revision)
  return revDiff <= 1000 ? 'warn' : 'old';
}

function classifyDevice(d) {
  var os  = (d.operatingSystem || '').toLowerCase();
  var ver = d.osVersion || '';
  if (os.indexOf('windows') >= 0) return classifyWindows(ver);
  var key = os.indexOf('android') >= 0 ? 'android'
           : (os.indexOf('ios') >= 0 || os.indexOf('ipad') >= 0) ? 'ios'
           : os.indexOf('mac') >= 0 ? 'macos' : null;
  if (!key || !ver) return 'warn';
  var min = MIN_VERSIONS[key];
  if (cmpVer(ver, min.current) >= 0) return 'current';
  if (cmpVer(ver, min.warn)    >= 0) return 'warn';
  return 'old';
}

// --- Intentar obtener builds actuales desde aka.ms (best-effort, puede fallar por CORS) ---
function tryFetchWinBuilds() {
  // No hay un JSON publico limpio sin CORS; usamos los valores hardcoded arriba.
  // Si en el futuro se expone un endpoint compatible, conectar aqui.
}

// --- Tipo de gestion ---
// managementAgent values: mdm, easMdm, configurationManagerClientMdm,
// configurationManagerClient, jamf, googleCloudDevicePolicyController, msSense, etc.
var MGMT_GROUPS = [
  { key: 'mdm',      label: 'MDM puro (Intune)',       color: '#63b3ed',
    match: function(a) { return a === 'mdm' || a === 'easmdm' || a === 'easMdm'; } },
  { key: 'sccm',     label: 'Co-management (SCCM+MDM)', color: '#f6ad55',
    match: function(a) { return a === 'configurationManagerClientMdm' || a === 'configurationManagerClientMdmEas'; } },
  { key: 'sccmonly', label: 'SCCM / ConfigMgr solo',   color: '#fc8181',
    match: function(a) { return a === 'configurationManagerClient'; } },
  { key: 'mde',      label: 'MDE (Defender ATP)',       color: '#a78bfa',
    match: function(a) { return a === 'msSense'; } },
  { key: 'jamf',     label: 'Jamf',                    color: '#4fd1c5',
    match: function(a) { return a === 'jamf'; } },
  { key: 'other',    label: 'Otro / Desconocido',       color: '#64748b',
    match: function(a) { return true; } } // catch-all
];

function getMgmtGroup(agent) {
  var a = (agent || '').trim();
  for (var i = 0; i < MGMT_GROUPS.length; i++) {
    if (MGMT_GROUPS[i].match(a)) return MGMT_GROUPS[i];
  }
  return MGMT_GROUPS[MGMT_GROUPS.length - 1];
}

function mgmtBadge(agent) {
  var g = getMgmtGroup(agent);
  return '<span class="badge" style="background:' + g.color + '22; color:' + g.color + '">' + g.label + '</span>';
}

var obsFilteredData = [];
var obsPage = 1;

function initObsolescencia() {
  var all = [].concat(DATA.windows||[], DATA.android||[], DATA.ios||[], DATA.macos||[]);
  var current = [], warn = [], old = [];
  all.forEach(function(d) {
    var c = classifyDevice(d);
    d._obsClass = c;
    if (c === 'current') current.push(d);
    else if (c === 'warn') warn.push(d);
    else old.push(d);
  });
  var total = all.length || 1;

  document.getElementById('obsCurrentVal').textContent = current.length;
  document.getElementById('obsOldVal').textContent = old.length;
  document.getElementById('obsTag').textContent = all.length + ' dispositivos';
  document.getElementById('obsBarCurrent').style.width = Math.round(current.length/total*100) + '%';
  document.getElementById('obsBarWarn').style.width    = Math.round(warn.length/total*100) + '%';
  document.getElementById('obsBarOld').style.width     = Math.round(old.length/total*100) + '%';
  document.getElementById('obsLblCurrent').textContent = 'Act. ' + Math.round(current.length/total*100) + '%';
  document.getElementById('obsLblWarn').textContent    = 'Riesgo ' + Math.round(warn.length/total*100) + '%';
  document.getElementById('obsLblOld').textContent     = 'Obs. ' + Math.round(old.length/total*100) + '%';

  // --- Tarjeta tipo de gestion ---
  var mgmtCount = {};
  all.forEach(function(d) {
    var g = getMgmtGroup(d.managementAgent || '');
    mgmtCount[g.key] = (mgmtCount[g.key] || 0) + 1;
  });
  var mgmtHtml = '';
  MGMT_GROUPS.forEach(function(g) {
    var cnt = mgmtCount[g.key] || 0;
    if (cnt === 0) return;
    var pct = Math.round(cnt / total * 100);
    mgmtHtml +=
      '<div onclick="showMgmtPanel(\'' + g.key + '\')" style="cursor:pointer; padding:6px 8px; border-radius:6px; transition:background .15s;" ' +
           'onmouseover="this.style.background=\'rgba(99,179,237,0.06)\'" onmouseout="this.style.background=\'transparent\'">' +
        '<div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:5px;">' +
          '<span style="display:flex; align-items:center; gap:6px;">' +
            '<span style="width:8px;height:8px;border-radius:50%;background:' + g.color + ';display:inline-block;flex-shrink:0;"></span>' +
            '<span style="font-family:var(--mono); font-size:11px; color:var(--text);">' + g.label + '</span>' +
          '</span>' +
          '<span style="font-family:var(--mono); font-size:10px; color:var(--muted);">' + cnt + ' <span style="color:' + g.color + '">(' + pct + '%)</span></span>' +
        '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%; background:' + g.color + ';"></div></div>' +
      '</div>';
  });
  document.getElementById('obsByMgmt').innerHTML = mgmtHtml ||
    '<span style="font-family:var(--mono);font-size:11px;color:var(--muted)">Sin datos de managementAgent</span>';
}

function showObsPanel(filter) {
  var all = [].concat(DATA.windows||[], DATA.android||[], DATA.ios||[], DATA.macos||[]);
  var titles = { current: 'Dispositivos Actualizados', warn: 'Dispositivos en Riesgo', old: 'Dispositivos Obsoletos' };
  obsFilteredData = all.filter(function(d) { return (d._obsClass || classifyDevice(d)) === filter; });
  obsPage = 1;
  document.getElementById('obsDetailTitle').textContent = titles[filter];
  document.getElementById('obsDetailCount').textContent = obsFilteredData.length + ' dispositivos';
  renderObsPage();
  var panel = document.getElementById('obsDetailPanel');
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior:'smooth', block:'start' });
}

function showMgmtPanel(mgmtKey) {
  var all = [].concat(DATA.windows||[], DATA.android||[], DATA.ios||[], DATA.macos||[]);
  var group = MGMT_GROUPS.filter(function(g) { return g.key === mgmtKey; })[0];
  var label = group ? group.label : mgmtKey;
  obsFilteredData = all.filter(function(d) {
    return getMgmtGroup(d.managementAgent || '').key === mgmtKey;
  });
  obsPage = 1;
  document.getElementById('obsDetailTitle').textContent = 'Dispositivos - ' + label;
  document.getElementById('obsDetailCount').textContent = obsFilteredData.length + ' dispositivos';
  renderObsPage();
  var panel = document.getElementById('obsDetailPanel');
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior:'smooth', block:'start' });
}

function renderObsPage() {
  var tbody = document.getElementById('obsDetailBody');
  var totalPages = Math.ceil(obsFilteredData.length / PAGE_SIZE) || 1;
  var start = (obsPage - 1) * PAGE_SIZE;
  var pageData = obsFilteredData.slice(start, start + PAGE_SIZE);
  document.getElementById('obsPageIndicator').textContent = 'Pagina ' + obsPage + ' de ' + totalPages;
  document.getElementById('obsPrevPage').disabled = (obsPage === 1);
  document.getElementById('obsNextPage').disabled = (obsPage === totalPages);
  document.getElementById('obsPrevPage').style.opacity = (obsPage === 1) ? '0.4' : '1';
  document.getElementById('obsNextPage').style.opacity = (obsPage === totalPages) ? '0.4' : '1';
  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:20px; font-family:var(--mono)">Sin dispositivos en esta categoria</td></tr>';
    return;
  }
  tbody.innerHTML = pageData.map(function(d) {
    var cls = d._obsClass || classifyDevice(d);
    var stateBadge = cls === 'current'
      ? '<span class="badge badge-compliant">Actualizado</span>'
      : cls === 'warn'
        ? '<span class="badge badge-warning">En riesgo</span>'
        : '<span class="badge badge-error">Obsoleto</span>';
    return '<tr>' +
      '<td style="font-weight:600">' + (d.deviceName||'-') + '</td>' +
      '<td style="font-family:var(--mono);font-size:11px;color:var(--muted)">' + (d.userPrincipalName||'-') + '</td>' +
      '<td style="font-family:var(--mono);font-size:11px;color:var(--muted)">' + (d.operatingSystem||'-') + '</td>' +
      '<td style="font-family:var(--mono);font-size:11px;color:var(--muted)">' + (d.osVersion||'-') + '</td>' +
      '<td>' + stateBadge + '</td>' +
      '<td>' + mgmtBadge(d.managementAgent) + '</td>' +
      '<td style="font-family:var(--mono);font-size:11px;color:var(--muted)">' + fmtDate(d.lastSyncDateTime) + '</td>' +
      '</tr>';
  }).join('');
}

function changeObsPage(step) {
  var totalPages = Math.ceil(obsFilteredData.length / PAGE_SIZE) || 1;
  var newPage = obsPage + step;
  if (newPage >= 1 && newPage <= totalPages) {
    obsPage = newPage;
    renderObsPage();
    document.getElementById('obsDetailPanel').scrollIntoView({ behavior:'smooth', block:'start' });
  }
}

// ---- INIT ----
try { renderRiskyUsers(); } catch(e) { console.warn('renderRiskyUsers:', e); }
try { renderCA(); }         catch(e) { console.warn('renderCA:', e); }
try { initEntraDonuts(); }  catch(e) { console.warn('initEntraDonuts:', e); }
try { initObsolescencia(); } catch(e) { console.warn('initObsolescencia:', e); }
</script>
</body>
</html>
'@


# ==============================
# REEMPLAZOS (orden correcto para evitar colisiones)
# ==============================
$cntNoCompliant = [string](($allIntune | Where-Object { $_.complianceState -ne 'compliant' }).Count)

# Calcular rotaciones del donut
$rotAndroid = [string]($offsetAndroid - 90)
$rotiOS     = [string]($offsetiOS - 90)
$rotMac     = [string]($offsetMac - 90)

# Alias sin ambiguedad para variables que comparten prefijo
$cntEntraNum = [string]$cntEntra
$cntCAPolNum = [string]$cntCAPol

$html = $html.Replace('$nombreCliente',  $nombreCliente)
$html = $html.Replace('$logoCliente',    $logoCliente)
$html = $html.Replace('$fechaReporte',   $fechaReporte)
# Intune KPIs
$html = $html.Replace('$cntWin',     [string]$cntWin)
$html = $html.Replace('$cntAndroid', [string]$cntAndroid)
$html = $html.Replace('$cntiOS',     [string]$cntiOS)
$html = $html.Replace('$cntMac',     [string]$cntMac)
$html = $html.Replace('$cntTotal',   [string]$cntTotal)
$html = $html.Replace('$compWin',     [string]$compWin)
$html = $html.Replace('$compAndroid', [string]$compAndroid)
$html = $html.Replace('$compiOS',     [string]$compiOS)
$html = $html.Replace('$compMac',     [string]$compMac)
$html = $html.Replace('$compGlobal',  [string]$compGlobal)
$html = $html.Replace('$pctWin',     [string]$pctWin)
$html = $html.Replace('$pctAndroid', [string]$pctAndroid)
$html = $html.Replace('$pctiOS',     [string]$pctiOS)
$html = $html.Replace('$pctMac',     [string]$pctMac)
# Donut
$html = $html.Replace('$dashWin',     $dashWin)
$html = $html.Replace('$dashAndroid', $dashAndroid)
$html = $html.Replace('$dashiOS',     $dashiOS)
$html = $html.Replace('$dashMac',     $dashMac)
$html = $html.Replace('$rotAndroid',  $rotAndroid)
$html = $html.Replace('$rotiOS',      $rotiOS)
$html = $html.Replace('$rotMac',      $rotMac)
# Entra ID - orden: primero los especificos, luego los genericos
$html = $html.Replace('$cntEntraAD',  [string]$cntEntraAD)
$html = $html.Replace('$cntEntraNum', $cntEntraNum)
$html = $html.Replace('$cntHAADJ',    [string]$cntHAADJ)
$html = $html.Replace('$cntRiskyU',   [string]$cntRiskyU)
$html = $html.Replace('$cntCAPol_En', [string]$cntCAPol_En)
$html = $html.Replace('$cntCAPolNum', $cntCAPolNum)
# Reporte
$html = $html.Replace('$cntNoCompliant', $cntNoCompliant)
# MFA
$pctMFAVal = [string]$pctMFA
$html = $html.Replace('$pctMFAVal', $pctMFAVal)
# JSON datos
$html = $html.Replace('$jsonWin',     $jsonWin)
$html = $html.Replace('$jsonAndroid', $jsonAndroid)
$html = $html.Replace('$jsoniOS',     $jsoniOS)
$html = $html.Replace('$jsonMac',     $jsonMac)
$html = $html.Replace('$jsonEntra',   $jsonEntra)
$html = $html.Replace('$jsonRisky',   $jsonRisky)
$html = $html.Replace('$jsonCA',      $jsonCA)

# ==============================
# GUARDAR Y ABRIR
# ==============================
$ruta = Join-Path $PSScriptRoot ("Assessment_{0}_{1}.html" -f $clienteSlug, $fechaFichero)

try {
    $html | Out-File -FilePath $ruta -Encoding UTF8 -Force
    Write-Host ""
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Dashboard generado correctamente" -ForegroundColor Green
    Write-Host "  Ruta: $ruta" -ForegroundColor White
    Write-Host "  Intune: $cntTotal dispositivos - Cumplimiento global: $compGlobal%" -ForegroundColor White
    Write-Host "  Entra ID: $cntEntra dispositivos - $cntRiskyU en riesgo" -ForegroundColor White
    Write-Host "  Acceso Condicional: $cntCAPol politicas ($cntCAPol_En habilitadas)" -ForegroundColor White
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    Invoke-Item $ruta
}
catch {
    Write-Host "  Error guardando el fichero: $_" -ForegroundColor Red
}
