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
$autorInforme  = "Ismael Morilla Orellana "
$anioCreacion  = "Abril - 2026"
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
# FUNCIONES UTILITARIAS (deben definirse antes de usarse)
# ==============================
function NullSafe {
    param($Value, $Default = "")
    if ($null -eq $Value) { return $Default }
    return [string]$Value
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
$intuneUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,model,manufacturer,serialNumber,lastSyncDateTime,enrolledDateTime,managementAgent,managedDeviceOwnerType"
$intuneDevices = Get-GraphPagedData -Uri $intuneUri -Headers $headers -Label "Dispositivos Intune"

# Entra Devices
$entraUri = "https://graph.microsoft.com/v1.0/devices?`$select=displayName,operatingSystem,operatingSystemVersion,isCompliant,isManaged,trustType,approximateLastSignInDateTime,mdmAppId,managementType,registrationDateTime,deviceId"
$entraDevices = Get-GraphPagedData -Uri $entraUri -Headers $headers -Label "Dispositivos Entra ID"

$riskyUsers = @()
$conditionalPolicies = @()
$compliancePolicies = @()
$compliancePolicyData = @()
$mfaRegistered = 0
$mfaTotal      = 0
$pctMFA = 0

# ==============================
# 4b. DIRECTIVA POR DEFECTO
# ==============================
$defaultPolicyId              = ""
$defaultPolicyNonCompl        = 0   # Has a compliance policy assigned  -> nonCompliant
$defaultPolicyError           = 0   # Is active                         -> nonCompliant
$defaultPolicyUnknown         = 0   # Enrolled user exists              -> nonCompliant

try {
    # Coger un dispositivo al azar de Intune para consultar sus estados de directiva
    $sampleDevice = $intuneDevices | Where-Object { $_.id } | Select-Object -First 1
    if ($sampleDevice) {
        $sampleId = $sampleDevice.id
        Write-Host "  -> Buscando Default Device Compliance Policy via dispositivo: $($sampleDevice.deviceName)" -ForegroundColor Gray
        $policyStates = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$sampleId/deviceCompliancePolicyStates" -Headers $headers -Method Get -ErrorAction Stop
        $defaultState = $policyStates.value | Where-Object { $_.displayName -match "Default Device Compliance Policy" } | Select-Object -First 1
        if ($defaultState) {
            $defaultPolicyId = $defaultState.id
            Write-Host "  -> Default Policy ID encontrado: $defaultPolicyId" -ForegroundColor Gray

            # Leer setting summaries — Graph devuelve settingName con ruta completa,
            # p.ej. "deviceCompliancePolicy/HasCompliancePolicyAssigned"
            $defSettings = @()
            try {
                $defSettingsUri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$defaultPolicyId/deviceSettingStateSummaries"
                $defSettingsResp = Invoke-RestMethod -Uri $defSettingsUri -Headers $headers -Method Get -ErrorAction Stop
                $defSettings = @($defSettingsResp.value)

                # Volcar todos los settingNames para diagnóstico
                Write-Host "  -> Default Policy settings encontrados ($($defSettings.Count)):" -ForegroundColor DarkGray
                foreach ($s in $defSettings) {
                    Write-Host ("     [{0}]  NC:{1}  Err:{2}  Unk:{3}" -f `
                        $s.settingName, $s.nonCompliantDeviceCount, $s.errorDeviceCount, $s.unknownDeviceCount) -ForegroundColor DarkGray
                }
            } catch {
                Write-Host "  ! No se pudieron leer deviceSettingStateSummaries: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }

            # Matching por la parte final del settingName (tras "/" o desde el inicio),
            # case-insensitive — cubre tanto "HasCompliancePolicyAssigned" como
            # "deviceCompliancePolicy/HasCompliancePolicyAssigned"
            function Get-DefaultSettingNC {
                param($Settings, [string]$Keyword)
                $match = $Settings | Where-Object {
                    ($_.settingName -split '/')[-1] -match "(?i)$Keyword"
                } | Select-Object -First 1
                if ($match) { return [int]($match.nonCompliantDeviceCount) }
                return 0
            }

            $defaultPolicyNonCompl = Get-DefaultSettingNC -Settings $defSettings -Keyword "RequireDeviceCompliancePolicyAssigned"
            $defaultPolicyError    = Get-DefaultSettingNC -Settings $defSettings -Keyword "RequireRemainContact"
            $defaultPolicyUnknown  = Get-DefaultSettingNC -Settings $defSettings -Keyword "RequireUserExistence"

            Write-Host ("  -> Default Policy valores: HasPolicy:{0}  IsActive:{1}  EnrolledUser:{2}" -f `
                $defaultPolicyNonCompl, $defaultPolicyError, $defaultPolicyUnknown) -ForegroundColor Cyan

        } else {
            Write-Host "  ! Default Device Compliance Policy no encontrada entre los estados del dispositivo de muestra" -ForegroundColor DarkYellow
            Write-Host "  -> Directivas encontradas en el dispositivo:" -ForegroundColor DarkGray
            foreach ($ps in $policyStates.value) {
                Write-Host "     $($ps.displayName)  [$($ps.id)]" -ForegroundColor DarkGray
            }
        }
    }
} catch {
    Write-Host "  ! No se pudo obtener la Default Device Compliance Policy: $($_.Exception.Message)" -ForegroundColor DarkYellow
}


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

# Tipo de Propiedad
$cntCorporate = @($allIntune | Where-Object { $_.managedDeviceOwnerType -eq "company" }).Count
$cntPersonal  = @($allIntune | Where-Object { $_.managedDeviceOwnerType -eq "personal" }).Count
$cntOwnerUnknown = $cntTotal - $cntCorporate - $cntPersonal
$pctCorporate = if ($cntTotal -gt 0) { [math]::Round(($cntCorporate / $cntTotal) * 100) } else { 0 }
$pctPersonal  = if ($cntTotal -gt 0) { [math]::Round(($cntPersonal  / $cntTotal) * 100) } else { 0 }
$pctOwnerUnknown = if ($cntTotal -gt 0) { [math]::Round(($cntOwnerUnknown / $cntTotal) * 100) } else { 0 }

# Entra ID KPIs
$cntEntra   = @($entraDevices).Count
$cntHAADJ   = @($entraDevices | Where-Object { $_.trustType -eq "ServerAd" }).Count
$cntEntraAD = @($entraDevices | Where-Object { $_.trustType -eq "AzureAd" }).Count
$cntRiskyU  = 0
$cntCAPol   = 0
$cntCAPol_En= 0

# ==============================
# 6. SERIALIZACION JSON (SEGURA)
# ==============================
# (NullSafe ya definida al inicio del script)

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
            enrolledDateTime       = NullSafe $item.enrolledDateTime
            managementAgent        = NullSafe $item.managementAgent
            managedDeviceOwnerType = NullSafe $item.managedDeviceOwnerType
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
            displayName          = NullSafe $item.displayName
            operatingSystem      = NullSafe $item.operatingSystem
            osVersion            = NullSafe $item.operatingSystemVersion
            trustType            = NullSafe $item.trustType
            mdmAppId             = NullSafe $item.mdmAppId
            managementType       = NullSafe $item.managementType
            registrationDateTime = NullSafe $item.registrationDateTime
            deviceId             = NullSafe $item.deviceId
            isCompliant          = $compliant
            isManaged            = $managed
            lastSignIn           = NullSafe $item.approximateLastSignInDateTime
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

function Test-ComplianceDeviceMatchesPlatform {
    param(
        [string]$PolicyPlatform,
        $Device
    )

    $policyPlatform = [string]$PolicyPlatform
    $devicePlatform = [string]$Device.platform

    if ([string]::IsNullOrWhiteSpace($policyPlatform)) { return $true }
    if ([string]::IsNullOrWhiteSpace($devicePlatform)) { return $false }

    switch -Regex ($policyPlatform.ToLower()) {
        'windows' { return $devicePlatform -match '(?i)windows' }
        'android' { return $devicePlatform -match '(?i)android' }
        '^ios$'   { return $devicePlatform -match '(?i)^ios$|iphone|ipad' }
        'mac'     { return $devicePlatform -match '(?i)mac' }
        default   { return $devicePlatform -match [regex]::Escape($policyPlatform) }
    }
}

$jsonWin     = ConvertTo-SafeJson -Data $winDevices
$jsonAndroid = ConvertTo-SafeJson -Data $androidDevices
$jsoniOS     = ConvertTo-SafeJson -Data $iosDevices
$jsonMac     = ConvertTo-SafeJson -Data $macDevices
$jsonEntra   = ConvertTo-SafeJsonEntra  -Data $entraDevices
$jsonRisky   = "[]"
$jsonCA      = "[]"
$jsonCompliancePolicies = "[]"

# IDs y nombres de dispositivos Intune para cruce con Entra (filtro huerfanos)
$allIntune = [System.Collections.Generic.List[PSObject]]::new()
foreach ($d in $winDevices)     { $allIntune.Add($d) }
foreach ($d in $androidDevices) { $allIntune.Add($d) }
foreach ($d in $iosDevices)     { $allIntune.Add($d) }
foreach ($d in $macDevices)     { $allIntune.Add($d) }
$intuneIdList = @($allIntune | Where-Object { $_.id } | ForEach-Object { '"' + $_.id.ToLower() + '"' }) -join ","
$intuneNameList = @($allIntune | Where-Object { $_.deviceName } | ForEach-Object { '"' + $_.deviceName.ToLower() + '"' }) -join ","
$jsonIntuneIds   = "[$intuneIdList]"
$jsonIntuneNames = "[$intuneNameList]"

# ==============================
# 6b. OBTENER BUILDS WINDOWS ACTUALIZADOS DESDE MICROSOFT
# ==============================
Write-Host "  Obteniendo builds actuales de Windows desde Microsoft..." -ForegroundColor Yellow

# Metadatos fijos por rama (prefijo, etiqueta, EoS, URL de referencia)
$winBranchMeta = @(
    @{ prefix='10.0.26200'; label='W11 26H1';         eol=$false; url='https://support.microsoft.com/topic/windows-11-version-26h1-update-history-253c73cd-cab1-4bfd-94dc-76c452273fc9' },
    @{ prefix='10.0.26100'; label='W11 24H2/25H2';    eol=$false; url='https://support.microsoft.com/topic/windows-11-version-24h2-update-history-0929c747-1815-4543-8461-0160d16f15e5' },
    @{ prefix='10.0.22631'; label='W11 23H2 (EoS)';   eol=$true;  url='https://support.microsoft.com/topic/windows-11-version-23h2-update-history-59875222-b990-4bd9-932f-91a5954de434' },
    @{ prefix='10.0.22621'; label='W11 22H2 (EoS)';   eol=$true;  url='https://support.microsoft.com/topic/windows-11-version-22h2-update-history-ec4229c3-9184-4bd8-b4d1-97f83765a053' },
    @{ prefix='10.0.19045'; label='W10 22H2 (EoS)';   eol=$true;  url='https://support.microsoft.com/topic/windows-10-update-history-8127c2c6-6edf-4fdf-8b9f-0f7be1ef3562' },
    @{ prefix='10.0.19044'; label='W10 21H2 (EoS)';   eol=$true;  url='https://support.microsoft.com/topic/windows-10-update-history-8127c2c6-6edf-4fdf-8b9f-0f7be1ef3562' }
)

# Fallback hardcodeado por si falla la conexion
$winFallback = @{
    '10.0.26200' = '10.0.26200.8246'
    '10.0.26100' = '10.0.26100.8246'
    '10.0.22631' = '10.0.22631.5189'
    '10.0.22621' = '10.0.22621.5189'
    '10.0.19045' = '10.0.19045.6456'
    '10.0.19044' = '10.0.19044.6456'
}

# Extrae la build mas alta que coincida con el prefijo dado de un bloque de texto HTML/JSON
function Select-HighestBuild {
    param([string]$Text, [string]$Prefix)
    $buildNum = $Prefix.Split('.')[2]
    # Parsear filas <tr>...</tr> buscando actualizaciones "B" mensuales
    $trMatches = [regex]::Matches($Text, "<tr>.*?</tr>", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $versiones = @()
    foreach ($m in $trMatches) {
        $fila = $m.Value
        if ($fila -match "$buildNum\.(\d{4,5})" -and $fila -match "\d{4}-\d{2} B") {
            $build = [regex]::Match($fila, "$buildNum\.\d{4,5}").Value
            $versiones += $build
        }
    }
    if ($versiones.Count -gt 0) {
        return ($versiones | Sort-Object { [int]($_.Split('.')[1]) } -Descending | Select-Object -First 1)
    }
    # Fallback: regex general sin filtro de "B"
    $pattern = "10\.0\.$([regex]::Escape($buildNum))\.(\d{4,5})"
    $hits = [regex]::Matches($Text, $pattern)
    if ($hits.Count -eq 0) { return $null }
    return ($hits | ForEach-Object { $_.Value } | Sort-Object { [int]($_.Split('.')[3]) } -Descending | Select-Object -First 1)
}

function Get-LatestWindowsBuild {
    param([string]$Prefix)

    $buildNum = $Prefix.Split('.')[2]
    $w11Builds = @('26200','26100','22631','22621','22000')

    # --- Fuente 1: Paginas oficiales Microsoft Release Health ---
    # W11: https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
    # W10: https://learn.microsoft.com/en-us/windows/release-health/release-information
    try {
        $releaseUrl = if ($buildNum -in $w11Builds) {
            'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information'
        } else {
            'https://learn.microsoft.com/en-us/windows/release-health/release-information'
        }
        $archivoHTML = "$env:TEMP\release_info_$($Prefix.Replace('.','_')).html"
        Invoke-WebRequest -Uri $releaseUrl -OutFile $archivoHTML -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $contenido = Get-Content -Path $archivoHTML -Raw -ErrorAction Stop
        if ($contenido -and $contenido.Length -gt 0) {
            $found = Select-HighestBuild -Text $contenido -Prefix $Prefix
            if ($found) { return $found }
        }
    } catch {}

    # --- Fuente 2: JSON oficial de Microsoft Release Info (blob Azure) ---
    try {
        $uri  = 'https://winreleaseinfoprod.blob.core.windows.net/winreleaseinfo/en-US.json'
        $data = Invoke-RestMethod -Uri $uri -TimeoutSec 20 -ErrorAction Stop
        $candidates = @()
        foreach ($product in $data.products) {
            foreach ($release in $product.releases) {
                $bn = [string]($release.buildNumber)
                if ($bn -match "^10\.0\.$([regex]::Escape($buildNum))\.\d+$") {
                    $candidates += [int]($bn.Split('.')[3])
                }
            }
        }
        if ($candidates.Count -gt 0) {
            $rev = ($candidates | Sort-Object -Descending | Select-Object -First 1)
            return "10.0.$buildNum.$rev"
        }
    } catch {}

    # --- Fuente 3: Windows Update Catalog ---
    try {
        $searchUri = "https://www.catalog.update.microsoft.com/Search.aspx?q=$buildNum+cumulative"
        $resp      = Invoke-WebRequest -Uri $searchUri -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
        $found     = Select-HighestBuild -Text $resp.Content -Prefix $Prefix
        if ($found) { return $found }
    } catch {}

    return $null
}

# Iterar cada rama
$winBuildResults = @{}
$winBuildSource  = @{}
foreach ($branch in $winBranchMeta) {
    $fetched = Get-LatestWindowsBuild -Prefix $branch.prefix
    if ($fetched) {
        $winBuildResults[$branch.prefix] = $fetched
        $winBuildSource[$branch.prefix]  = 'live'
        Write-Host "    $($branch.prefix) -> $fetched  [OK - en vivo]" -ForegroundColor Green
    } else {
        $winBuildResults[$branch.prefix] = $winFallback[$branch.prefix]
        $winBuildSource[$branch.prefix]  = 'fallback'
        Write-Host "    $($branch.prefix) -> $($winFallback[$branch.prefix])  [fallback]" -ForegroundColor DarkYellow
    }
}

$allFallback = -not ($winBuildSource.Values -contains 'live')
if ($allFallback) {
    Write-Host "  [!] Todas las ramas usaron fallback. Verifica la conexion a internet." -ForegroundColor Yellow
}

# Construir bloque JS con origen de cada build
$buildOrigin = if ($allFallback) { "FALLBACK (sin conexion) - $fechaReporte" } else { "Obtenidos automaticamente desde Microsoft - $fechaReporte" }
$winLatestJs = "var WIN_LATEST = {`n"
foreach ($branch in $winBranchMeta) {
    $p      = $branch.prefix
    $build  = $winBuildResults[$p]
    $label  = $branch.label
    $eolJs  = if ($branch.eol) { 'true' } else { 'false' }
    $url    = $branch.url
    $src    = $winBuildSource[$p]
    $winLatestJs += "  '$p': { build: '$build', label: '$label', eol: $eolJs, url: '$url', source: '$src' },`n"
}
$winLatestJs += "};`nvar WIN_MONTH_BASELINE = {`n"
foreach ($branch in $winBranchMeta) {
    $p = $branch.prefix
    $baseline = $winFallback[$p]
    $winLatestJs += "  '$p': '$baseline',`n"
}
$winLatestJs += "};`n// $buildOrigin"

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

# Donut Tipo de Propiedad
$dashCorporate    = Get-DashArray -Count $cntCorporate    -Total $cntTotal
$dashPersonal     = Get-DashArray -Count $cntPersonal     -Total $cntTotal
$dashOwnerUnknown = Get-DashArray -Count $cntOwnerUnknown -Total $cntTotal
$rotPersonal      = [string]([math]::Round(($cntCorporate    / [math]::Max($cntTotal,1)) * 360) - 90)
$rotOwnerUnknown  = [string]([math]::Round((($cntCorporate + $cntPersonal) / [math]::Max($cntTotal,1)) * 360) - 90)

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
body { font-family: var(--font); background: var(--bg); color: var(--text); font-size: 14px; padding-bottom: 64px; }
.header { background: #0d1b35; border-bottom: 1px solid var(--border); padding: 0 32px;
  display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 24px;
  min-height: 72px; position: relative; }
.header::after { content:''; position:absolute; bottom:0; left:0; right:0; height:1px;
  background: linear-gradient(90deg, transparent, var(--blue), var(--cyan), transparent); }
.logo-area { display:flex; align-items:center; gap:12px; }
.logo-icon { width:56px; height:56px; border-radius:10px; display:flex; align-items:center;
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
  display:flex; justify-content:space-between; align-items:center;
  position:fixed; bottom:0; left:0; right:0; z-index:100; }
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
  <div class="tab" onclick="switchTab('reporte', this)">Reporte Ejecutivo</div>
  <div class="tab" onclick="switchTab('leyendas', this)">Leyendas</div>
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
      <div class="kpi-card" style="--card-accent:#fc8181; --icon-bg:rgba(252,129,129,0.12); grid-column: span 2;" onclick="showDuplicatesPanel()">
        <div class="kpi-header">
          <div class="kpi-platform">Dispositivos Duplicados (por N&#xBA; de Serie)</div>
          <div class="kpi-icon">&#x26A0;&#xFE0F;</div>
        </div>
        <div style="display:flex; align-items:baseline; gap:16px;">
          <div class="kpi-count" id="dupCount">-</div>
          <div class="kpi-pct" id="dupSubtitle">Calculando...</div>
        </div>
        <div class="kpi-footer">
          <span class="kpi-label">Haz clic para ver detalle</span>
          <span class="badge badge-error" id="dupBadge">-</span>
        </div>
      </div>
      <div class="kpi-card" style="--card-accent:#fc8181; --icon-bg:rgba(252,129,129,0.12); grid-column: span 2;" onclick="showIntuneStalePanel()">
        <div class="kpi-header">
          <div class="kpi-platform">Dispositivos Obsoletos Intune (sin sincronizacion &gt; 3 meses)</div>
          <div class="kpi-icon">&#x1F4C5;</div>
        </div>
        <div style="display:flex; align-items:baseline; gap:16px;">
          <div class="kpi-count" id="intuneStaleCount">-</div>
          <div class="kpi-pct" id="intuneStaleSubtitle">Calculando...</div>
        </div>
        <div class="kpi-footer">
          <span class="kpi-label">Haz clic para ver detalle</span>
          <span class="badge badge-error" id="intuneStaleBadge">-</span>
        </div>
      </div>
    </div>

    <div class="two-col">
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Tipo de Propiedad</span>
          <span class="panel-tag">$cntTotal dispositivos</span>
        </div>
        <div class="panel-body">
          <div class="chart-donut-wrap">
            <svg width="130" height="130" viewBox="0 0 130 130" style="flex-shrink:0">
              <circle cx="65" cy="65" r="46" fill="none" stroke="#1a2235" stroke-width="22"/>
              <circle cx="65" cy="65" r="46" fill="none" stroke="#63b3ed" stroke-width="22"
                stroke-dasharray="$dashCorporate" transform="rotate(-90 65 65)"/>
              <circle cx="65" cy="65" r="46" fill="none" stroke="#f6ad55" stroke-width="22"
                stroke-dasharray="$dashPersonal" transform="rotate($rotPersonal 65 65)"/>
              <circle cx="65" cy="65" r="46" fill="none" stroke="#64748b" stroke-width="22"
                stroke-dasharray="$dashOwnerUnknown" transform="rotate($rotOwnerUnknown 65 65)"/>
              <text x="65" y="60" text-anchor="middle" fill="#e2e8f0" font-size="20" font-weight="700" font-family="Syne,sans-serif">$cntTotal</text>
              <text x="65" y="76" text-anchor="middle" fill="#64748b" font-size="9" font-family="IBM Plex Mono,monospace">TOTAL</text>
            </svg>
            <div class="donut-legend">
              <div class="legend-row" style="cursor:pointer;" onclick="showOwnerPanel('company')" onmouseover="this.style.background='rgba(99,179,237,0.04)'" onmouseout="this.style.background=''">
                <div class="legend-left"><span class="legend-dot" style="background:#63b3ed"></span>Corporativo</div>
                <div><span class="legend-count">$cntCorporate</span><span class="legend-pct">$pctCorporate%</span></div>
              </div>
              <div class="legend-row" style="cursor:pointer;" onclick="showOwnerPanel('personal')" onmouseover="this.style.background='rgba(246,173,85,0.04)'" onmouseout="this.style.background=''">
                <div class="legend-left"><span class="legend-dot" style="background:#f6ad55"></span>Personal (BYOD)</div>
                <div><span class="legend-count">$cntPersonal</span><span class="legend-pct">$pctPersonal%</span></div>
              </div>
              <div class="legend-row" style="cursor:pointer;" onclick="showOwnerPanel('unknown')" onmouseover="this.style.background='rgba(100,116,139,0.04)'" onmouseout="this.style.background=''">
                <div class="legend-left"><span class="legend-dot" style="background:#64748b"></span>Desconocido</div>
                <div><span class="legend-count">$cntOwnerUnknown</span><span class="legend-pct">$pctOwnerUnknown%</span></div>
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
          <div style="display:flex; gap:8px; align-items:center;">
            <span class="panel-tag" id="obsTag">-</span>
            <span class="panel-tag" id="obsBuildsTag" style="border-color:rgba(79,209,197,0.3); color:var(--cyan); background:rgba(79,209,197,0.06);" title="Builds obtenidos automaticamente desde Microsoft Release Health al generar este informe">&#x1F5D8; Builds auto</span>
          </div>
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
          <span class="panel-tag">Haz clic en cada leyenda</span>
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

    <!-- PANEL TIPO DE PROPIEDAD -->
    <div class="panel" id="ownerPanel" style="display:none; margin-top:24px;">
      <div class="panel-header">
        <span class="panel-title" id="ownerPanelTitle">Dispositivos</span>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="panel-tag" id="ownerPanelCount">-</span>
          <button class="close-btn" onclick="document.getElementById('ownerPanel').style.display='none'">Cerrar X</button>
        </div>
      </div>
      <div class="panel-body">
        <div class="search-wrap">
          <span class="search-icon">&#x1F50D;</span>
          <input class="search-input" id="searchOwner" placeholder="Buscar por nombre, usuario, OS..." oninput="filterOwnerDevices()">
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
          <tbody id="ownerTableBody"></tbody>
        </table>
        <div style="display:flex; justify-content:center; align-items:center; gap:15px; margin-top:15px; padding-top:15px; border-top:1px solid var(--border);">
          <button class="export-btn" id="ownerPrevPage" onclick="changeOwnerPage(-1)" style="padding:5px 12px;">&laquo; Anterior</button>
          <span id="ownerPageIndicator" style="font-family:var(--mono); font-size:12px; color:var(--muted);">Pagina 1 de 1</span>
          <button class="export-btn" id="ownerNextPage" onclick="changeOwnerPage(1)" style="padding:5px 12px;">Siguiente &raquo;</button>
        </div>
      </div>
    </div>

    <!-- PANEL DISPOSITIVOS DUPLICADOS -->
    <div class="panel" id="duplicatesPanel" style="display:none; margin-bottom:24px;">
      <div class="panel-header">
        <span class="panel-title">Dispositivos Duplicados por N&#xBA; de Serie</span>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="panel-tag" id="dupPanelCount">-</span>
          <button class="close-btn" onclick="document.getElementById('duplicatesPanel').style.display='none'">Cerrar X</button>
        </div>
      </div>
      <div class="panel-body">
        <div class="search-wrap">
          <span class="search-icon">&#x1F50D;</span>
          <input class="search-input" id="searchDup" placeholder="Buscar por nombre, numero de serie, propietario..." oninput="filterDuplicates()">
        </div>
        <table class="device-table" id="dupTable">
          <thead>
            <tr>
              <th style="width:28px"></th>
              <th>N&#xBA; de Serie</th>
              <th>Duplicados</th>
              <th>Propietarios</th>
            </tr>
          </thead>
          <tbody id="dupTableBody"></tbody>
        </table>
        <div style="display:flex; justify-content:center; align-items:center; gap:15px; margin-top:15px; padding-top:15px; border-top:1px solid var(--border);">
          <button class="export-btn" id="dupPrevPage" onclick="changeDupPage(-1)" style="padding:5px 12px;">&laquo; Anterior</button>
          <span id="dupPageIndicator" style="font-family:var(--mono); font-size:12px; color:var(--muted);">Pagina 1 de 1</span>
          <button class="export-btn" id="dupNextPage" onclick="changeDupPage(1)" style="padding:5px 12px;">Siguiente &raquo;</button>
        </div>
      </div>
    </div>

    <!-- PANEL OBSOLETOS INTUNE (sync > 3 meses) -->
    <div class="panel" id="intuneStalePanel" style="display:none; margin-bottom:24px;">
      <div class="panel-header">
        <span class="panel-title">Dispositivos sin sincronizacion &gt; 3 meses</span>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="panel-tag" id="intuneStalePanelCount">-</span>
          <button class="close-btn" onclick="document.getElementById('intuneStalePanel').style.display='none'">Cerrar X</button>
        </div>
      </div>
      <div class="panel-body">
        <div class="search-wrap">
          <span class="search-icon">&#x1F50D;</span>
          <input class="search-input" id="searchIntuneStale" placeholder="Buscar por nombre, usuario, OS..." oninput="filterIntuneStale()">
        </div>
        <table class="device-table">
          <thead><tr>
            <th>Dispositivo</th><th>Usuario</th><th>OS</th><th>Version</th><th>Cumplimiento</th><th>Ultima Sync</th><th>Dias sin Sync</th>
          </tr></thead>
          <tbody id="intuneStaleBody"></tbody>
        </table>
        <div style="display:flex; justify-content:center; align-items:center; gap:15px; margin-top:15px; padding-top:15px; border-top:1px solid var(--border);">
          <button class="export-btn" id="intuneStalePrev" onclick="changeIntuneStale(-1)" style="padding:5px 12px;">&laquo; Anterior</button>
          <span id="intuneStaleIndicator" style="font-family:var(--mono); font-size:12px; color:var(--muted);">Pagina 1 de 1</span>
          <button class="export-btn" id="intuneStaleNext" onclick="changeIntuneStale(1)" style="padding:5px 12px;">Siguiente &raquo;</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- TAB ENTRA ID -->
<div class="tab-content" id="tab-entra">
  <div class="main">
    <div class="section-label">Resumen Entra ID</div>

    <!-- GRID 4x2 -->
    <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:24px;" id="entraStatGrid">
      <!-- FILA 1: tipos de union -->
      <div class="entra-stat" onclick="showEntraPanel('all')">
        <div class="entra-stat-label">Total Registrados</div>
        <div class="entra-stat-value" style="color:var(--blue)">$cntEntraNum</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">Haz clic para ver todos</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('haadj')">
        <div class="entra-stat-label">Union Hibrida (HAADJ)</div>
        <div class="entra-stat-value" style="color:var(--cyan)">$cntHAADJ</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">trustType: ServerAd</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('aadj')">
        <div class="entra-stat-label">Union Pura Entra (AADJ)</div>
        <div class="entra-stat-value" style="color:var(--purple)">$cntEntraAD</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">trustType: AzureAd</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('registered')">
        <div class="entra-stat-label">Registered con MDM</div>
        <div class="entra-stat-value" style="color:var(--green)" id="cntRegisteredMdm">-</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">trustType: Workplace + MDM</div>
      </div>
      <!-- FILA 2: anomalias -->
      <div class="entra-stat" onclick="showEntraPanel('huerfanos')" style="border-color:rgba(252,129,129,0.25);">
        <div class="entra-stat-label" style="color:var(--red)">&#x26A0; Huerfanos</div>
        <div class="entra-stat-value" style="color:var(--red)" id="cntHuerfanos">-</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">Sin MDM, sin propietario, reg. pendiente</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('o365mobile')" style="border-color:rgba(246,173,85,0.25);">
        <div class="entra-stat-label" style="color:var(--orange)">Office 365 Mobile</div>
        <div class="entra-stat-value" style="color:var(--orange)" id="cntO365Mobile">-</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">MDM: Office365 (no gestionado)</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('reg-sin-mdm')" style="border-color:rgba(167,139,250,0.25);">
        <div class="entra-stat-label" style="color:var(--purple)">Registered sin MDM</div>
        <div class="entra-stat-value" style="color:var(--purple)" id="cntRegSinMdm">-</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">Workplace + actividad reciente</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('obsoletos-entra')" style="border-color:rgba(252,129,129,0.25);">
        <div class="entra-stat-label" style="color:var(--red)">Obsoletos Entra</div>
        <div class="entra-stat-value" style="color:var(--red)" id="cntObsoletosEntra">-</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">Sin actividad &gt; 6 meses</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('correccion-identidad')" style="border-color:rgba(79,209,197,0.25);">
        <div class="entra-stat-label" style="color:var(--cyan)">&#x1F527; Correccion Identidad</div>
        <div class="entra-stat-value" style="color:var(--cyan)" id="cntCorreccionIdentidad">-</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">MDM registrado, sin fecha de registro</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('solo-mde')" style="border-color:rgba(167,139,250,0.25);">
        <div class="entra-stat-label" style="color:var(--purple)">&#x1F6E1; Solo MDE / Defender</div>
        <div class="entra-stat-value" style="color:var(--purple)" id="cntSoloMde">-</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">managementType: MicrosoftSense</div>
      </div>
      <div class="entra-stat" onclick="showEntraPanel('dup-entra')" style="border-color:rgba(252,129,129,0.25);">
        <div class="entra-stat-label" style="color:var(--red)">&#x26A0; Duplicados Entra ID</div>
        <div class="entra-stat-value" style="color:var(--red)" id="cntDupEntra">-</div>
        <div style="font-family:var(--mono); font-size:9px; color:var(--muted); margin-top:6px;">Mismo nombre de dispositivo en Entra</div>
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
        <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:14px;" id="entraFilterPlatBtns">
          <button class="ver-plat-btn active" data-plat="all"     onclick="selectEntraPlat(this,'all')">Todos</button>
          <button class="ver-plat-btn"        data-plat="windows" onclick="selectEntraPlat(this,'windows')">Windows</button>
          <button class="ver-plat-btn"        data-plat="android" onclick="selectEntraPlat(this,'android')">Android</button>
          <button class="ver-plat-btn"        data-plat="ios"     onclick="selectEntraPlat(this,'ios')">iOS</button>
          <button class="ver-plat-btn"        data-plat="macos"   onclick="selectEntraPlat(this,'macos')">macOS</button>
        </div>
        <table class="device-table">
          <thead>
            <tr>
              <th>Nombre</th>
              <th>OS</th>
              <th>Version</th>
              <th>Tipo de Union</th>
              <th>MDM</th>
              <th>Gestionado</th>
              <th>Conforme</th>
              <th>Ultimo Inicio de Sesion</th>
              <th id="thDiasSinActividad" style="display:none">Dias sin Actividad</th>
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

    <!-- PANEL DUPLICADOS ENTRA ID (agrupado por nombre) -->
    <div class="panel" id="entraDupPanel" style="display:none; margin-bottom:24px;">
      <div class="panel-header">
        <span class="panel-title">Dispositivos Duplicados en Entra ID (por nombre)</span>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="panel-tag" id="entraDupPanelCount">-</span>
          <button class="close-btn" onclick="document.getElementById('entraDupPanel').style.display='none'">Cerrar X</button>
        </div>
      </div>
      <div class="panel-body">
        <div class="search-wrap">
          <span class="search-icon">&#x1F50D;</span>
          <input class="search-input" id="searchEntraDup" placeholder="Buscar por nombre, tipo de union, propietario..." oninput="filterEntraDuplicates()">
        </div>
        <table class="device-table" id="entraDupTable">
          <thead>
            <tr>
              <th style="width:28px"></th>
              <th>Nombre</th>
              <th>Duplicados</th>
              <th>Tipos de Union</th>
            </tr>
          </thead>
          <tbody id="entraDupTableBody"></tbody>
        </table>
        <div style="display:flex; justify-content:center; align-items:center; gap:15px; margin-top:15px; padding-top:15px; border-top:1px solid var(--border);">
          <button class="export-btn" id="entraDupPrevPage" onclick="changeEntraDupPage(-1)" style="padding:5px 12px;">&laquo; Anterior</button>
          <span id="entraDupPageIndicator" style="font-family:var(--mono); font-size:12px; color:var(--muted);">Pagina 1 de 1</span>
          <button class="export-btn" id="entraDupNextPage" onclick="changeEntraDupPage(1)" style="padding:5px 12px;">Siguiente &raquo;</button>
        </div>
      </div>
    </div>

  </div>
</div>

<!-- TAB REPORTE -->
<div class="tab-content" id="tab-reporte">
  <div class="main">
    <div class="section-label">Resumen Ejecutivo</div>
    <div class="report-kpi-row" style="grid-template-columns:repeat(3,1fr);">
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--green)">$compGlobal%</div>
        <div class="report-kpi-lbl">Cumplimiento Global Intune</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--blue)">$cntTotal</div>
        <div class="report-kpi-lbl">Dispositivos Intune</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--red)">$cntNoCompliant</div>
        <div class="report-kpi-lbl">Dispositivos No Conformes</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--cyan)">$cntEntraNum</div>
        <div class="report-kpi-lbl">Dispositivos Entra ID</div>
      </div>
      <div class="report-kpi" style="cursor:pointer;" onclick="switchTab('entra', document.querySelector('.tab:nth-child(2)')); setTimeout(function(){ showEntraPanel('registered'); }, 100);">
        <div class="report-kpi-val" style="color:var(--green)" id="rptRegisteredMdm">-</div>
        <div class="report-kpi-lbl">Registered con MDM</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--purple)">$cntHAADJ</div>
        <div class="report-kpi-lbl">Union Hibrida (HAADJ)</div>
      </div>
    </div>
    <div class="section-label" style="margin-top:8px;">Anomalias Entra ID</div>
    <div class="report-kpi-row" style="grid-template-columns:repeat(3,1fr);">
      <div class="report-kpi" style="cursor:pointer;" onclick="switchTab('entra', document.querySelector('.tab:nth-child(2)')); setTimeout(function(){ showEntraPanel('huerfanos'); }, 100);">
        <div class="report-kpi-val" style="color:var(--red)" id="rptHuerfanos">-</div>
        <div class="report-kpi-lbl">&#x26A0; Huerfanos</div>
      </div>
      <div class="report-kpi" style="cursor:pointer;" onclick="switchTab('entra', document.querySelector('.tab:nth-child(2)')); setTimeout(function(){ showEntraPanel('o365mobile'); }, 100);">
        <div class="report-kpi-val" style="color:var(--orange)" id="rptO365Mobile">-</div>
        <div class="report-kpi-lbl">Office 365 Mobile</div>
      </div>
      <div class="report-kpi" style="cursor:pointer;" onclick="switchTab('entra', document.querySelector('.tab:nth-child(2)')); setTimeout(function(){ showEntraPanel('correccion-identidad'); }, 100);">
        <div class="report-kpi-val" style="color:var(--cyan)" id="rptCorreccion">-</div>
        <div class="report-kpi-lbl">&#x1F527; Correccion Identidad</div>
      </div>
    </div>
    <div class="section-label" style="margin-top:8px;">Directiva por Defecto <span style="font-family:var(--mono); font-size:9px; color:var(--muted); letter-spacing:0; text-transform:none; font-weight:400;">Default Device Compliance Policy &bull; <span style="opacity:0.6;">$defaultPolicyId</span></span></div>
    <div class="report-kpi-row" style="grid-template-columns:repeat(3,1fr);" id="rptDefaultPolicyRow">
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--red)">$defaultPolicyNonCompl</div>
        <div class="report-kpi-lbl">&#x2715; Has a compliance policy assigned</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--orange)">$defaultPolicyError</div>
        <div class="report-kpi-lbl">&#x1F4F6; Is active (remain contact)</div>
      </div>
      <div class="report-kpi">
        <div class="report-kpi-val" style="color:var(--muted)">$defaultPolicyUnknown</div>
        <div class="report-kpi-lbl">&#x1F464; Enrolled user exists</div>
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

<!-- TAB LEYENDAS -->
<div class="tab-content" id="tab-leyendas">
  <div class="main">
    <div class="section-label">Leyendas del Dashboard</div>
    <div class="report-kpi-row" style="grid-template-columns:repeat(2,1fr);">
      
      <!-- INTUNE -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Intune</span>
          <span class="panel-tag">Resumen</span>
        </div>
        <div class="panel-body" style="display:flex; flex-direction:column; gap:12px; font-size:12px; color:var(--text);">
          
          <div><strong>Plataformas</strong>: distribucion de dispositivos gestionados por sistema operativo, incluyendo su peso porcentual sobre el total y su nivel de cumplimiento.</div>
          
          <div><strong>Tipo de propiedad</strong>: clasificacion de los dispositivos en corporativos, personales o sin determinar.</div>
          
          <div><strong>Tipo de gestion</strong>: segmentacion segun el origen de la gestion, como Intune MDM, Microsoft Defender o Android Enterprise.</div>
          
          <div><strong>Estado de actualizacion</strong>: categorizacion de dispositivos en actualizados, en riesgo u obsoletos en funcion de la version detectada del sistema operativo Windows.</div>
          
          <div><strong>Dispositivos duplicados</strong>: identificacion de equipos con el mismo numero de serie, agrupados para detectar duplicidades, inconsistencias en los datos o posibles errores de inventario.</div>
          
          <div><strong>Dispositivos obsoletos en Intune</strong>: dispositivos que no han sincronizado con Intune durante mas de 90 dias. Se consideran no conformes y requieren revision.</div>
        
        </div>
      </div>

      <!-- ENTRA ID -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Entra ID</span>
          <span class="panel-tag">Identidad</span>
        </div>
        <div class="panel-body" style="display:flex; flex-direction:column; gap:12px; font-size:12px; color:var(--text);">
          
          <div><strong>HAADJ</strong>: dispositivos unidos a Active Directory local y sincronizados con Entra ID (Hybrid Azure AD Join).</div>
          
          <div><strong>AADJ</strong>: dispositivos unidos directamente a Entra ID (Azure AD Join).</div>
          
          <div><strong>Registered</strong>: dispositivos registrados en Entra ID, habitualmente escenarios BYOD o movilidad ligera. Se recomienda revision si estan inscritos en MDM.</div>
          
          <div><strong>Huerfanos</strong>: objetos de dispositivos presentes en Active Directory local sin correspondencia con un dispositivo activo. Se recomienda su revision y eliminacion si procede.</div>
          
          <div><strong>Office365Mobile</strong>: dispositivos asociados a usuarios sin licencia asignada.</div>
          
          <div><strong>Registered sin MDM</strong>: dispositivos registrados en Entra ID sin gestion mediante MDM, normalmente en escenarios BYOD.</div>
          
          <div><strong>Obsoletos Entra</strong>: dispositivos que no han mostrado actividad durante un periodo superior a 6 meses.</div>
          
          <div><strong>Correccion de identidad</strong>: dispositivos presentes en Entra ID e Intune cuya identidad no esta completamente alineada, requiriendo acciones de correccion.</div>
          
          <div><strong>Solo MDE</strong>: dispositivos gestionados exclusivamente mediante Microsoft Defender for Endpoint, sin inscripcion en Intune.</div>
          
          <div><strong>Duplicados en Entra ID</strong>: dispositivos registrados con el mismo nombre, lo que puede indicar duplicidades o inconsistencias.</div>
        
        </div>
      </div>

      <!-- INTERACCION -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Interaccion</span>
          <span class="panel-tag">Uso</span>
        </div>
        <div class="panel-body" style="display:flex; flex-direction:column; gap:12px; font-size:12px; color:var(--text);">
          
          <div><strong>Tarjetas</strong>: al seleccionar una tarjeta, se muestra el detalle filtrado correspondiente.</div>
          
          <div><strong>Leyendas y barras</strong>: los elementos interactivos permiten acceder al listado asociado al hacer clic.</div>
          
          <div><strong>Paginacion</strong>: los listados extensos se presentan en paginas para facilitar su analisis.</div>
          
          <div><strong>Busqueda</strong>: permite filtrar dinamicamente el contenido visible dentro de cada panel sin necesidad de recargar la pagina.</div>
        
        </div>
      </div>

    </div>
  </div>
</div>

<footer class="footer" style="display:flex; align-items:center; justify-content:space-between;">
  
  <!-- IZQUIERDA -->
  <div style="flex:1; display:flex; flex-direction:column; gap:2px;">
    <div class="footer-text">Microsoft Graph API v1.0 &#x2022; $nombreCliente &#x2022; Assessment: $fechaReporte</div>
    <div class="footer-text" style="color:var(--blue);">Elaborado por: $autorInforme &#x2022; $anioCreacion</div>
  </div>

  <!-- CENTRO (LOGO OPCIONAL) -->
  <div style="flex:1; display:flex; justify-content:center;">
    <!-- img src="$logoUrl" alt="Logo" style="height:40px;" onerror="this.style.display='none'"-->
    <img src="https://proimg.seidor.com/sites/default/files/styles/open_graph/public/2022-03/LOGO_COLOR_POSITIVE.png?itok=TSczsmGz" alt="Logo" style="height:40px;" onerror="this.style.display='none'">
  </div>

  <!-- DERECHA -->
  <div style="flex:1; display:flex; justify-content:flex-end; gap:10px;">
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
  entra:   ensureArray($jsonEntra)
};
// Sets de IDs y nombres Intune para cruce rapido O(1) en filtro huerfanos
var INTUNE_IDS   = new Set(ensureArray($jsonIntuneIds).map(function(x){ return String(x).toLowerCase(); }));
var INTUNE_NAMES = new Set(ensureArray($jsonIntuneNames).map(function(x){ return String(x).toLowerCase(); }));

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

function isSystemUpn(upn) {
  if (!upn) return true;
  var u = upn.toLowerCase();
  return /^(scep|cert|system|enrollment|autopilot|intune|device|noreply|no-reply|test|svc|service)[^@]*@/.test(u) ||
         /\.(sys|svc|cert|scep|bot)@/.test(u);
}

function showPanel(platform) {
  currentPlatform = platform;
  var devs = (DATA[platform] || []).filter(function(d) { return !isSystemUpn(d.userPrincipalName); });
  document.getElementById('panelTitle').textContent = 'Dispositivos - ' + platformNames[platform];
  document.getElementById('panelCount').textContent = devs.length + ' dispositivos (usuarios)';
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
  var base = (DATA[currentPlatform] || []).filter(function(d) { return !isSystemUpn(d.userPrincipalName); });
  var devs = base.filter(function(d) {
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

function changePage(step) {
  var totalPages = Math.ceil(filteredEntraData.length / PAGE_SIZE) || 1;
  var newPage = entraPage + step;
  if (newPage >= 1 && newPage <= totalPages) {
    entraPage = newPage;
    renderEntraPage();
    document.getElementById('entraDevPanel').scrollIntoView({ behavior:'smooth', block:'start' });
  }
}

var entraActivePlatFilter = 'all';
var entraShowDaysCol = false;

function selectEntraPlat(btn, platKey) {
  document.querySelectorAll('#entraFilterPlatBtns .ver-plat-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  entraActivePlatFilter = platKey;
  filterEntra();
}

function filterEntra() {
  var q = document.getElementById('searchEntra').value.toLowerCase();
  var platRe = VER_PLAT_MAP[entraActivePlatFilter] || null;
  var results = currentEntraData.filter(function(d) {
    var matchText = (d.displayName||'').toLowerCase().indexOf(q) >= 0 ||
                    (d.operatingSystem||'').toLowerCase().indexOf(q) >= 0;
    var matchPlat = !platRe || platRe.test(d.operatingSystem || '');
    return matchText && matchPlat;
  });
  updateEntraView(results);
}

function closePanel() {
  document.getElementById('devicePanel').style.display = 'none';
}

// ---- HELPERS ENTRA ----
var SIX_MONTHS_MS  = 6  * 30 * 24 * 3600 * 1000;
var THREE_MONTHS_MS = 3 * 30 * 24 * 3600 * 1000;

function isO365Mobile(d) {
  // MDM AppId de Office 365 Mobile: 7add3ecd-5b01-452e-b4bf-cdaf9df1d097
  return (d.mdmAppId || '').toLowerCase().indexOf('7add3ecd') >= 0;
}
function isHuerfano(d) {
  // Replica exacta del filtro PowerShell:
  //   - Windows (no Server)
  //   - registrationDateTime == null (sin fecha de registro)
  //   - managementType != MicrosoftSense
  //   - No existe en Intune por deviceId NI por displayName
  var isWindows  = /windows/i.test(d.operatingSystem || '');
  var isServer   = /server/i.test(d.operatingSystem || '');
  var noRegDate  = !d.registrationDateTime || d.registrationDateTime === '';
  var notSense   = (d.managementType || '').toLowerCase() !== 'microsoftsense';
  var notInIntune = (
    (!d.deviceId   || !INTUNE_IDS.has(String(d.deviceId).toLowerCase())) &&
    (!d.displayName || !INTUNE_NAMES.has(String(d.displayName).toLowerCase()))
  );
  return isWindows && !isServer && noRegDate && notSense && notInIntune;
}
function isRegisteredSinMdm(d) {
  var isWork   = d.trustType === 'Workplace';
  var noMdm    = !d.mdmAppId || d.mdmAppId === '';
  var notO365  = !isO365Mobile(d);
  var recent   = d.lastSignIn && (Date.now() - new Date(d.lastSignIn).getTime()) < SIX_MONTHS_MS;
  return isWork && noMdm && notO365 && recent;
}
function isSoloMde(d) {
  // managementType === MicrosoftSense y tiene fecha de registro (no huerfano)
  return (d.managementType || '').toLowerCase() === 'microsoftsense';
}

function isObsoletoEntra(d) {
  // Los que no tienen lastSignIn se clasifican como huerfanos/MDE, no como obsoletos
  if (!d.lastSignIn || d.lastSignIn === '') return false;
  return (Date.now() - new Date(d.lastSignIn).getTime()) > SIX_MONTHS_MS;
}
function isRegisteredMdm(d) {
  // Solo Windows, trustType Workplace, con MDM, excluye Office365Mobile
  var isWindows = /windows/i.test(d.operatingSystem || '');
  return isWindows && d.trustType === 'Workplace' && d.mdmAppId && d.mdmAppId !== '' && !isO365Mobile(d);
}
function isCorreccionIdentidad(d) {
  // Dispositivos con propietario MDM registrado (isManaged=true) Y sin fecha de registro
  // Excluye Office365Mobile y MicrosoftSense
  var hasOwner  = d.isManaged === true;
  var hasMdm    = d.mdmAppId && d.mdmAppId !== '';
  var noReg     = !d.registrationDateTime || d.registrationDateTime === '';
  var notSense  = (d.managementType || '').toLowerCase() !== 'microsoftsense';
  var notO365   = !isO365Mobile(d);
  return (hasOwner || hasMdm) && noReg && notSense && notO365;
}

// Precalculo de duplicados Entra por displayName
var ENTRA_DUPES = {};
(function() {
  var nameMap = {};
  (DATA.entra || []).forEach(function(d) {
    var n = (d.displayName || '').trim().toLowerCase();
    if (!n) return;
    nameMap[n] = (nameMap[n] || []);
    nameMap[n].push(d);
  });
  Object.keys(nameMap).forEach(function(k) {
    if (nameMap[k].length > 1) ENTRA_DUPES[k] = nameMap[k];
  });
})();

function isDuplicadoEntra(d) {
  var n = (d.displayName || '').trim().toLowerCase();
  return !!ENTRA_DUPES[n];
}

// Inicializar contadores de las tarjetas Entra anomalias
function initEntraCards() {
  var devs = DATA.entra || [];
  var cntRM   = devs.filter(isRegisteredMdm).length;
  var cntHu   = devs.filter(isHuerfano).length;
  var cntO365 = devs.filter(isO365Mobile).length;
  var cntRSM  = devs.filter(isRegisteredSinMdm).length;
  var cntObs  = devs.filter(isObsoletoEntra).length;
  var cntCorr = devs.filter(isCorreccionIdentidad).length;
  var cntMde  = devs.filter(isSoloMde).length;
  var cntDupE = Object.keys(ENTRA_DUPES).length;
  document.getElementById('cntRegisteredMdm').textContent         = cntRM;
  document.getElementById('cntHuerfanos').textContent             = cntHu;
  document.getElementById('cntO365Mobile').textContent            = cntO365;
  document.getElementById('cntRegSinMdm').textContent             = cntRSM;
  document.getElementById('cntObsoletosEntra').textContent        = cntObs;
  document.getElementById('cntCorreccionIdentidad').textContent   = cntCorr;
  if (document.getElementById('cntSoloMde'))    document.getElementById('cntSoloMde').textContent    = cntMde;
  if (document.getElementById('cntDupEntra'))   document.getElementById('cntDupEntra').textContent   = cntDupE;
  // Reporte ejecutivo - anomalias
  if (document.getElementById('rptHuerfanos'))    document.getElementById('rptHuerfanos').textContent    = cntHu;
  if (document.getElementById('rptO365Mobile'))  document.getElementById('rptO365Mobile').textContent   = cntO365;
  if (document.getElementById('rptCorreccion'))  document.getElementById('rptCorreccion').textContent   = cntCorr;
  if (document.getElementById('rptRegisteredMdm')) document.getElementById('rptRegisteredMdm').textContent = cntRM;
}

// ---- ENTRA panel generico ----
function showEntraPanel(tipo) {
  var titles = {
    'all':                  'Todos los Dispositivos Entra ID',
    'haadj':                'Dispositivos Hibridos (HAADJ)',
    'aadj':                 'Dispositivos Entra puro (AADJ)',
    'registered':           'Dispositivos Registered con MDM',
    'huerfanos':            'Dispositivos Huerfanos',
    'o365mobile':           'Dispositivos Office 365 Mobile',
    'reg-sin-mdm':          'Registered sin MDM (actividad reciente)',
    'obsoletos-entra':      'Dispositivos Obsoletos Entra (sin actividad > 6 meses)',
    'correccion-identidad': 'Correccion de Identidad (MDM registrado, sin fecha de registro)',
    'solo-mde':             'Dispositivos solo gestionados por MDE (Defender)',
    'dup-entra':            'Dispositivos Duplicados en Entra ID (mismo nombre)',
  };

  document.getElementById('entraDevPanel').style.display = 'none';

  if (tipo === 'risky') {
    document.getElementById('riskyPanel').scrollIntoView({ behavior:'smooth', block:'start' });
    return;
  }


  var devs = DATA.entra || [];
  var filtered;
  if      (tipo === 'haadj')           filtered = devs.filter(function(d){ return d.trustType === 'ServerAd'; });
  else if (tipo === 'aadj')            filtered = devs.filter(function(d){ return d.trustType === 'AzureAd'; });
  else if (tipo === 'registered')      filtered = devs.filter(isRegisteredMdm);
  else if (tipo === 'huerfanos')       filtered = devs.filter(isHuerfano);
  else if (tipo === 'o365mobile')      filtered = devs.filter(isO365Mobile);
  else if (tipo === 'reg-sin-mdm')     filtered = devs.filter(isRegisteredSinMdm);
  else if (tipo === 'obsoletos-entra')      filtered = devs.filter(isObsoletoEntra);
  else if (tipo === 'correccion-identidad') filtered = devs.filter(isCorreccionIdentidad);
  else if (tipo === 'solo-mde')             filtered = devs.filter(isSoloMde);
  else if (tipo === 'dup-entra') {
    showEntraDuplicatesPanel();
    return;
  }
  else                                       filtered = devs;

  currentEntraData = filtered;
  entraActivePlatFilter = 'all';
  entraShowDaysCol = (tipo === 'obsoletos-entra');
  var thDias = document.getElementById('thDiasSinActividad');
  if (thDias) thDias.style.display = entraShowDaysCol ? '' : 'none';
  document.querySelectorAll('#entraFilterPlatBtns .ver-plat-btn').forEach(function(b) {
    b.classList.toggle('active', b.dataset.plat === 'all');
  });
  document.getElementById('entraDevTitle').textContent = titles[tipo] || tipo;
  document.getElementById('entraDevCount').textContent = filtered.length + ' dispositivos';
  document.getElementById('searchEntra').value = '';
  updateEntraView(filtered);
  var panel = document.getElementById('entraDevPanel');
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior:'smooth', block:'start' });
}

function renderEntraPage() {
  var tbody = document.getElementById('entraTableBody');
  var totalPages = Math.ceil(filteredEntraData.length / PAGE_SIZE) || 1;
  var start = (entraPage - 1) * PAGE_SIZE;
  var pageData = filteredEntraData.slice(start, start + PAGE_SIZE);
  var trustMap = { 'ServerAd':'Hibrida (HAADJ)', 'AzureAd':'Entra (AADJ)', 'Workplace':'Registered' };

  document.getElementById('pageIndicator').textContent = 'Pagina ' + entraPage + ' de ' + totalPages;
  document.getElementById('prevPage').disabled = (entraPage === 1);
  document.getElementById('nextPage').disabled = (entraPage === totalPages);
  document.getElementById('prevPage').style.opacity = (entraPage === 1) ? '0.4' : '1';
  document.getElementById('nextPage').style.opacity = (entraPage === totalPages) ? '0.4' : '1';

  var colSpan = entraShowDaysCol ? 9 : 8;
  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="' + colSpan + '" style="text-align:center; color:var(--muted); padding:24px; font-family:var(--mono)">Sin datos de Entra ID</td></tr>';
    return;
  }

  // Etiqueta MDM legible
  function mdmLabel(d) {
    if (isO365Mobile(d)) return '<span class="badge badge-warning">Office365Mobile</span>';
    if (d.mdmAppId && d.mdmAppId !== '') return '<span class="badge badge-info" title="' + d.mdmAppId + '">MDM</span>';
    return '<span class="badge badge-muted">Sin MDM</span>';
  }

  var now = Date.now();
  tbody.innerHTML = pageData.map(function(d) {
    var staleEntra = isObsoletoEntra(d);
    var diasCell = '';
    if (entraShowDaysCol) {
      var signInMs = d.lastSignIn ? new Date(d.lastSignIn).getTime() : 0;
      var dias = signInMs ? Math.floor((now - signInMs) / 86400000) : 9999;
      var diasColor = dias > 365 ? 'var(--red)' : dias > 180 ? 'var(--orange)' : 'var(--muted)';
      var diasTxt = signInMs ? dias + 'd' : 'Sin registro';
      diasCell = '<td style="font-family:var(--mono); font-size:12px; font-weight:700; color:' + diasColor + '">' + diasTxt + '</td>';
    }
    return '<tr' + (staleEntra ? ' style="opacity:0.65"' : '') + '>' +
      '<td style="font-weight:600">' + (d.displayName || '-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.operatingSystem || '-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.osVersion || '-') + '</td>' +
      '<td style="font-size:11px; color:var(--muted)">' + (trustMap[d.trustType] || d.trustType || '-') + '</td>' +
      '<td>' + mdmLabel(d) + '</td>' +
      '<td>' + (d.isManaged ? '<span class="badge badge-compliant">Si</span>' : '<span class="badge badge-muted">No</span>') + '</td>' +
      '<td>' + (d.isCompliant ? '<span class="badge badge-compliant">Si</span>' : '<span class="badge badge-muted">No</span>') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:' + (staleEntra ? 'var(--red)' : 'var(--muted)') + '">' + fmtDate(d.lastSignIn) + '</td>' +
      diasCell +
      '</tr>';
  }).join('');
}

// ---- INTUNE OBSOLETOS (sync > 3 meses) ----
var intuneStaleAll = [];
var intuneStaleFilt = [];
var intuneStalePageN = 1;

function initIntuneStale() {
  var all = [].concat(DATA.windows||[], DATA.android||[], DATA.ios||[], DATA.macos||[]);
  var now = Date.now();
  intuneStaleAll = all.filter(function(d) {
    if (!d.lastSyncDateTime || d.lastSyncDateTime === '') return true;
    return (now - new Date(d.lastSyncDateTime).getTime()) > THREE_MONTHS_MS;
  }).sort(function(a, b) {
    var ta = a.lastSyncDateTime ? new Date(a.lastSyncDateTime).getTime() : 0;
    var tb = b.lastSyncDateTime ? new Date(b.lastSyncDateTime).getTime() : 0;
    return ta - tb; // mas antiguos primero
  });

  var cnt = intuneStaleAll.length;
  document.getElementById('intuneStaleCount').textContent   = cnt;
  document.getElementById('intuneStaleSubtitle').textContent = 'sin sincronizar en mas de 90 dias';
  document.getElementById('intuneStaleBadge').textContent    = cnt + ' dispositivos';
}

function showIntuneStalePanel() {
  intuneStaleFilt = intuneStaleAll.slice();
  intuneStalePageN = 1;
  document.getElementById('intuneStalePanelCount').textContent = intuneStaleFilt.length + ' dispositivos';
  document.getElementById('searchIntuneStale').value = '';
  renderIntuneStale();
  var panel = document.getElementById('intuneStalePanel');
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior:'smooth', block:'start' });
}

function filterIntuneStale() {
  var q = document.getElementById('searchIntuneStale').value.toLowerCase();
  intuneStaleFilt = intuneStaleAll.filter(function(d) {
    return (d.deviceName||'').toLowerCase().indexOf(q) >= 0 ||
           (d.userPrincipalName||'').toLowerCase().indexOf(q) >= 0 ||
           (d.operatingSystem||'').toLowerCase().indexOf(q) >= 0;
  });
  intuneStalePageN = 1;
  document.getElementById('intuneStalePanelCount').textContent = intuneStaleFilt.length + ' dispositivos';
  renderIntuneStale();
}

function renderIntuneStale() {
  var tbody = document.getElementById('intuneStaleBody');
  var totalPages = Math.ceil(intuneStaleFilt.length / PAGE_SIZE) || 1;
  var start = (intuneStalePageN - 1) * PAGE_SIZE;
  var pageData = intuneStaleFilt.slice(start, start + PAGE_SIZE);
  var now = Date.now();

  document.getElementById('intuneStaleIndicator').textContent = 'Pagina ' + intuneStalePageN + ' de ' + totalPages;
  document.getElementById('intuneStalePrev').disabled = (intuneStalePageN === 1);
  document.getElementById('intuneStaleNext').disabled = (intuneStalePageN === totalPages);
  document.getElementById('intuneStalePrev').style.opacity = (intuneStalePageN === 1) ? '0.4' : '1';
  document.getElementById('intuneStaleNext').style.opacity = (intuneStalePageN === totalPages) ? '0.4' : '1';

  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:24px; font-family:var(--mono)">Sin dispositivos obsoletos</td></tr>';
    return;
  }
  tbody.innerHTML = pageData.map(function(d) {
    var syncMs   = d.lastSyncDateTime ? new Date(d.lastSyncDateTime).getTime() : 0;
    var diasSinc = syncMs ? Math.floor((now - syncMs) / 86400000) : 999;
    var diasColor = diasSinc > 180 ? 'var(--red)' : diasSinc > 90 ? 'var(--orange)' : 'var(--muted)';
    return '<tr>' +
      '<td style="font-weight:600">' + (d.deviceName||'-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.userPrincipalName||'-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.operatingSystem||'-') + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--muted)">' + (d.osVersion||'-') + '</td>' +
      '<td>' + badge(d.complianceState) + '</td>' +
      '<td style="font-family:var(--mono); font-size:11px; color:var(--orange)">' + fmtDate(d.lastSyncDateTime) + '</td>' +
      '<td style="font-family:var(--mono); font-size:12px; font-weight:700; color:' + diasColor + '">' + diasSinc + 'd</td>' +
      '</tr>';
  }).join('');
}

function changeIntuneStale(step) {
  var totalPages = Math.ceil(intuneStaleFilt.length / PAGE_SIZE) || 1;
  var np = intuneStalePageN + step;
  if (np >= 1 && np <= totalPages) {
    intuneStalePageN = np;
    renderIntuneStale();
    document.getElementById('intuneStalePanel').scrollIntoView({ behavior:'smooth', block:'start' });
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
  var hu   = document.getElementById('rptHuerfanos')  ? document.getElementById('rptHuerfanos').textContent  : '-';
  var o365 = document.getElementById('rptO365Mobile') ? document.getElementById('rptO365Mobile').textContent : '-';
  var cor  = document.getElementById('rptCorreccion') ? document.getElementById('rptCorreccion').textContent : '-';
  var txt = 'ASSESSMENT - $nombreCliente\nFecha: $fechaReporte\n--------------------------\nINTUNE\n  Total: $cntTotal dispositivos\n  Windows: $cntWin ($compWin% cumplimiento)\n  Android: $cntAndroid ($compAndroid% cumplimiento)\n  iOS: $cntiOS ($compiOS% cumplimiento)\n  macOS: $cntMac ($compMac% cumplimiento)\n  Cumplimiento Global: $compGlobal%\n\nENTRA ID\n  Total registrados: $cntEntraNum\n  Hibrida (HAADJ): $cntHAADJ\n  Entra puro (AADJ): $cntEntraAD\n  Huerfanos: ' + hu + '\n  Office 365 Mobile: ' + o365 + '\n  Correccion Identidad: ' + cor;
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

// --- Builds B oficiales de Microsoft - generados automaticamente al ejecutar el script ---
$WIN_LATEST_PLACEHOLDER$

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
  var monthBaseline = WIN_MONTH_BASELINE[prefix];

  // Si no conocemos la rama, la tratamos como obsoleta
  if (!entry) return 'old';

  var isWindows10 = prefix.indexOf('10.0.1904') === 0;
  var isWindows11 = !isWindows10;

  // Windows 10:
  // - 22H2 (19045) siempre "en riesgo", incluso si va al dia
  // - resto de ramas Windows 10, obsoleto
  if (isWindows10) {
    if (prefix === '10.0.19045') {
      var w10Latest = parseVer(monthBaseline || entry.build);
      var w10Parts  = parseVer(ver);
      var w10RevDiff = (w10Latest[3] || 0) - (w10Parts[3] || 0);
      return w10RevDiff <= 1000 ? 'warn' : 'old';
    }
    return 'old';
  }

  // Windows 11:
  // - ramas activas: ultima build B del mes actual => actualizado
  // - ramas EoS: aunque esten al dia, en riesgo
  // - un ciclo mensual por detras => en riesgo
  // - mas atras => obsoleto
  if (isWindows11) {
    if (entry.eol) {
      if (monthBaseline && cmpVer(ver, monthBaseline) >= 0) return 'warn';
      var eolLatestParts = parseVer(monthBaseline || entry.build);
      var eolVerParts    = parseVer(ver);
      var eolRevDiff     = (eolLatestParts[3] || 0) - (eolVerParts[3] || 0);
      return eolRevDiff <= 1000 ? 'warn' : 'old';
    }
    if (monthBaseline && cmpVer(ver, monthBaseline) >= 0) return 'current';
    var latestParts = parseVer(monthBaseline || entry.build);
    var verParts    = parseVer(ver);
    var revDiff     = (latestParts[3] || 0) - (verParts[3] || 0);
    return revDiff <= 1000 ? 'warn' : 'old';
  }

  return 'warn';
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

// --- Tipo de gestion ---
// managementAgent values: mdm, easMdm, configurationManagerClientMdm,
// configurationManagerClient, jamf, googleCloudDevicePolicyController, msSense, etc.
var MGMT_GROUPS = [
  { key: 'mdm',      label: 'Intune',       color: '#63b3ed',
    match: function(a) { return a === 'mdm' || a === 'easmdm' || a === 'easMdm'; } },
  { key: 'sccm',     label: 'Co-management (SCCM+MDM)', color: '#f6ad55',
    match: function(a) { return a === 'configurationManagerClientMdm' || a === 'configurationManagerClientMdmEas'; } },
  { key: 'sccmonly', label: 'SCCM / ConfigMgr solo',   color: '#fc8181',
    match: function(a) { return a === 'configurationManagerClient'; } },
  { key: 'mde',      label: 'MDE',       color: '#a78bfa',
    match: function(a) { return a === 'msSense'; } },
  { key: 'jamf',     label: 'Jamf',                    color: '#4fd1c5',
    match: function(a) { return a === 'jamf'; } },
  { key: 'gcp',      label: 'Android Enterprise (Intune)', color: '#68d391',
    match: function(a) { return a === 'googleCloudDevicePolicyController'; } },
  { key: 'other',    label: 'Otro / Desconocido',       color: '#64748b',
    match: function(a) { return true; } } // catch-all
];

var MGMT_DISPLAY = [
  { key: 'mde',  label: 'Defender (MDE)', color: '#a78bfa',
    match: function(a) { return a === 'msSense'; } },
  { key: 'mdm',  label: 'Intune (MDM)',   color: '#63b3ed',
    match: function(a) { return a === 'mdm' || a === 'easMdm' || a === 'easmdm'; } },
  { key: 'gcp',  label: 'Android Enterprise', color: '#68d391',
    match: function(a) { return a === 'googleCloudDevicePolicyController'; } }
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
  // Solo Windows gestionados por Intune (MDM puro o co-management)
  var intuneAgents = ['mdm','easmdm','easMdm','configurationManagerClientMdm','configurationManagerClientMdmEas'];
  var all = (DATA.windows||[]).filter(function(d) {
    return intuneAgents.indexOf((d.managementAgent||'').trim()) >= 0;
  });
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

  // --- Tarjeta tipo de gestion (todos los dispositivos, 3 tipos fijos) ---
  var allDevices = [].concat(DATA.windows||[], DATA.android||[], DATA.ios||[], DATA.macos||[]);
  var mgmtCount = {};
  allDevices.forEach(function(d) {
    var agent = (d.managementAgent || '').trim();
    MGMT_DISPLAY.forEach(function(g) { if (g.match(agent)) mgmtCount[g.key] = (mgmtCount[g.key]||0)+1; });
  });
  var mgmtTotal = allDevices.length || 1;
  var mgmtHtml = '';
  MGMT_DISPLAY.forEach(function(g) {
    var cnt = mgmtCount[g.key] || 0;
    if (cnt === 0) return;
    var pct = Math.round(cnt / mgmtTotal * 100);
    var total = mgmtTotal; // alias para compatibilidad con el bloque de renderizado siguiente
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
  // Mismo alcance que la tarjeta de actualizacion: Windows gestionados por Intune o co-management
  var intuneAgents = ['mdm','easmdm','easMdm','configurationManagerClientMdm','configurationManagerClientMdmEas'];
  var winManaged = (DATA.windows||[]).filter(function(d) {
    return intuneAgents.indexOf((d.managementAgent || '').trim()) >= 0;
  });
  var titles = { current: 'Dispositivos Actualizados', warn: 'Dispositivos en Riesgo', old: 'Dispositivos Obsoletos' };
  obsFilteredData = winManaged.filter(function(d) { return (d._obsClass || classifyDevice(d)) === filter; });
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
  var group = MGMT_DISPLAY.filter(function(g) { return g.key === mgmtKey; })[0];
  var label = group ? group.label : mgmtKey;
  obsFilteredData = group ? all.filter(function(d) {
    return group.match((d.managementAgent || '').trim());
  }) : all;
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

// =====================================================================
// DISPOSITIVOS DUPLICADOS POR NUMERO DE SERIE
// =====================================================================
var dupAllGroups = [];
var dupFilteredGroups = [];
var dupPage = 1;

function initDuplicates() {
  var all = [].concat(DATA.windows||[], DATA.android||[], DATA.ios||[], DATA.macos||[]);

  // Agrupar por serialNumber (ignorar vacios/unknown)
  var serialMap = {};
  all.forEach(function(d) {
    var sn = (d.serialNumber || '').trim();
    if (!sn || sn.toLowerCase() === 'unknown') return;
    if (!serialMap[sn]) serialMap[sn] = [];
    serialMap[sn].push(d);
  });

  // Construir grupos con mas de un dispositivo
  dupAllGroups = Object.keys(serialMap)
    .filter(function(sn) { return serialMap[sn].length > 1; })
    .map(function(sn) {
      var devs = serialMap[sn];
      var owners = devs.map(function(d) { return d.userPrincipalName || '-'; })
                       .filter(function(u, i, a) { return a.indexOf(u) === i; });
      return {
        serialNumber: sn,
        count:        devs.length,
        owners:       owners,
        devices:      devs
      };
    });

  // Ordenar por mayor numero de duplicados primero
  dupAllGroups.sort(function(a, b) { return b.count - a.count; });

  var totalSNs  = dupAllGroups.length;
  var totalDevs = dupAllGroups.reduce(function(s, g) { return s + g.count; }, 0);

  // Actualizar tarjeta KPI
  document.getElementById('dupCount').textContent    = totalSNs;
  document.getElementById('dupSubtitle').textContent = totalDevs + ' registros afectados en ' + totalSNs + ' numeros de serie';
  document.getElementById('dupBadge').textContent    = totalSNs > 0 ? totalSNs + ' duplicados' : 'Sin duplicados';
}

function showDuplicatesPanel() {
  dupFilteredGroups = dupAllGroups.slice();
  dupPage = 1;
  document.getElementById('dupPanelCount').textContent = dupFilteredGroups.length + ' series duplicadas';
  document.getElementById('searchDup').value = '';
  renderDupPage();
  var panel = document.getElementById('duplicatesPanel');
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior:'smooth', block:'start' });
}

function filterDuplicates() {
  var q = document.getElementById('searchDup').value.toLowerCase();
  dupFilteredGroups = dupAllGroups.filter(function(g) {
    var ownerStr = g.owners.join(' ').toLowerCase();
    var devNames = g.devices.map(function(d){ return d.deviceName||''; }).join(' ').toLowerCase();
    return g.serialNumber.toLowerCase().indexOf(q) >= 0 ||
           ownerStr.indexOf(q) >= 0 ||
           devNames.indexOf(q) >= 0;
  });
  dupPage = 1;
  document.getElementById('dupPanelCount').textContent = dupFilteredGroups.length + ' series duplicadas';
  renderDupPage();
}

function toggleDupGroup(sn) {
  var safeId = sn.replace(/[^a-zA-Z0-9]/g,'_');
  var rows = document.querySelectorAll('.dup-detail-' + safeId);
  var btn  = document.getElementById('dup-btn-' + safeId);
  if (!rows.length) return;
  var isOpen = rows[0].style.display !== 'none';
  rows.forEach(function(r) { r.style.display = isOpen ? 'none' : ''; });
  if (btn) btn.innerHTML = isOpen ? '&#9654;' : '&#9660;';
}

function renderDupPage() {
  var tbody = document.getElementById('dupTableBody');
  var totalPages = Math.ceil(dupFilteredGroups.length / PAGE_SIZE) || 1;
  var start  = (dupPage - 1) * PAGE_SIZE;
  var pageData = dupFilteredGroups.slice(start, start + PAGE_SIZE);

  document.getElementById('dupPageIndicator').textContent = 'Pagina ' + dupPage + ' de ' + totalPages;
  document.getElementById('dupPrevPage').disabled = (dupPage === 1);
  document.getElementById('dupNextPage').disabled = (dupPage === totalPages);
  document.getElementById('dupPrevPage').style.opacity = (dupPage === 1) ? '0.4' : '1';
  document.getElementById('dupNextPage').style.opacity = (dupPage === totalPages) ? '0.4' : '1';

  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--muted); padding:24px; font-family:var(--mono)">No hay dispositivos duplicados</td></tr>';
    return;
  }

  var html = '';
  pageData.forEach(function(g) {
    var safeId = g.serialNumber.replace(/[^a-zA-Z0-9]/g,'_');
    var safeSN = g.serialNumber.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
    var countColor = g.count >= 3 ? 'var(--red)' : 'var(--orange)';
    var ownersHtml = g.owners.map(function(o) {
      return '<span style="display:inline-block; background:rgba(99,179,237,0.08); border:1px solid rgba(99,179,237,0.2); border-radius:4px; padding:2px 7px; font-size:10px; margin:2px 2px 2px 0; font-family:var(--mono); color:var(--blue)">' + o + '</span>';
    }).join('');

    // Fila resumen del grupo (clickable)
    html += '<tr style="cursor:pointer; background:rgba(99,179,237,0.03);" onclick="toggleDupGroup(\'' + safeSN + '\')">' +
      '<td style="width:32px; text-align:center; font-size:14px; color:var(--blue); user-select:none;"><span id="dup-btn-' + safeId + '">&#9654;</span></td>' +
      '<td><span style="font-family:var(--mono); font-weight:600; font-size:12px; color:var(--text)">' + g.serialNumber + '</span></td>' +
      '<td style="text-align:left"><span class="badge" style="background:rgba(252,129,129,0.12); color:' + countColor + '; font-size:13px; font-weight:700">' + g.count + 'x</span></td>' +
      '<td>' + ownersHtml + '</td>' +
      '</tr>';

    // Filas de detalle (colapsables, se identifican por clase CSS)
    // Cabecera de detalle
    html += '<tr class="dup-detail-' + safeId + '" style="display:none; background:rgba(26,34,53,0.7);">' +
      '<td></td>' +
      '<td colspan="3" style="padding:0;">' +
        '<table style="width:100%; border-collapse:collapse; font-size:11px;">' +
        '<thead><tr>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Nombre</th>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Propietario</th>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Cumplimiento</th>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Fecha Inscripcion</th>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Ultima Sincro</th>' +
        '</tr></thead>' +
        '<tbody>';
    g.devices.forEach(function(d, idx) {
      var isLast = idx === g.devices.length - 1;
      html +=
        '<tr style="' + (isLast ? '' : 'border-bottom:1px solid rgba(255,255,255,0.04)') + '">' +
        '<td style="padding:8px 12px; font-weight:600; color:var(--text)">' + (d.deviceName||'-') + '</td>' +
        '<td style="padding:8px 12px; font-family:var(--mono); color:var(--muted)">' + (d.userPrincipalName||'-') + '</td>' +
        '<td style="padding:8px 12px">' + badge(d.complianceState) + '</td>' +
        '<td style="padding:8px 12px; font-family:var(--mono); color:var(--muted)">' + fmtDate(d.enrolledDateTime) + '</td>' +
        '<td style="padding:8px 12px; font-family:var(--mono); color:var(--muted)">' + fmtDate(d.lastSyncDateTime) + '</td>' +
        '</tr>';
    });
    // Fila de cierre del subtable (misma clase para colapsar junto)
    html += '</tbody></table></td></tr>';
  });

  tbody.innerHTML = html;
}

function changeDupPage(step) {
  var totalPages = Math.ceil(dupFilteredGroups.length / PAGE_SIZE) || 1;
  var newPage = dupPage + step;
  if (newPage >= 1 && newPage <= totalPages) {
    dupPage = newPage;
    renderDupPage();
    document.getElementById('duplicatesPanel').scrollIntoView({ behavior:'smooth', block:'start' });
  }
}

// =====================================================================
// DUPLICADOS ENTRA ID (agrupados por displayName)
// =====================================================================
var entraDupAllGroups  = [];
var entraDupFiltered   = [];
var entraDupPage       = 1;

function initEntraDuplicates() {
  var nameMap = {};
  (DATA.entra || []).forEach(function(d) {
    var n = (d.displayName || '').trim();
    if (!n) return;
    var k = n.toLowerCase();
    if (!nameMap[k]) nameMap[k] = { displayName: n, devices: [] };
    nameMap[k].devices.push(d);
  });

  entraDupAllGroups = Object.keys(nameMap)
    .filter(function(k) { return nameMap[k].devices.length > 1; })
    .map(function(k) {
      var devs = nameMap[k].devices;
      var trustTypes = devs.map(function(d) { return d.trustType || 'Sin tipo'; })
                           .filter(function(v, i, a) { return a.indexOf(v) === i; });
      return {
        displayName: nameMap[k].displayName,
        count:       devs.length,
        trustTypes:  trustTypes,
        devices:     devs
      };
    })
    .sort(function(a, b) { return b.count - a.count; });

  var totalNames = entraDupAllGroups.length;
  var totalDevs  = entraDupAllGroups.reduce(function(s, g) { return s + g.count; }, 0);
  if (document.getElementById('cntDupEntra'))
    document.getElementById('cntDupEntra').textContent = totalNames;
}

function showEntraDuplicatesPanel() {
  entraDupFiltered = entraDupAllGroups.slice();
  entraDupPage = 1;
  document.getElementById('entraDupPanelCount').textContent = entraDupFiltered.length + ' nombres duplicados';
  document.getElementById('searchEntraDup').value = '';
  renderEntraDupPage();
  var panel = document.getElementById('entraDupPanel');
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function filterEntraDuplicates() {
  var q = document.getElementById('searchEntraDup').value.toLowerCase();
  entraDupFiltered = entraDupAllGroups.filter(function(g) {
    var trustStr = g.trustTypes.join(' ').toLowerCase();
    var propStr  = g.devices.map(function(d) { return d.displayName || ''; }).join(' ').toLowerCase();
    return g.displayName.toLowerCase().indexOf(q) >= 0 ||
           trustStr.indexOf(q) >= 0 ||
           propStr.indexOf(q) >= 0;
  });
  entraDupPage = 1;
  document.getElementById('entraDupPanelCount').textContent = entraDupFiltered.length + ' nombres duplicados';
  renderEntraDupPage();
}

function toggleEntraDupGroup(name) {
  var safeId = name.replace(/[^a-zA-Z0-9]/g, '_');
  var rows = document.querySelectorAll('.entra-dup-detail-' + safeId);
  var btn  = document.getElementById('entra-dup-btn-' + safeId);
  if (!rows.length) return;
  var isOpen = rows[0].style.display !== 'none';
  rows.forEach(function(r) { r.style.display = isOpen ? 'none' : ''; });
  if (btn) btn.innerHTML = isOpen ? '&#9654;' : '&#9660;';
}

var trustMap = { 'ServerAd': 'Hibrida (HAADJ)', 'AzureAd': 'Entra (AADJ)', 'Workplace': 'Registered' };
function trustBadgeEntra(trustType) {
  var labels = { 'ServerAd': 'HAADJ', 'AzureAd': 'AADJ', 'Workplace': 'Registered' };
  var colors = { 'ServerAd': 'var(--cyan)', 'AzureAd': 'var(--purple)', 'Workplace': 'var(--green)' };
  var lbl = labels[trustType] || (trustType || 'Sin tipo');
  var col = colors[trustType] || 'var(--muted)';
  return '<span class="badge" style="background:' + col + '22; color:' + col + '">' + lbl + '</span>';
}

function renderEntraDupPage() {
  var tbody = document.getElementById('entraDupTableBody');
  var totalPages = Math.ceil(entraDupFiltered.length / PAGE_SIZE) || 1;
  var start    = (entraDupPage - 1) * PAGE_SIZE;
  var pageData = entraDupFiltered.slice(start, start + PAGE_SIZE);

  document.getElementById('entraDupPageIndicator').textContent = 'Pagina ' + entraDupPage + ' de ' + totalPages;
  document.getElementById('entraDupPrevPage').disabled = (entraDupPage === 1);
  document.getElementById('entraDupNextPage').disabled = (entraDupPage === totalPages);
  document.getElementById('entraDupPrevPage').style.opacity = (entraDupPage === 1) ? '0.4' : '1';
  document.getElementById('entraDupNextPage').style.opacity = (entraDupPage === totalPages) ? '0.4' : '1';

  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--muted); padding:24px; font-family:var(--mono)">No hay dispositivos duplicados en Entra ID</td></tr>';
    return;
  }

  var html = '';
  pageData.forEach(function(g) {
    var safeId    = g.displayName.replace(/[^a-zA-Z0-9]/g, '_');
    var safeName  = g.displayName.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    var countColor = g.count >= 3 ? 'var(--red)' : 'var(--orange)';

    // Badges de tipos de union presentes en el grupo
    var trustsHtml = g.trustTypes.map(function(t) {
      return trustBadgeEntra(t);
    }).join(' ');

    // Fila resumen del grupo (clickable)
    html += '<tr style="cursor:pointer; background:rgba(99,179,237,0.03);" onclick="toggleEntraDupGroup(\'' + safeName + '\')">' +
      '<td style="width:32px; text-align:center; font-size:14px; color:var(--blue); user-select:none;"><span id="entra-dup-btn-' + safeId + '">&#9654;</span></td>' +
      '<td><span style="font-family:var(--mono); font-weight:600; font-size:12px; color:var(--text)">' + g.displayName + '</span></td>' +
      '<td style="text-align:left"><span class="badge" style="background:rgba(252,129,129,0.12); color:' + countColor + '; font-size:13px; font-weight:700">' + g.count + 'x</span></td>' +
      '<td>' + trustsHtml + '</td>' +
      '</tr>';

    // Filas de detalle colapsables
    html += '<tr class="entra-dup-detail-' + safeId + '" style="display:none; background:rgba(26,34,53,0.7);">' +
      '<td></td>' +
      '<td colspan="3" style="padding:0;">' +
        '<table style="width:100%; border-collapse:collapse; font-size:11px;">' +
        '<thead><tr>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Nombre</th>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Tipo Union</th>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Gestion</th>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">F. Registro</th>' +
          '<th style="font-family:var(--mono); font-size:9px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); text-align:left; padding:8px 12px 6px; border-bottom:1px solid var(--border);">Ultimo Inicio Sesion</th>' +
        '</tr></thead>' +
        '<tbody>';
    g.devices.forEach(function(d, idx) {
      var isLast = idx === g.devices.length - 1;
      var mgmtLbl = d.managementType || '-';
      html +=
        '<tr style="' + (isLast ? '' : 'border-bottom:1px solid rgba(255,255,255,0.04)') + '">' +
        '<td style="padding:8px 12px; font-weight:600; color:var(--text)">'           + (d.displayName || '-')         + '</td>' +
        '<td style="padding:8px 12px">'                                                + trustBadgeEntra(d.trustType)   + '</td>' +
        '<td style="padding:8px 12px; font-family:var(--mono); font-size:10px; color:var(--muted)">' + mgmtLbl + '</td>' +
        '<td style="padding:8px 12px; font-family:var(--mono); color:var(--muted)">'  + fmtDate(d.registrationDateTime) + '</td>' +
        '<td style="padding:8px 12px; font-family:var(--mono); color:var(--muted)">'  + fmtDate(d.lastSignIn)           + '</td>' +
        '</tr>';
    });
    html += '</tbody></table></td></tr>';
  });

  tbody.innerHTML = html;
}

function changeEntraDupPage(step) {
  var totalPages = Math.ceil(entraDupFiltered.length / PAGE_SIZE) || 1;
  var np = entraDupPage + step;
  if (np >= 1 && np <= totalPages) {
    entraDupPage = np;
    renderEntraDupPage();
    document.getElementById('entraDupPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// =====================================================================
// TAB CUMPLIMIENTO
// =====================================================================
var cumplActivePlatform = 'all';
var cumplDevAllData     = [];
var cumplDevFiltered    = [];
var cumplDevPage        = 1;

var PLATFORM_COLORS = {
  'Windows':           '#63b3ed',
  'Windows Mobile':    '#90cdf4',
  'Windows 8.1':       '#bee3f8',
  'Android':           '#68d391',
  'Android Enterprise':'#4fd1c5',
  'iOS':               '#a78bfa',
  'macOS':             '#f6ad55',
  'Otro':              '#94a3b8'
};

function getPlatColor(platform) {
  for (var k in PLATFORM_COLORS) {
    if (platform && platform.toLowerCase().indexOf(k.toLowerCase()) >= 0) return PLATFORM_COLORS[k];
  }
  return '#64748b';
}

function cumplStatusBadge(status) {
  var map = {
    nonCompliant:  '<span class="badge badge-error">No Conforme</span>',
    compliant:     '<span class="badge badge-compliant">Conforme</span>',
    error:         '<span class="badge badge-error">Error</span>',
    unknown:       '<span class="badge badge-muted">Desconocido</span>',
    inGracePeriod: '<span class="badge badge-warning">Periodo Gracia</span>',
    conflict:      '<span class="badge badge-warning">Conflicto</span>'
  };
  return map[status] || '<span class="badge badge-muted">' + (status||'-') + '</span>';
}

// =====================================================================
// PANEL TIPO DE PROPIEDAD
// =====================================================================
var ownerPage = 1;
var ownerAllData = [];
var ownerFiltered = [];

var OWNER_LABELS = { company: 'Corporativo', personal: 'Personal (BYOD)', unknown: 'Desconocido' };
var OWNER_COLORS = { company: 'var(--blue)', personal: 'var(--orange)', unknown: 'var(--muted)' };

function showOwnerPanel(ownerType) {
  var allDevices = [].concat(
    DATA.windows || [], DATA.android || [], DATA.ios || [], DATA.macos || []
  ).filter(function(d) { return !isSystemUpn(d.userPrincipalName); });

  var filtered = allDevices.filter(function(d) {
    var t = (d.managedDeviceOwnerType || '').toLowerCase();
    if (ownerType === 'company')  return t === 'company';
    if (ownerType === 'personal') return t === 'personal';
    return t !== 'company' && t !== 'personal';
  });

  ownerAllData  = filtered;
  ownerFiltered = filtered.slice();
  ownerPage = 1;

  var label = OWNER_LABELS[ownerType] || ownerType;
  document.getElementById('ownerPanelTitle').textContent = 'Dispositivos - ' + label;
  document.getElementById('ownerPanelCount').textContent = filtered.length + ' dispositivos';
  document.getElementById('searchOwner').value = '';
  renderOwnerPage();

  var panel = document.getElementById('ownerPanel');
  panel.style.display = 'block';
  setTimeout(function() { panel.scrollIntoView({ behavior:'smooth', block:'start' }); }, 50);
}

function filterOwnerDevices() {
  var q = document.getElementById('searchOwner').value.toLowerCase();
  ownerFiltered = ownerAllData.filter(function(d) {
    return (d.deviceName        || '').toLowerCase().indexOf(q) >= 0 ||
           (d.userPrincipalName || '').toLowerCase().indexOf(q) >= 0 ||
           (d.operatingSystem   || '').toLowerCase().indexOf(q) >= 0;
  });
  ownerPage = 1;
  document.getElementById('ownerPanelCount').textContent = ownerFiltered.length + ' dispositivos';
  renderOwnerPage();
}

function renderOwnerPage() {
  var tbody      = document.getElementById('ownerTableBody');
  var totalPages = Math.ceil(ownerFiltered.length / PAGE_SIZE) || 1;
  var start      = (ownerPage - 1) * PAGE_SIZE;
  var pageData   = ownerFiltered.slice(start, start + PAGE_SIZE);

  document.getElementById('ownerPageIndicator').textContent = 'Pagina ' + ownerPage + ' de ' + totalPages;
  document.getElementById('ownerPrevPage').disabled    = (ownerPage === 1);
  document.getElementById('ownerNextPage').disabled    = (ownerPage === totalPages);
  document.getElementById('ownerPrevPage').style.opacity = (ownerPage === 1)          ? '0.4' : '1';
  document.getElementById('ownerNextPage').style.opacity = (ownerPage === totalPages) ? '0.4' : '1';

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

function changeOwnerPage(step) {
  var totalPages = Math.ceil(ownerFiltered.length / PAGE_SIZE) || 1;
  var np = ownerPage + step;
  if (np >= 1 && np <= totalPages) {
    ownerPage = np;
    renderOwnerPage();
    document.getElementById('ownerPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// =====================================================================
// REPORTE EJECUTIVO — SECCION CUMPLIMIENTO
// =====================================================================
// ---- INIT ----
try { initEntraDonuts(); }            catch(e) { console.warn('initEntraDonuts:', e); }
try { initEntraCards(); }             catch(e) { console.warn('initEntraCards:', e); }
try { initObsolescencia(); }          catch(e) { console.warn('initObsolescencia:', e); }
try { initDuplicates(); }             catch(e) { console.warn('initDuplicates:', e); }
try { initIntuneStale(); }            catch(e) { console.warn('initIntuneStale:', e); }
try { initEntraDuplicates(); }        catch(e) { console.warn('initEntraDuplicates:', e); }
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
# Reporte
$html = $html.Replace('$cntNoCompliant', $cntNoCompliant)
# Ownership / Tipo de Propiedad
$html = $html.Replace('$cntCorporate',    [string]$cntCorporate)
$html = $html.Replace('$cntPersonal',     [string]$cntPersonal)
$html = $html.Replace('$cntOwnerUnknown', [string]$cntOwnerUnknown)
$html = $html.Replace('$pctCorporate',    [string]$pctCorporate)
$html = $html.Replace('$pctPersonal',     [string]$pctPersonal)
$html = $html.Replace('$pctOwnerUnknown', [string]$pctOwnerUnknown)
$html = $html.Replace('$dashCorporate',   $dashCorporate)
$html = $html.Replace('$dashPersonal',    $dashPersonal)
$html = $html.Replace('$dashOwnerUnknown',$dashOwnerUnknown)
$html = $html.Replace('$rotPersonal',     $rotPersonal)
$html = $html.Replace('$rotOwnerUnknown', $rotOwnerUnknown)
# JSON datos
$html = $html.Replace('$jsonWin',     $jsonWin)
$html = $html.Replace('$jsonAndroid', $jsonAndroid)
$html = $html.Replace('$jsoniOS',     $jsoniOS)
$html = $html.Replace('$jsonMac',     $jsonMac)
$html = $html.Replace('$jsonEntra',      $jsonEntra)
$html = $html.Replace('$jsonIntuneIds',   $jsonIntuneIds)
$html = $html.Replace('$jsonIntuneNames', $jsonIntuneNames)
# Directiva por defecto
$html = $html.Replace('$defaultPolicyNonCompl', [string]$defaultPolicyNonCompl)
$html = $html.Replace('$defaultPolicyError',    [string]$defaultPolicyError)
$html = $html.Replace('$defaultPolicyUnknown',  [string]$defaultPolicyUnknown)
$html = $html.Replace('$defaultPolicyId',       $defaultPolicyId)
$html = $html.Replace('$autorInforme',    $autorInforme)
$html = $html.Replace('$anioCreacion',    $anioCreacion)
# Builds Windows dinamicos
$html = $html.Replace('$WIN_LATEST_PLACEHOLDER$', $winLatestJs)

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
    Write-Host "  Entra ID: $cntEntra dispositivos registrados" -ForegroundColor White
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    Invoke-Item $ruta
}
catch {
    Write-Host "  Error guardando el fichero: $_" -ForegroundColor Red
}
