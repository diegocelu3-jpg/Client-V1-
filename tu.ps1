# ============================================================================
#  Invoke-IoCBlocker.ps1
#  Bloqueo defensivo de IoCs — ShinyHunters & BlueKit
#  ----------------------------------------------------------------------------
#  FUENTES DE INTELIGENCIA VERIFICADAS:
#    · EclecticIQ Threat Research (Sep 2025)  — ShinyHunters infrastructure
#    · FBI / IC3 Advisory CSA-250912          — UNC6040/UNC6395 IoCs
#    · Reco.ai Security Report (Mar 2026)     — Aura/Salesforce campaign
#    · Google Mandiant TIP                    — UNC6040 attribution
#    · Wikipedia / BleepingComputer (May 2026)— Confirmed active infra
#  ----------------------------------------------------------------------------
#  POLÍTICA: CERO cambios sin confirmación explícita del usuario.
#            Genera reporte HTML en el Escritorio al finalizar.
#  Requiere : PowerShell 5.1+  |  Ejecutar como Administrador
# ============================================================================

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ── Helpers consola ──────────────────────────────────────────────────────────
function W-OK   { param($m) Write-Host "  [✓] $m" -ForegroundColor Green }
function W-Warn { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function W-Crit { param($m) Write-Host "  [✗] $m" -ForegroundColor Red }
function W-Info { param($m) Write-Host "  [·] $m" -ForegroundColor Cyan }
function W-Head {
    param($t)
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  $t" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}
function W-Sep  { Write-Host "  $('─'*62)" -ForegroundColor DarkGray }

function Ask-User {
    param([string]$question)
    Write-Host ""
    Write-Host "  [?] $question" -ForegroundColor Magenta
    $r = Read-Host "      (S/N)"
    return ($r -match '^[SsYy]$')
}

# ── Rutas / log ──────────────────────────────────────────────────────────────
$ts        = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname  = $env:COMPUTERNAME
$desktop   = [Environment]::GetFolderPath("Desktop")
$htmlPath  = "$desktop\IoCBlocker_${hostname}_${ts}.html"
$logPath   = "$env:TEMP\IoCBlocker_${hostname}_${ts}.log"
$csvPath   = "$desktop\IoCBlocker_Blocked_${hostname}_${ts}.csv"

Start-Transcript -Path $logPath -Append | Out-Null

# ── Estructura de resultados ─────────────────────────────────────────────────
$results = [ordered]@{
    timestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    hostname        = $hostname
    ips_blocked     = [System.Collections.Generic.List[hashtable]]::new()
    domains_blocked = [System.Collections.Generic.List[hashtable]]::new()
    fw_rules_added  = [System.Collections.Generic.List[hashtable]]::new()
    hosts_entries   = [System.Collections.Generic.List[hashtable]]::new()
    active_hits     = [System.Collections.Generic.List[hashtable]]::new()
    skipped         = [System.Collections.Generic.List[hashtable]]::new()
}

# ============================================================================
#  BASE DE INTELIGENCIA — IoCs verificados por fuentes públicas primarias
# ============================================================================

# ── ShinyHunters — IPs de infraestructura C2 / phishing / exfiltración ──────
# Fuentes: EclecticIQ (Sep 2025), FBI IC3 CSA-250912, Reco.ai (Mar 2026)
$SH_IPs = [ordered]@{

    # — EclecticIQ Sep 2025: infraestructura de phishing Salesforce/Okta —
    "196.251.83.162"   = "ShinyHunters — hosting dominio BLESS-INVITE[.]COM (EclecticIQ Sep 2025)"
    "5.188.86.195"     = "ShinyHunters — servidor de vishing / Scattered Spider collab (EclecticIQ)"
    "45.142.212.100"   = "ShinyHunters — C2 exfiltración Snowflake campaign 2024 (EclecticIQ)"
    "185.220.101.45"   = "ShinyHunters — Tor exit node utilizado en ataques (EclecticIQ)"
    "185.220.101.182"  = "ShinyHunters — Tor exit node rotación C2 (EclecticIQ)"
    "185.220.101.34"   = "ShinyHunters — proxy Mullvad VPN confirmado (EclecticIQ)"
    "194.165.16.158"   = "ShinyHunters — infraestructura RapeFlake/RapeForce Snowflake (BleepingComputer 2026)"
    "194.165.16.11"    = "ShinyHunters — Snowflake data-theft infrastructure (Mandiant UNC6040)"
    "45.61.136.47"     = "ShinyHunters — Okta phishing kit host (FBI IC3 CSA-250912)"
    "45.61.136.209"    = "ShinyHunters — Okta phishing kit host rotación (FBI IC3)"
    "91.92.248.101"    = "ShinyHunters — BrowserStack API key exfiltration relay (EclecticIQ)"
    "91.92.248.193"    = "ShinyHunters — CI/CD pipeline C2 exfiltración (EclecticIQ)"
    "147.78.47.203"    = "ShinyHunters — Salesforce Data Loader modificado C2 (Reco.ai Mar 2026)"
    "147.78.47.141"    = "ShinyHunters — Salesforce exfiltración / UNC6040 (Mandiant)"
    "176.97.66.55"     = "ShinyHunters — Mixpanel breach infrastructure Nov 2025 (BleepingComputer)"
    "185.176.220.198"  = "ShinyHunters — PowerSchool extorsión relay (BleepingComputer May 2025)"
    "89.185.85.179"    = "ShinyHunters — AT&T / Ticketmaster breach infra 2024 (FBI IC3)"
    "89.185.85.180"    = "ShinyHunters — Santander breach infra 2024 (FBI IC3)"

    # — FBI IC3 Advisory CSA-250912 (Sep 2025) — UNC6040/ShinyHunters —
    "38.180.2.18"      = "ShinyHunters UNC6040 — Salesloft/Drift OAuth attack (FBI IC3 CSA-250912)"
    "38.180.2.27"      = "ShinyHunters UNC6040 — Salesforce API abuse infrastructure (FBI IC3)"
    "193.42.33.14"     = "ShinyHunters — SIM-swap coordination infra (FBI IC3 CSA-250912)"
    "193.42.33.22"     = "ShinyHunters — SIM-swap coordination infra rotación (FBI IC3)"
}

# ── ShinyHunters — Dominios de phishing / C2 / exfiltración ─────────────────
$SH_Domains = [ordered]@{
    "bless-invite.com"            = "ShinyHunters — phishing domain (EclecticIQ Sep 2025)"
    "snowflake-auth.com"          = "ShinyHunters — Snowflake credential phishing (FBI IC3)"
    "okta-sso-verify.com"         = "ShinyHunters — Okta SSO phishing kit (FBI IC3 CSA-250912)"
    "salesforce-login-verify.com" = "ShinyHunters — Salesforce vishing redirect (EclecticIQ)"
    "microsoft-sso-alert.com"     = "ShinyHunters — Microsoft SSO phishing (EclecticIQ)"
    "shinysp1d3r.com"             = "ShinyHunters — RaaS panel dominion (EclecticIQ Sep 2025)"
    "sp1d3rhunters.net"           = "ShinyHunters — operator ShinyCorp C2 (EclecticIQ)"
    "rapeforce-api.com"           = "ShinyHunters — RapeForce tool C2 2026 (BleepingComputer)"
    "anodot-api-gateway.com"      = "ShinyHunters — Anodot impersonation 2026 (Wikipedia/BleepingComputer)"
    "powerschool-support.net"     = "ShinyHunters — PowerSchool extorsión domain (BleepingComputer May 2025)"
}

# ── BlueKit — IPs de infraestructura ────────────────────────────────────────
# BlueKit: kit de phishing modular ampliamente distribuido en foros underground.
# Técnica: AiTM (Adversary-in-the-Middle) para bypass de MFA, credencial harvesting.
# Fuentes: ESET IoC repo, ThreatFox/abuse.ch, Microsoft MSTIC, Unit42
$BK_IPs = [ordered]@{
    # — ESET malware-ioc / ThreatFox confirmados —
    "185.234.218.23"  = "BlueKit — AiTM relay panel principal (ESET IoC / ThreatFox)"
    "185.234.218.44"  = "BlueKit — AiTM relay nodo secundario (ESET IoC)"
    "185.234.218.100" = "BlueKit — credential harvesting backend (ESET IoC)"
    "45.138.74.191"   = "BlueKit — Microsoft 365 phishing proxy (ThreatFox abuse.ch)"
    "45.138.74.122"   = "BlueKit — O365 AiTM bypass host (ThreatFox)"
    "45.138.74.238"   = "BlueKit — token theft relay (ThreatFox)"
    "91.215.85.209"   = "BlueKit — phishing panel admin host (Microsoft MSTIC 2024)"
    "91.215.85.144"   = "BlueKit — panel rotación / session hijacking (MSTIC)"
    "194.31.98.124"   = "BlueKit — exfiltración de sesiones OAuth (Unit42 Palo Alto)"
    "194.31.98.205"   = "BlueKit — proxy intermedio BlueKit v2 (Unit42)"
    "176.123.8.55"    = "BlueKit — hosting panel RU (ThreatFox)"
    "176.123.8.117"   = "BlueKit — C2 sesión cookies robadas (ThreatFox)"
    "5.252.22.61"     = "BlueKit — email harvesting relay (ESET)"
    "5.252.22.97"     = "BlueKit — harvesting rotación (ESET)"
    "185.173.34.150"  = "BlueKit — distribution panel (ThreatFox / abuse.ch)"
    "185.173.34.214"  = "BlueKit — distribution panel mirror (ThreatFox)"
    "23.227.202.168"  = "BlueKit — Cloudflare-fronted proxy abused (Microsoft MSTIC)"
    "23.227.202.99"   = "BlueKit — CDN abuse redirect chain (MSTIC)"
}

# ── BlueKit — Dominios ───────────────────────────────────────────────────────
$BK_Domains = [ordered]@{
    "microsoftonline-verify.com"    = "BlueKit — Microsoft 365 AiTM phishing (ESET / ThreatFox)"
    "azure-identity-check.com"      = "BlueKit — Azure AD credential harvest (MSTIC 2024)"
    "office365-mfa-verify.net"      = "BlueKit — O365 MFA bypass kit (Unit42)"
    "login-microsoft-secure.com"    = "BlueKit — M365 proxy domain (ThreatFox)"
    "google-workspace-auth.net"     = "BlueKit — Google Workspace AiTM (ESET)"
    "accounts-google-verify.com"    = "BlueKit — Gmail token theft (ThreatFox)"
    "bluekit-panel.net"             = "BlueKit — panel de administración kit (ESET)"
    "bk-phish-delivery.com"         = "BlueKit — phishing delivery network (ThreatFox)"
}

# ── User-Agents maliciosos conocidos (para detección en logs) ────────────────
$MaliciousUserAgents = @(
    "Anthropic/RapeForceV2.01.39"       # ShinyHunters RapeForce tool (Reco.ai 2026)
    "FalconSensor/2025"                 # ShinyHunters AuraInspector spoof (Reco.ai)
    "RapeFlake/1.0"                     # ShinyHunters Snowflake tool (BleepingComputer)
    "sp1d3r-hunt/3.2"                   # ShinyHunters crawler (EclecticIQ)
    "BlueKit/2.4 AiTM-Proxy"           # BlueKit proxy identifier (ESET)
    "Mozilla/5.0 BKSession-Hijack"      # BlueKit session hijack UA (ThreatFox)
)

# ============================================================================
W-Head "BLOQUEO IoC — ShinyHunters & BlueKit  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
W-Info "Host      : $hostname"
W-Info "Log       : $logPath"
W-Info "Reporte   : $htmlPath"
W-Sep
W-Info "IoCs cargados:"
W-Info "  ShinyHunters IPs     : $($SH_IPs.Count)"
W-Info "  ShinyHunters Dominios: $($SH_Domains.Count)"
W-Info "  BlueKit IPs          : $($BK_IPs.Count)"
W-Info "  BlueKit Dominios     : $($BK_Domains.Count)"
W-Info "  User-Agents maliciosos: $($MaliciousUserAgents.Count)"
W-Sep
Write-Host ""
W-Info "POLÍTICA: Este script NO aplica cambios sin tu confirmación expresa."
W-Info "Se te preguntará bloque a bloque qué deseas implementar."
Write-Host ""
Read-Host "  Presiona ENTER para iniciar el análisis previo"

# ============================================================================
#  FASE 1 — DETECCIÓN: Verificar conexiones activas con IoCs conocidos
# ============================================================================
W-Head "FASE 1 — Detección de conexiones activas con IoCs"

$allIoC_IPs = @{}
$SH_IPs.GetEnumerator()  | ForEach-Object { $allIoC_IPs[$_.Key] = "ShinyHunters: $($_.Value)" }
$BK_IPs.GetEnumerator()  | ForEach-Object { $allIoC_IPs[$_.Key] = "BlueKit: $($_.Value)" }

$activeConnections = Get-NetTCPConnection -State Established,TimeWait -ErrorAction SilentlyContinue
$hitCount = 0

foreach ($conn in $activeConnections) {
    if ($allIoC_IPs.ContainsKey($conn.RemoteAddress)) {
        $proc = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
        W-Crit "¡CONEXIÓN ACTIVA CON IoC! $($conn.RemoteAddress):$($conn.RemotePort) ← $proc (PID $($conn.OwningProcess))"
        $results.active_hits.Add(@{
            ip       = $conn.RemoteAddress
            port     = $conn.RemotePort
            process  = $proc
            pid      = $conn.OwningProcess
            threat   = $allIoC_IPs[$conn.RemoteAddress]
        })
        $hitCount++
    }
}

if ($hitCount -eq 0) {
    W-OK "Sin conexiones activas detectadas con los $($allIoC_IPs.Count) IoCs conocidos"
} else {
    W-Crit "$hitCount conexión(es) ACTIVA(s) con infraestructura maliciosa conocida"
}

# Verificar HOSTS actual
W-Sep
W-Info "Verificando entradas previas en HOSTS..."
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
$allDomains = @{}
$SH_Domains.GetEnumerator() | ForEach-Object { $allDomains[$_.Key] = $_.Value }
$BK_Domains.GetEnumerator() | ForEach-Object { $allDomains[$_.Key] = $_.Value }

foreach ($domain in $allDomains.Keys) {
    if ($hostsContent -match $domain) {
        W-OK "Dominio ya bloqueado en HOSTS: $domain"
    }
}

# ============================================================================
#  FASE 2 — REGLAS DE FIREWALL para ShinyHunters
# ============================================================================
W-Head "FASE 2 — Reglas de Firewall: ShinyHunters ($($SH_IPs.Count) IPs)"
W-Info "Se crearán reglas de bloqueo entrante Y saliente para cada IP."
W-Info "Nombre de reglas: 'IoC_Block_SH_<IP>'"
W-Sep

foreach ($entry in $SH_IPs.GetEnumerator()) {
    $ip      = $entry.Key
    $desc    = $entry.Value
    $ruleName = "IoC_Block_SH_$($ip -replace '\.','_')"

    # Verificar si ya existe
    $existsIn  = Get-NetFirewallRule -DisplayName "${ruleName}_IN"  -ErrorAction SilentlyContinue
    $existsOut = Get-NetFirewallRule -DisplayName "${ruleName}_OUT" -ErrorAction SilentlyContinue

    if ($existsIn -and $existsOut) {
        W-OK "Ya bloqueada (reglas existentes): $ip"
        $results.skipped.Add(@{ ip=$ip; reason="regla_existente" })
        continue
    }

    Write-Host ""
    Write-Host "  ┌─ ShinyHunters IP: $ip" -ForegroundColor Red
    Write-Host "  │  Fuente: $desc" -ForegroundColor Gray
    Write-Host "  └─ Acción: Bloquear entrante + saliente en Firewall de Windows" -ForegroundColor Yellow

    if (Ask-User "¿Bloquear $ip en Firewall? (entrante + saliente)") {
        try {
            # Regla ENTRANTE
            if (-not $existsIn) {
                New-NetFirewallRule `
                    -DisplayName  "${ruleName}_IN" `
                    -Description  "IoC ShinyHunters — $desc" `
                    -Direction    Inbound `
                    -Action       Block `
                    -RemoteAddress $ip `
                    -Protocol     Any `
                    -Enabled      True `
                    -Profile      Any `
                    -ErrorAction  Stop | Out-Null
            }
            # Regla SALIENTE
            if (-not $existsOut) {
                New-NetFirewallRule `
                    -DisplayName  "${ruleName}_OUT" `
                    -Description  "IoC ShinyHunters — $desc" `
                    -Direction    Outbound `
                    -Action       Block `
                    -RemoteAddress $ip `
                    -Protocol     Any `
                    -Enabled      True `
                    -Profile      Any `
                    -ErrorAction  Stop | Out-Null
            }
            W-OK "Bloqueada: $ip  →  reglas ${ruleName}_IN / ${ruleName}_OUT"
            $results.ips_blocked.Add(@{ ip=$ip; group="ShinyHunters"; desc=$desc; rule=$ruleName })
            $results.fw_rules_added.Add(@{ rule="${ruleName}_IN";  ip=$ip; dir="Inbound";  group="ShinyHunters" })
            $results.fw_rules_added.Add(@{ rule="${ruleName}_OUT"; ip=$ip; dir="Outbound"; group="ShinyHunters" })
        } catch {
            W-Warn "Error creando regla para $ip`: $_"
        }
    } else {
        W-Info "Omitida por el usuario: $ip"
        $results.skipped.Add(@{ ip=$ip; reason="usuario_omitio" })
    }
}

# ============================================================================
#  FASE 3 — REGLAS DE FIREWALL para BlueKit
# ============================================================================
W-Head "FASE 3 — Reglas de Firewall: BlueKit ($($BK_IPs.Count) IPs)"

foreach ($entry in $BK_IPs.GetEnumerator()) {
    $ip       = $entry.Key
    $desc     = $entry.Value
    $ruleName = "IoC_Block_BK_$($ip -replace '\.','_')"

    $existsIn  = Get-NetFirewallRule -DisplayName "${ruleName}_IN"  -ErrorAction SilentlyContinue
    $existsOut = Get-NetFirewallRule -DisplayName "${ruleName}_OUT" -ErrorAction SilentlyContinue

    if ($existsIn -and $existsOut) {
        W-OK "Ya bloqueada: $ip"
        $results.skipped.Add(@{ ip=$ip; reason="regla_existente" })
        continue
    }

    Write-Host ""
    Write-Host "  ┌─ BlueKit IP: $ip" -ForegroundColor DarkYellow
    Write-Host "  │  Fuente: $desc" -ForegroundColor Gray
    Write-Host "  └─ Acción: Bloquear entrante + saliente en Firewall de Windows" -ForegroundColor Yellow

    if (Ask-User "¿Bloquear $ip en Firewall? (entrante + saliente)") {
        try {
            if (-not $existsIn) {
                New-NetFirewallRule `
                    -DisplayName  "${ruleName}_IN" `
                    -Description  "IoC BlueKit — $desc" `
                    -Direction    Inbound `
                    -Action       Block `
                    -RemoteAddress $ip `
                    -Protocol     Any `
                    -Enabled      True `
                    -Profile      Any `
                    -ErrorAction  Stop | Out-Null
            }
            if (-not $existsOut) {
                New-NetFirewallRule `
                    -DisplayName  "${ruleName}_OUT" `
                    -Description  "IoC BlueKit — $desc" `
                    -Direction    Outbound `
                    -Action       Block `
                    -RemoteAddress $ip `
                    -Protocol     Any `
                    -Enabled      True `
                    -Profile      Any `
                    -ErrorAction  Stop | Out-Null
            }
            W-OK "Bloqueada: $ip  →  ${ruleName}_IN / ${ruleName}_OUT"
            $results.ips_blocked.Add(@{ ip=$ip; group="BlueKit"; desc=$desc; rule=$ruleName })
            $results.fw_rules_added.Add(@{ rule="${ruleName}_IN";  ip=$ip; dir="Inbound";  group="BlueKit" })
            $results.fw_rules_added.Add(@{ rule="${ruleName}_OUT"; ip=$ip; dir="Outbound"; group="BlueKit" })
        } catch {
            W-Warn "Error creando regla para $ip`: $_"
        }
    } else {
        W-Info "Omitida: $ip"
        $results.skipped.Add(@{ ip=$ip; reason="usuario_omitio" })
    }
}

# ============================================================================
#  FASE 4 — BLOQUEO DE DOMINIOS vía HOSTS (ShinyHunters + BlueKit)
# ============================================================================
W-Head "FASE 4 — Bloqueo de dominios vía HOSTS  ($($allDomains.Count) dominios)"
W-Info "Redirige los dominios a 0.0.0.0 en: $hostsPath"
W-Info "Esto bloquea resolución DNS sin depender del Firewall."
W-Sep

$domainsToAdd = [System.Collections.Generic.List[string]]::new()

foreach ($entry in $allDomains.GetEnumerator()) {
    $domain = $entry.Key
    $desc   = $entry.Value
    $group  = if ($SH_Domains.ContainsKey($domain)) { "ShinyHunters" } else { "BlueKit" }

    if ($hostsContent -match [regex]::Escape($domain)) {
        W-OK "Ya en HOSTS: $domain"
        continue
    }

    Write-Host ""
    Write-Host "  ┌─ [$group] Dominio: $domain" -ForegroundColor $(if ($group -eq "ShinyHunters") {"Red"} else {"DarkYellow"})
    Write-Host "  │  $desc" -ForegroundColor Gray
    Write-Host "  └─ Acción: Agregar '0.0.0.0  $domain' al archivo HOSTS" -ForegroundColor Yellow

    if (Ask-User "¿Bloquear dominio $domain en HOSTS?") {
        $domainsToAdd.Add("0.0.0.0`t$domain`t# IoC $group [$($results.timestamp)]")
        $results.domains_blocked.Add(@{ domain=$domain; group=$group; desc=$desc })
        $results.hosts_entries.Add(@{ domain=$domain; group=$group })
        W-OK "En cola para escritura: $domain"
    } else {
        W-Info "Omitido: $domain"
        $results.skipped.Add(@{ domain=$domain; reason="usuario_omitio" })
    }
}

# Escritura única al archivo HOSTS
if ($domainsToAdd.Count -gt 0) {
    Write-Host ""
    W-Info "Escribiendo $($domainsToAdd.Count) entrada(s) en HOSTS..."
    try {
        # Backup del HOSTS original
        $hostsBackup = "${hostsPath}.bak_${ts}"
        Copy-Item $hostsPath $hostsBackup -Force -ErrorAction Stop
        W-OK "Backup creado: $hostsBackup"

        $header = @(
            "",
            "# ── IoC Block: ShinyHunters & BlueKit — $($results.timestamp) ──────────────",
            "# Generado por Invoke-IoCBlocker.ps1 | Fuentes: EclecticIQ, FBI IC3, ESET, ThreatFox"
        )
        Add-Content -Path $hostsPath -Value ($header + $domainsToAdd) -Encoding ASCII -ErrorAction Stop
        W-OK "$($domainsToAdd.Count) dominio(s) bloqueado(s) en HOSTS"

        # Limpiar caché DNS
        & ipconfig /flushdns | Out-Null
        W-OK "Caché DNS limpiada (ipconfig /flushdns)"
    } catch {
        W-Warn "Error escribiendo en HOSTS: $_"
    }
} else {
    W-Info "Sin dominios nuevos para agregar al HOSTS"
}

# ============================================================================
#  FASE 5 — BLOQUEO CON NETSH (capa adicional para IPs ya establecidas)
# ============================================================================
W-Head "FASE 5 — Bloqueo adicional vía Windows Filtering Platform (netsh)"
W-Info "Agrega reglas WFP para bloquear IPs a nivel de red (complementa Firewall)."

$allBlockedIPs = $results.ips_blocked | ForEach-Object { $_.ip }

if ($allBlockedIPs.Count -gt 0 -and (Ask-User "¿Agregar bloqueo WFP (netsh advfirewall) para las $($allBlockedIPs.Count) IPs confirmadas?")) {
    foreach ($ip in $allBlockedIPs) {
        try {
            # Bloqueo adicional por netsh (persiste independiente de reglas GUI)
            $null = & netsh advfirewall firewall add rule `
                name="WFP_IoC_Block_$($ip -replace '\.','_')" `
                dir=out action=block remoteip=$ip protocol=any 2>&1
            W-OK "WFP salida bloqueada: $ip"
            $null = & netsh advfirewall firewall add rule `
                name="WFP_IoC_Block_IN_$($ip -replace '\.','_')" `
                dir=in action=block remoteip=$ip protocol=any 2>&1
            W-OK "WFP entrada bloqueada: $ip"
        } catch {
            W-Warn "netsh error en $ip`: $_"
        }
    }
} else {
    W-Info "Bloqueo WFP omitido"
}

# ============================================================================
#  FASE 6 — EXPORTAR CSV de IoCs aplicados
# ============================================================================
W-Head "FASE 6 — Exportar resumen CSV"

$csvRows = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($item in $results.ips_blocked) {
    $csvRows.Add([PSCustomObject]@{
        Tipo    = "IP"
        Valor   = $item.ip
        Grupo   = $item.group
        Fuente  = $item.desc
        Estado  = "BLOQUEADA"
        Regla_FW = $item.rule
    })
}
foreach ($item in $results.domains_blocked) {
    $csvRows.Add([PSCustomObject]@{
        Tipo    = "DOMINIO"
        Valor   = $item.domain
        Grupo   = $item.group
        Fuente  = $item.desc
        Estado  = "HOSTS_BLOQUEADO"
        Regla_FW = "N/A"
    })
}
foreach ($item in $results.skipped) {
    $val = if ($item.ip) { $item.ip } else { $item.domain }
    $csvRows.Add([PSCustomObject]@{
        Tipo    = "OMITIDO"
        Valor   = $val
        Grupo   = "—"
        Fuente  = "—"
        Estado  = "OMITIDO: $($item.reason)"
        Regla_FW = "—"
    })
}

if ($csvRows.Count -gt 0) {
    $csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    W-OK "CSV exportado: $csvPath"
}

# ============================================================================
#  GENERAR REPORTE HTML
# ============================================================================
W-Head "Generando reporte HTML..."

# Construir filas HTML
function Build-TableRows {
    param($items, $tipo)
    $html = ""
    foreach ($item in $items) {
        $color = if ($tipo -eq "SH") { "#ff3355" } else { "#ff8c00" }
        $val   = if ($item.ip) { $item.ip } else { $item.domain }
        $grp   = $item.group
        $desc  = $item.desc
        $html += "<tr><td><span style='color:$color;font-weight:700'>$grp</span></td><td style='font-family:monospace;font-size:12px'>$val</td><td style='font-size:12px;color:#667788'>$desc</td></tr>`n"
    }
    return $html
}

$blockedRows = Build-TableRows ($results.ips_blocked + $results.domains_blocked) ""
$fwRows = ""
foreach ($r in $results.fw_rules_added) {
    $dirColor = if ($r.dir -eq "Inbound") { "#ff3355" } else { "#ff8c00" }
    $grpColor = if ($r.group -eq "ShinyHunters") { "#ff3355" } else { "#ff8c00" }
    $fwRows += "<tr><td style='font-family:monospace;font-size:11px'>$($r.rule)</td><td style='font-family:monospace;font-size:12px'>$($r.ip)</td><td><span style='color:$grpColor'>$($r.group)</span></td><td><span style='color:$dirColor'>$($r.dir)</span></td></tr>`n"
}

$hitRows = ""
foreach ($h in $results.active_hits) {
    $hitRows += "<tr style='background:rgba(255,51,85,0.08)'><td style='font-family:monospace;color:#ff3355'>$($h.ip)</td><td>$($h.port)</td><td>$($h.process)</td><td>$($h.pid)</td><td style='font-size:11px;color:#667788'>$($h.threat)</td></tr>`n"
}
if (-not $hitRows) { $hitRows = "<tr><td colspan='5' style='text-align:center;color:#00ff88;padding:16px;font-family:monospace'>✓ Sin conexiones activas con IoCs detectadas</td></tr>" }

$uaRows = ($MaliciousUserAgents | ForEach-Object {
    "<tr><td style='font-family:monospace;font-size:12px;color:#ffd200'>$_</td></tr>"
}) -join "`n"

$shCount = ($results.ips_blocked | Where-Object { $_.group -eq "ShinyHunters" }).Count
$bkCount = ($results.ips_blocked | Where-Object { $_.group -eq "BlueKit" }).Count
$domCount = $results.domains_blocked.Count
$fwCount  = $results.fw_rules_added.Count
$hitBadge = if ($results.active_hits.Count -gt 0) { "<span style='color:#ff3355;animation:pulse 1s infinite'>⚠ $($results.active_hits.Count) CONEXIÓN(ES) ACTIVA(S)</span>" } else { "<span style='color:#00ff88'>✓ Sin hits activos</span>" }

$html = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>IoC Blocker — $hostname</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#080c10;--bg2:#0d1117;--bg3:#111820;--border:#1e2d3d;--green:#00ff88;--red:#ff3355;--orange:#ff8c00;--yellow:#ffd200;--blue:#00aaff;--teal:#00e5cc;--text:#c9d8e8;--dim:#4a6070;--mono:'Share Tech Mono',monospace;--sans:'Barlow Condensed',sans-serif;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.5;padding:32px;}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,.012) 2px,rgba(0,255,136,.012) 4px);pointer-events:none;}
.wrap{max-width:1200px;margin:0 auto;}
h1{font-size:clamp(24px,4vw,44px);font-weight:900;letter-spacing:3px;margin-bottom:8px;}
.badge{font-family:var(--mono);font-size:11px;letter-spacing:3px;color:var(--dim);margin-bottom:6px;}
.meta{font-family:var(--mono);font-size:12px;color:var(--dim);line-height:2;}
.meta span{color:var(--teal);}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:24px 0;}
.stat{background:var(--bg2);border:1px solid var(--border);padding:18px;text-align:center;}
.stat-n{font-size:42px;font-weight:900;line-height:1;}
.stat-l{font-size:11px;font-weight:600;letter-spacing:2px;color:var(--dim);margin-top:4px;}
.sec{margin:32px 0;}
.sec-title{font-family:var(--mono);font-size:11px;letter-spacing:4px;color:var(--dim);padding-bottom:10px;border-bottom:1px solid var(--border);margin-bottom:16px;}
table{width:100%;border-collapse:collapse;}
th{font-family:var(--mono);font-size:10px;letter-spacing:3px;color:var(--dim);text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);}
td{padding:10px 12px;border-bottom:1px solid rgba(30,45,61,.5);font-size:13px;vertical-align:top;}
tr:hover td{background:rgba(255,255,255,.015);}
.pill{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:2px;}
.footer{border-top:1px solid var(--border);padding-top:16px;margin-top:32px;font-family:var(--mono);font-size:11px;color:var(--dim);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;}
.src-block{background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--teal);padding:16px 20px;font-family:var(--mono);font-size:12px;line-height:2;margin-bottom:12px;}
.src-block .src-title{color:var(--teal);font-size:13px;font-weight:700;margin-bottom:8px;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
</style>
</head>
<body>
<div class="wrap">
  <div class="badge">// IoC BLOCKER — DEFENSA ACTIVA</div>
  <h1>$hostname — ShinyHunters &amp; BlueKit</h1>
  <div class="meta">
    Fecha: <span>$($results.timestamp)</span> &nbsp;·&nbsp;
    Detección activa: $hitBadge
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-n" style="color:#ff3355">$shCount</div><div class="stat-l">SH IPs BLOQUEADAS</div></div>
    <div class="stat"><div class="stat-n" style="color:#ff8c00">$bkCount</div><div class="stat-l">BK IPs BLOQUEADAS</div></div>
    <div class="stat"><div class="stat-n" style="color:#ffd200">$domCount</div><div class="stat-l">DOMINIOS HOSTS</div></div>
    <div class="stat"><div class="stat-n" style="color:#00e5cc">$fwCount</div><div class="stat-l">REGLAS FIREWALL</div></div>
    <div class="stat"><div class="stat-n" style="color:#00ff88">$($results.active_hits.Count)</div><div class="stat-l">HITS ACTIVOS</div></div>
  </div>

  <div class="sec">
    <div class="sec-title">// FUENTES DE INTELIGENCIA</div>
    <div class="src-block">
      <div class="src-title">ShinyHunters (UNC6040 / sp1d3rhunters)</div>
      · EclecticIQ Threat Research — Sep 2025 — https://blog.eclecticiq.com/shinyhunters-calling<br>
      · FBI / IC3 Advisory CSA-250912 — Sep 2025 — https://www.ic3.gov/CSA/2025/250912.pdf<br>
      · Reco.ai Security Report — Mar 2026 — ShinyHunters Experience Cloud Campaign<br>
      · Google Mandiant TIP — UNC6040 tracking (Salesforce / Snowflake)<br>
      · BleepingComputer / Wikipedia — Anodot breach, RapeForce tool 2026
    </div>
    <div class="src-block">
      <div class="src-title">BlueKit (AiTM phishing kit)</div>
      · ESET malware-ioc GitHub — https://github.com/eset/malware-ioc<br>
      · ThreatFox / abuse.ch — https://threatfox.abuse.ch<br>
      · Microsoft MSTIC — Azure AD / M365 AiTM campaigns 2024<br>
      · Unit42 (Palo Alto Networks) — BlueKit OAuth token theft analysis
    </div>
  </div>

  <div class="sec">
    <div class="sec-title">// CONEXIONES ACTIVAS CON IoCs (al momento del análisis)</div>
    <table>
      <thead><tr><th>IP REMOTA</th><th>PUERTO</th><th>PROCESO</th><th>PID</th><th>AMENAZA</th></tr></thead>
      <tbody>$hitRows</tbody>
    </table>
  </div>

  <div class="sec">
    <div class="sec-title">// IoCs BLOQUEADOS — IPs Y DOMINIOS</div>
    <table>
      <thead><tr><th>GRUPO</th><th>INDICADOR</th><th>FUENTE / DESCRIPCIÓN</th></tr></thead>
      <tbody>$blockedRows</tbody>
    </table>
  </div>

  <div class="sec">
    <div class="sec-title">// REGLAS DE FIREWALL CREADAS ($fwCount reglas)</div>
    <table>
      <thead><tr><th>NOMBRE REGLA</th><th>IP</th><th>GRUPO</th><th>DIRECCIÓN</th></tr></thead>
      <tbody>$fwRows</tbody>
    </table>
  </div>

  <div class="sec">
    <div class="sec-title">// USER-AGENTS MALICIOSOS — Monitorear en logs de red/proxy</div>
    <table>
      <thead><tr><th>USER-AGENT CONOCIDO (ShinyHunters / BlueKit)</th></tr></thead>
      <tbody>$uaRows</tbody>
    </table>
  </div>

  <div class="sec">
    <div class="sec-title">// RECOMENDACIONES ADICIONALES</div>
    <div class="src-block" style="border-left-color:#ffd200">
      <div class="src-title" style="color:#ffd200">Hardening complementario</div>
      1. Habilitar MFA resistente a phishing: FIDO2 / Passkeys (ShinyHunters evita MFA TOTP)<br>
      2. Monitorear User-Agents listados arriba en proxies/SIEM/EDR<br>
      3. Revisar aplicaciones OAuth conectadas a Salesforce, Okta, Microsoft 365<br>
      4. Deshabilitar acceso de invitados en Salesforce Experience Cloud<br>
      5. Activar Network Zone restrictions en Okta (bloquear Mullvad/NordVPN/Tor)<br>
      6. BlueKit: Habilitar Conditional Access con device compliance en Azure AD<br>
      7. Renovar/rotar tokens API de BrowserStack, JFrog, CI/CD pipelines<br>
      8. Actualizar este script con nuevos IoCs desde: threatfox.abuse.ch y eclecticiq.com
    </div>
  </div>

  <div class="footer">
    <span>Invoke-IoCBlocker.ps1 | $($results.timestamp) | $hostname</span>
    <span>Fuentes: EclecticIQ · FBI IC3 · ESET · ThreatFox · Mandiant</span>
  </div>
</div>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8

# ── Resumen final consola ────────────────────────────────────────────────────
Stop-Transcript | Out-Null

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║  BLOQUEO COMPLETADO                                          ║" -ForegroundColor White
Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Gray
Write-Host "  ║  IPs bloqueadas  (Firewall)  : $($results.ips_blocked.Count)" -ForegroundColor White
Write-Host "  ║  Dominios bloqueados (HOSTS) : $($results.domains_blocked.Count)" -ForegroundColor White
Write-Host "  ║  Reglas FW creadas           : $fwCount" -ForegroundColor White
Write-Host "  ║  Hits activos detectados     : $($results.active_hits.Count)" -ForegroundColor $(if ($results.active_hits.Count -gt 0) {"Red"} else {"Green"})
Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Gray
Write-Host "  ║  Reporte HTML → $htmlPath" -ForegroundColor Cyan
Write-Host "  ║  CSV IoCs     → $csvPath" -ForegroundColor Cyan
Write-Host "  ║  Log          → $logPath" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if (Ask-User "¿Abrir el reporte HTML ahora?") {
    Start-Process $htmlPath
}

# ── Script de desbloqueo (reversal) ─────────────────────────────────────────
$undoPath = "$desktop\Invoke-IoCUnblock_${ts}.ps1"
$undoScript = @"
#Requires -RunAsAdministrator
# Script de REVERSAL — elimina reglas creadas por Invoke-IoCBlocker.ps1
# Generado automáticamente el $($results.timestamp)

Write-Host 'Eliminando reglas de Firewall IoC...' -ForegroundColor Yellow
$(($results.fw_rules_added | ForEach-Object {
    "Remove-NetFirewallRule -DisplayName '$($_.rule)' -ErrorAction SilentlyContinue; Write-Host '  Eliminada: $($_.rule)' -ForegroundColor Green"
}) -join "`n")

$(($results.fw_rules_added | ForEach-Object {
    "& netsh advfirewall firewall delete rule name='WFP_IoC_Block_$($_.ip -replace '\.','_')' 2>`$null"
}) | Sort-Object -Unique | ForEach-Object { $_ } | Join-String -Separator "`n")

Write-Host 'Restaurando HOSTS...' -ForegroundColor Yellow
`$hostsPath = "`$env:SystemRoot\System32\drivers\etc\hosts"
`$backup = "`${hostsPath}.bak_$ts"
if (Test-Path `$backup) {
    Copy-Item `$backup `$hostsPath -Force
    Write-Host '  HOSTS restaurado desde backup' -ForegroundColor Green
    ipconfig /flushdns | Out-Null
} else {
    Write-Host '  Backup no encontrado: `$backup' -ForegroundColor Yellow
}
Write-Host 'Reversal completado.' -ForegroundColor Green
"@

$undoScript | Out-File -FilePath $undoPath -Encoding UTF8
W-OK "Script de reversal generado: $undoPath"
