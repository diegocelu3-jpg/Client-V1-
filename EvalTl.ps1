# ================================================================
#  Invoke-MalwareEval.ps1
#  Evaluación completa de Malware — 13 módulos
#  Genera: MalwareEval_TIMESTAMP.json  (para el dashboard HTML)
#          MalwareEval_TIMESTAMP.log   (transcripción completa)
#  Requiere: PowerShell 5.1+  |  Ejecutar como Administrador
# ================================================================
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ── Helpers ─────────────────────────────────────────────────────
function W-OK   { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function W-Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function W-Crit { param($m) Write-Host "  [CRIT] $m" -ForegroundColor Red }
function W-Info { param($m) Write-Host "  [INFO] $m" -ForegroundColor Cyan }
function W-Step { param($n,$t)
    Write-Host "`n$('─'*64)" -ForegroundColor DarkCyan
    Write-Host "  [M$n/13] $t" -ForegroundColor White
    Write-Host "$('─'*64)" -ForegroundColor DarkCyan
}

$ts        = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir    = "$env:USERPROFILE\Desktop"
$jsonPath  = "$outDir\MalwareEval_$ts.json"
$logPath   = "$env:TEMP\MalwareEval_$ts.log"
Start-Transcript -Path $logPath -Append | Out-Null

$report = [ordered]@{
    meta = @{
        timestamp    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        hostname     = $env:COMPUTERNAME
        user         = $env:USERNAME
        os           = (Get-WmiObject Win32_OperatingSystem).Caption
        ps_version   = $PSVersionTable.PSVersion.ToString()
    }
    score       = 0
    risk_level  = "BAJO"
    modules     = @{}
    findings    = @()
    summary     = @{}
}

function Add-Finding {
    param($module, $severity, $title, $detail, [int]$weight)
    $report.findings += @{
        module   = $module
        severity = $severity   # CRITICAL / HIGH / MEDIUM / LOW / INFO
        title    = $title
        detail   = $detail
        weight   = $weight
    }
    $report.score += $weight
}

# Whitelist legítimas
$legitPaths = @(
    "*\Windows\System32\*","*\Windows\SysWOW64\*","*\Windows\WinSxS\*",
    "*\Program Files\*","*\Program Files (x86)\*",
    "*\AppData\Local\Microsoft\*","*\AppData\Roaming\Microsoft\*",
    "*\AppData\Local\ESET\*","*\AppData\Local\uv\*","*\AppData\Roaming\uv\*"
)
function Is-Legit { param($p) foreach ($w in $legitPaths) { if ($p -like $w) { return $true } } return $false }

# ================================================================
#  M1 — Procesos sospechosos en memoria
# ================================================================
W-Step 1 "Procesos sospechosos en memoria"
$m1 = @{ status="CLEAN"; items=@() }

$suspProcPatterns = @("powershell","cmd","wscript","cscript","mshta","regsvr32",
                      "rundll32","certutil","bitsadmin","nc","ncat","netcat",
                      "mimikatz","psexec","procdump","wmic")
$hiddenProc = @()

Get-Process | ForEach-Object {
    $p = $_
    # Procesos sin ventana, sin descripción, corriendo desde rutas inusuales
    $path = try { $p.MainModule.FileName } catch { "" }
    $isSuspPath = $path -and -not (Is-Legit $path) -and
                  ($path -like "*\Temp\*" -or $path -like "*\AppData\Roaming\*" -or
                   $path -like "*\Users\Public\*" -or $path -like "*\ProgramData\*")

    if ($isSuspPath) {
        $hiddenProc += "$($p.Name) (PID:$($p.Id)) → $path"
        Add-Finding "M1" "HIGH" "Proceso en ruta inusual" "$($p.Name) ejecutándose desde $path" 8
        W-Crit "Proceso sospechoso: $($p.Name) → $path"
        $m1.status = "ALERT"
        $m1.items += @{ pid=$p.Id; name=$p.Name; path=$path; type="suspicious_path" }
    }

    # Doble extensión o nombres que imitan sistema
    if ($p.Name -match "\.(exe|bat|cmd|vbs)$" -or
        $p.Name -match "^(svchost|lsass|csrss|winlogon|explorer)_\d+$") {
        Add-Finding "M1" "CRITICAL" "Proceso imitando nombre del sistema" $p.Name 12
        W-Crit "Proceso con nombre de camuflaje: $($p.Name)"
        $m1.status = "ALERT"
        $m1.items += @{ pid=$p.Id; name=$p.Name; path=$path; type="name_spoofing" }
    }
}

if ($m1.items.Count -eq 0) { W-OK "Sin procesos sospechosos detectados" }
$report.modules["M1_Procesos"] = $m1

# ================================================================
#  M2 — Conexiones de red activas sospechosas
# ================================================================
W-Step 2 "Conexiones de red activas"
$m2 = @{ status="CLEAN"; items=@() }

$suspPorts  = @(4444,1234,31337,6666,6667,9001,8888,2222,12345,54321,1337)
$c2Ranges   = @("185\.","194\.","45\.","91\.","176\.")  # rangos comunes C2

$netConns = Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue
foreach ($conn in $netConns) {
    $isSuspPort = $conn.RemotePort -in $suspPorts -or $conn.LocalPort -in $suspPorts
    $isSuspIP   = $false
    foreach ($r in $c2Ranges) { if ($conn.RemoteAddress -match $r) { $isSuspIP = $true; break } }

    if ($isSuspPort -or $isSuspIP) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $info = "$($proc.Name) (PID:$($conn.OwningProcess)) → $($conn.RemoteAddress):$($conn.RemotePort)"
        Add-Finding "M2" "HIGH" "Conexión red sospechosa" $info 7
        W-Crit "Conexión: $info"
        $m2.status = "ALERT"
        $m2.items += @{ pid=$conn.OwningProcess; proc=$proc.Name;
                        remote="$($conn.RemoteAddress):$($conn.RemotePort)";
                        local_port=$conn.LocalPort; reason=if($isSuspPort){"puerto_sospechoso"}else{"ip_c2"} }
    }
}

# Procesos escuchando en puertos inusuales altos
$listening = $netConns | Where-Object { $_.State -eq "Listen" -and $_.LocalPort -gt 49151 }
if ($listening.Count -gt 5) {
    Add-Finding "M2" "MEDIUM" "Muchos puertos efímeros en escucha" "$($listening.Count) puertos >49151 abiertos" 4
    W-Warn "$($listening.Count) puertos efímeros escuchando"
}

if ($m2.items.Count -eq 0) { W-OK "Sin conexiones de red sospechosas" }
$report.modules["M2_Red"] = $m2

# ================================================================
#  M3 — Persistencia: Run Keys + Scheduled Tasks + Startup
# ================================================================
W-Step 3 "Mecanismos de persistencia"
$m3 = @{ status="CLEAN"; items=@() }

$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
)

foreach ($key in $runKeys) {
    if (-not (Test-Path $key)) { continue }
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    foreach ($prop in ($props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" })) {
        $val = "$($prop.Value)"
        $isSusp = $val -match "(%TEMP%|\\Temp\\|\\AppData\\Roaming\\(?!Microsoft)|\\.vbs|\\.hta|powershell.*-e[nc]|mshta|wscript|cscript|regsvr32|rundll32|certutil)"
        if ($isSusp) {
            Add-Finding "M3" "HIGH" "Entrada Run sospechosa" "[$($prop.Name)] = $val" 8
            W-Crit "Run: [$($prop.Name)] = $val"
            $m3.status = "ALERT"
            $m3.items += @{ type="run_key"; key=$key; name=$prop.Name; value=$val }
        } else {
            W-Info "Run legítima: [$($prop.Name)]"
        }
    }
}

# Tareas programadas
# Rutas legítimas de Windows que usan .vbs/.hta y NO deben reportarse
$legitTaskPaths = @(
    "*\system32\*", "*\SysWOW64\*", "*\Windows\*",
    "*\Microsoft\Windows\*", "*\Program Files\*", "*\Program Files (x86)\*"
)
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
foreach ($task in $tasks) {
    foreach ($action in $task.Actions) {
        $exec = "$($action.Execute) $($action.Arguments)"
        # Expandir %windir%, %systemroot%, etc. para comparar rutas reales
        $execExpanded = [System.Environment]::ExpandEnvironmentVariables($exec)

        # Saltar si la ruta apunta a un directorio del sistema legítimo
        $isLegitTask = $false
        foreach ($lp in $legitTaskPaths) {
            if ($execExpanded -like $lp) { $isLegitTask = $true; break }
        }
        if ($isLegitTask) { W-Info "Tarea legítima del SO: $($task.TaskName)"; continue }

        $isSusp = $exec -match "(\\Temp\\|\\AppData\\(?!Local\\Microsoft|Roaming\\Microsoft|Local\\ESET|Roaming\\uv)|\.vbs|\.hta|powershell.*-e[nc]|mshta|certutil.*-decode)"
        if ($isSusp) {
            Add-Finding "M3" "HIGH" "Tarea programada sospechosa" "$($task.TaskName): $exec" 8
            W-Crit "Tarea: $($task.TaskName) → $exec"
            $m3.status = "ALERT"
            $m3.items += @{ type="scheduled_task"; name=$task.TaskName; exec=$exec }
        }
    }
}

# Startup folders
$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
foreach ($sd in $startupDirs) {
    if (-not (Test-Path $sd)) { continue }
    $items = Get-ChildItem $sd -Include *.lnk,*.bat,*.vbs,*.hta,*.ps1,*.cmd -Recurse
    foreach ($item in $items) {
        Add-Finding "M3" "MEDIUM" "Archivo en carpeta Startup" $item.FullName 5
        W-Warn "Startup: $($item.FullName)"
        $m3.status = "ALERT"
        $m3.items += @{ type="startup_file"; path=$item.FullName }
    }
}

if ($m3.items.Count -eq 0) { W-OK "Sin mecanismos de persistencia sospechosos" }
$report.modules["M3_Persistencia"] = $m3

# ================================================================
#  M4 — Scripts ofuscados en TEMP / AppData
# ================================================================
W-Step 4 "Scripts ofuscados en directorios temporales"
$m4 = @{ status="CLEAN"; items=@() }

$scriptDirs = @($env:TEMP, $env:APPDATA, "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads")
$scriptExts = @("*.ps1","*.vbs","*.hta","*.bat","*.js","*.wsf","*.cmd")

foreach ($dir in $scriptDirs) {
    if (-not (Test-Path $dir)) { continue }
    $scripts = Get-ChildItem -Path $dir -Recurse -Include $scriptExts -ErrorAction SilentlyContinue |
               Where-Object { $_.Length -gt 300 }
    foreach ($scr in $scripts) {
        # ── Exclusiones de rutas legítimas ──────────────────────
        if (Is-Legit $scr.FullName) { continue }

        # Herramientas de seguridad / pentest / desarrollo conocidas
        $knownLegitApps = @(
            "*\uv\*",                   # Python uv
            "*\ESET\*",                 # ESET AV
            "*\BurpSuite\*",            # Burp Suite (proxy pentest — JS minificado esperado)
            "*\PortSwigger\*",          # Burp alternativo
            "*\node_modules\*",         # paquetes npm
            "*\AppData\Local\Programs\*", # apps instaladas por usuario (VS Code, etc.)
            "*\AppData\Local\Google\*", # Chrome
            "*\AppData\Local\Microsoft\Teams\*",
            "*\AppData\Roaming\npm\*",  # npm global
            "*\AppData\Roaming\nvm\*",  # Node version manager
            "*\AppData\Local\electron\*"
        )
        $isKnownApp = $false
        foreach ($kla in $knownLegitApps) {
            if ($scr.FullName -like $kla) { $isKnownApp = $true; break }
        }
        if ($isKnownApp) {
            W-Info "Excluido (app conocida): $($scr.FullName)"
            continue
        }

        # Archivos JS/TS minificados legítimos (bootstrap, jquery, etc.)
        $isMinified = $scr.Name -match '\.(min|bundle|esm)\.(js|css)$' -or
                      $scr.Name -match '^(jquery|bootstrap|react|vue|angular|lodash|moment)'
        if ($isMinified) { continue }

        # Buscar indicadores de ofuscación
        $content = Get-Content $scr.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        $ofuscIndicators = 0
        if ($content -match "[A-Za-z0-9+/]{100,}={0,2}")  { $ofuscIndicators++ }  # Base64 largo
        if ($content -match "chr\(\d+\)")                  { $ofuscIndicators++ }  # Chr() VBS
        if ($content -match "\^[A-Za-z0-9]")               { $ofuscIndicators++ }  # XOR cmd
        if ($content -match '(\[char\]|\[convert\]|IEX|Invoke-Expression|FromBase64)') { $ofuscIndicators++ }
        if ($content -match '(-join|-replace|\$env:|-split).*\|.*(IEX|&)') { $ofuscIndicators++ }

        # Scripts en Downloads: umbral más alto (≥3) para evitar falsos positivos
        # de scripts descargados legítimos con algo de complejidad
        $isDownloads  = $scr.FullName -like "*\Downloads\*"
        $threshold    = if ($isDownloads) { 3 } else { 2 }
        $warnThreshold = if ($isDownloads) { 99 } else { 1 }  # no WARN en Downloads

        if ($ofuscIndicators -ge $threshold) {
            Add-Finding "M4" "HIGH" "Script altamente ofuscado" "$($scr.FullName) ($ofuscIndicators indicadores)" 9
            W-Crit "Script ofuscado ($ofuscIndicators indicadores): $($scr.FullName)"
            $m4.status = "ALERT"
            $m4.items += @{ path=$scr.FullName; size=$scr.Length; indicators=$ofuscIndicators }
        } elseif ($ofuscIndicators -ge $warnThreshold) {
            Add-Finding "M4" "MEDIUM" "Script posiblemente ofuscado" $scr.FullName 4
            W-Warn "Script sospechoso ($ofuscIndicators indicador/es): $($scr.FullName)"
            $m4.items += @{ path=$scr.FullName; size=$scr.Length; indicators=$ofuscIndicators }
        }
    }
}

if ($m4.items.Count -eq 0) { W-OK "Sin scripts ofuscados detectados" }
$report.modules["M4_Scripts"] = $m4

# ================================================================
#  M5 — Inyección DLL (procesos accesibles + WMI)
# ================================================================
W-Step 5 "Inyección de DLL en procesos"
$m5 = @{ status="CLEAN"; items=@() }

$critProcs = @("explorer","winlogon","lsass","svchost","services","csrss","smss","wininit")

foreach ($name in $critProcs) {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    foreach ($proc in $procs) {
        try {
            $mods = $proc.Modules
            foreach ($mod in $mods) {
                if (-not $mod.FileName) { continue }
                if (Is-Legit $mod.FileName) { continue }
                # Excluir DLLs de apps conocidas en AppData (BurpSuite, VS Code, etc.)
                $knownAppDLLs = @("*\BurpSuite\*","*\PortSwigger\*","*\electron\*",
                                  "*\Local\Programs\*","*\Roaming\npm\*")
                $isKnownDLL = $false
                foreach ($k in $knownAppDLLs) { if ($mod.FileName -like $k) { $isKnownDLL = $true; break } }
                if ($isKnownDLL) { continue }

                $isSusp = $mod.FileName -like "*\Temp\*" -or
                          ($mod.FileName -like "*\AppData\*" -and -not (Is-Legit $mod.FileName))
                if ($isSusp) {
                    Add-Finding "M5" "CRITICAL" "Posible inyección DLL" "$name (PID:$($proc.Id)) → $($mod.FileName)" 15
                    W-Crit "DLL inyectada en $name: $($mod.FileName)"
                    $m5.status = "ALERT"
                    $m5.items += @{ proc=$name; pid=$proc.Id; dll=$mod.FileName }
                }
            }
            W-OK "$name (PID $($proc.Id)) — módulos inspeccionados"
        } catch {
            # Win32Exception normal para procesos SYSTEM (lsass, csrss, smss…)
            # Cubiertos por M1/M2 via tasklist y WMI
            W-Info "$name (PID $($proc.Id)) — acceso denegado por Windows (proceso protegido SYSTEM)"
        }
    }
}

if ($m5.items.Count -eq 0) { W-OK "Sin inyecciones DLL detectadas (procesos accesibles)" }
$report.modules["M5_DLL"] = $m5

# ================================================================
#  M6 — Notas de ransomware + extensiones cifradas
# ================================================================
W-Step 6 "Indicadores de ransomware"
$m6 = @{ status="CLEAN"; items=@() }

$ransomKeywords = "DECRYPT|README_FOR_DECRYPT|RECOVER|RESTORE|LOCKED|HOW_TO|YOUR_FILES|ENCRYPTED|ATTENTION"
$ransomPaths    = @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents",
                    "$env:USERPROFILE\Downloads","C:\Users\Public")

foreach ($rp in $ransomPaths) {
    if (-not (Test-Path $rp)) { continue }
    $notes = Get-ChildItem -Path $rp -Recurse -Include *.txt,*.html,*.hta -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match $ransomKeywords }
    foreach ($n in $notes) {
        Add-Finding "M6" "CRITICAL" "Nota de ransomware detectada" $n.FullName 20
        W-Crit "NOTA RANSOMWARE: $($n.FullName)"
        $m6.status = "ALERT"
        $m6.items += @{ type="ransom_note"; path=$n.FullName }
    }
}

# Extensiones de archivos cifrados conocidas
$ransomExts = @("*.locked","*.encrypted","*.crypt","*.enc","*.crypted","*.crypto",
                "*.zepto","*.cerber","*.locky","*.wncry","*.wannacry","*.petya",
                "*.zzzzz","*.thor","*.aesir","*.odin","*.wallet","*.dharma")
foreach ($rp in @("$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop")) {
    if (-not (Test-Path $rp)) { continue }
    $encFiles = Get-ChildItem -Path $rp -Recurse -Include $ransomExts -ErrorAction SilentlyContinue
    if ($encFiles.Count -gt 0) {
        Add-Finding "M6" "CRITICAL" "Archivos con extensión de cifrado ransomware" "$($encFiles.Count) archivos" 25
        W-Crit "$($encFiles.Count) archivos con extensión ransomware en $rp"
        $m6.status = "ALERT"
        $m6.items += @{ type="encrypted_files"; count=$encFiles.Count; path=$rp }
    }
}

if ($m6.items.Count -eq 0) { W-OK "Sin indicadores de ransomware" }
$report.modules["M6_Ransomware"] = $m6

# ================================================================
#  M7 — Servicios de Windows sospechosos
# ================================================================
W-Step 7 "Servicios de Windows sospechosos"
$m7 = @{ status="CLEAN"; items=@() }

$services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
foreach ($svc in $services) {
    $path = $svc.PathName
    if (-not $path) { continue }
    $isSusp = $path -match "(\\Temp\\|\\AppData\\Roaming\\(?!Microsoft)|\.exe.*\.exe|cmd\.exe|powershell|mshta|wscript|cscript)" -and
              -not (Is-Legit $path)
    if ($isSusp) {
        Add-Finding "M7" "HIGH" "Servicio Windows sospechoso" "$($svc.Name): $path" 9
        W-Crit "Servicio sospechoso: $($svc.Name) → $path"
        $m7.status = "ALERT"
        $m7.items += @{ name=$svc.Name; path=$path; state=$svc.State; start=$svc.StartMode }
    }
}

if ($m7.items.Count -eq 0) { W-OK "Sin servicios sospechosos detectados" }
$report.modules["M7_Servicios"] = $m7

# ================================================================
#  M8 — Drivers cargados sin firma
# ================================================================
W-Step 8 "Drivers del kernel sin firma digital"
$m8 = @{ status="CLEAN"; items=@() }

$drivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
foreach ($drv in $drivers) {
    if (-not $drv.PathName) { continue }
    $drvPath = $drv.PathName -replace '\\\\','\'
    if ($drvPath -notlike "*\Windows\*" -and $drvPath -notlike "*\Program Files\*") {
        $sig = Get-AuthenticodeSignature $drvPath -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne "Valid") {
            Add-Finding "M8" "CRITICAL" "Driver sin firma válida" "$($drv.Name): $drvPath [$($sig.Status)]" 12
            W-Crit "Driver sin firma: $($drv.Name) → $drvPath [$($sig.Status)]"
            $m8.status = "ALERT"
            $m8.items += @{ name=$drv.Name; path=$drvPath; sig_status=$sig.Status }
        }
    }
}

if ($m8.items.Count -eq 0) { W-OK "Sin drivers sospechosos detectados" }
$report.modules["M8_Drivers"] = $m8

# ================================================================
#  M9 — Modificaciones de hosts + DNS
# ================================================================
W-Step 9 "Archivo HOSTS y configuración DNS"
$m9 = @{ status="CLEAN"; items=@() }

$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
$suspHosts = $hostsContent | Where-Object {
    $_ -notmatch "^#" -and $_ -match "\S" -and
    $_ -notmatch "^127\.0\.0\.1\s+localhost$" -and
    $_ -notmatch "^::1\s+localhost$" -and
    $_ -notmatch "^0\.0\.0\.0\s+0\.0\.0\.0$"
}

foreach ($entry in $suspHosts) {
    Add-Finding "M9" "HIGH" "Entrada sospechosa en HOSTS" $entry.Trim() 8
    W-Crit "HOSTS: $($entry.Trim())"
    $m9.status = "ALERT"
    $m9.items += @{ type="hosts_entry"; entry=$entry.Trim() }
}

# DNS configurado manualmente (fuera de DHCP puede indicar DNS poisoning)
$adapters = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses }
foreach ($adapter in $adapters) {
    foreach ($dns in $adapter.ServerAddresses) {
        $isKnown = $dns -match "^(8\.8\.|1\.1\.|9\.9\.|208\.67\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
        if (-not $isKnown) {
            Add-Finding "M9" "MEDIUM" "Servidor DNS desconocido" "$($adapter.InterfaceAlias): $dns" 5
            W-Warn "DNS inusual en $($adapter.InterfaceAlias): $dns"
            $m9.items += @{ type="unknown_dns"; interface=$adapter.InterfaceAlias; dns=$dns }
        }
    }
}

if ($m9.items.Count -eq 0) { W-OK "Archivo HOSTS y DNS sin modificaciones sospechosas" }
$report.modules["M9_DNS_Hosts"] = $m9

# ================================================================
#  M10 — Cuentas de usuario y grupos privilegiados
# ================================================================
W-Step 10 "Cuentas de usuario y privilegios"
$m10 = @{ status="CLEAN"; items=@() }

# Cuentas locales habilitadas
$localUsers = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
foreach ($user in $localUsers) {
    $isAdmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*$($user.Name)" }).Count -gt 0
    $isSusp = $user.Name -match "^(admin|administrator|support|helper|backdoor|guest\d|user\d{3,}|svc_|service_)" -and
              $isAdmin
    if ($isSusp) {
        Add-Finding "M10" "HIGH" "Cuenta admin con nombre sospechoso" "$($user.Name) — admin habilitada" 8
        W-Crit "Cuenta admin sospechosa: $($user.Name)"
        $m10.status = "ALERT"
        $m10.items += @{ name=$user.Name; is_admin=$isAdmin; last_logon="$($user.LastLogon)" }
    } else {
        W-Info "Usuario: $($user.Name) $(if($isAdmin){'[ADMIN]'})"
    }
}

# RDP habilitado
$rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
if ($rdp.fDenyTSConnections -eq 0) {
    Add-Finding "M10" "MEDIUM" "RDP habilitado" "Remote Desktop está activo" 4
    W-Warn "RDP está habilitado"
    $m10.items += @{ type="rdp_enabled" }
}

if ($m10.items.Count -eq 0) { W-OK "Sin cuentas o configuraciones de acceso sospechosas" }
$report.modules["M10_Cuentas"] = $m10

# ================================================================
#  M11 — Claves de registro críticas (hijacking / COM)
# ================================================================
W-Step 11 "Registro: Image File Execution / AppInit / COM hijacking"
$m11 = @{ status="CLEAN"; items=@() }

# Image File Execution Options (IFEO) — usado por malware para interceptar ejecutables
$ifeoKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoKey) {
    $ifeoEntries = Get-ChildItem $ifeoKey -ErrorAction SilentlyContinue
    foreach ($entry in $ifeoEntries) {
        $debugger = (Get-ItemProperty $entry.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            $isLegit = $debugger -match "(vsjitdebugger|drwtsn32|ntsd|cdb)" 
            if (-not $isLegit) {
                Add-Finding "M11" "CRITICAL" "IFEO Debugger sospechoso" "$($entry.PSChildName) → $debugger" 14
                W-Crit "IFEO: $($entry.PSChildName) → $debugger"
                $m11.status = "ALERT"
                $m11.items += @{ type="IFEO"; target=$entry.PSChildName; debugger=$debugger }
            }
        }
    }
}

# AppInit_DLLs
$appInitKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
$appInit = (Get-ItemProperty $appInitKey -ErrorAction SilentlyContinue).AppInit_DLLs
if ($appInit -and $appInit -ne "") {
    Add-Finding "M11" "HIGH" "AppInit_DLLs configurada" $appInit 10
    W-Crit "AppInit_DLLs: $appInit"
    $m11.status = "ALERT"
    $m11.items += @{ type="AppInit_DLLs"; value=$appInit }
}

# Winlogon Userinit/Shell (indicador de backdoor clásico)
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($winlogon.Userinit -and $winlogon.Userinit -notmatch "^C:\\Windows\\system32\\userinit\.exe,?$") {
    Add-Finding "M11" "CRITICAL" "Winlogon Userinit modificado" $winlogon.Userinit 15
    W-Crit "Winlogon Userinit: $($winlogon.Userinit)"
    $m11.status = "ALERT"
    $m11.items += @{ type="Winlogon_Userinit"; value=$winlogon.Userinit }
}
if ($winlogon.Shell -and $winlogon.Shell -notmatch "^explorer\.exe$") {
    Add-Finding "M11" "CRITICAL" "Winlogon Shell modificado" $winlogon.Shell 15
    W-Crit "Winlogon Shell: $($winlogon.Shell)"
    $m11.status = "ALERT"
    $m11.items += @{ type="Winlogon_Shell"; value=$winlogon.Shell }
}

if ($m11.items.Count -eq 0) { W-OK "Sin modificaciones de registro críticas detectadas" }
$report.modules["M11_Registro"] = $m11

# ================================================================
#  M12 — Firewall y herramientas de seguridad
# ================================================================
W-Step 12 "Estado del Firewall y Defender"
$m12 = @{ status="CLEAN"; items=@() }

# Windows Firewall
$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($profile in $fwProfiles) {
    if (-not $profile.Enabled) {
        Add-Finding "M12" "HIGH" "Firewall deshabilitado" "Perfil $($profile.Name) está DESACTIVADO" 8
        W-Crit "Firewall DESHABILITADO: $($profile.Name)"
        $m12.status = "ALERT"
        $m12.items += @{ type="firewall_disabled"; profile=$profile.Name }
    } else {
        W-OK "Firewall activo: $($profile.Name)"
    }
}

# Windows Defender
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    if (-not $defender.AntivirusEnabled) {
        Add-Finding "M12" "CRITICAL" "Windows Defender deshabilitado" "Antivirus DESACTIVADO" 15
        W-Crit "DEFENDER DESHABILITADO"
        $m12.status = "ALERT"
        $m12.items += @{ type="defender_disabled" }
    } else { W-OK "Windows Defender activo" }

    if (-not $defender.RealTimeProtectionEnabled) {
        Add-Finding "M12" "HIGH" "Protección en tiempo real deshabilitada" "" 10
        W-Crit "Protección en tiempo real OFF"
        $m12.status = "ALERT"
        $m12.items += @{ type="realtime_protection_off" }
    }

    $sigAge = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
    $report.modules["M12_Seguridad"] = $m12
    $m12.defender = @{
        av_enabled     = $defender.AntivirusEnabled
        realtime       = $defender.RealTimeProtectionEnabled
        sig_date       = "$($defender.AntivirusSignatureLastUpdated)"
        sig_age_days   = $sigAge
        last_scan      = "$($defender.QuickScanStartTime)"
    }
    if ($sigAge -gt 7) {
        Add-Finding "M12" "MEDIUM" "Firmas de Defender desactualizadas" "Última actualización hace $sigAge días" 4
        W-Warn "Firmas de Defender: $sigAge días sin actualizar"
    }
}

$report.modules["M12_Seguridad"] = $m12

# ================================================================
#  M13 — Artefactos recientes sospechosos (Prefetch + Recent)
# ================================================================
W-Step 13 "Artefactos de ejecución reciente sospechosos"
$m13 = @{ status="CLEAN"; items=@() }

$suspExecPatterns = @("MIMIKATZ","PSEXEC","NETCAT","PROCDUMP","PWDUMP",
                      "LAZAGNE","COBALT","METERPRETER","EMPIRE","METASPLOIT",
                      "KEYLOG","ROOTKIT","BYPAS","INJECT")

# Prefetch
$prefetchDir = "C:\Windows\Prefetch"
if (Test-Path $prefetchDir) {
    $pfFiles = Get-ChildItem $prefetchDir -Include *.pf -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 100
    foreach ($pf in $pfFiles) {
        foreach ($pat in $suspExecPatterns) {
            if ($pf.Name -match $pat) {
                Add-Finding "M13" "HIGH" "Herramienta de ataque en Prefetch" $pf.Name 10
                W-Crit "Prefetch sospechoso: $($pf.Name)"
                $m13.status = "ALERT"
                $m13.items += @{ type="prefetch"; file=$pf.Name; last_run="$($pf.LastWriteTime)" }
                break
            }
        }
    }
}

# Recent items (LNK en %AppData%\Microsoft\Windows\Recent)
$recentDir = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentDir) {
    $recentFiles = Get-ChildItem $recentDir -Include *.lnk -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
    foreach ($lnk in $recentFiles) {
        foreach ($pat in $suspExecPatterns) {
            if ($lnk.Name -match $pat) {
                Add-Finding "M13" "MEDIUM" "Archivo reciente sospechoso" $lnk.Name 6
                W-Warn "Recent: $($lnk.Name)"
                $m13.items += @{ type="recent_lnk"; file=$lnk.Name; date="$($lnk.LastWriteTime)" }
                break
            }
        }
    }
}

if ($m13.items.Count -eq 0) { W-OK "Sin artefactos de ejecución sospechosos" }
$report.modules["M13_Artefactos"] = $m13

# ================================================================
#  PUNTUACIÓN FINAL
# ================================================================
$score = $report.score

$report.risk_level = switch ($true) {
    ($score -ge 40) { "CRÍTICO" }
    ($score -ge 20) { "ALTO" }
    ($score -ge 8)  { "MEDIO" }
    ($score -ge 1)  { "BAJO" }
    default         { "LIMPIO" }
}

$cleanModules = ($report.modules.Values | Where-Object { $_.status -eq "CLEAN" }).Count
$alertModules = ($report.modules.Values | Where-Object { $_.status -eq "ALERT" }).Count

$report.summary = @{
    total_modules  = 13
    clean          = $cleanModules
    with_alerts    = $alertModules
    total_findings = $report.findings.Count
    critical       = ($report.findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
    high           = ($report.findings | Where-Object { $_.severity -eq "HIGH" }).Count
    medium         = ($report.findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
    low            = ($report.findings | Where-Object { $_.severity -eq "LOW" }).Count
}

# ── Exportar JSON ────────────────────────────────────────────────
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Stop-Transcript | Out-Null

Write-Host "`n$('='*64)" -ForegroundColor $(
    if ($score -ge 40) {"Red"} elseif ($score -ge 20) {"Yellow"} else {"Green"}
)
Write-Host "  EVALUACIÓN COMPLETA — Nivel de riesgo: $($report.risk_level)" -ForegroundColor White
Write-Host "  Score: $score  |  Módulos alertados: $alertModules/13" -ForegroundColor White
Write-Host "  JSON exportado: $jsonPath" -ForegroundColor Cyan
Write-Host "  Abre MalwareEval_Dashboard.html y carga ese JSON" -ForegroundColor Cyan
Write-Host "$('='*64)`n" -ForegroundColor $(
    if ($score -ge 40) {"Red"} elseif ($score -ge 20) {"Yellow"} else {"Green"}
)
