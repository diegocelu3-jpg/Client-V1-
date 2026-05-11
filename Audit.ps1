# ==============================================================================
#  Invoke-SecurityAudit.ps1
#  Auditoría Completa de Seguridad — PC Personal
#  ------------------------------------------------------------------------------
#  POLÍTICA: CERO cambios automáticos.
#            Cada acción correctiva requiere confirmación explícita del usuario.
#  MÓDULOS  : 15 vectores de análisis
#  REPORTE  : SecurityAudit_<hostname>_<timestamp>.html  (Escritorio)
#             SecurityAudit_<hostname>_<timestamp>.log   (%TEMP%)
#  Requiere : PowerShell 5.1+  |  Ejecutar como Administrador
# ==============================================================================

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ── Paleta de colores consola ────────────────────────────────────────────────
function W-OK    { param($m) Write-Host "    [✓] $m" -ForegroundColor Green }
function W-Warn  { param($m) Write-Host "    [!] $m" -ForegroundColor Yellow }
function W-Crit  { param($m) Write-Host "    [✗] $m" -ForegroundColor Red }
function W-Info  { param($m) Write-Host "    [·] $m" -ForegroundColor Cyan }
function W-Ask   { param($m) Write-Host "`n    [?] $m" -ForegroundColor Magenta }
function W-Step  {
    param([int]$n, [string]$t)
    Write-Host "`n" -NoNewline
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  [$n/15]  $t" -ForegroundColor White
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
}
function W-Head  {
    param($t)
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       AUDITORÍA COMPLETA DE SEGURIDAD — PC PERSONAL         ║" -ForegroundColor Cyan
    Write-Host "  ║       $t" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ── Preguntar al usuario (S/N) ───────────────────────────────────────────────
function Ask-User {
    param([string]$question)
    W-Ask $question
    $r = Read-Host "         Respuesta (S/N)"
    return ($r -match '^[SsYy]$')
}

# ── Confirmación antes de CUALQUIER cambio ───────────────────────────────────
function Confirm-Action {
    param([string]$description, [scriptblock]$action)
    if (Ask-User "¿Aplicar corrección? → $description") {
        try {
            & $action
            W-OK "Aplicado: $description"
            return $true
        } catch {
            W-Warn "No se pudo aplicar: $_"
            return $false
        }
    } else {
        W-Info "Omitido por el usuario: $description"
        return $false
    }
}

# ── Estructura del reporte ───────────────────────────────────────────────────
$ts        = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname  = $env:COMPUTERNAME
$username  = $env:USERNAME
$reportDir = [System.Environment]::GetFolderPath("Desktop")
$htmlPath  = "$reportDir\SecurityAudit_${hostname}_${ts}.html"
$logPath   = "$env:TEMP\SecurityAudit_${hostname}_${ts}.log"

Start-Transcript -Path $logPath -Append | Out-Null

$audit = [ordered]@{
    meta      = @{
        hostname   = $hostname
        user       = $username
        date       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        os         = (Get-WmiObject Win32_OperatingSystem).Caption
        os_build   = (Get-WmiObject Win32_OperatingSystem).BuildNumber
        ps_ver     = $PSVersionTable.PSVersion.ToString()
        uptime_h   = [math]::Round(((Get-Date) - (Get-Date).AddMilliseconds(-(Get-WmiObject Win32_OperatingSystem).LastBootUpTime -replace '[^0-9]','')).TotalHours, 1)
    }
    score     = 0
    max_score = 0
    modules   = [ordered]@{}
    findings  = [System.Collections.Generic.List[hashtable]]::new()
    actions   = [System.Collections.Generic.List[hashtable]]::new()
}

# Whitelist rutas legítimas
$legitPaths = @(
    "*\Windows\System32\*","*\Windows\SysWOW64\*","*\Windows\WinSxS\*",
    "*\Program Files\*","*\Program Files (x86)\*",
    "*\AppData\Local\Microsoft\*","*\AppData\Roaming\Microsoft\*",
    "*\AppData\Local\ESET\*","*\AppData\Local\uv\*","*\AppData\Roaming\uv\*",
    "*\BurpSuite\*","*\PortSwigger\*","*\AppData\Local\Programs\*"
)
function Is-Legit { param($p) foreach ($w in $legitPaths) { if ($p -like $w) { return $true } } return $false }

function Add-Finding {
    param(
        [string]$module,
        [string]$severity,    # CRITICAL / HIGH / MEDIUM / LOW / PASS
        [string]$title,
        [string]$detail,
        [int]$impact,         # puntos de riesgo
        [string]$recommendation = "",
        [scriptblock]$fix = $null
    )
    $audit.findings.Add(@{
        module=$module; severity=$severity; title=$title
        detail=$detail; impact=$impact; recommendation=$recommendation
        fix=$fix; fixed=$false
    })
    if ($severity -ne "PASS") { $audit.score += $impact }
    $audit.max_score += $impact
}

function Set-ModuleResult {
    param([string]$key, [string]$status, [array]$items = @())
    $audit.modules[$key] = @{ status=$status; items=$items; count=$items.Count }
}

# ══════════════════════════════════════════════════════════════════════════════
W-Head "Iniciando análisis — $(Get-Date -Format 'HH:mm:ss')"
W-Info "Host: $hostname  |  Usuario: $username"
W-Info "Reporte HTML → $htmlPath"
W-Info ""
W-Info "POLÍTICA: Este script NO realiza cambios sin tu confirmación."
W-Info "Al finalizar el análisis se te preguntará qué correcciones aplicar."
Write-Host ""
Read-Host "  Presiona ENTER para comenzar"

# ══════════════════════════════════════════════════════════════════════════════
#  M01 — FIREWALL (análisis completo)
# ══════════════════════════════════════════════════════════════════════════════
W-Step 1 "Auditoría de Firewall de Windows"
$m01 = @()

$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($p in $profiles) {
    if (-not $p.Enabled) {
        W-Crit "Firewall DESHABILITADO: perfil $($p.Name)"
        Add-Finding "M01_Firewall" "CRITICAL" "Firewall deshabilitado — perfil $($p.Name)" `
            "El perfil $($p.Name) está completamente desactivado." 20 `
            "Habilitar: Set-NetFirewallProfile -Profile $($p.Name) -Enabled True" `
            { Set-NetFirewallProfile -Profile $p.Name -Enabled True }
        $m01 += @{ profile=$p.Name; enabled=$false }
    } else {
        W-OK "Firewall activo: $($p.Name) | Entrante: $($p.DefaultInboundAction) | Saliente: $($p.DefaultOutboundAction)"
        if ($p.DefaultInboundAction -ne "Block") {
            Add-Finding "M01_Firewall" "HIGH" "Firewall perfil $($p.Name): entrante no bloqueado por defecto" `
                "DefaultInboundAction = $($p.DefaultInboundAction)" 10 `
                "Set-NetFirewallProfile -Profile $($p.Name) -DefaultInboundAction Block"
        } else {
            Add-Finding "M01_Firewall" "PASS" "Firewall $($p.Name) configurado correctamente" "" 0
        }
        $m01 += @{ profile=$p.Name; enabled=$true; inbound=$p.DefaultInboundAction; outbound=$p.DefaultOutboundAction }
    }
}

# Reglas de firewall permisivas (Allow Any-Any)
$permissiveRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.Profile -match "Public" -or $_.DisplayName -match "(\*|Any|All)" } |
    Select-Object -First 20
if ($permissiveRules.Count -gt 0) {
    W-Warn "$($permissiveRules.Count) reglas entrantes permisivas activas en perfil Public"
    Add-Finding "M01_Firewall" "MEDIUM" "$($permissiveRules.Count) reglas entrantes permisivas (Public)" `
        ($permissiveRules | ForEach-Object { $_.DisplayName } | Select-Object -First 5 | Out-String).Trim() 6 `
        "Revisar y deshabilitar reglas innecesarias en perfil Public"
}

# Puertos abiertos hacia Internet (escuchando en 0.0.0.0)
$openPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq "0.0.0.0" -and $_.LocalPort -lt 49152 } |
    Sort-Object LocalPort -Unique
$suspPorts = $openPorts | Where-Object { $_.LocalPort -notin @(80,443,135,139,445,3306,5432,8080,8443) }
foreach ($sp in $suspPorts) {
    $owner = (Get-Process -Id $sp.OwningProcess -ErrorAction SilentlyContinue).Name
    W-Warn "Puerto $($sp.LocalPort) escuchando en 0.0.0.0 → proceso: $owner (PID $($sp.OwningProcess))"
    Add-Finding "M01_Firewall" "MEDIUM" "Puerto $($sp.LocalPort) expuesto en todas las interfaces" `
        "Proceso: $owner (PID $($sp.OwningProcess))" 5 `
        "Verificar si este puerto debe estar expuesto. Considera agregar regla de firewall restrictiva."
}
Set-ModuleResult "M01_Firewall" $(if ($m01 | Where-Object {-not $_.enabled}) {"ALERT"} else {"OK"}) $m01

# ══════════════════════════════════════════════════════════════════════════════
#  M02 — WINDOWS DEFENDER & ANTIVIRUS
# ══════════════════════════════════════════════════════════════════════════════
W-Step 2 "Estado de Windows Defender y Antivirus"
$m02 = @()
$def = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($def) {
    $sigAge = ((Get-Date) - $def.AntivirusSignatureLastUpdated).Days

    if (-not $def.AntivirusEnabled) {
        W-Crit "Windows Defender DESHABILITADO"
        Add-Finding "M02_Defender" "CRITICAL" "Antivirus deshabilitado" "Windows Defender está inactivo" 20 `
            "Habilitar Defender: Set-MpPreference -DisableRealtimeMonitoring `$false" `
            { Set-MpPreference -DisableRealtimeMonitoring $false }
    } else { W-OK "Windows Defender activo" }

    if (-not $def.RealTimeProtectionEnabled) {
        W-Crit "Protección en tiempo real DESHABILITADA"
        Add-Finding "M02_Defender" "HIGH" "Protección en tiempo real OFF" "" 15 `
            "Set-MpPreference -DisableRealtimeMonitoring `$false" `
            { Set-MpPreference -DisableRealtimeMonitoring $false }
    } else { W-OK "Protección en tiempo real: ACTIVA" }

    if (-not $def.BehaviorMonitorEnabled) {
        W-Warn "Monitor de comportamiento deshabilitado"
        Add-Finding "M02_Defender" "MEDIUM" "Behavioral monitoring OFF" "" 8 `
            "Set-MpPreference -DisableBehaviorMonitoring `$false"
    } else { W-OK "Monitor de comportamiento: ACTIVO" }

    if ($sigAge -gt 3) {
        W-Warn "Firmas desactualizadas: $sigAge días"
        Add-Finding "M02_Defender" "MEDIUM" "Firmas de Defender: $sigAge días sin actualizar" `
            "Última actualización: $($def.AntivirusSignatureLastUpdated)" 7 `
            "Ejecutar: Update-MpSignature" { Update-MpSignature }
    } else { W-OK "Firmas al día (actualizadas hace $sigAge día/s)" }

    if (-not $def.IoavProtectionEnabled) {
        Add-Finding "M02_Defender" "LOW" "Protección IOAV (archivos descargados) OFF" "" 4 `
            "Set-MpPreference -DisableIOAVProtection `$false"
    }

    $m02 += @{
        av_enabled=$def.AntivirusEnabled; realtime=$def.RealTimeProtectionEnabled
        behavioral=$def.BehaviorMonitorEnabled; sig_age=$sigAge
        last_scan="$($def.QuickScanStartTime)"; sig_version=$def.AntivirusSignatureVersion
    }
} else {
    W-Warn "No se pudo acceder a Windows Defender"
    Add-Finding "M02_Defender" "HIGH" "Defender no responde" "Get-MpComputerStatus sin resultado" 12 `
        "Verificar el servicio WinDefend: Get-Service WinDefend"
}
Set-ModuleResult "M02_Defender" $(if ($def -and $def.AntivirusEnabled -and $def.RealTimeProtectionEnabled) {"OK"} else {"ALERT"}) $m02

# ══════════════════════════════════════════════════════════════════════════════
#  M03 — ACTUALIZACIONES DE WINDOWS
# ══════════════════════════════════════════════════════════════════════════════
W-Step 3 "Estado de actualizaciones de Windows"
$m03 = @()
$wu = Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
      Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($wu) {
    try {
        $lastPatch = [datetime]::Parse($wu.InstalledOn)
        $patchAge  = ((Get-Date) - $lastPatch).Days
        W-Info "Último parche instalado: $($wu.HotFixID) — hace $patchAge días"
        if ($patchAge -gt 30) {
            Add-Finding "M03_Updates" "HIGH" "Windows sin actualizar: $patchAge días" `
                "Último parche: $($wu.HotFixID) ($($wu.InstalledOn))" 12 `
                "Ejecutar Windows Update manualmente o vía: wuauclt /detectnow"
            W-Crit "Último parche hace $patchAge días"
        } elseif ($patchAge -gt 14) {
            Add-Finding "M03_Updates" "MEDIUM" "Actualizaciones con $patchAge días de retraso" `
                "Último parche: $($wu.HotFixID)" 6 "Revisar Windows Update"
            W-Warn "Parche hace $patchAge días"
        } else {
            Add-Finding "M03_Updates" "PASS" "Windows actualizado (hace $patchAge días)" "" 0
            W-OK "Sistema al día"
        }
        $m03 += @{ last_patch=$wu.HotFixID; age_days=$patchAge; installed=$wu.InstalledOn }
    } catch { W-Warn "No se pudo parsear fecha del parche" }
}

# Verificar si Windows Update está deshabilitado
$wuReg = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
if ($wuReg.NoAutoUpdate -eq 1) {
    W-Crit "Actualizaciones automáticas deshabilitadas por política"
    Add-Finding "M03_Updates" "HIGH" "Windows Update deshabilitado (GPO/Registro)" `
        "HKLM:\...\WindowsUpdate\AU → NoAutoUpdate = 1" 10 `
        "Eliminar clave o cambiar a 0: Set-ItemProperty -Path 'HKLM:\...\AU' -Name NoAutoUpdate -Value 0"
}
Set-ModuleResult "M03_Updates" "OK" $m03

# ══════════════════════════════════════════════════════════════════════════════
#  M04 — PERSISTENCIA (Run Keys / Tareas / Startup)
# ══════════════════════════════════════════════════════════════════════════════
W-Step 4 "Mecanismos de persistencia"
$m04 = @()

$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $runKeys) {
    if (-not (Test-Path $key)) { continue }
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    foreach ($prop in ($props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" })) {
        $val = "$($prop.Value)"
        $isSusp = $val -match '(%TEMP%|\\Temp\\|\\AppData\\Roaming\\(?!Microsoft)|\.vbs|\.hta|powershell.*-e[nc]|mshta|wscript|certutil|regsvr32|rundll32.*AppData)'
        if ($isSusp) {
            W-Crit "Run sospechosa: [$($prop.Name)] = $val"
            Add-Finding "M04_Persistencia" "HIGH" "Entrada Run sospechosa: $($prop.Name)" `
                "Clave: $key`nValor: $val" 9 `
                "Eliminar: Remove-ItemProperty -Path '$key' -Name '$($prop.Name)'" `
                { Remove-ItemProperty -Path $key -Name $prop.Name -Force }
            $m04 += @{ type="run_key"; key=$key; name=$prop.Name; value=$val; suspicious=$true }
        } else {
            W-Info "Run legítima: [$($prop.Name)]"
            $m04 += @{ type="run_key"; name=$prop.Name; suspicious=$false }
        }
    }
}

# Tareas programadas sospechosas
$legitTaskPaths = @("*\system32\*","*\SysWOW64\*","*\Windows\*","*\Program Files\*","*\Program Files (x86)\*")
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $task = $_
    foreach ($action in $task.Actions) {
        $exec = "$($action.Execute) $($action.Arguments)"
        $execExp = [System.Environment]::ExpandEnvironmentVariables($exec)
        $isLegit = $false
        foreach ($lp in $legitTaskPaths) { if ($execExp -like $lp) { $isLegit = $true; break } }
        if (-not $isLegit) {
            $isSusp = $exec -match '(\\Temp\\|\\AppData\\(?!Local\\Microsoft|Roaming\\Microsoft|Local\\ESET)|\.hta|powershell.*-e[nc]|mshta|certutil.*-decode)'
            if ($isSusp) {
                W-Crit "Tarea sospechosa: $($task.TaskName) → $exec"
                Add-Finding "M04_Persistencia" "HIGH" "Tarea programada sospechosa: $($task.TaskName)" `
                    "Ejecuta: $exec" 9 `
                    "Deshabilitar: Disable-ScheduledTask -TaskName '$($task.TaskName)'"
                $m04 += @{ type="task"; name=$task.TaskName; exec=$exec; suspicious=$true }
            }
        }
    }
}

# Startup folders
@("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Include *.lnk,*.bat,*.vbs,*.hta,*.ps1,*.cmd -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            W-Warn "Startup: $($_.FullName)"
            Add-Finding "M04_Persistencia" "MEDIUM" "Archivo en carpeta Startup" $_.FullName 5 `
                "Revisar si es legítimo. Eliminar si no lo reconoces."
            $m04 += @{ type="startup"; path=$_.FullName }
        }
    }
}
Set-ModuleResult "M04_Persistencia" $(if ($m04 | Where-Object { $_.suspicious }) {"ALERT"} else {"OK"}) $m04

# ══════════════════════════════════════════════════════════════════════════════
#  M05 — REGISTRO CRÍTICO (IFEO / AppInit / Winlogon)
# ══════════════════════════════════════════════════════════════════════════════
W-Step 5 "Claves de registro críticas"
$m05 = @()

# IFEO
$ifeoKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoKey) {
    Get-ChildItem $ifeoKey -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($dbg -and $dbg -notmatch "(vsjitdebugger|drwtsn32|ntsd|cdb)") {
            W-Crit "IFEO Debugger: $($_.PSChildName) → $dbg"
            Add-Finding "M05_Registro" "CRITICAL" "IFEO Debugger sospechoso: $($_.PSChildName)" `
                "Debugger: $dbg" 15 `
                "Eliminar: Remove-ItemProperty -Path '$($_.PSPath)' -Name Debugger"
            $m05 += @{ type="IFEO"; target=$_.PSChildName; debugger=$dbg }
        }
    }
}

# AppInit_DLLs
$appInit = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue).AppInit_DLLs
if ($appInit -and $appInit -ne "") {
    W-Crit "AppInit_DLLs: $appInit"
    Add-Finding "M05_Registro" "HIGH" "AppInit_DLLs configurada" $appInit 12 `
        "Limpiar: Set-ItemProperty -Path 'HKLM:\...\Windows' -Name AppInit_DLLs -Value ''"
    $m05 += @{ type="AppInit"; value=$appInit }
}

# Winlogon
$wl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($wl.Userinit -and $wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') {
    W-Crit "Winlogon Userinit modificado: $($wl.Userinit)"
    Add-Finding "M05_Registro" "CRITICAL" "Winlogon Userinit modificado" $wl.Userinit 18 `
        "Restaurar: Set-ItemProperty -Path '...\Winlogon' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,'"
    $m05 += @{ type="Winlogon_Userinit"; value=$wl.Userinit }
}
if ($wl.Shell -and $wl.Shell -notmatch '^explorer\.exe$') {
    W-Crit "Winlogon Shell modificado: $($wl.Shell)"
    Add-Finding "M05_Registro" "CRITICAL" "Winlogon Shell modificado" $wl.Shell 18 `
        "Restaurar: Set-ItemProperty -Path '...\Winlogon' -Name Shell -Value 'explorer.exe'"
    $m05 += @{ type="Winlogon_Shell"; value=$wl.Shell }
}
if ($m05.Count -eq 0) { W-OK "Registro crítico sin modificaciones"; Add-Finding "M05_Registro" "PASS" "Registro crítico limpio" "" 0 }
Set-ModuleResult "M05_Registro" $(if ($m05.Count -gt 0) {"ALERT"} else {"OK"}) $m05

# ══════════════════════════════════════════════════════════════════════════════
#  M06 — CUENTAS DE USUARIO Y PRIVILEGIOS
# ══════════════════════════════════════════════════════════════════════════════
W-Step 6 "Cuentas de usuario y privilegios"
$m06 = @()

$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
W-Info "Administradores locales: $($admins.Count)"
foreach ($a in $admins) { W-Info "  Admin: $($a.Name)" }
if ($admins.Count -gt 2) {
    Add-Finding "M06_Cuentas" "MEDIUM" "$($admins.Count) cuentas con privilegios de Administrador" `
        ($admins | ForEach-Object { $_.Name } | Out-String).Trim() 6 `
        "Revisar si todas las cuentas admin son necesarias"
}

# Cuenta Guest habilitada
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) {
    W-Crit "Cuenta Guest habilitada"
    Add-Finding "M06_Cuentas" "HIGH" "Cuenta Guest habilitada" "" 10 `
        "Deshabilitar: Disable-LocalUser -Name 'Guest'" `
        { Disable-LocalUser -Name 'Guest' }
} else { W-OK "Cuenta Guest deshabilitada" }

# Cuenta Administrator built-in
$builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" }
if ($builtinAdmin -and $builtinAdmin.Enabled) {
    W-Warn "Cuenta Administrator built-in (SID 500) habilitada"
    Add-Finding "M06_Cuentas" "MEDIUM" "Cuenta Administrator built-in activa" `
        "Nombre: $($builtinAdmin.Name)" 6 `
        "Considera renombrarla o deshabilitarla si no la usas"
}

# Contraseñas nunca expiran
Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.PasswordNeverExpires -and $_.Enabled } | ForEach-Object {
    W-Warn "Contraseña sin caducidad: $($_.Name)"
    Add-Finding "M06_Cuentas" "LOW" "Contraseña sin caducidad: $($_.Name)" "" 3 `
        "Set-LocalUser -Name '$($_.Name)' -PasswordNeverExpires `$false"
}

# RDP
$rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
if ($rdp.fDenyTSConnections -eq 0) {
    W-Warn "RDP habilitado"
    Add-Finding "M06_Cuentas" "MEDIUM" "Remote Desktop (RDP) habilitado" `
        "Asegúrate de tener NLA y contraseña fuerte si lo usas" 5 `
        "Deshabilitar RDP si no lo necesitas: Set-ItemProperty -Path '...\Terminal Server' -Name fDenyTSConnections -Value 1"
} else { W-OK "RDP deshabilitado" }
Set-ModuleResult "M06_Cuentas" "OK" $m06

# ══════════════════════════════════════════════════════════════════════════════
#  M07 — SERVICIOS DE WINDOWS SOSPECHOSOS
# ══════════════════════════════════════════════════════════════════════════════
W-Step 7 "Servicios de Windows"
$m07 = @()
Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $path = $_.PathName
    if (-not $path) { return }
    $isSusp = $path -match '(\\Temp\\|\\AppData\\Roaming\\(?!Microsoft)|\.exe.*\.exe|cmd\.exe.*\/c|powershell|mshta|wscript)' -and -not (Is-Legit $path)
    if ($isSusp) {
        W-Crit "Servicio sospechoso: $($_.Name) → $path"
        Add-Finding "M07_Servicios" "HIGH" "Servicio sospechoso: $($_.Name)" $path 9 `
            "Revisar y detener: Stop-Service '$($_.Name)'; Set-Service '$($_.Name)' -StartupType Disabled"
        $m07 += @{ name=$_.Name; path=$path; state=$_.State }
    }
}
if ($m07.Count -eq 0) { W-OK "Sin servicios sospechosos"; Add-Finding "M07_Servicios" "PASS" "Servicios limpios" "" 0 }
Set-ModuleResult "M07_Servicios" $(if ($m07.Count -gt 0) {"ALERT"} else {"OK"}) $m07

# ══════════════════════════════════════════════════════════════════════════════
#  M08 — PROCESOS EN MEMORIA
# ══════════════════════════════════════════════════════════════════════════════
W-Step 8 "Procesos en memoria"
$m08 = @()
Get-Process | ForEach-Object {
    $proc = $_
    $path = try { $proc.MainModule.FileName } catch { "" }
    if ($path -and -not (Is-Legit $path)) {
        $isSusp = $path -like "*\Temp\*" -or $path -like "*\AppData\Roaming\*" -or
                  $path -like "*\Users\Public\*" -or $path -like "*\ProgramData\*"
        if ($isSusp -and $path -notlike "*\BurpSuite\*") {
            W-Crit "Proceso en ruta inusual: $($proc.Name) → $path"
            Add-Finding "M08_Procesos" "HIGH" "Proceso ejecutándose desde ruta inusual" `
                "$($proc.Name) (PID:$($proc.Id)) → $path" 8 `
                "Investigar. Si es malicioso: Stop-Process -Id $($proc.Id) -Force"
            $m08 += @{ name=$proc.Name; pid=$proc.Id; path=$path }
        }
    }
}
if ($m08.Count -eq 0) { W-OK "Sin procesos en rutas sospechosas"; Add-Finding "M08_Procesos" "PASS" "Procesos limpios" "" 0 }
Set-ModuleResult "M08_Procesos" $(if ($m08.Count -gt 0) {"ALERT"} else {"OK"}) $m08

# ══════════════════════════════════════════════════════════════════════════════
#  M09 — CONEXIONES DE RED ACTIVAS
# ══════════════════════════════════════════════════════════════════════════════
W-Step 9 "Conexiones de red activas"
$m09 = @()
$suspPorts = @(4444,1234,31337,6666,6667,9001,8888,2222,12345,54321,1337,4445,5555,7777,9999)
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
    $conn = $_
    $isSuspPort = $conn.RemotePort -in $suspPorts -or $conn.LocalPort -in $suspPorts
    if ($isSuspPort) {
        $proc = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
        W-Crit "Conexión sospechosa: $proc → $($conn.RemoteAddress):$($conn.RemotePort)"
        Add-Finding "M09_Red" "HIGH" "Conexión a puerto C2 conocido" `
            "$proc (PID:$($conn.OwningProcess)) → $($conn.RemoteAddress):$($conn.RemotePort)" 10 `
            "Investigar el proceso. Puerto $($conn.RemotePort) es conocido en listas C2."
        $m09 += @{ proc=$proc; remote="$($conn.RemoteAddress):$($conn.RemotePort)" }
    }
}
# Resumen de conexiones activas
$totalConn = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).Count
W-Info "Total conexiones TCP establecidas: $totalConn"
if ($m09.Count -eq 0) { W-OK "Sin conexiones a puertos C2 conocidos"; Add-Finding "M09_Red" "PASS" "Red limpia" "" 0 }
Set-ModuleResult "M09_Red" $(if ($m09.Count -gt 0) {"ALERT"} else {"OK"}) $m09

# ══════════════════════════════════════════════════════════════════════════════
#  M10 — DNS Y ARCHIVO HOSTS
# ══════════════════════════════════════════════════════════════════════════════
W-Step 10 "DNS y archivo HOSTS"
$m10 = @()
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
$suspHosts = $hostsContent | Where-Object {
    $_ -notmatch "^#" -and $_ -match "\S" -and
    $_ -notmatch "^127\.0\.0\.1\s+localhost$" -and
    $_ -notmatch "^::1\s+localhost$" -and
    $_ -notmatch "^0\.0\.0\.0\s+0\.0\.0\.0$"
}
if ($suspHosts) {
    foreach ($entry in $suspHosts) {
        W-Crit "HOSTS modificado: $($entry.Trim())"
        Add-Finding "M10_DNS" "HIGH" "Entrada sospechosa en HOSTS" $entry.Trim() 8 `
            "Editar: notepad $hostsFile"
        $m10 += @{ type="hosts"; entry=$entry.Trim() }
    }
} else { W-OK "Archivo HOSTS sin modificaciones" }

# DNS inusuales
Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object {
    foreach ($dns in $_.ServerAddresses) {
        $isKnown = $dns -match "^(8\.8\.|1\.1\.|9\.9\.|208\.67\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
        if (-not $isKnown) {
            W-Warn "DNS inusual en $($_.InterfaceAlias): $dns"
            Add-Finding "M10_DNS" "MEDIUM" "Servidor DNS desconocido en $($_.InterfaceAlias)" $dns 5 `
                "Verificar si este DNS es legítimo (ISP propio, VPN, etc.)"
            $m10 += @{ type="dns"; interface=$_.InterfaceAlias; dns=$dns }
        }
    }
}
Set-ModuleResult "M10_DNS" $(if ($m10.Count -gt 0) {"ALERT"} else {"OK"}) $m10

# ══════════════════════════════════════════════════════════════════════════════
#  M11 — DRIVERS SIN FIRMA DIGITAL
# ══════════════════════════════════════════════════════════════════════════════
W-Step 11 "Drivers del kernel sin firma"
$m11 = @()
Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object {
    $drvPath = $_.PathName -replace '\\\\','\'
    if ($drvPath -and $drvPath -notlike "*\Windows\*" -and $drvPath -notlike "*\Program Files\*") {
        $sig = Get-AuthenticodeSignature $drvPath -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne "Valid") {
            W-Crit "Driver sin firma válida: $($_.Name) → $drvPath [$($sig.Status)]"
            Add-Finding "M11_Drivers" "CRITICAL" "Driver sin firma: $($_.Name)" `
                "$drvPath — Estado firma: $($sig.Status)" 14 `
                "Investigar origen del driver. Si es desconocido, deshabilitar el servicio."
            $m11 += @{ name=$_.Name; path=$drvPath; sig=$sig.Status }
        }
    }
}
if ($m11.Count -eq 0) { W-OK "Sin drivers con firma inválida"; Add-Finding "M11_Drivers" "PASS" "Drivers firmados correctamente" "" 0 }
Set-ModuleResult "M11_Drivers" $(if ($m11.Count -gt 0) {"ALERT"} else {"OK"}) $m11

# ══════════════════════════════════════════════════════════════════════════════
#  M12 — SCRIPTS SOSPECHOSOS EN DIRECTORIOS TEMPORALES
# ══════════════════════════════════════════════════════════════════════════════
W-Step 12 "Scripts en directorios temporales"
$m12 = @()
$knownLegitApps = @("*\uv\*","*\ESET\*","*\BurpSuite\*","*\node_modules\*","*\AppData\Local\Programs\*","*\AppData\Local\Google\*")
$scriptDirs = @($env:TEMP,"$env:LOCALAPPDATA\Temp")
Get-ChildItem -Path $scriptDirs -Recurse -Include *.ps1,*.vbs,*.hta,*.bat,*.js,*.wsf -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 300 } | ForEach-Object {
    $scr = $_
    if (Is-Legit $scr.FullName) { return }
    $isKnown = $false
    foreach ($k in $knownLegitApps) { if ($scr.FullName -like $k) { $isKnown = $true; break } }
    if ($isKnown) { return }

    $content = Get-Content $scr.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { return }
    $ind = 0
    if ($content -match "[A-Za-z0-9+/]{100,}={0,2}") { $ind++ }
    if ($content -match "chr\(\d+\)")                 { $ind++ }
    if ($content -match '(\[char\]|IEX|Invoke-Expression|FromBase64)') { $ind++ }
    if ($content -match '(-join|-replace|\$env:|-split).*\|.*(IEX|&)') { $ind++ }

    if ($ind -ge 2) {
        W-Crit "Script ofuscado en TEMP ($ind indicadores): $($scr.FullName)"
        Add-Finding "M12_Scripts" "HIGH" "Script ofuscado en directorio temporal" `
            "$($scr.FullName) — $ind indicadores de ofuscación" 9 `
            "Revisar contenido. Eliminar si no lo reconoces: Remove-Item '$($scr.FullName)' -Force" `
            { Remove-Item $scr.FullName -Force }
        $m12 += @{ path=$scr.FullName; indicators=$ind }
    } elseif ($ind -eq 1) {
        W-Warn "Script sospechoso en TEMP: $($scr.FullName)"
        Add-Finding "M12_Scripts" "MEDIUM" "Script posiblemente sospechoso en TEMP" $scr.FullName 4 `
            "Revisar contenido manualmente"
        $m12 += @{ path=$scr.FullName; indicators=$ind }
    }
}
if ($m12.Count -eq 0) { W-OK "Sin scripts sospechosos en directorios temporales"; Add-Finding "M12_Scripts" "PASS" "TEMP limpio" "" 0 }
Set-ModuleResult "M12_Scripts" $(if ($m12.Count -gt 0) {"ALERT"} else {"OK"}) $m12

# ══════════════════════════════════════════════════════════════════════════════
#  M13 — CONFIGURACIÓN DE SEGURIDAD DEL SISTEMA
# ══════════════════════════════════════════════════════════════════════════════
W-Step 13 "Configuración de seguridad del sistema"
$m13 = @()

# UAC
$uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
if ($uac.EnableLUA -eq 0) {
    W-Crit "UAC completamente deshabilitado"
    Add-Finding "M13_Config" "CRITICAL" "UAC deshabilitado" "EnableLUA = 0" 18 `
        "Habilitar: Set-ItemProperty -Path '...\Policies\System' -Name EnableLUA -Value 1" `
        { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 }
} elseif ($uac.ConsentPromptBehaviorAdmin -eq 0) {
    W-Warn "UAC habilitado pero sin pedir confirmación a admins"
    Add-Finding "M13_Config" "MEDIUM" "UAC sin prompt para administradores" `
        "ConsentPromptBehaviorAdmin = 0" 7 `
        "Cambiar a 2 (notificar siempre): Set-ItemProperty ... -Name ConsentPromptBehaviorAdmin -Value 2"
} else { W-OK "UAC configurado correctamente" }

# SMBv1
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($smb1 -and $smb1.State -eq "Enabled") {
    W-Crit "SMBv1 HABILITADO — vector conocido de ransomware (WannaCry, NotPetya)"
    Add-Finding "M13_Config" "CRITICAL" "SMBv1 habilitado (vector ransomware)" "" 20 `
        "Deshabilitar: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" `
        { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart }
} else { W-OK "SMBv1 deshabilitado" }

# PowerShell v2 (sin logging moderno)
$psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
if ($psv2 -and $psv2.State -eq "Enabled") {
    W-Warn "PowerShell v2 instalado (evade Script Block Logging)"
    Add-Finding "M13_Config" "MEDIUM" "PowerShell v2 disponible" "Puede usarse para evadir logging" 6 `
        "Deshabilitar: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
}

# PowerShell Script Block Logging
$psLogging = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
if (-not $psLogging -or $psLogging.EnableScriptBlockLogging -ne 1) {
    W-Warn "PowerShell Script Block Logging deshabilitado"
    Add-Finding "M13_Config" "MEDIUM" "PS Script Block Logging deshabilitado" `
        "Sin auditoría de scripts PowerShell ejecutados" 6 `
        "Habilitar vía GPO o registro: EnableScriptBlockLogging = 1"
} else { W-OK "PS Script Block Logging activo" }

# SecureBoot
$sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if ($sb -eq $false) {
    W-Warn "Secure Boot deshabilitado"
    Add-Finding "M13_Config" "MEDIUM" "Secure Boot deshabilitado" "" 7 `
        "Habilitar Secure Boot desde la UEFI/BIOS del equipo"
} elseif ($sb -eq $true) { W-OK "Secure Boot habilitado" }

Set-ModuleResult "M13_Config" "OK" $m13

# ══════════════════════════════════════════════════════════════════════════════
#  M14 — ARTEFACTOS DE EJECUCIÓN (Prefetch)
# ══════════════════════════════════════════════════════════════════════════════
W-Step 14 "Artefactos de ejecución reciente"
$m14 = @()
$suspTools = @("MIMIKATZ","PSEXEC","NETCAT","PROCDUMP","PWDUMP","LAZAGNE",
               "COBALT","METERPRETER","EMPIRE","METASPLOIT","KEYLOG",
               "ROOTKIT","BYPASS","INJECT","WCESERVICE","FGDUMP","GSECDUMP")
$pf = "C:\Windows\Prefetch"
if (Test-Path $pf) {
    Get-ChildItem $pf -Filter *.pf -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 200 | ForEach-Object {
        foreach ($tool in $suspTools) {
            if ($_.Name -match $tool) {
                W-Crit "Herramienta de ataque en Prefetch: $($_.Name) (ejecutada: $($_.LastWriteTime))"
                Add-Finding "M14_Artefactos" "HIGH" "Herramienta de ataque en Prefetch" `
                    "$($_.Name) — última ejecución: $($_.LastWriteTime)" 12 `
                    "Investigar. Ejecuta un análisis completo de Defender."
                $m14 += @{ file=$_.Name; last_run="$($_.LastWriteTime)"; tool=$tool }
                break
            }
        }
    }
} else { W-Info "Prefetch no disponible (puede estar deshabilitado)" }
if ($m14.Count -eq 0) { W-OK "Sin herramientas de ataque en Prefetch"; Add-Finding "M14_Artefactos" "PASS" "Prefetch limpio" "" 0 }
Set-ModuleResult "M14_Artefactos" $(if ($m14.Count -gt 0) {"ALERT"} else {"OK"}) $m14

# ══════════════════════════════════════════════════════════════════════════════
#  M15 — CIFRADO DE DISCO Y POLÍTICA DE CONTRASEÑAS
# ══════════════════════════════════════════════════════════════════════════════
W-Step 15 "Cifrado de disco y política de contraseñas"
$m15 = @()

# BitLocker
$bl = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.MountPoint -eq "C:" }
if ($bl) {
    if ($bl.ProtectionStatus -eq "Off") {
        W-Warn "BitLocker deshabilitado en C:"
        Add-Finding "M15_Cifrado" "MEDIUM" "BitLocker deshabilitado en disco del sistema" "" 8 `
            "Habilitar: Enable-BitLocker -MountPoint 'C:' -RecoveryPasswordProtector"
    } else { W-OK "BitLocker activo en C: — Estado: $($bl.VolumeStatus)" }
    $m15 += @{ drive="C:"; status=$bl.ProtectionStatus; volume_status=$bl.VolumeStatus }
} else { W-Info "BitLocker no disponible o no configurado" }

# Política de contraseñas
$pwPolicy = & net accounts 2>$null
if ($pwPolicy) {
    $minLen = ($pwPolicy | Select-String "Minimum password length") -replace '\D+',''
    $maxAge = ($pwPolicy | Select-String "Maximum password age") -replace '\D+',''
    if ($minLen -and [int]$minLen -lt 8) {
        W-Warn "Longitud mínima de contraseña: $minLen (recomendado ≥12)"
        Add-Finding "M15_Cifrado" "MEDIUM" "Política de contraseñas débil" `
            "Longitud mínima: $minLen caracteres" 6 `
            "Aumentar: net accounts /minpwlen:12"
    } else { W-OK "Longitud mínima de contraseña: $minLen" }
    if ($maxAge -and [int]$maxAge -gt 90) {
        W-Warn "Contraseñas sin caducidad suficiente: máx $maxAge días"
        Add-Finding "M15_Cifrado" "LOW" "Contraseñas con caducidad alta: $maxAge días" "" 3 `
            "Cambiar: net accounts /maxpwage:90"
    }
}
Set-ModuleResult "M15_Cifrado" "OK" $m15

# ══════════════════════════════════════════════════════════════════════════════
#  PUNTUACIÓN FINAL
# ══════════════════════════════════════════════════════════════════════════════
$critCount = ($audit.findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
$highCount  = ($audit.findings | Where-Object { $_.severity -eq "HIGH" }).Count
$medCount   = ($audit.findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
$lowCount   = ($audit.findings | Where-Object { $_.severity -eq "LOW" }).Count
$passCount  = ($audit.findings | Where-Object { $_.severity -eq "PASS" }).Count
$totalRisk  = $audit.score

$riskLevel = switch ($true) {
    ($totalRisk -ge 60) { "CRÍTICO" }
    ($totalRisk -ge 35) { "ALTO" }
    ($totalRisk -ge 15) { "MEDIO" }
    ($totalRisk -ge 1)  { "BAJO" }
    default             { "SEGURO" }
}

# ══════════════════════════════════════════════════════════════════════════════
#  FASE DE CORRECCIONES — preguntar por cada hallazgo con fix disponible
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "  ║           FASE DE CORRECCIONES — BAJO DEMANDA               ║" -ForegroundColor Yellow
Write-Host "  ║   Se te preguntará antes de aplicar CUALQUIER cambio        ║" -ForegroundColor Yellow
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

$fixableFindings = $audit.findings | Where-Object { $_.fix -ne $null -and $_.severity -ne "PASS" }
if ($fixableFindings.Count -eq 0) {
    W-Info "No hay correcciones automáticas disponibles para los hallazgos encontrados."
} else {
    W-Info "$($fixableFindings.Count) hallazgo(s) con corrección disponible."
    foreach ($f in $fixableFindings) {
        Write-Host ""
        Write-Host "  ┌─ $($f.severity) — $($f.title)" -ForegroundColor $(
            switch ($f.severity) { "CRITICAL"{"Red"} "HIGH"{"DarkYellow"} default{"Yellow"} }
        )
        Write-Host "  │  Módulo    : $($f.module)" -ForegroundColor Gray
        if ($f.detail) { Write-Host "  │  Detalle   : $($f.detail)" -ForegroundColor Gray }
        Write-Host "  │  Corrección: $($f.recommendation)" -ForegroundColor Cyan
        Write-Host "  └─" -ForegroundColor Gray

        $applied = Confirm-Action $f.title $f.fix
        if ($applied) { $f.fixed = $true }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  GENERAR REPORTE HTML
# ══════════════════════════════════════════════════════════════════════════════
$riskColor = switch ($riskLevel) {
    "CRÍTICO" { "#ff3355" } "ALTO" { "#ff8c00" } "MEDIO" { "#ffd200" } "BAJO" { "#00e5cc" } default { "#00ff88" }
}

$findingsHTML = ""
$sevOrder = @("CRITICAL","HIGH","MEDIUM","LOW","PASS")
foreach ($sev in $sevOrder) {
    $group = $audit.findings | Where-Object { $_.severity -eq $sev }
    if (-not $group) { continue }
    foreach ($f in $group) {
        $sevColor = switch ($f.severity) {
            "CRITICAL"{"#ff3355"} "HIGH"{"#ff8c00"} "MEDIUM"{"#ffd200"} "LOW"{"#00aaff"} "PASS"{"#00ff88"} default{"#667788"}
        }
        $fixedBadge = if ($f.fixed) { '<span style="color:#00ff88;font-size:11px;margin-left:8px;">[CORREGIDO]</span>' } else { "" }
        $recHTML = if ($f.recommendation) { "<div class='rec'>💡 $($f.recommendation)</div>" } else { "" }
        $detHTML = if ($f.detail)         { "<div class='det'>$($f.detail)</div>" } else { "" }
        $findingsHTML += @"
        <tr class="sev-$($f.severity.ToLower())">
          <td><span class="pill" style="background:$($sevColor)22;color:$sevColor;border:1px solid $($sevColor)44">$($f.severity)</span></td>
          <td style="font-family:monospace;font-size:12px;color:#00e5cc">$($f.module)</td>
          <td><strong>$($f.title)</strong>$fixedBadge$detHTML$recHTML</td>
        </tr>
"@
    }
}

$modulesHTML = ""
foreach ($mk in $audit.modules.Keys) {
    $mv = $audit.modules[$mk]
    $statusColor = if ($mv.status -eq "ALERT") { "#ff3355" } else { "#00ff88" }
    $statusIcon  = if ($mv.status -eq "ALERT") { "✗" } else { "✓" }
    $modulesHTML += @"
    <div class="mod-chip" style="border-left:3px solid $statusColor">
      <span style="color:$statusColor;font-weight:700">$statusIcon</span>
      <span>$mk</span>
    </div>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auditoría de Seguridad — $hostname</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080c10;--bg2:#0d1117;--bg3:#111820;
  --border:#1e2d3d;--border2:#243444;
  --green:#00ff88;--red:#ff3355;--orange:#ff8c00;
  --yellow:#ffd200;--blue:#00aaff;--teal:#00e5cc;
  --text:#c9d8e8;--dim:#4a6070;
  --mono:'Share Tech Mono',monospace;
  --sans:'Barlow Condensed',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.5;}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,.012) 2px,rgba(0,255,136,.012) 4px);pointer-events:none;z-index:9999;}
.wrap{max-width:1200px;margin:0 auto;padding:32px 24px;}
/* Header */
.header{border-bottom:1px solid var(--border);padding-bottom:28px;margin-bottom:32px;}
.badge{font-family:var(--mono);font-size:11px;letter-spacing:3px;color:var(--dim);margin-bottom:8px;}
h1{font-size:clamp(26px,4vw,46px);font-weight:900;letter-spacing:3px;color:var(--text);}
.meta{font-family:var(--mono);font-size:12px;color:var(--dim);margin-top:10px;line-height:2;}
.meta span{color:var(--teal);}
/* Risk block */
.risk-block{display:flex;gap:32px;align-items:flex-start;flex-wrap:wrap;margin:28px 0;}
.risk-card{background:var(--bg2);border:1px solid var(--border);border-top:3px solid $riskColor;padding:24px 32px;min-width:200px;}
.risk-label{font-family:var(--mono);font-size:10px;letter-spacing:3px;color:var(--dim);}
.risk-val{font-size:56px;font-weight:900;line-height:1;color:$riskColor;}
.risk-txt{font-family:var(--mono);font-size:14px;color:$riskColor;letter-spacing:2px;margin-top:4px;}
/* Stats */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;flex:1;}
.stat{background:var(--bg2);border:1px solid var(--border);padding:16px;text-align:center;}
.stat-n{font-size:38px;font-weight:900;line-height:1;}
.stat-l{font-size:11px;font-weight:600;letter-spacing:2px;color:var(--dim);margin-top:4px;}
/* Modules */
.modules{display:flex;flex-wrap:wrap;gap:10px;margin:24px 0;}
.mod-chip{background:var(--bg2);border:1px solid var(--border);padding:8px 14px;font-size:12px;font-family:var(--mono);display:flex;gap:8px;align-items:center;}
/* Section */
.section{margin:32px 0;}
.sec-title{font-family:var(--mono);font-size:11px;letter-spacing:4px;color:var(--dim);padding-bottom:10px;border-bottom:1px solid var(--border);margin-bottom:16px;}
/* Table */
table{width:100%;border-collapse:collapse;}
th{font-family:var(--mono);font-size:10px;letter-spacing:3px;color:var(--dim);text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);}
td{padding:12px;border-bottom:1px solid rgba(30,45,61,.5);vertical-align:top;font-size:14px;}
tr:hover td{background:rgba(255,255,255,.02);}
.pill{font-family:var(--mono);font-size:10px;letter-spacing:1px;padding:3px 10px;border-radius:2px;white-space:nowrap;}
.det{font-family:var(--mono);font-size:11px;color:var(--dim);margin-top:5px;word-break:break-all;}
.rec{font-size:12px;color:var(--teal);margin-top:6px;font-family:var(--mono);}
/* Footer */
.footer{border-top:1px solid var(--border);padding-top:16px;margin-top:32px;font-family:var(--mono);font-size:11px;color:var(--dim);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;}
@media print{body::before{display:none;}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="badge">// AUDITORÍA COMPLETA DE SEGURIDAD — PC PERSONAL</div>
    <h1>$hostname</h1>
    <div class="meta">
      Fecha: <span>$($audit.meta.date)</span> &nbsp;·&nbsp;
      Usuario: <span>$($audit.meta.user)</span> &nbsp;·&nbsp;
      Sistema: <span>$($audit.meta.os)</span> &nbsp;·&nbsp;
      Build: <span>$($audit.meta.os_build)</span> &nbsp;·&nbsp;
      PowerShell: <span>$($audit.meta.ps_ver)</span>
    </div>
  </div>

  <div class="risk-block">
    <div class="risk-card">
      <div class="risk-label">NIVEL DE RIESGO</div>
      <div class="risk-val">$totalRisk</div>
      <div class="risk-txt">$riskLevel</div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-n" style="color:#ff3355">$critCount</div><div class="stat-l">CRÍTICOS</div></div>
      <div class="stat"><div class="stat-n" style="color:#ff8c00">$highCount</div><div class="stat-l">ALTOS</div></div>
      <div class="stat"><div class="stat-n" style="color:#ffd200">$medCount</div><div class="stat-l">MEDIOS</div></div>
      <div class="stat"><div class="stat-n" style="color:#00aaff">$lowCount</div><div class="stat-l">BAJOS</div></div>
      <div class="stat"><div class="stat-n" style="color:#00ff88">$passCount</div><div class="stat-l">PASADOS</div></div>
      <div class="stat"><div class="stat-n" style="color:#00e5cc">15</div><div class="stat-l">MÓDULOS</div></div>
    </div>
  </div>

  <div class="section">
    <div class="sec-title">// ESTADO DE MÓDULOS</div>
    <div class="modules">$modulesHTML</div>
  </div>

  <div class="section">
    <div class="sec-title">// HALLAZGOS DETALLADOS — $($audit.findings.Count) TOTAL</div>
    <table>
      <thead><tr><th>SEVERIDAD</th><th>MÓDULO</th><th>HALLAZGO / RECOMENDACIÓN</th></tr></thead>
      <tbody>$findingsHTML</tbody>
    </table>
  </div>

  <div class="footer">
    <span>Auditoría: $($audit.meta.date) | $hostname | Generado por Invoke-SecurityAudit.ps1</span>
    <span>POLÍTICA: Cero cambios sin confirmación explícita del usuario</span>
  </div>
</div>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8

# ══════════════════════════════════════════════════════════════════════════════
#  RESUMEN CONSOLA FINAL
# ══════════════════════════════════════════════════════════════════════════════
Stop-Transcript | Out-Null

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $(
    switch ($riskLevel) {"CRÍTICO"{"Red"} "ALTO"{"DarkYellow"} "MEDIO"{"Yellow"} default{"Cyan"}}
)
Write-Host "  ║  AUDITORÍA COMPLETADA                                        ║" -ForegroundColor White
Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Gray
Write-Host "  ║  Nivel de riesgo  : $riskLevel$('' * (36 - $riskLevel.Length))║" -ForegroundColor White
Write-Host "  ║  Puntuación total : $totalRisk$('' * (36 - "$totalRisk".Length))║" -ForegroundColor White
Write-Host "  ║  Críticos/Altos   : $critCount / $highCount$('' * (33 - "$critCount / $highCount".Length))║" -ForegroundColor White
Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Gray
Write-Host "  ║  Reporte HTML → Escritorio\SecurityAudit_${hostname}_${ts}  ║" -ForegroundColor Cyan
Write-Host "  ║  Log completo  → %TEMP%\SecurityAudit_${hostname}_${ts}.log ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $(
    switch ($riskLevel) {"CRÍTICO"{"Red"} "ALTO"{"DarkYellow"} "MEDIO"{"Yellow"} default{"Cyan"}}
)
Write-Host ""

# Abrir reporte automáticamente
if (Ask-User "¿Abrir el reporte HTML en el navegador ahora?") {
    Start-Process $htmlPath
}
