<#
.SYNOPSIS
    Échantillon de test BÉNIN T12 : scénario combiné (ATT&CK T1082 + T1547.001).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (réseau coupé).
    Enchaîne trois comportements pour tester leur corrélation par l'agent :
    1. découverte : systeminfo.exe, sortie enregistrée dans C:\travail\malsight_t12_info.txt ;
    2. persistance : valeur Run « MalsightTest12 » -> notepad.exe ;
    3. tentative DNS vers c2.malsight.lab (échec attendu : réseau coupé, domaine inexistant).
    Vérité terrain : lab/verite-terrain/T12.json.

.PARAMETER Nettoyer
    Supprime la valeur Run et le fichier créés.
#>
param([switch]$Nettoyer)

$CleRun  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$NomRun  = 'MalsightTest12'
$Fichier = 'C:\travail\malsight_t12_info.txt'
$Domaine = 'c2.malsight.lab'

if ($Nettoyer) {
    Remove-ItemProperty -Path $CleRun -Name $NomRun -ErrorAction SilentlyContinue
    Remove-Item -Path $Fichier -ErrorAction SilentlyContinue
    Write-Host 'T12 : valeur Run et fichier supprimés.'
    return
}

Write-Host '=== T12 : scénario combiné (test bénin) ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $Fichier) | Out-Null

# 1. Découverte
& systeminfo.exe | Set-Content -Path $Fichier -Encoding UTF8
Write-Host "[1] systeminfo.exe -> $Fichier"

# 2. Persistance
$cible = Join-Path $env:WINDIR 'System32\notepad.exe'
New-ItemProperty -Path $CleRun -Name $NomRun -Value $cible -PropertyType String -Force | Out-Null
Write-Host "[2] Registre : $CleRun\$NomRun = $cible"

# 3. Tentative DNS
try {
    $r = Resolve-DnsName -Name $Domaine -DnsOnly -ErrorAction Stop
    Write-Host "[3] DNS : $Domaine -> $($r.IPAddress -join ', ') (inattendu)" -ForegroundColor Yellow
} catch {
    Write-Host "[3] DNS : $Domaine -> échec attendu ($($_.Exception.Message))"
}
Write-Host 'T12 terminé.'
