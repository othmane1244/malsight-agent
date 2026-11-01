<#
.SYNOPSIS
    Échantillon de test BÉNIN T01 : simule une persistance par clé Run (ATT&CK T1547.001).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Le script ne télécharge rien, ne lance rien et n'a aucune charge utile :
    1. écrit la valeur « MalsightTest » dans HKCU\...\CurrentVersion\Run, pointant vers notepad.exe ;
    2. crée le fichier C:\travail\malsight_test.txt ;
    3. tente une résolution DNS de test.malsight.lab (échec attendu : réseau coupé) ;
    4. affiche ce qu'il a fait.
    Vérité terrain : lab/verite-terrain/T01.json.

.PARAMETER Nettoyer
    Supprime la valeur Run et le fichier créés (inutile dans la sandbox, qui est jetable).
#>
param([switch]$Nettoyer)

$CleRun  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$NomRun  = 'MalsightTest'
$Cible   = Join-Path $env:WINDIR 'System32\notepad.exe'
$Fichier = 'C:\travail\malsight_test.txt'
$Domaine = 'test.malsight.lab'

if ($Nettoyer) {
    Remove-ItemProperty -Path $CleRun -Name $NomRun -ErrorAction SilentlyContinue
    Remove-Item -Path $Fichier -ErrorAction SilentlyContinue
    Write-Host 'T01 : valeur Run et fichier supprimés.'
    return
}

Write-Host '=== T01 : persistance par clé Run (test bénin) ===' -ForegroundColor Cyan

# 1. Valeur Run -> notepad.exe
New-ItemProperty -Path $CleRun -Name $NomRun -Value $Cible -PropertyType String -Force | Out-Null
Write-Host "[1] Registre : $CleRun\$NomRun = $Cible"

# 2. Fichier témoin
New-Item -ItemType Directory -Force -Path (Split-Path $Fichier) | Out-Null
Set-Content -Path $Fichier -Value "MalSight T01 - fichier de test cree le $(Get-Date -Format o)" -Encoding UTF8
Write-Host "[2] Fichier  : $Fichier"

# 3. Résolution DNS (échec attendu, réseau coupé)
try {
    $r = Resolve-DnsName -Name $Domaine -DnsOnly -ErrorAction Stop
    Write-Host "[3] DNS      : $Domaine -> $($r.IPAddress -join ', ')"
} catch {
    Write-Host "[3] DNS      : $Domaine -> échec ($($_.Exception.Message))"
}

Write-Host ''
Write-Host 'T01 terminé. Attendre 2 à 3 minutes puis lancer collect.ps1 -Echantillon T01_persistance_run.ps1'
