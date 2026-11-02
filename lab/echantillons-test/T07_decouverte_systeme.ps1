<#
.SYNOPSIS
    Échantillon de test BÉNIN T07 : découverte d'informations système (ATT&CK T1082).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Lance systeminfo.exe et hostname.exe, et enregistre leur sortie dans
    C:\travail\malsight_t07.txt. Vérité terrain : lab/verite-terrain/T07.json.

.PARAMETER Nettoyer
    Supprime le fichier créé.
#>
param([switch]$Nettoyer)

$Fichier = 'C:\travail\malsight_t07.txt'

if ($Nettoyer) {
    Remove-Item -Path $Fichier -ErrorAction SilentlyContinue
    Write-Host 'T07 : fichier supprimé.'
    return
}

Write-Host '=== T07 : découverte du système (test bénin) ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $Fichier) | Out-Null
$sortie = @(& hostname.exe) + @(& systeminfo.exe)
$sortie | Set-Content -Path $Fichier -Encoding UTF8
Write-Host "[1] hostname.exe + systeminfo.exe -> $Fichier ($($sortie.Count) lignes)"
Write-Host 'T07 terminé.'
