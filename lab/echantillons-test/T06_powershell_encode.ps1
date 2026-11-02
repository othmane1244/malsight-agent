<#
.SYNOPSIS
    Échantillon de test BÉNIN T06 : PowerShell avec commande encodée (ATT&CK T1059.001).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Lance « powershell -EncodedCommand » dont la commande décodée écrit seulement
    C:\travail\malsight_t06.txt. La commande en clair est affichée avant l'exécution.
    Vérité terrain : lab/verite-terrain/T06.json.

.PARAMETER Nettoyer
    Supprime le fichier créé.
#>
param([switch]$Nettoyer)

$Fichier = 'C:\travail\malsight_t06.txt'

if ($Nettoyer) {
    Remove-Item -Path $Fichier -ErrorAction SilentlyContinue
    Write-Host 'T06 : fichier supprimé.'
    return
}

Write-Host '=== T06 : PowerShell -EncodedCommand (test bénin) ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $Fichier) | Out-Null
$commande = "Set-Content -Path '$Fichier' -Value 'MalSight T06'"
$encodee  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($commande))
Write-Host "[1] Commande en clair : $commande"
& powershell.exe -NoProfile -EncodedCommand $encodee
Write-Host "[2] Fichier : $Fichier (existe : $(Test-Path $Fichier))"
Write-Host 'T06 terminé.'
