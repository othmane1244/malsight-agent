<#
.SYNOPSIS
    Échantillon de test BÉNIN T08 : découverte de la configuration réseau (ATT&CK T1016).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Lance ipconfig /all, route print et arp -a, et enregistre leur sortie dans
    C:\travail\malsight_t08.txt. Vérité terrain : lab/verite-terrain/T08.json.

.PARAMETER Nettoyer
    Supprime le fichier créé.
#>
param([switch]$Nettoyer)

$Fichier = 'C:\travail\malsight_t08.txt'

if ($Nettoyer) {
    Remove-Item -Path $Fichier -ErrorAction SilentlyContinue
    Write-Host 'T08 : fichier supprimé.'
    return
}

Write-Host '=== T08 : découverte du réseau (test bénin) ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $Fichier) | Out-Null
$sortie = @(& ipconfig.exe /all) + @(& route.exe print) + @(& arp.exe -a)
$sortie | Set-Content -Path $Fichier -Encoding UTF8
Write-Host "[1] ipconfig /all + route print + arp -a -> $Fichier ($($sortie.Count) lignes)"
Write-Host 'T08 terminé.'
