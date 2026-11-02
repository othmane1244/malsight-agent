<#
.SYNOPSIS
    Échantillon de test BÉNIN T09 : archivage de données collectées (ATT&CK T1560).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Crée 3 fichiers texte factices dans C:\travail\collecte\ et les compresse dans
    C:\travail\collecte.zip (ce .zip reste dans la sandbox, jamais dans git).
    Vérité terrain : lab/verite-terrain/T09.json.

.PARAMETER Nettoyer
    Supprime le dossier et l'archive créés.
#>
param([switch]$Nettoyer)

$Dossier  = 'C:\travail\collecte'
$Archive  = 'C:\travail\collecte.zip'

if ($Nettoyer) {
    Remove-Item -Path $Dossier -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path $Archive -ErrorAction SilentlyContinue
    Write-Host 'T09 : dossier et archive supprimés.'
    return
}

Write-Host '=== T09 : archivage de données (test bénin) ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $Dossier | Out-Null
foreach ($i in 1..3) {
    Set-Content -Path (Join-Path $Dossier "document$i.txt") -Value "MalSight T09 - document factice $i"
}
Write-Host "[1] 3 fichiers factices dans $Dossier"
Compress-Archive -Path (Join-Path $Dossier '*') -DestinationPath $Archive -Force
Write-Host "[2] Archive : $Archive"
Write-Host 'T09 terminé.'
