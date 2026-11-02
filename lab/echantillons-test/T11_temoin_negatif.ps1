<#
.SYNOPSIS
    Échantillon de test BÉNIN T11 : TÉMOIN NÉGATIF (aucune technique ATT&CK).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Script banal : lit la date et l'ajoute dans un journal texte C:\travail\journal_t11.txt.
    Aucune persistance, aucun réseau, aucune découverte. Sert à mesurer les faux positifs
    et le taux d'hallucination de l'agent. Vérité terrain : lab/verite-terrain/T11.json
    (« attack » vide).

.PARAMETER Nettoyer
    Supprime le journal créé.
#>
param([switch]$Nettoyer)

$Journal = 'C:\travail\journal_t11.txt'

if ($Nettoyer) {
    Remove-Item -Path $Journal -ErrorAction SilentlyContinue
    Write-Host 'T11 : journal supprimé.'
    return
}

Write-Host '=== T11 : témoin négatif ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $Journal) | Out-Null
$date = Get-Date
Add-Content -Path $Journal -Value ("{0:yyyy-MM-dd HH:mm:ss} - nouvelle entrée du journal" -f $date)
Write-Host "[1] Date lue : $date"
Write-Host "[2] Ligne ajoutée à $Journal"
Write-Host 'T11 terminé.'
