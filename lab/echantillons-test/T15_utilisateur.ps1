<#
.SYNOPSIS
    Échantillon de VALIDATION BÉNIN T15 : découverte de l'utilisateur (ATT&CK T1033).

.DESCRIPTION
    Jeu de validation (D4) : écrit avant les règles artefact -> technique, jamais utilisé pour
    les régler. Technique absente du jeu de développement. À exécuter UNIQUEMENT dans la
    Windows Sandbox du labo (voir lab/README.md).
    Lance whoami.exe /all (utilisateur, groupes, privilèges du compte courant) et enregistre la
    sortie dans C:\travail\malsight_t15.txt. Vérité terrain : lab/verite-terrain/T15.json.

.PARAMETER Nettoyer
    Supprime le fichier créé.
#>
param([switch]$Nettoyer)

$Fichier = 'C:\travail\malsight_t15.txt'

if ($Nettoyer) {
    Remove-Item -Path $Fichier -ErrorAction SilentlyContinue
    Write-Host 'T15 : fichier supprimé.'
    return
}

Write-Host '=== T15 : découverte de l''utilisateur (test bénin) ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $Fichier) | Out-Null
$sortie = @(& whoami.exe /all)
$sortie | Set-Content -Path $Fichier -Encoding UTF8
Write-Host "[1] whoami.exe /all -> $Fichier ($($sortie.Count) lignes)"
Write-Host 'T15 terminé.'
