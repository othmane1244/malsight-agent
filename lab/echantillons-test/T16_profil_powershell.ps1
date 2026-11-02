<#
.SYNOPSIS
    Échantillon de VALIDATION BÉNIN T16 : persistance par profil PowerShell (ATT&CK T1546.013).

.DESCRIPTION
    Jeu de validation (D4) : écrit avant les règles artefact -> technique, jamais utilisé pour
    les régler. Technique absente du jeu de développement. À exécuter UNIQUEMENT dans la
    Windows Sandbox du labo (voir lab/README.md).
    Ajoute au profil PowerShell de l'utilisateur courant (profil CurrentUserCurrentHost :
    Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1) une ligne inoffensive qui
    affiche un message. Le profil ne serait chargé qu'au prochain lancement de PowerShell sans
    -NoProfile. Vérité terrain : lab/verite-terrain/T16.json.

.PARAMETER Nettoyer
    Supprime le profil créé.
#>
param([switch]$Nettoyer)

$Profil = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'

if ($Nettoyer) {
    Remove-Item -Path $Profil -ErrorAction SilentlyContinue
    Write-Host 'T16 : profil supprimé.'
    return
}

Write-Host '=== T16 : persistance par profil PowerShell (test bénin) ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $Profil) | Out-Null
Add-Content -Path $Profil -Value "Write-Host 'MalSight T16 - profil PowerShell de test'"
Write-Host "[1] Profil : $Profil (ligne Write-Host ajoutée)"
Write-Host 'T16 terminé.'
