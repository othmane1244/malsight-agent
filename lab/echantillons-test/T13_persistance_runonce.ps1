<#
.SYNOPSIS
    Échantillon de VALIDATION BÉNIN T13 : persistance par clé RunOnce (ATT&CK T1547.001).

.DESCRIPTION
    Jeu de validation (D4) : écrit avant les règles artefact -> technique, jamais utilisé pour
    les régler. À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Écrit la valeur « MalsightTest13 » dans HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce,
    pointant vers notepad.exe (lancé une seule fois à la prochaine ouverture de session, qui
    n'a pas lieu dans la sandbox). Vérité terrain : lab/verite-terrain/T13.json.

.PARAMETER Nettoyer
    Supprime la valeur créée.
#>
param([switch]$Nettoyer)

$Cle = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$Nom = 'MalsightTest13'

if ($Nettoyer) {
    Remove-ItemProperty -Path $Cle -Name $Nom -ErrorAction SilentlyContinue
    Write-Host 'T13 : valeur RunOnce supprimée.'
    return
}

Write-Host '=== T13 : persistance par clé RunOnce (test bénin) ===' -ForegroundColor Cyan
if (-not (Test-Path $Cle)) { New-Item -Path $Cle -Force | Out-Null }
$cible = Join-Path $env:WINDIR 'System32\notepad.exe'
New-ItemProperty -Path $Cle -Name $Nom -Value $cible -PropertyType String -Force | Out-Null
Write-Host "[1] Registre : $Cle\$Nom = $cible"
Write-Host 'T13 terminé.'
