<#
.SYNOPSIS
    Échantillon de test BÉNIN T03 : création d'un service Windows (ATT&CK T1543.003).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (console administrateur).
    Crée le service « MalsightTest » (démarrage manuel, binaire notepad.exe). Le service
    n'est jamais démarré. Vérité terrain : lab/verite-terrain/T03.json.

.PARAMETER Nettoyer
    Supprime le service créé.
#>
param([switch]$Nettoyer)

$Nom = 'MalsightTest'

if ($Nettoyer) {
    & sc.exe delete $Nom | Out-Null
    Write-Host 'T03 : service supprimé.'
    return
}

Write-Host '=== T03 : service Windows (test bénin) ===' -ForegroundColor Cyan
New-Service -Name $Nom -DisplayName 'MalSight Test' -StartupType Manual `
    -BinaryPathName (Join-Path $env:WINDIR 'System32\notepad.exe') | Out-Null
Write-Host "[1] Service « $Nom » créé (démarrage manuel, jamais démarré) -> notepad.exe"
Write-Host 'T03 terminé.'
