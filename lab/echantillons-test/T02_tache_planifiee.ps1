<#
.SYNOPSIS
    Échantillon de test BÉNIN T02 : tâche planifiée (ATT&CK T1053.005).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Crée la tâche « MalsightTest » qui lancerait notepad.exe le 1er janvier 2099 :
    elle ne se déclenche jamais pendant l'analyse. Vérité terrain : lab/verite-terrain/T02.json.

.PARAMETER Nettoyer
    Supprime la tâche créée.
#>
param([switch]$Nettoyer)

$Nom = 'MalsightTest'

if ($Nettoyer) {
    Unregister-ScheduledTask -TaskName $Nom -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host 'T02 : tâche supprimée.'
    return
}

Write-Host '=== T02 : tâche planifiée (test bénin) ===' -ForegroundColor Cyan
$action  = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\notepad.exe')
$trigger = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01T00:00:00')
Register-ScheduledTask -TaskName $Nom -Action $action -Trigger $trigger -Force | Out-Null
Write-Host "[1] Tâche « $Nom » -> notepad.exe, déclenchement le 2099-01-01 (jamais pendant l'analyse)"
Write-Host 'T02 terminé.'
