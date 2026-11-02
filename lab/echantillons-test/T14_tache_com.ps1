<#
.SYNOPSIS
    Échantillon de VALIDATION BÉNIN T14 : tâche planifiée via l'API COM (ATT&CK T1053.005).

.DESCRIPTION
    Jeu de validation (D4) : écrit avant les règles artefact -> technique, jamais utilisé pour
    les régler. À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Crée la tâche « MalsightTest14 » avec l'objet COM Schedule.Service (et non le module
    ScheduledTasks ni schtasks.exe) : action notepad.exe, déclenchement unique le 1er janvier
    2099, donc jamais pendant l'analyse. Vérité terrain : lab/verite-terrain/T14.json.

.PARAMETER Nettoyer
    Supprime la tâche créée.
#>
param([switch]$Nettoyer)

$Nom = 'MalsightTest14'
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$racine = $service.GetFolder('\')

if ($Nettoyer) {
    try { $racine.DeleteTask($Nom, 0) } catch { }
    Write-Host 'T14 : tâche supprimée.'
    return
}

Write-Host '=== T14 : tâche planifiée via COM (test bénin) ===' -ForegroundColor Cyan
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = 'MalSight T14 - tâche de test bénigne'
$declencheur = $definition.Triggers.Create(1)            # 1 = TASK_TRIGGER_TIME (une fois)
$declencheur.StartBoundary = '2099-01-01T00:00:00'
$action = $definition.Actions.Create(0)                  # 0 = TASK_ACTION_EXEC
$action.Path = Join-Path $env:WINDIR 'System32\notepad.exe'
# 6 = TASK_CREATE_OR_UPDATE ; 3 = TASK_LOGON_INTERACTIVE_TOKEN (utilisateur courant)
$racine.RegisterTaskDefinition($Nom, $definition, 6, $null, $null, 3) | Out-Null
Write-Host "[1] Tâche « $Nom » -> notepad.exe, déclenchement le 2099-01-01 (API COM Schedule.Service)"
Write-Host 'T14 terminé.'
