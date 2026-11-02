<#
.SYNOPSIS
    Échantillon de test BÉNIN T05 : modification du registre (ATT&CK T1112).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Crée la clé HKCU\Software\MalsightTest et la valeur « Config ». Cette clé n'est pas
    couverte par la config Sysmon SwiftOnSecurity : elle n'est visible que dans Procmon
    (sert à tester la fusion Sysmon + Procmon). Vérité terrain : lab/verite-terrain/T05.json.

.PARAMETER Nettoyer
    Supprime la clé créée.
#>
param([switch]$Nettoyer)

$Cle = 'HKCU:\Software\MalsightTest'

if ($Nettoyer) {
    Remove-Item -Path $Cle -Recurse -ErrorAction SilentlyContinue
    Write-Host 'T05 : clé supprimée.'
    return
}

Write-Host '=== T05 : modification du registre (test bénin) ===' -ForegroundColor Cyan
New-Item -Path $Cle -Force | Out-Null
New-ItemProperty -Path $Cle -Name 'Config' -Value 'mode=test;intervalle=60' -PropertyType String -Force | Out-Null
Write-Host "[1] Registre : $Cle\Config = mode=test;intervalle=60"
Write-Host 'T05 terminé.'
