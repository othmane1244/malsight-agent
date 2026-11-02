<#
.SYNOPSIS
    Échantillon de test BÉNIN T04 : script de logon (ATT&CK T1037.001).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (voir lab/README.md).
    Écrit HKCU\Environment\UserInitMprLogonScript = notepad.exe (pris en compte seulement
    à la prochaine ouverture de session, qui n'a pas lieu dans la sandbox).
    Vérité terrain : lab/verite-terrain/T04.json.

.PARAMETER Nettoyer
    Supprime la valeur créée.
#>
param([switch]$Nettoyer)

$Cle  = 'HKCU:\Environment'
$Nom  = 'UserInitMprLogonScript'

if ($Nettoyer) {
    Remove-ItemProperty -Path $Cle -Name $Nom -ErrorAction SilentlyContinue
    Write-Host 'T04 : valeur supprimée.'
    return
}

Write-Host '=== T04 : script de logon (test bénin) ===' -ForegroundColor Cyan
$cible = Join-Path $env:WINDIR 'System32\notepad.exe'
New-ItemProperty -Path $Cle -Name $Nom -Value $cible -PropertyType String -Force | Out-Null
Write-Host "[1] Registre : $Cle\$Nom = $cible"
Write-Host 'T04 terminé.'
