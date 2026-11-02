<#
.SYNOPSIS
    Mode automatique (décision D3) : analyse UN échantillon de test dans une Windows Sandbox.

.DESCRIPTION
    À lancer sur l'HÔTE, depuis la racine du dépôt :
    1. N'accepte qu'un identifiant de lab/echantillons-test/ (T01, T02...) ayant une vérité
       terrain dans lab/verite-terrain/ ; refuse tout le reste.
    2. Génère un .wsb temporaire à partir de lab/analyse.wsb (mêmes restrictions : réseau,
       vGPU, presse-papiers coupés) dont la LogonCommand lance analyse-auto.ps1.
    3. Copie les scripts et l'échantillon dans C:\labo\entree, puis lance verifier-prerequis.ps1.
    4. Ouvre la sandbox, attend le dossier de résultats (ou un journal d'erreur), puis supprime
       le .wsb temporaire. La sandbox s'éteint toute seule après la collecte.

.PARAMETER Echantillon
    Identifiant de l'échantillon (ex. : T02).

.PARAMETER Attente
    Secondes d'attente entre l'exécution et la collecte (défaut : 90).

.PARAMETER SansLancer
    Valide l'échantillon et génère le .wsb, sans rien copier ni lancer (vérification, tests).

.EXAMPLE
    .\lab\scripts\lancer-analyse.ps1 -Echantillon T02
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^T\d{2}$')][string]$Echantillon,
    [ValidateRange(30, 600)][int]$Attente = 90,
    [string]$Labo = 'C:\labo',
    [ValidateRange(120, 3600)][int]$DelaiMax = 900,
    [switch]$SansLancer,
    [string]$SortieWsb
)
$ErrorActionPreference = 'Stop'

$Depot       = Split-Path (Split-Path $PSScriptRoot)
$DossierEch  = [IO.Path]::Combine($Depot, 'lab', 'echantillons-test')
$Verite      = [IO.Path]::Combine($Depot, 'lab', 'verite-terrain', "$Echantillon.json")
$ModeleWsb   = [IO.Path]::Combine($Depot, 'lab', 'analyse.wsb')

# --- 1. Échantillon autorisé ? ------------------------------------------------------
$scripts = @(Get-ChildItem -Path $DossierEch -File -Filter "${Echantillon}_*.ps1")
if ($scripts.Count -ne 1) {
    Write-Host "Refusé : $Echantillon ne correspond pas à exactement un script de lab/echantillons-test/ ($($scripts.Count) trouvé(s))." -ForegroundColor Red
    exit 2
}
if (-not (Test-Path $Verite)) {
    Write-Host "Refusé : pas de vérité terrain pour $Echantillon ($Verite)." -ForegroundColor Red
    exit 2
}
$Fichier = $scripts[0].Name

# --- 2. .wsb temporaire ---------------------------------------------------------------
$wsb = New-Object System.Xml.XmlDocument
$wsb.Load($ModeleWsb)
if ($wsb.SelectSingleNode('/Configuration/Networking').InnerText -ne 'Disable') {
    throw "lab/analyse.wsb n'a plus le réseau désactivé : refus de lancer une analyse automatique."
}
$commande = 'cmd.exe /c start "MalSight auto {0}" powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File C:\entree\scripts\analyse-auto.ps1 -Echantillon {1} -Attente {2}' -f $Echantillon, $Fichier, $Attente
$wsb.SelectSingleNode('/Configuration/LogonCommand/Command').InnerText = $commande
if (-not $SortieWsb) {
    $SortieWsb = Join-Path ([IO.Path]::GetTempPath()) ("malsight-{0}-{1}.wsb" -f $Echantillon, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$wsb.Save([IO.Path]::GetFullPath($SortieWsb))
Write-Host "Échantillon : $Fichier (vérité terrain : $Echantillon.json)"
Write-Host ".wsb généré : $SortieWsb"
if ($SansLancer) { exit 0 }

# --- 3. Copie et prérequis ---------------------------------------------------------------
$entree = [IO.Path]::Combine($Labo, 'entree')
Copy-Item -Path ([IO.Path]::Combine($Depot, 'lab', 'scripts', '*.ps1')), ([IO.Path]::Combine($Depot, 'lab', 'sysmon-malsight.xml')) `
    -Destination ([IO.Path]::Combine($entree, 'scripts')) -Force
Copy-Item -Path $scripts[0].FullName -Destination ([IO.Path]::Combine($entree, 'samples')) -Force
& (Join-Path $PSScriptRoot 'verifier-prerequis.ps1') -Labo $Labo
if ($LASTEXITCODE -ne 0) { Remove-Item $SortieWsb -ErrorAction SilentlyContinue; exit 1 }

if (Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue) {
    Remove-Item $SortieWsb -ErrorAction SilentlyContinue
    Write-Host 'Une Windows Sandbox est déjà ouverte : la fermer avant de lancer une analyse.' -ForegroundColor Red
    exit 1
}

# --- 4. Lancement et attente des résultats ------------------------------------------------
$resultats = [IO.Path]::Combine($Labo, 'resultats')
$debut = Get-Date
Write-Host "Ouverture de la sandbox (délai maximal : $DelaiMax s)..." -ForegroundColor Cyan
Start-Process -FilePath $SortieWsb

$prefixe = ($Fichier -replace '[^\w.\-]', '_') + '_'
$issue = $null
while (-not $issue -and ((Get-Date) - $debut).TotalSeconds -lt $DelaiMax) {
    Start-Sleep -Seconds 10
    $ok = Get-ChildItem $resultats -Directory -Filter "$prefixe*" -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -ge $debut -and (Test-Path (Join-Path $_.FullName 'auto.json')) } |
        Select-Object -First 1
    $err = Get-ChildItem $resultats -File -Filter '*-erreur_*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -ge $debut } | Select-Object -First 1
    if ($ok) { $issue = "ok:$($ok.FullName)" } elseif ($err) { $issue = "erreur:$($err.FullName)" }
}
Remove-Item $SortieWsb -ErrorAction SilentlyContinue

# Après un succès, la sandbox s'éteint d'elle-même (shutdown /t 10) : attendre qu'elle soit
# fermée avant de rendre la main, sinon l'analyse suivante trouverait une sandbox ouverte.
if ($issue -like 'ok:*') {
    $fin = (Get-Date).AddSeconds(180)
    while ((Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $fin) {
        Start-Sleep -Seconds 5
    }
    if (Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue) {
        Write-Host 'Résultats complets, mais la sandbox est toujours ouverte après 180 s : la fermer avant l''analyse suivante.' -ForegroundColor Yellow
        exit 1
    }
}

switch -Wildcard ($issue) {
    'ok:*'     { Write-Host "Analyse terminée : $($issue.Substring(3)) (sandbox fermée)" -ForegroundColor Green; exit 0 }
    'erreur:*' { Write-Host "Échec, journal : $($issue.Substring(7)) (la sandbox est restée ouverte)" -ForegroundColor Red; exit 1 }
    default    { Write-Host "Délai dépassé ($DelaiMax s) sans résultat : vérifier la fenêtre de la sandbox." -ForegroundColor Red; exit 1 }
}
