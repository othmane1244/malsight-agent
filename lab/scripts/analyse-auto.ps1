<#
.SYNOPSIS
    Analyse automatique d'UN échantillon de test, DANS la Windows Sandbox (décision D3).

.DESCRIPTION
    Lancé par la LogonCommand du .wsb temporaire généré par lab/scripts/lancer-analyse.ps1.
    1. Prépare la sandbox (setup-sandbox.ps1 : Sysmon, Procmon, C:\travail).
    2. Copie l'échantillon de C:\entree\samples vers C:\travail et l'exécute dans un processus
       PowerShell séparé (son PID est noté pour filtrer les journaux).
    3. Attend -Attente secondes, puis lance collect.ps1.
    4. Écrit auto.json dans le dossier de résultats, puis éteint la sandbox.
    En cas d'erreur : message en rouge, journal copié dans C:\resultats\auto-erreur_<date>.log,
    et la sandbox reste ouverte pour le diagnostic.

.PARAMETER Echantillon
    Nom du fichier dans C:\entree\samples (ex. : T02_tache_planifiee.ps1).
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^T\d{2}_[\w-]+\.ps1$')][string]$Echantillon,
    [ValidateRange(30, 600)][int]$Attente = 90,
    [switch]$SansExtinction
)
$ErrorActionPreference = 'Stop'

$Scripts   = 'C:\entree\scripts'
$Resultats = 'C:\resultats'
$Travail   = 'C:\travail'
$Journal   = Join-Path $env:TEMP 'malsight-analyse-auto.log'

Start-Transcript -Path $Journal -Force | Out-Null
try {
    Write-Host "=== MalSight : analyse automatique de $Echantillon ===" -ForegroundColor Cyan

    # 1. Préparation (setup-sandbox.ps1 n'interrompt pas l'appelant : on vérifie son état)
    & (Join-Path $Scripts 'setup-sandbox.ps1')
    if (-not (Test-Path 'C:\labo-outils\session.json')) {
        throw 'La préparation de la sandbox a échoué (voir le message rouge ci-dessus).'
    }

    # 2. Exécution de l'échantillon dans un processus séparé
    $source = Join-Path 'C:\entree\samples' $Echantillon
    if (-not (Test-Path $source)) { throw "Échantillon introuvable : $source" }
    Copy-Item $source $Travail -Force
    $cible = Join-Path $Travail $Echantillon
    $debut = Get-Date
    Write-Host "[auto] Exécution de $cible"
    $proc = Start-Process -FilePath 'powershell.exe' -PassThru -Wait -NoNewWindow -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$cible`"")
    Write-Host "[auto] Terminé : PID $($proc.Id), code de sortie $($proc.ExitCode)"

    # 3. Attente puis collecte
    Write-Host "[auto] Attente de $Attente s avant la collecte..."
    Start-Sleep -Seconds $Attente
    & (Join-Path $Scripts 'collect.ps1') -Echantillon $Echantillon

    # 4. Trace de l'exécution automatique, dans le dossier que collect.ps1 vient de créer
    $nom = [IO.Path]::GetFileName($Echantillon) -replace '[^\w.\-]', '_'
    $sortie = Get-ChildItem $Resultats -Directory -Filter "${nom}_*" |
        Sort-Object LastWriteTime | Select-Object -Last 1
    if (-not $sortie) { throw 'Dossier de résultats introuvable après collect.ps1.' }
    [ordered]@{
        mode            = 'automatique (lancer-analyse.ps1, D3)'
        echantillon     = $Echantillon
        pid_echantillon = $proc.Id
        code_sortie     = $proc.ExitCode
        debut_execution = $debut.ToString('o')
        attente_s       = $Attente
    } | ConvertTo-Json | Set-Content -Path (Join-Path $sortie.FullName 'auto.json') -Encoding UTF8
    Write-Host "[auto] Résultats : $($sortie.FullName)" -ForegroundColor Green
    Stop-Transcript | Out-Null
}
catch {
    Write-Host ''
    Write-Host '=== ÉCHEC DE L''ANALYSE AUTOMATIQUE : la sandbox reste ouverte ===' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Stop-Transcript | Out-Null
    Copy-Item $Journal (Join-Path $Resultats ("auto-erreur_{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))) -ErrorAction SilentlyContinue
    return
}

if (-not $SansExtinction) {
    Write-Host '[auto] Extinction de la sandbox dans 10 s (tout son contenu sera détruit).'
    & shutdown.exe /s /t 10
}
