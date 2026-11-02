<#
.SYNOPSIS
    Prépare la Windows Sandbox du labo MalSight : installe Sysmon et lance Procmon.

.DESCRIPTION
    Lancé automatiquement par la LogonCommand de lab/analyse.wsb (fenêtre -NoExit).
    1. Règle ExecutionPolicy Bypass pour la session et crée C:\travail.
    2. Copie les outils de C:\entree\outils (lecture seule) vers C:\labo-outils.
    3. Installe Sysmon avec la config SwiftOnSecurity fusionnée avec lab/sysmon-malsight.xml.
    4. Lance Procmon en capture LOCALE (C:\labo-outils\procmon.PML) : Procmon gère mal
       l'écriture directe dans un dossier partagé avec l'hôte ; collect.ps1 copie ensuite.
    5. Enregistre l'état de la session pour collect.ps1 et affiche les consignes.
    En cas d'erreur : message en rouge dans la fenêtre, et journal copié dans
    C:\resultats\setup-erreur_<date>.log pour qu'il soit visible depuis l'hôte.

    Ce script n'exécute aucun échantillon : l'exécution est faite à la main par l'analyste.
#>
$ErrorActionPreference = 'Stop'

$Entree       = 'C:\entree'
$Resultats    = 'C:\resultats'
$Travail      = 'C:\travail'
$OutilsSrc    = Join-Path $Entree 'outils'
$OutilsLoc    = 'C:\labo-outils'
$Etat         = Join-Path $OutilsLoc 'session.json'
$Journal      = Join-Path $OutilsLoc 'setup.log'
$ConfigSysmon = Join-Path $OutilsSrc 'sysmonconfig-export.xml'
$ReglesMaison = Join-Path $Entree 'scripts\sysmon-malsight.xml'
$ConfigFusion = Join-Path $OutilsLoc 'sysmon-config-fusion.xml'
$Pml          = Join-Path $OutilsLoc 'procmon.PML'

function Find-Outil([string[]]$Noms) {
    foreach ($n in $Noms) {
        $p = Join-Path $OutilsLoc $n
        if (Test-Path $p) { return $p }
    }
    throw "Outil introuvable dans $OutilsSrc : $($Noms -join ', ')"
}

New-Item -ItemType Directory -Force -Path $OutilsLoc, $Travail | Out-Null
Start-Transcript -Path $Journal -Force | Out-Null

try {
    Write-Host '=== MalSight : préparation de la sandbox ===' -ForegroundColor Cyan

    # --- Session : ExecutionPolicy et dossier de travail ------------------------
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Write-Host "ExecutionPolicy Bypass (session) ; dossier de travail : $Travail"

    # --- Prérequis (voir aussi lab/scripts/verifier-prerequis.ps1 côté hôte) ----
    $manquants = @($OutilsSrc, $ConfigSysmon, $ReglesMaison, $Resultats) | Where-Object { -not (Test-Path $_) }
    if ($manquants) {
        throw "Prérequis manquants : $($manquants -join ', '). Lancer lab\scripts\verifier-prerequis.ps1 sur l'hôte."
    }

    # --- Copie locale des outils (le dossier d'entrée est en lecture seule) ------
    Copy-Item -Path (Join-Path $OutilsSrc '*') -Destination $OutilsLoc -Recurse -Force
    $Sysmon  = Find-Outil @('Sysmon64.exe', 'Sysmon.exe')
    $Procmon = Find-Outil @('Procmon64.exe', 'Procmon.exe')

    # --- Sysmon : config SwiftOnSecurity + règles maison (événement 11 dans C:\travail\)
    & (Join-Path $Entree 'scripts\Merge-SysmonConfig.ps1') -Base $ConfigSysmon -Ajout $ReglesMaison -Sortie $ConfigFusion
    Write-Host "[1/2] Installation de Sysmon ($([IO.Path]::GetFileName($Sysmon)))..."
    & $Sysmon -accepteula -i $ConfigFusion | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Échec de l'installation de Sysmon (code $LASTEXITCODE)" }

    # --- Procmon : capture en local ----------------------------------------------
    Write-Host "[2/2] Démarrage de Procmon -> $Pml"
    Start-Process -FilePath $Procmon -ArgumentList @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', "`"$Pml`"")
    $limite = (Get-Date).AddSeconds(30)
    while (-not (Test-Path $Pml) -and (Get-Date) -lt $limite) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path $Pml)) { throw "Procmon n'a pas créé $Pml en 30 s." }

    # --- État de session pour collect.ps1 -----------------------------------------
    @{
        debut         = (Get-Date).ToString('o')
        procmon       = $Procmon
        pml           = $Pml
        sysmon_config = $ConfigFusion
    } | ConvertTo-Json | Set-Content -Path $Etat -Encoding UTF8

    Write-Host ''
    Write-Host '=== Sandbox prête : Sysmon et Procmon enregistrent ===' -ForegroundColor Green
    Write-Host @"

Consignes (dans CETTE fenêtre, ExecutionPolicy déjà réglée) :
  1. Copier l'échantillon BÉNIN dans le dossier de travail :
       Copy-Item C:\entree\samples\<fichier> $Travail\ -Force
     (ne rien exécuter depuis C:\resultats)
  2. Exécuter l'échantillon depuis $Travail, puis attendre 2 à 3 minutes.
       ex. : & $Travail\T01_persistance_run.ps1
  3. Lancer la collecte :
       C:\entree\scripts\collect.ps1 -Echantillon <fichier>
  4. Vérifier les fichiers sur l'hôte dans C:\labo\resultats\<fichier>_<date>\
  5. Fermer la Windows Sandbox : tout son contenu est détruit.

Rappel : réseau coupé, échantillons bénins uniquement (docs/ethique.md).
"@
}
catch {
    Write-Host ''
    Write-Host '=== ÉCHEC DE LA PRÉPARATION : ne pas exécuter d''échantillon ===' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "Journal : $Journal" -ForegroundColor Yellow
    Stop-Transcript | Out-Null
    if (Test-Path $Resultats) {
        $copie = Join-Path $Resultats ("setup-erreur_{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Copy-Item $Journal $copie -ErrorAction SilentlyContinue
        Write-Host "Copie du journal pour l'hôte : $copie" -ForegroundColor Yellow
    }
    return
}
Stop-Transcript | Out-Null
