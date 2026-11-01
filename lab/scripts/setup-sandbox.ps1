<#
.SYNOPSIS
    Prépare la Windows Sandbox du labo MalSight : installe Sysmon et lance Procmon.

.DESCRIPTION
    Lancé automatiquement par la LogonCommand de lab/analyse.wsb.
    1. Copie les outils de C:\entree\outils (lecture seule) vers C:\labo-outils.
    2. Installe Sysmon avec C:\entree\outils\sysmonconfig-export.xml.
    3. Lance Procmon en capture vers C:\resultats\procmon_<date>.PML.
    4. Enregistre l'état de la session pour collect.ps1 et affiche les consignes.

    Ce script n'exécute aucun échantillon : l'exécution est faite à la main par l'analyste.
#>
$ErrorActionPreference = 'Stop'

$Entree     = 'C:\entree'
$Resultats  = 'C:\resultats'
$OutilsSrc  = Join-Path $Entree 'outils'
$OutilsLoc  = 'C:\labo-outils'
$Etat       = 'C:\labo-outils\session.json'
$ConfigSysmon = Join-Path $OutilsSrc 'sysmonconfig-export.xml'

function Find-Outil([string[]]$Noms) {
    foreach ($n in $Noms) {
        $p = Join-Path $OutilsLoc $n
        if (Test-Path $p) { return $p }
    }
    throw "Outil introuvable dans $OutilsSrc : $($Noms -join ', ')"
}

Write-Host '=== MalSight : préparation de la sandbox ===' -ForegroundColor Cyan

# --- Vérifications ---------------------------------------------------------
foreach ($p in @($OutilsSrc, $ConfigSysmon, $Resultats)) {
    if (-not (Test-Path $p)) { throw "Chemin manquant : $p (voir lab/README.md)" }
}

# --- Copie locale des outils (le dossier d'entrée est en lecture seule) ------
New-Item -ItemType Directory -Force -Path $OutilsLoc | Out-Null
Copy-Item -Path (Join-Path $OutilsSrc '*') -Destination $OutilsLoc -Recurse -Force

$Sysmon  = Find-Outil @('Sysmon64.exe', 'Sysmon.exe')
$Procmon = Find-Outil @('Procmon64.exe', 'Procmon.exe')

# --- Sysmon ----------------------------------------------------------------
Write-Host "[1/2] Installation de Sysmon ($([IO.Path]::GetFileName($Sysmon)))..."
& $Sysmon -accepteula -i (Join-Path $OutilsLoc 'sysmonconfig-export.xml') | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Échec de l'installation de Sysmon (code $LASTEXITCODE)" }

# --- Procmon ---------------------------------------------------------------
$Horodatage = Get-Date -Format 'yyyyMMdd-HHmmss'
$Pml = Join-Path $Resultats "procmon_$Horodatage.PML"
Write-Host "[2/2] Démarrage de Procmon -> $Pml"
Start-Process -FilePath $Procmon -ArgumentList @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', "`"$Pml`"")

# Attendre que la capture démarre réellement
$limite = (Get-Date).AddSeconds(30)
while (-not (Test-Path $Pml) -and (Get-Date) -lt $limite) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $Pml)) { Write-Warning "Le fichier $Pml n'apparaît pas encore : vérifier que Procmon tourne." }

# --- État de session pour collect.ps1 ---------------------------------------
@{
    debut   = (Get-Date).ToString('o')
    procmon = $Procmon
    pml     = $Pml
} | ConvertTo-Json | Set-Content -Path $Etat -Encoding UTF8

# --- Consignes -------------------------------------------------------------
Write-Host ''
Write-Host '=== Sandbox prête : Sysmon et Procmon enregistrent ===' -ForegroundColor Green
Write-Host @"

Consignes :
  1. Copier l'échantillon BÉNIN dans un dossier local, par exemple :
       Copy-Item C:\entree\samples\<fichier> C:\travail\ -Force
     (créer C:\travail au besoin ; ne rien exécuter depuis C:\resultats)
  2. Exécuter l'échantillon depuis C:\travail, puis attendre 2 à 3 minutes.
  3. Lancer la collecte dans cette fenêtre (PowerShell) :
       C:\entree\scripts\collect.ps1 -Echantillon <fichier>
  4. Vérifier les fichiers sur l'hôte dans C:\labo\resultats\<fichier>_<date>\
  5. Fermer la Windows Sandbox : tout son contenu est détruit.

Rappel : réseau coupé, échantillons bénins uniquement (docs/ethique.md).
"@
