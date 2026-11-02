<#
.SYNOPSIS
    Vérifie, côté HÔTE, les prérequis du labo avant d'ouvrir lab\analyse.wsb.

.DESCRIPTION
    Contrôle l'arborescence C:\labo : outils (Sysmon, Procmon, config SwiftOnSecurity valide),
    scripts copiés et à jour par rapport au dépôt, échantillons présents, dossier de résultats
    vide. Code de sortie 0 si tout est bon, 1 sinon. Ne modifie rien.

.PARAMETER Labo
    Racine du labo (défaut : C:\labo).

.EXAMPLE
    .\lab\scripts\verifier-prerequis.ps1
#>
param([string]$Labo = 'C:\labo')

$Depot   = Split-Path (Split-Path $PSScriptRoot)   # racine du dépôt (lab\scripts\..\..)
$Outils  = [IO.Path]::Combine($Labo, 'entree', 'outils')
$Scripts = [IO.Path]::Combine($Labo, 'entree', 'scripts')
$Samples = [IO.Path]::Combine($Labo, 'entree', 'samples')
$Result  = Join-Path $Labo 'resultats'

$erreurs = 0
function Ok([string]$m)     { Write-Host "  [OK]  $m" -ForegroundColor Green }
function Ko([string]$m)     { Write-Host "  [KO]  $m" -ForegroundColor Red; $script:erreurs++ }
function Avert([string]$m)  { Write-Host "  [!!]  $m" -ForegroundColor Yellow }
function Un-De([string]$dir, [string[]]$noms) {
    foreach ($n in $noms) { if (Test-Path (Join-Path $dir $n)) { return $n } }
    return $null
}

Write-Host "=== Prérequis du labo MalSight ($Labo) ===" -ForegroundColor Cyan

# --- Windows Sandbox -------------------------------------------------------------
if ($env:WINDIR -and (Test-Path ([IO.Path]::Combine($env:WINDIR, 'System32', 'WindowsSandbox.exe')))) { Ok 'Windows Sandbox activée' }
else { Avert 'WindowsSandbox.exe introuvable : vérifier que la fonctionnalité est activée' }

# --- Dossiers ---------------------------------------------------------------------
foreach ($d in @($Outils, $Scripts, $Samples, $Result)) {
    if (Test-Path $d -PathType Container) { Ok "Dossier $d" } else { Ko "Dossier manquant : $d" }
}

# --- Outils -----------------------------------------------------------------------
$s = Un-De $Outils @('Sysmon64.exe', 'Sysmon.exe')
if ($s) { Ok "Sysmon ($s)" } else { Ko "Sysmon64.exe introuvable dans $Outils" }
$p = Un-De $Outils @('Procmon64.exe', 'Procmon.exe')
if ($p) { Ok "Procmon ($p)" } else { Ko "Procmon64.exe introuvable dans $Outils" }

$cfg = Join-Path $Outils 'sysmonconfig-export.xml'
if (-not (Test-Path $cfg)) {
    Ko "sysmonconfig-export.xml manquant dans $Outils (SwiftOnSecurity/sysmon-config)"
} else {
    try {
        $x = New-Object System.Xml.XmlDocument; $x.Load($cfg)
        if ($x.SelectSingleNode('/Sysmon/EventFiltering')) { Ok 'sysmonconfig-export.xml valide' }
        else { Ko 'sysmonconfig-export.xml : pas de /Sysmon/EventFiltering' }
    } catch { Ko "sysmonconfig-export.xml illisible : $($_.Exception.Message)" }
}

# --- Scripts copiés et à jour ------------------------------------------------------
$attendus = @('setup-sandbox.ps1', 'collect.ps1', 'Merge-SysmonConfig.ps1', 'sysmon-malsight.xml')
foreach ($f in $attendus) {
    $cible = Join-Path $Scripts $f
    $source = if ($f -like '*.xml') { [IO.Path]::Combine($Depot, 'lab', $f) } else { [IO.Path]::Combine($Depot, 'lab', 'scripts', $f) }
    if (-not (Test-Path $cible)) { Ko "Script manquant : $cible"; continue }
    if ((Test-Path $source) -and ((Get-FileHash $source).Hash -ne (Get-FileHash $cible).Hash)) {
        Ko "$f n'est pas à jour par rapport au dépôt (recopier, voir lab/README.md)"
    } else { Ok "Script $f" }
}

# --- Échantillons et résultats ---------------------------------------------------------
if ((Test-Path $Samples) -and (Get-ChildItem $Samples -File)) { Ok "Échantillon(s) dans $Samples" }
else { Avert "Aucun échantillon dans $Samples" }
if ((Test-Path $Result) -and (Get-ChildItem $Result)) {
    Avert "$Result n'est pas vide : copier les résultats précédents puis le vider (docs/ethique.md)"
}

Write-Host ''
if ($erreurs) {
    Write-Host "$erreurs prérequis manquant(s) : ne pas lancer analyse.wsb." -ForegroundColor Red
    exit 1
}
Write-Host 'Tout est prêt : double-cliquer sur lab\analyse.wsb.' -ForegroundColor Green
exit 0
