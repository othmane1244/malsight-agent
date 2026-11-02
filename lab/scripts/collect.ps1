<#
.SYNOPSIS
    Collecte les journaux d'une analyse dans la Windows Sandbox du labo MalSight.

.DESCRIPTION
    À lancer après l'exécution de l'échantillon (dans la sandbox, en administrateur) :
    1. Arrête Procmon (attend la fin du processus), convertit la capture locale .PML en CSV,
       puis copie les deux vers le dossier de résultats.
    2. Exporte le journal Sysmon en .evtx et en CSV (une colonne par champ EventData).
    3. Range le tout dans C:\resultats\<nom-echantillon>_<date>\ avec un manifeste JSON.

.PARAMETER Echantillon
    Nom du fichier de l'échantillon (ex. : test-registre.exe). Sert à nommer le dossier
    de sortie ; si le fichier existe dans C:\entree\samples, son SHA-256 est ajouté au manifeste.

.EXAMPLE
    C:\entree\scripts\collect.ps1 -Echantillon test-registre.exe
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Echantillon
)
$ErrorActionPreference = 'Stop'

$Resultats = 'C:\resultats'
$Etat      = 'C:\labo-outils\session.json'
$Temp      = Join-Path $env:TEMP 'malsight-collecte'
$LogSysmon = 'Microsoft-Windows-Sysmon/Operational'

if (-not (Test-Path $Etat)) { throw "Session introuvable ($Etat) : setup-sandbox.ps1 a-t-il été lancé ?" }
$session = Get-Content $Etat -Raw | ConvertFrom-Json

# --- Dossier de sortie -----------------------------------------------------
$nom = [IO.Path]::GetFileName($Echantillon) -replace '[^\w.\-]', '_'
$Horodatage = Get-Date -Format 'yyyyMMdd-HHmmss'
$Sortie = Join-Path $Resultats "${nom}_$Horodatage"
New-Item -ItemType Directory -Force -Path $Sortie, $Temp | Out-Null
Write-Host "=== Collecte vers $Sortie ===" -ForegroundColor Cyan

# --- 1. Procmon : arrêt, conversion en local, puis copie ----------------------
# Le PML est écrit en local (C:\labo-outils) : il n'est finalisé qu'une fois Procmon
# complètement arrêté. On attend donc la fin du processus avant toute conversion,
# et on ne copie vers C:\resultats qu'à la fin.
function Wait-Procmon([int]$Secondes = 120) {
    $procs = Get-Process -Name 'Procmon', 'Procmon64', 'Procmon64a' -ErrorAction SilentlyContinue
    if ($procs) { $procs | Wait-Process -Timeout $Secondes -ErrorAction SilentlyContinue }
    if (Get-Process -Name 'Procmon', 'Procmon64', 'Procmon64a' -ErrorAction SilentlyContinue) {
        throw "Procmon tourne encore après $Secondes s : relancer collect.ps1."
    }
}

Write-Host '[1/3] Arrêt de Procmon...'
Start-Process -FilePath $session.procmon -ArgumentList '/Terminate' -Wait
Wait-Procmon

$pml = $session.pml
if (Test-Path $pml) {
    $flux = [IO.File]::OpenRead($pml); $entete = New-Object byte[] 4
    [void]$flux.Read($entete, 0, 4); $flux.Close()
    $sig = [Text.Encoding]::ASCII.GetString($entete)
    if ($sig -ne 'PML_') { Write-Warning "En-tête PML inattendu ('$sig') : la capture n'est peut-être pas finalisée." }

    $csvLocal = Join-Path $Temp 'procmon.csv'
    Write-Host '      Conversion PML -> CSV (en local)...'
    Start-Process -FilePath $session.procmon -Wait -ArgumentList @(
        '/AcceptEula', '/Quiet', '/Minimized',
        '/OpenLog', "`"$pml`"", '/SaveAs', "`"$csvLocal`"")
    Wait-Procmon
    if (-not (Test-Path $csvLocal)) { Write-Warning 'La conversion Procmon n''a pas produit de CSV.' }

    Write-Host '      Copie vers le dossier de résultats...'
    # Procmon peut découper la capture (procmon-1.PML...) : on copie aussi les morceaux
    $base = [IO.Path]::GetFileNameWithoutExtension($pml)
    Get-ChildItem -Path (Split-Path $pml) -Filter "$base*.PML" | Copy-Item -Destination $Sortie
    if (Test-Path $csvLocal) { Copy-Item $csvLocal (Join-Path $Sortie 'procmon.csv') }
} else {
    Write-Warning "Capture Procmon introuvable : $pml"
}

# --- 2. Sysmon : EVTX ------------------------------------------------------
# wevtutil écrit via le service Journal d'événements : on exporte en local puis on copie.
Write-Host '[2/3] Export du journal Sysmon (.evtx)...'
$evtxLocal = Join-Path $Temp 'sysmon.evtx'
if (Test-Path $evtxLocal) { Remove-Item $evtxLocal -Force }
& wevtutil.exe epl $LogSysmon $evtxLocal
if ($LASTEXITCODE -ne 0) { throw "Échec de l'export Sysmon (code $LASTEXITCODE)" }
Copy-Item $evtxLocal (Join-Path $Sortie 'sysmon.evtx')
# Config Sysmon effectivement utilisée (SwiftOnSecurity + règles maison), pour la traçabilité
if ($session.sysmon_config -and (Test-Path $session.sysmon_config)) {
    Copy-Item $session.sysmon_config (Join-Path $Sortie 'sysmon-config.xml')
}

# --- 3. Sysmon : CSV -------------------------------------------------------
Write-Host '[3/3] Conversion du journal Sysmon en CSV...'
$lignes = @()
$evenements = @(Get-WinEvent -Path $evtxLocal -Oldest -ErrorAction SilentlyContinue)
foreach ($e in $evenements) {
    $ligne = [ordered]@{
        TimeCreated = $e.TimeCreated.ToString('o')
        EventID     = $e.Id
        Task        = $e.TaskDisplayName
        RecordID    = $e.RecordId
    }
    foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $ligne[$d.Name] = $d.'#text' }
    $lignes += [pscustomobject]$ligne
}
$csvSysmon = Join-Path $Sortie 'sysmon.csv'
if ($lignes.Count -gt 0) {
    # Export-Csv ne garde que les colonnes du premier objet : on prend l'union des champs.
    $colonnes = [System.Collections.Generic.List[string]]::new()
    foreach ($l in $lignes) {
        foreach ($p in $l.PSObject.Properties.Name) { if (-not $colonnes.Contains($p)) { $colonnes.Add($p) } }
    }
    $lignes | Select-Object -Property $colonnes | Export-Csv -Path $csvSysmon -NoTypeInformation -Encoding UTF8
} else {
    Write-Warning 'Aucun événement Sysmon.'
}

# --- Manifeste ---------------------------------------------------------------
$sha256 = $null
$chemin = Join-Path 'C:\entree\samples' ([IO.Path]::GetFileName($Echantillon))
if (Test-Path $chemin) { $sha256 = (Get-FileHash -Path $chemin -Algorithm SHA256).Hash.ToLower() }

[ordered]@{
    echantillon      = $Echantillon
    sha256           = $sha256
    debut_capture    = $session.debut
    fin_capture      = (Get-Date).ToString('o')
    evenements_sysmon = $evenements.Count
    environnement    = 'Windows Sandbox, reseau coupe'
    fichiers         = @(Get-ChildItem $Sortie -File | ForEach-Object Name)
} | ConvertTo-Json | Set-Content -Path (Join-Path $Sortie 'manifeste.json') -Encoding UTF8

Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host "Collecte terminée : $Sortie" -ForegroundColor Green
Get-ChildItem $Sortie | Format-Table Name, Length -AutoSize | Out-Host
Write-Host 'Vous pouvez fermer la Windows Sandbox (tout son contenu sera détruit).'
