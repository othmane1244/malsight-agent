<#
.SYNOPSIS
    Collecte les journaux d'une analyse dans la Windows Sandbox du labo MalSight.

.DESCRIPTION
    À lancer après l'exécution de l'échantillon (dans la sandbox, en administrateur) :
    1. Arrête Procmon et convertit sa capture .PML en CSV.
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

# --- 1. Procmon : arrêt puis conversion ------------------------------------
Write-Host '[1/3] Arrêt de Procmon...'
Start-Process -FilePath $session.procmon -ArgumentList '/Terminate' -Wait
$limite = (Get-Date).AddSeconds(30)
while ((Get-Process -Name 'Procmon*' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $limite) {
    Start-Sleep -Milliseconds 500
}

$pml = Join-Path $Sortie 'procmon.PML'
if (Test-Path $session.pml) {
    Move-Item -Path $session.pml -Destination $pml
    # Procmon peut découper la capture (procmon_xxx-1.PML...) : on récupère les morceaux
    $base = [IO.Path]::GetFileNameWithoutExtension($session.pml)
    Get-ChildItem -Path $Resultats -Filter "$base-*.PML" -ErrorAction SilentlyContinue |
        Move-Item -Destination $Sortie
    Write-Host '      Conversion PML -> CSV...'
    Start-Process -FilePath $session.procmon -Wait -ArgumentList @(
        '/AcceptEula', '/Quiet', '/Minimized',
        '/OpenLog', "`"$pml`"", '/SaveAs', "`"$(Join-Path $Sortie 'procmon.csv')`"")
} else {
    Write-Warning "Capture Procmon introuvable : $($session.pml)"
}

# --- 2. Sysmon : EVTX ------------------------------------------------------
# wevtutil écrit via le service Journal d'événements : on exporte en local puis on copie.
Write-Host '[2/3] Export du journal Sysmon (.evtx)...'
$evtxLocal = Join-Path $Temp 'sysmon.evtx'
if (Test-Path $evtxLocal) { Remove-Item $evtxLocal -Force }
& wevtutil.exe epl $LogSysmon $evtxLocal
if ($LASTEXITCODE -ne 0) { throw "Échec de l'export Sysmon (code $LASTEXITCODE)" }
Copy-Item $evtxLocal (Join-Path $Sortie 'sysmon.evtx')

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
