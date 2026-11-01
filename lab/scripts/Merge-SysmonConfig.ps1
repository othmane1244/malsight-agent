<#
.SYNOPSIS
    Fusionne des règles Sysmon maison dans une config Sysmon de base.

.DESCRIPTION
    Pour chaque règle (ex. <FileCreate onmatch="include">) du fichier -Ajout :
    - si la base a déjà un RuleGroup avec le même événement et le même onmatch,
      les conditions y sont ajoutées (Sysmon refuse deux groupes pour un même couple) ;
    - sinon, un nouveau RuleGroup est créé dans EventFiltering.
    Le résultat est écrit dans -Sortie ; la base n'est pas modifiée.

.EXAMPLE
    .\Merge-SysmonConfig.ps1 -Base sysmonconfig-export.xml -Ajout sysmon-malsight.xml -Sortie fusion.xml
#>
param(
    [Parameter(Mandatory = $true)][string]$Base,
    [Parameter(Mandatory = $true)][string]$Ajout,
    [Parameter(Mandatory = $true)][string]$Sortie
)
$ErrorActionPreference = 'Stop'

$docBase = New-Object System.Xml.XmlDocument
$docBase.Load((Resolve-Path $Base).Path)
$docAjout = New-Object System.Xml.XmlDocument
$docAjout.Load((Resolve-Path $Ajout).Path)

$filtrage = $docBase.SelectSingleNode('/Sysmon/EventFiltering')
if (-not $filtrage) { throw "EventFiltering introuvable dans $Base" }

$ajoutees = 0
foreach ($groupe in $docAjout.SelectNodes('/Sysmon/EventFiltering/RuleGroup')) {
    foreach ($regle in @($groupe.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })) {
        $onmatch = $regle.GetAttribute('onmatch')
        $cible = $filtrage.SelectSingleNode("RuleGroup/$($regle.LocalName)[@onmatch='$onmatch']")
        if ($cible) {
            foreach ($cond in @($regle.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })) {
                [void]$cible.AppendChild($docBase.ImportNode($cond, $true))
                $ajoutees++
            }
        } else {
            $nouveau = $docBase.CreateElement('RuleGroup')
            $nouveau.SetAttribute('name', $groupe.GetAttribute('name'))
            $nouveau.SetAttribute('groupRelation', $groupe.GetAttribute('groupRelation'))
            [void]$nouveau.AppendChild($docBase.ImportNode($regle, $true))
            [void]$filtrage.AppendChild($nouveau)
            $ajoutees += @($regle.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count
        }
    }
}

$docBase.Save([IO.Path]::GetFullPath($Sortie))
Write-Host "Fusion Sysmon : $ajoutees condition(s) ajoutée(s) -> $Sortie"
