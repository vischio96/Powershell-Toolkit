#Requires -Version 5.1
<#
.SYNOPSIS
    Report HTML dei permessi NTFS e di condivisione di cartelle locali o share di rete (struttura ad albero).

.DESCRIPTION
    Non richiede il modulo ActiveDirectory e non esegue query LDAP: legge solo ACL NTFS e permessi SMB.
    Il report (un unico file HTML con ricerca, filtri, ordinamento ed esportazione CSV) contiene:
      - Riepilogo e rilevazioni (permessi di scrittura a gruppi ampi, lettura a Everyone, SID orfani,
        ACE di negazione, ereditarietà disabilitata, errori di accesso)
      - Permessi di condivisione SMB
      - Albero delle cartelle con proprietario e ACE (esplicite o tutte)
      - Elenco delle cartelle (e opzionalmente dei file) con permessi espliciti o ereditarietà disabilitata
      - Vista "chi ha accesso a cosa" raggruppata per identità
    Lo script è in SOLA LETTURA.

.PARAMETER Path
    Uno o più percorsi locali o UNC (es. 'D:\Dati', '\\FS01\Condivisa'). Se non indicato (e senza -ComputerName)
    viene mostrata una finestra di selezione cartella.

.PARAMETER ComputerName
    Uno o più file server: vengono analizzate tutte le condivisioni disco (escluse quelle amministrative).

.PARAMETER IncludeAdminShares
    Con -ComputerName include anche le condivisioni amministrative (C$, ADMIN$, ...).

.PARAMETER Depth
    Profondità massima delle sottocartelle (predefinito 5).

.PARAMETER MaxFolders
    Numero massimo di cartelle analizzate in totale (predefinito 20000).

.PARAMETER IncludeInheritedAces
    Mostra nell'albero anche le ACE ereditate delle sottocartelle (di default solo quelle esplicite).

.PARAMETER IncludeFiles
    Controlla anche i file e riporta quelli con permessi espliciti o ereditarietà disabilitata (più lento).

.PARAMETER MaxFiles
    Numero massimo di file controllati con -IncludeFiles (predefinito 100000).

.PARAMETER OutputFolder
    Cartella di destinazione del report. Predefinito: cartella dello script.

.PARAMETER ExportCsv
    Esporta anche i dati in CSV (separatore ';', UTF-8).

.PARAMETER OpenReport
    Apre il report al termine.

.EXAMPLE
    .\Get-SharePermissionReport.ps1 -Path '\\FS01\Dati' -Depth 4 -OpenReport

.EXAMPLE
    .\Get-SharePermissionReport.ps1 -ComputerName FS01,FS02 -Depth 3 -ExportCsv

.EXAMPLE
    .\Get-SharePermissionReport.ps1 -Path 'D:\Condivisioni' -IncludeFiles -IncludeInheritedAces
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string[]]$ComputerName,
    [switch]$IncludeAdminShares,
    [ValidateRange(0, 50)][int]$Depth = 5,
    [ValidateRange(1, 1000000)][int]$MaxFolders = 20000,
    [switch]$IncludeInheritedAces,
    [switch]$IncludeFiles,
    [ValidateRange(1, 5000000)][int]$MaxFiles = 100000,
    [string]$OutputFolder,
    [switch]$ExportCsv,
    [switch]$OpenReport
)

Set-StrictMode -Off
$ScriptVersion = '1.0'
$StartTime = Get-Date
if (-not $OutputFolder) { $OutputFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }

#region ===================== FUNZIONI DI SUPPORTO =====================

$script:ReportLog = New-Object System.Collections.Generic.List[object]
$script:TableSeq = 0

function Write-Step { param([string]$Message) Write-Host ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message) -ForegroundColor Cyan }

function Add-Log {
    param([string]$Area, [string]$Message, [string]$Level = 'Avviso')
    $script:ReportLog.Add([pscustomobject][ordered]@{ 'Livello' = $Level; 'Area' = $Area; 'Messaggio' = $Message })
    if ($Level -ne 'Info') { Write-Warning "[$Area] $Message" }
}

function Enc { param($Value) if ($null -eq $Value) { return '' }; return [System.Net.WebUtility]::HtmlEncode([string]$Value) }

function Format-Date {
    param($Date)
    if ($Date -is [datetime] -and $Date.Year -gt 1601) { return $Date.ToString('yyyy-MM-dd HH:mm') }
    return ''
}

function New-Raw { param([string]$Html, [string]$Text) [pscustomobject]@{ PSTypeName = 'RawHtml'; Html = $Html; Text = $Text } }

function New-Badge {
    param([string]$Text, [string]$Class = 'b-info')
    New-Raw -Html ("<span class='bdg {0}'>{1}</span>" -f $Class, (Enc $Text)) -Text $Text
}

function Format-Cell {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) {
        if ($Value.Length -gt 90) { return "<div class='lt'>" + (Enc $Value) + '</div>' }
        return (Enc $Value)
    }
    if ($Value -is [bool]) { if ($Value) { return 'Sì' } else { return 'No' } }
    if ($Value -is [datetime]) { return (Format-Date $Value) }
    if ($Value.PSObject.TypeNames -contains 'RawHtml') { return $Value.Html }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($it in $Value) { if ($null -ne $it -and "$it" -ne '') { $items.Add((Format-Cell $it)) } }
        if ($items.Count -eq 0) { return '' }
        return "<div class='cl'>" + ($items -join '<br>') + '</div>'
    }
    return (Enc ([string]$Value))
}

function ConvertTo-PlainText {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { if ($Value) { return 'Sì' } else { return 'No' } }
    if ($Value -is [datetime]) { return (Format-Date $Value) }
    if ($Value.PSObject.TypeNames -contains 'RawHtml') { return $Value.Text }
    if ($Value -is [System.Collections.IEnumerable]) { return ((@(foreach ($i in $Value) { ConvertTo-PlainText $i }) | Where-Object { $_ -ne '' }) -join ' | ') }
    return [string]$Value
}

function New-HtmlTable {
    param([object[]]$Data, [string]$Id, [System.Collections.IDictionary]$Filters, [string]$EmptyText = 'Nessun elemento da mostrare.', [switch]$NoToolbar)
    if (-not $Data -or $Data.Count -eq 0) { return "<p class='empty'>$(Enc $EmptyText)</p>" }
    if (-not $Id) { $script:TableSeq++; $Id = "t$($script:TableSeq)" }
    $cols = @($Data[0].PSObject.Properties | Where-Object { -not $_.Name.StartsWith('_') } | ForEach-Object { $_.Name })
    $sb = New-Object System.Text.StringBuilder
    if (-not $NoToolbar) {
        [void]$sb.Append("<div class='tb'><input type='search' id='$Id-q' placeholder='Cerca...' oninput=""tblQ('$Id')"">")
        if ($Filters -and $Filters.Count) {
            [void]$sb.Append("<select id='$Id-f' onchange=""tblFilter('$Id')""><option value=''>Tutti</option>")
            foreach ($k in $Filters.Keys) { [void]$sb.Append("<option value='$($Filters[$k])'>$(Enc $k)</option>") }
            [void]$sb.Append('</select>')
        }
        [void]$sb.Append("<span class='cnt' id='$Id-n'>$($Data.Count) / $($Data.Count)</span><button type='button' onclick=""tblCsv('$Id')"">Esporta CSV</button></div>")
    }
    [void]$sb.Append("<div class='tw'><table class='dt' id='$Id'><thead><tr>")
    foreach ($c in $cols) { [void]$sb.Append("<th onclick='tblSort(this)'>$(Enc $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $Data) {
        $rc = $row.PSObject.Properties['_RowClass']
        if ($rc -and $rc.Value) { [void]$sb.Append("<tr class='$($rc.Value)'>") } else { [void]$sb.Append('<tr>') }
        foreach ($c in $cols) { [void]$sb.Append('<td>').Append((Format-Cell $row.$c)).Append('</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function New-Card {
    param([string]$Label, $Value, [string]$Class = '', [string]$Href)
    $inner = "<div class='v'>$(Enc $Value)</div><div class='l'>$(Enc $Label)</div>"
    if ($Href) { return "<a class='card $Class' href='$Href'>$inner</a>" }
    return "<div class='card $Class'>$inner</div>"
}

function Export-ReportCsv {
    param([object[]]$Data, [string]$Name)
    if (-not $ExportCsv -or -not $Data -or $Data.Count -eq 0) { return }
    try {
        if (-not (Test-Path -LiteralPath $CsvFolder)) { New-Item -ItemType Directory -Path $CsvFolder -Force | Out-Null }
        $rows = foreach ($r in $Data) {
            $o = [ordered]@{}
            foreach ($p in $r.PSObject.Properties) { if ($p.Name.StartsWith('_')) { continue }; $o[$p.Name] = ConvertTo-PlainText $p.Value }
            [pscustomobject]$o
        }
        $rows | Export-Csv -LiteralPath (Join-Path $CsvFolder "$Name.csv") -NoTypeInformation -Delimiter ';' -Encoding UTF8
    } catch { Add-Log 'Esportazione CSV' "$($Name): $($_.Exception.Message)" }
}

$script:SidNameCache = @{}
function Resolve-SidName {
    param([string]$Sid)
    if ($script:SidNameCache.ContainsKey($Sid)) { return $script:SidNameCache[$Sid] }
    $n = $null
    try { $n = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value } catch { $n = $null }
    $script:SidNameCache[$Sid] = $n
    return $n
}

function Resolve-NameSid {
    param([string]$Name)
    try { return ([System.Security.Principal.NTAccount]$Name).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { return $null }
}

# Gruppi "ampi": Everyone, Anonymous, Authenticated Users, Users, Guests, Domain Users/Guests/Computers (qualsiasi dominio)
function Test-BroadSid {
    param([string]$Sid)
    if (-not $Sid) { return $false }
    if ($Sid -in 'S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546') { return $true }
    return ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(513|514|515)$')
}
function Test-EveryoneSid { param([string]$Sid) return ($Sid -in 'S-1-1-0', 'S-1-5-7') }

function Get-RightsText {
    param([int64]$Mask)
    $m = $Mask -band 4294967295
    $parts = New-Object System.Collections.Generic.List[string]
    if ($m -band 268435456) { $parts.Add('Controllo completo (generico)') }
    if ($m -band 2147483648) { $parts.Add('Lettura (generico)') }
    if ($m -band 1073741824) { $parts.Add('Scrittura (generico)') }
    if ($m -band 536870912) { $parts.Add('Esecuzione (generico)') }
    $std = $m -band 268435455
    if ($std -ne 0) {
        $name = switch ($std -bor 1048576) {
            2032127 { 'Controllo completo' }
            1245631 { 'Modifica' }
            1180095 { 'Lettura ed esecuzione + Scrittura' }
            1180063 { 'Lettura + Scrittura' }
            1179817 { 'Lettura ed esecuzione' }
            1179785 { 'Lettura' }
            1048854 { 'Scrittura' }
            default { $null }
        }
        if (-not $name) { $name = 'Speciali: ' + ([System.Security.AccessControl.FileSystemRights][int]$std).ToString() }
        $parts.Add($name)
    }
    return ($parts -join ', ')
}

function Get-AppliesTo {
    param([int]$Inh, [int]$Prop)
    $ci = ($Inh -band 1) -ne 0; $oi = ($Inh -band 2) -ne 0
    $np = ($Prop -band 1) -ne 0; $io = ($Prop -band 2) -ne 0
    if (-not $ci -and -not $oi) { $t = 'Solo questo oggetto' }
    elseif ($io) { $t = if ($ci -and $oi) { 'Solo sottocartelle e file' } elseif ($ci) { 'Solo sottocartelle' } else { 'Solo file' } }
    else { $t = if ($ci -and $oi) { 'Questa cartella, sottocartelle e file' } elseif ($ci) { 'Questa cartella e sottocartelle' } else { 'Questa cartella e file' } }
    if ($np) { $t += ' (solo primo livello)' }
    return $t
}

#endregion

#region ===================== RACCOLTA PERMESSI =====================

# Scrittura/modifica: WriteData, AppendData, WriteEA, DeleteSubdirs, WriteAttributes, Delete, ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE
$RiskyMask = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 268435456 -bor 1073741824
# Lettura dati: ReadData, GENERIC_READ, GENERIC_ALL
$ReadMask = 1 -bor 2147483648 -bor 268435456

$AllAces = New-Object System.Collections.Generic.List[object]       # ACE esplicite + ACE della radice
$FolderExceptions = New-Object System.Collections.Generic.List[object]
$FileExceptions = New-Object System.Collections.Generic.List[object]
$RiskyAces = New-Object System.Collections.Generic.List[object]
$EveryoneRead = New-Object System.Collections.Generic.List[object]
$DenyAces = New-Object System.Collections.Generic.List[object]
$OrphanAces = New-Object System.Collections.Generic.List[object]
$AccessErrors = New-Object System.Collections.Generic.List[object]
$ShareRows = New-Object System.Collections.Generic.List[object]
$ShareRisky = New-Object System.Collections.Generic.List[object]
$script:FolderCount = 0
$script:FileCount = 0
$script:FolderTruncated = $false
$script:FileTruncated = $false

function Read-AclInfo {
    # Legge l'ACL di un oggetto e registra ACE esplicite e anomalie. Restituisce i dati dell'ACL.
    param([string]$Path, [bool]$IsRoot, [bool]$IsFile)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = ''
    try {
        $osid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $on = Resolve-SidName $osid
        $owner = if ($on) { $on } else { "$osid (non risolto)" }
    } catch { $owner = $acl.Owner }
    $aces = New-Object System.Collections.Generic.List[object]
    $explicit = 0
    $kind = if ($IsFile) { 'File' } else { 'Cartella' }
    foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $r.IdentityReference.Value
        $rn = Resolve-SidName $sid
        $idName = if ($rn) { $rn } else { "$sid (non risolto)" }
        $mask = ([int64][int]$r.FileSystemRights) -band 4294967295
        $allow = ([string]$r.AccessControlType -eq 'Allow')
        $rights = Get-RightsText $mask
        $applies = Get-AppliesTo ([int]$r.InheritanceFlags) ([int]$r.PropagationFlags)
        $risky = [bool]($allow -and (Test-BroadSid $sid) -and ($mask -band $RiskyMask))
        $evRead = [bool]($allow -and (Test-EveryoneSid $sid) -and ($mask -band $ReadMask) -and -not $risky)
        $orphan = (-not $rn) -and $sid -like 'S-1-5-21-*'
        $inh = [bool]$r.IsInherited
        $aces.Add([pscustomobject]@{ Identity = $idName; Sid = $sid; Allow = $allow; Rights = $rights; AppliesTo = $applies; Inherited = $inh; Risky = $risky; Orphan = $orphan })
        if (-not $inh) { $explicit++ }
        # Le ACE ereditate vengono registrate solo sulla radice per evitare migliaia di duplicati
        if (-not $inh -or $IsRoot) {
            $row = [pscustomobject][ordered]@{ 'Percorso' = $Path; 'Oggetto' = $kind; 'Identità' = $idName; 'SID' = $sid; 'Tipo' = $(if ($allow) { 'Consenti' } else { 'Nega' }); 'Diritti' = $rights; 'Si applica a' = $applies; 'Ereditata' = $inh }
            $AllAces.Add($row)
            if ($risky) { $RiskyAces.Add($row) }
            if ($evRead) { $EveryoneRead.Add($row) }
            if (-not $allow) { $DenyAces.Add($row) }
            if ($orphan) { $OrphanAces.Add($row) }
        }
    }
    return [pscustomobject]@{ Owner = $owner; Protected = [bool]$acl.AreAccessRulesProtected; Aces = $aces.ToArray(); Explicit = $explicit }
}

function Get-FolderAclNode {
    param([string]$Path, [int]$Level, [bool]$NoRecurse)
    $script:FolderCount++
    if ($script:FolderCount % 200 -eq 0) { Write-Progress -Activity 'Analisi permessi' -Status "$($script:FolderCount) cartelle - $Path" }
    $name = if ($Level -eq 0) { $Path } else { [System.IO.Path]::GetFileName($Path.TrimEnd('\')) }
    $node = [pscustomobject]@{
        Path = $Path; Name = $name; Level = $Level; Owner = ''; Protected = $false; Aces = @(); ExplicitCount = 0
        Risky = $false; Error = $null; Note = $null; Truncated = $false; FileExceptions = 0
        Children = (New-Object System.Collections.Generic.List[object])
    }
    try {
        $info = Read-AclInfo -Path $Path -IsRoot ($Level -eq 0) -IsFile $false
        $node.Owner = $info.Owner; $node.Protected = $info.Protected; $node.Aces = $info.Aces; $node.ExplicitCount = $info.Explicit
        $node.Risky = [bool](@($info.Aces | Where-Object { $_.Risky -and (-not $_.Inherited -or $Level -eq 0) }).Count)
        if ($Level -gt 0 -and ($node.Protected -or $node.ExplicitCount -gt 0)) {
            $FolderExceptions.Add([pscustomobject][ordered]@{
                    'Percorso'      = $Path
                    'Livello'       = $Level
                    'Ereditarietà'  = $(if ($node.Protected) { New-Badge 'Disabilitata' 'b-med' } else { 'Attiva' })
                    'ACE esplicite' = @($info.Aces | Where-Object { -not $_.Inherited } | ForEach-Object { "$($_.Identity): $($_.Rights) ($(if ($_.Allow) { 'Consenti' } else { 'Nega' }))" })
                    'Proprietario'  = $node.Owner
                    '_RowClass'     = $(if ($node.Protected) { 'f-prot' } else { 'f-expl' })
                })
        }
    } catch {
        $node.Error = $_.Exception.Message
        $AccessErrors.Add([pscustomobject][ordered]@{ 'Percorso' = $Path; 'Errore' = $_.Exception.Message })
    }

    $di = $null
    if ($IncludeFiles -or (-not $NoRecurse -and $Level -lt $Depth)) {
        try { $di = New-Object System.IO.DirectoryInfo -ArgumentList $Path } catch { $di = $null }
    }

    # File con permessi espliciti / ereditarietà disabilitata
    if ($IncludeFiles -and $di -and -not $NoRecurse) {
        try {
            foreach ($f in $di.GetFiles()) {
                if ($script:FileCount -ge $MaxFiles) { $script:FileTruncated = $true; break }
                $script:FileCount++
                try {
                    $fi = Read-AclInfo -Path $f.FullName -IsRoot $false -IsFile $true
                    if ($fi.Protected -or $fi.Explicit -gt 0) {
                        $node.FileExceptions++
                        $FileExceptions.Add([pscustomobject][ordered]@{
                                'File'          = $f.FullName
                                'Ereditarietà'  = $(if ($fi.Protected) { New-Badge 'Disabilitata' 'b-med' } else { 'Attiva' })
                                'ACE esplicite' = @($fi.Aces | Where-Object { -not $_.Inherited } | ForEach-Object { "$($_.Identity): $($_.Rights) ($(if ($_.Allow) { 'Consenti' } else { 'Nega' }))" })
                                'Proprietario'  = $fi.Owner
                                'Modificato'    = $f.LastWriteTime
                            })
                    }
                } catch { $AccessErrors.Add([pscustomobject][ordered]@{ 'Percorso' = $f.FullName; 'Errore' = $_.Exception.Message }) }
            }
        } catch { $AccessErrors.Add([pscustomobject][ordered]@{ 'Percorso' = $Path; 'Errore' = "Impossibile elencare i file: $($_.Exception.Message)" }) }
    }

    # Sottocartelle
    if (-not $NoRecurse -and $Level -lt $Depth -and $di) {
        try {
            foreach ($s in @($di.GetDirectories() | Sort-Object Name)) {
                if ($script:FolderCount -ge $MaxFolders) { $node.Truncated = $true; $script:FolderTruncated = $true; break }
                $isReparse = ($s.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                $child = Get-FolderAclNode -Path $s.FullName -Level ($Level + 1) -NoRecurse $isReparse
                if ($isReparse) { $child.Note = 'Collegamento / junction: non esplorato' }
                $node.Children.Add($child)
            }
        } catch {
            $msg = "Impossibile elencare le sottocartelle: $($_.Exception.Message)"
            if (-not $node.Error) { $node.Error = $msg }
            $AccessErrors.Add([pscustomobject][ordered]@{ 'Percorso' = $Path; 'Errore' = $msg })
        }
    }
    return $node
}

function ConvertTo-FolderTreeHtml {
    param($Node)
    $isRoot = $Node.Level -eq 0
    $childSb = New-Object System.Text.StringBuilder
    $childSpecial = $false
    foreach ($ch in $Node.Children) {
        $r = ConvertTo-FolderTreeHtml $ch
        [void]$childSb.Append($r.Html)
        if ($r.Special) { $childSpecial = $true }
    }
    $selfSpecial = [bool]($Node.Protected -or $Node.Risky -or $Node.Error -or $Node.FileExceptions -gt 0 -or (-not $isRoot -and $Node.ExplicitCount -gt 0))
    $special = $selfSpecial -or $childSpecial -or $isRoot
    $b = New-Object System.Collections.Generic.List[string]
    if ($Node.Protected -and -not $isRoot) { $b.Add("<span class='bdg b-med'>Ereditarietà disabilitata</span>") }
    if ($Node.ExplicitCount -gt 0 -and -not $isRoot) { $b.Add("<span class='bdg b-info'>$($Node.ExplicitCount) ACE esplicite</span>") }
    if ($Node.Risky) { $b.Add("<span class='bdg b-high'>Scrittura a gruppi ampi</span>") }
    if ($Node.FileExceptions -gt 0) { $b.Add("<span class='bdg b-low'>$($Node.FileExceptions) file con permessi propri</span>") }
    if ($Node.Error) { $b.Add("<span class='bdg b-high'>Errore</span>") }
    if ($Node.Note) { $b.Add("<span class='bdg b-off'>$(Enc $Node.Note)</span>") }
    if ($Node.Truncated) { $b.Add("<span class='bdg b-off'>Limite cartelle raggiunto</span>") }
    $showAces = if ($isRoot -or $IncludeInheritedAces) { @($Node.Aces) } else { @($Node.Aces | Where-Object { -not $_.Inherited }) }
    $inhCount = @($Node.Aces | Where-Object { $_.Inherited }).Count
    $body = New-Object System.Text.StringBuilder
    [void]$body.Append("<div class='node'><div><code>$(Enc $Node.Path)</code></div><div>Proprietario: <b>$(Enc $Node.Owner)</b></div>")
    if ($Node.Error) { [void]$body.Append("<div class='err'>$(Enc $Node.Error)</div>") }
    if ($showAces.Count) {
        [void]$body.Append("<table class='mini'><tr><th>Identità</th><th>Tipo</th><th>Diritti</th><th>Si applica a</th><th>Ereditata</th></tr>")
        foreach ($a in $showAces) {
            $rc = @()
            if (-not $a.Allow) { $rc += 'ace-deny' }
            if ($a.Risky) { $rc += 'ace-risk' }
            if ($a.Inherited) { $rc += 'ace-inh' }
            [void]$body.Append("<tr class='$($rc -join ' ')'><td>$(Enc $a.Identity)$(if ($a.Orphan) { " <span class='bdg b-low'>SID orfano</span>" })</td><td>$(if ($a.Allow) { 'Consenti' } else { "<span class='bdg b-high'>Nega</span>" })</td><td>$(Enc $a.Rights)</td><td>$(Enc $a.AppliesTo)</td><td>$(if ($a.Inherited) { 'Sì' } else { '<b>No</b>' })</td></tr>")
        }
        [void]$body.Append('</table>')
    }
    if (-not $isRoot -and -not $IncludeInheritedAces -and $inhCount -gt 0) { [void]$body.Append("<div class='empty'>$inhCount ACE ereditate non mostrate (uguali a quelle della cartella superiore).</div>") }
    [void]$body.Append('</div>')
    $open = if ($isRoot) { ' open' } else { '' }
    $html = "<li class='fnode' data-x='$([int]$special)'><details$open><summary>&#128193; $(Enc $Node.Name) $($b -join ' ')</summary>$($body.ToString())"
    if ($Node.Children.Count) { $html += "<ul>$($childSb.ToString())</ul>" }
    $html += '</details></li>'
    return [pscustomobject]@{ Html = $html; Special = $special }
}

function Add-ShareAccess {
    param([string]$Server, [string]$ShareName, [string]$SharePath)
    try {
        $acc = if ($Server) { Get-SmbShareAccess -Name $ShareName -CimSession $Server -ErrorAction Stop } else { Get-SmbShareAccess -Name $ShareName -ErrorAction Stop }
        foreach ($sa in $acc) {
            $unc = if ($Server) { "\\$Server\$ShareName" } else { "\\$env:COMPUTERNAME\$ShareName" }
            $sid = Resolve-NameSid $sa.AccountName
            $broadWrite = ([string]$sa.AccessControlType -eq 'Allow') -and ([string]$sa.AccessRight -in 'Full', 'Change') -and (Test-BroadSid $sid)
            $row = [pscustomobject][ordered]@{
                'Condivisione'    = $unc
                'Percorso locale' = $SharePath
                'Account'         = $sa.AccountName
                'Tipo'            = $(if ([string]$sa.AccessControlType -eq 'Allow') { 'Consenti' } else { New-Badge 'Nega' 'b-high' })
                'Diritto'         = $(switch ([string]$sa.AccessRight) { 'Full' { 'Controllo completo' } 'Change' { 'Modifica' } 'Read' { 'Lettura' } default { [string]$sa.AccessRight } })
                '_RowClass'       = $(if ($broadWrite) { 'f-risk' } else { '' })
            }
            $ShareRows.Add($row)
            if ($broadWrite) { $ShareRisky.Add("$unc - $($sa.AccountName): $($row.Diritto)") }
        }
    } catch { Add-Log 'Permessi condivisione' "$ShareName su $(if ($Server) { $Server } else { 'computer locale' }): $($_.Exception.Message)" }
}

#endregion

#region ===================== DETERMINAZIONE DEI PERCORSI =====================

Write-Step "Share Permission Report v$ScriptVersion - avvio"
$Targets = New-Object System.Collections.Generic.List[string]

foreach ($cn in @($ComputerName | Where-Object { $_ })) {
    Write-Step "Enumerazione condivisioni su $cn"
    try {
        $shares = @(Get-SmbShare -CimSession $cn -ErrorAction Stop | Where-Object { [string]$_.ShareType -eq 'FileSystemDirectory' -and $_.Name -ne 'IPC$' -and ($IncludeAdminShares -or (-not $_.Special -and $_.Name -notmatch '\$$')) })
        if (-not $shares.Count) { Add-Log 'Condivisioni' "Nessuna condivisione disco trovata su $cn" 'Info' }
        foreach ($s in $shares) {
            Add-ShareAccess -Server $cn -ShareName $s.Name -SharePath $s.Path
            $Targets.Add("\\$cn\$($s.Name)")
        }
    } catch { Add-Log 'Condivisioni' "Impossibile enumerare le condivisioni di $($cn): $($_.Exception.Message)" }
}

if (-not $Path -and -not $ComputerName -and [Environment]::UserInteractive) {
    $sel = $null
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Seleziona la cartella o la condivisione di cui analizzare i permessi'
        $dlg.ShowNewFolderButton = $false
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $sel = $dlg.SelectedPath }
    } catch { $sel = Read-Host 'Percorso da analizzare (locale o UNC)' }
    if ($sel) { $Path = @($sel) }
}

foreach ($p in @($Path | Where-Object { $_ })) {
    $p = $p.TrimEnd('\')
    if ($p -match '^[A-Za-z]:$') { $p += '\' }
    if ($p -match '^\\\\([^\\]+)\\([^\\]+)') {
        # Percorso UNC: permessi della condivisione
        $srv = $matches[1]; $sh = $matches[2]
        if (-not ($ShareRows | Where-Object { $_.Condivisione -eq "\\$srv\$sh" })) { Add-ShareAccess -Server $srv -ShareName $sh -SharePath '' }
    } else {
        # Percorso locale: condivisioni locali che espongono questa cartella o una cartella superiore/inferiore
        try {
            $full = [System.IO.Path]::GetFullPath($p).TrimEnd('\')
            foreach ($s in @(Get-SmbShare -ErrorAction Stop | Where-Object { [string]$_.ShareType -eq 'FileSystemDirectory' -and -not $_.Special -and $_.Path })) {
                $sp = $s.Path.TrimEnd('\')
                if ($full.StartsWith($sp, [StringComparison]::OrdinalIgnoreCase) -or $sp.StartsWith($full, [StringComparison]::OrdinalIgnoreCase)) {
                    Add-ShareAccess -Server '' -ShareName $s.Name -SharePath $s.Path
                }
            }
        } catch { Add-Log 'Condivisioni locali' $_.Exception.Message 'Info' }
    }
    $Targets.Add($p)
}

if ($Targets.Count -eq 0) { Write-Warning 'Nessun percorso da analizzare. Specificare -Path o -ComputerName.'; return }

$stamp = Get-Date -Format 'yyyyMMdd_HHmm'
if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$ReportFile = Join-Path $OutputFolder "Report_Permessi_$stamp.html"
$CsvFolder = Join-Path $OutputFolder "Report_Permessi_$($stamp)_csv"

#endregion

#region ===================== ANALISI =====================

$TreeSections = New-Object System.Collections.Generic.List[string]
$RootSummary = New-Object System.Collections.Generic.List[object]
$treeIdx = 0
foreach ($t in ($Targets | Select-Object -Unique)) {
    $treeIdx++
    Write-Step "Analisi permessi: $t (profondità $Depth)"
    if (-not (Test-Path -LiteralPath $t -PathType Container)) {
        Add-Log 'Percorsi' "Percorso non trovato o non accessibile: $t"
        $TreeSections.Add("<h3>$(Enc $t)</h3><p class='err'>Percorso non trovato o non accessibile.</p>")
        continue
    }
    $fBefore = $script:FolderCount; $exBefore = $FolderExceptions.Count; $rkBefore = $RiskyAces.Count; $erBefore = $AccessErrors.Count
    $root = Get-FolderAclNode -Path $t -Level 0 -NoRecurse $false
    $analyzed = $script:FolderCount - $fBefore
    $RootSummary.Add([pscustomobject][ordered]@{
            'Percorso'                 = $t
            'Proprietario radice'      = $root.Owner
            'Cartelle analizzate'      = $analyzed
            'Cartelle con eccezioni'   = $FolderExceptions.Count - $exBefore
            'ACE a rischio'            = $RiskyAces.Count - $rkBefore
            'Errori'                   = $AccessErrors.Count - $erBefore
        })
    $tid = "ftree$treeIdx"
    $tree = (ConvertTo-FolderTreeHtml $root).Html
    $TreeSections.Add(@"
<h3>&#128194; $(Enc $t)</h3>
<p class='intro'>Cartelle analizzate: <b>$analyzed</b> &middot; Profondità massima: <b>$Depth</b> &middot; Proprietario radice: <b>$(Enc $root.Owner)</b></p>
<div class='tb'><button type='button' onclick="treeAll('$tid',true)">Espandi tutto</button><button type='button' onclick="treeAll('$tid',false)">Comprimi tutto</button>
<label><input type='checkbox' onchange="treeX('$tid',this)"> Mostra solo cartelle con eccezioni (permessi espliciti, ereditarietà disabilitata, rischi, errori)</label></div>
<ul class='tree' id='$tid'>$tree</ul>
"@)
}
Write-Progress -Activity 'Analisi permessi' -Completed

# Vista per identità: chi ha accesso a cosa (ACE esplicite + ACE della radice)
$IdentityRows = foreach ($grp in ($AllAces | Group-Object 'Identità' | Sort-Object Count -Descending)) {
    $items = @($grp.Group)
    $broad = Test-BroadSid $items[0].SID
    [pscustomobject][ordered]@{
        'Identità'         = $grp.Name
        'SID'              = $items[0].SID
        'Gruppo ampio'     = $(if ($broad) { New-Badge 'Sì' 'b-warn' } else { 'No' })
        'Oggetti'          = @($items | Select-Object -ExpandProperty Percorso -Unique).Count
        'Consenti'         = @($items | Where-Object { $_.Tipo -eq 'Consenti' }).Count
        'Nega'             = @($items | Where-Object { $_.Tipo -eq 'Nega' }).Count
        'Permessi'         = @($items | Select-Object -First 300 | ForEach-Object { "$($_.Percorso) -> $($_.Diritti)$(if ($_.Tipo -eq 'Nega') { ' [NEGA]' })" })
        '_RowClass'        = $(if ($broad) { 'f-broad' } else { '' })
    }
}

#endregion

#region ===================== RILEVAZIONI =====================

$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([string]$Severity, [string]$Title, [string]$Description, [string]$Recommendation, [object[]]$Objects, [string]$Section)
    $Findings.Add([pscustomobject]@{ Severity = $Severity; Title = $Title; Description = $Description; Recommendation = $Recommendation; Objects = @($Objects | Where-Object { $_ }); Section = $Section })
}
if ($RiskyAces.Count) { Add-Finding 'Alto' "Permessi di scrittura/modifica concessi a gruppi ampi ($($RiskyAces.Count))" 'Everyone, Authenticated Users, Users o Domain Users possono modificare o eliminare i dati: rischio elevato in caso di ransomware o errori.' 'Sostituire con gruppi di sicurezza dedicati (modello AGDLP) applicando il minimo privilegio.' @($RiskyAces | ForEach-Object { "$($_.Percorso) - $($_.'Identità'): $($_.Diritti)" }) 'sec-risk' }
if ($EveryoneRead.Count) { Add-Finding 'Medio' "Lettura concessa a Everyone / Anonymous ($($EveryoneRead.Count))" 'I dati sono leggibili da chiunque, inclusi account guest o anonimi se consentiti.' 'Limitare l''accesso in lettura a gruppi specifici.' @($EveryoneRead | ForEach-Object { "$($_.Percorso) - $($_.'Identità'): $($_.Diritti)" }) 'sec-risk' }
if ($ShareRisky.Count) { Add-Finding 'Basso' "Condivisioni con Modifica/Controllo completo a gruppi ampi ($($ShareRisky.Count))" 'I permessi di condivisione non limitano l''accesso: la protezione dipende interamente dai permessi NTFS.' 'Accettabile se i permessi NTFS sono restrittivi; altrimenti limitare anche a livello di condivisione.' $ShareRisky 'sec-shares' }
if ($OrphanAces.Count) { Add-Finding 'Basso' "ACE con SID orfani - account o gruppi eliminati ($($OrphanAces.Count))" 'Permessi assegnati a identità che non esistono più: rendono le ACL difficili da leggere.' 'Rimuovere le ACE orfane.' @($OrphanAces | ForEach-Object { "$($_.Percorso) - $($_.SID)" }) 'sec-exc' }
$prot = @($FolderExceptions | Where-Object { $_.'Ereditarietà' -isnot [string] })
if ($prot.Count) { Add-Finding 'Info' "Cartelle con ereditarietà disabilitata ($($prot.Count))" 'Le cartelle hanno ACL indipendenti da quella superiore: le modifiche ai permessi della radice non si propagano.' 'Verificare che l''interruzione dell''ereditarietà sia voluta e documentata.' @($prot | ForEach-Object { $_.Percorso }) 'sec-exc' }
if ($DenyAces.Count) { Add-Finding 'Info' "ACE di tipo Nega ($($DenyAces.Count))" 'Le negazioni esplicite complicano la gestione e possono causare blocchi inattesi.' 'Preferire la rimozione dei permessi alle negazioni esplicite.' @($DenyAces | ForEach-Object { "$($_.Percorso) - $($_.'Identità'): $($_.Diritti)" }) 'sec-exc' }
if ($FileExceptions.Count) { Add-Finding 'Info' "File con permessi propri ($($FileExceptions.Count))" 'File con ACE esplicite o ereditarietà disabilitata.' 'Gestire i permessi a livello di cartella, non di singolo file.' @($FileExceptions | ForEach-Object { $_.File }) 'sec-files' }
if ($AccessErrors.Count) { Add-Finding 'Info' "Oggetti non analizzabili ($($AccessErrors.Count))" 'Accesso negato o percorso non leggibile con l''account in uso.' 'Eseguire con un account con diritti di lettura sulle ACL (es. amministratore del file server).' @($AccessErrors | ForEach-Object { "$($_.Percorso) - $($_.Errore)" }) 'sec-err' }
if ($script:FolderTruncated) { Add-Finding 'Info' "Raggiunto il limite di $MaxFolders cartelle" 'L''analisi è parziale.' 'Aumentare -MaxFolders o ridurre -Depth / il perimetro.' @() 'sec-tree' }

$SevOrder = @{ 'Critico' = 0; 'Alto' = 1; 'Medio' = 2; 'Basso' = 3; 'Info' = 4 }
$SevClass = @{ 'Critico' = 'b-crit'; 'Alto' = 'b-high'; 'Medio' = 'b-med'; 'Basso' = 'b-low'; 'Info' = 'b-info' }
$SecNames = @{ 'sec-risk' = 'Permessi a rischio'; 'sec-shares' = 'Condivisioni'; 'sec-exc' = 'Eccezioni'; 'sec-files' = 'File'; 'sec-err' = 'Errori'; 'sec-tree' = 'Albero' }
$FindingRows = foreach ($f in ($Findings | Sort-Object { $SevOrder[$_.Severity] })) {
    $objHtml = ''
    if ($f.Objects.Count) {
        $shown = @($f.Objects | Select-Object -First 1000 | ForEach-Object { Enc $_ })
        $more = if ($f.Objects.Count -gt 1000) { "<br>... e altri $($f.Objects.Count - 1000)" } else { '' }
        $objHtml = "<details><summary>$($f.Objects.Count) oggetti</summary><div class='objlist'>$($shown -join '<br>')$more</div></details>"
    }
    [pscustomobject][ordered]@{
        'Gravità'         = New-Badge $f.Severity $SevClass[$f.Severity]
        'Controllo'       = New-Raw "<b>$(Enc $f.Title)</b>" $f.Title
        'Descrizione'     = New-Raw "<div class='lt'>$(Enc $f.Description)</div>" $f.Description
        'Raccomandazione' = New-Raw "<div class='lt'>$(Enc $f.Recommendation)</div>" $f.Recommendation
        'Oggetti'         = New-Raw $objHtml (($f.Objects | Select-Object -First 1000) -join ' | ')
        'Sezione'         = $(if ($f.Section) { New-Raw "<a href='#$($f.Section)'>$(Enc $SecNames[$f.Section])</a>" $SecNames[$f.Section] } else { '' })
        '_RowClass'       = "sev-$($f.Severity)"
    }
}

#endregion

#region ===================== HTML =====================

Write-Step 'Generazione del report HTML'
$Sections = New-Object System.Collections.Generic.List[object]
function Add-Section { param([string]$Id, [string]$Title, [string]$Html, [string]$Intro, $Count) $Sections.Add([pscustomobject]@{ Id = $Id; Title = $Title; Html = $Html; Intro = $Intro; Count = $Count }) }

$sevCount = @{}
foreach ($s in 'Alto', 'Medio', 'Basso', 'Info') { $sevCount[$s] = @($Findings | Where-Object { $_.Severity -eq $s }).Count }

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append("<div class='cards'>")
[void]$sb.Append((New-Card 'Rilevazioni Alto' $sevCount['Alto'] 'c-high' '#sec-findings'))
[void]$sb.Append((New-Card 'Rilevazioni Medio' $sevCount['Medio'] 'c-med' '#sec-findings'))
[void]$sb.Append((New-Card 'Rilevazioni Basso' $sevCount['Basso'] 'c-low' '#sec-findings'))
[void]$sb.Append((New-Card 'Rilevazioni Info' $sevCount['Info'] 'c-info' '#sec-findings'))
[void]$sb.Append((New-Card 'Cartelle analizzate' $script:FolderCount '' '#sec-tree'))
if ($IncludeFiles) { [void]$sb.Append((New-Card 'File controllati' $script:FileCount '' '#sec-files')) }
[void]$sb.Append((New-Card 'Cartelle con eccezioni' $FolderExceptions.Count 'c-med' '#sec-exc'))
[void]$sb.Append((New-Card 'ACE a rischio' $RiskyAces.Count 'c-high' '#sec-risk'))
[void]$sb.Append((New-Card 'Identità con accesso' @($IdentityRows).Count '' '#sec-ident'))
[void]$sb.Append((New-Card 'Errori di accesso' $AccessErrors.Count '' '#sec-err'))
[void]$sb.Append('</div>')
[void]$sb.Append("<h3>Percorsi analizzati</h3>" + (New-HtmlTable -Data $RootSummary -Id 'tRoots' -NoToolbar))
Add-Section 'sec-summary' 'Riepilogo' $sb.ToString() "Analisi del $(Format-Date $StartTime)."

Add-Section 'sec-findings' 'Rilevazioni' (New-HtmlTable -Data @($FindingRows) -Id 'tFindings' -Filters ([ordered]@{ 'Alto' = 'sev-Alto'; 'Medio' = 'sev-Medio'; 'Basso' = 'sev-Basso'; 'Info' = 'sev-Info' }) -EmptyText 'Nessuna rilevazione.') 'Controlli automatici ordinati per gravità.' $Findings.Count

Add-Section 'sec-shares' 'Permessi di condivisione' (New-HtmlTable -Data $ShareRows -Id 'tShares' -Filters ([ordered]@{ 'Scrittura a gruppi ampi' = 'f-risk' }) -EmptyText 'Nessun permesso di condivisione rilevato (percorso locale non condiviso o permessi insufficienti per leggerli).') 'Permessi SMB delle condivisioni analizzate. L''accesso effettivo via rete è il più restrittivo tra permessi di condivisione e NTFS.' $ShareRows.Count

$h = "<div class='note'>Per le sottocartelle sono mostrate solo le ACE <b>esplicite</b>$(if ($IncludeInheritedAces) { ' e quelle ereditate' }); la radice mostra tutte le ACE effettive. In rosso le ACE che concedono scrittura a gruppi ampi, in giallo le negazioni.</div>" + ($TreeSections -join "`n")
Add-Section 'sec-tree' 'Struttura ad albero' $h 'Albero delle cartelle con proprietario e permessi NTFS.' $script:FolderCount

Add-Section 'sec-exc' 'Cartelle con eccezioni' (New-HtmlTable -Data $FolderExceptions -Id 'tExc' -Filters ([ordered]@{ 'Ereditarietà disabilitata' = 'f-prot'; 'Solo ACE esplicite aggiunte' = 'f-expl' }) -EmptyText 'Nessuna eccezione: tutte le sottocartelle ereditano i permessi.') 'Sottocartelle con permessi espliciti aggiunti o con ereditarietà disabilitata.' $FolderExceptions.Count

$h = "<h3>Scrittura / modifica a gruppi ampi</h3>" + (New-HtmlTable -Data $RiskyAces -Id 'tRisk' -EmptyText 'Nessuna ACE a rischio.')
$h += "<h3>Lettura a Everyone / Anonymous</h3>" + (New-HtmlTable -Data $EveryoneRead -Id 'tEvRead' -EmptyText 'Nessuna.')
$h += "<h3>ACE di negazione</h3>" + (New-HtmlTable -Data $DenyAces -Id 'tDeny' -EmptyText 'Nessuna.')
$h += "<h3>SID orfani</h3>" + (New-HtmlTable -Data $OrphanAces -Id 'tOrphan' -EmptyText 'Nessuno.')
Add-Section 'sec-risk' 'Permessi a rischio' $h 'Gruppi ampi: Everyone, Anonymous, Authenticated Users, Users, Guests, Domain Users, Domain Guests, Domain Computers.' $RiskyAces.Count

Add-Section 'sec-ident' 'Accessi per identità' (New-HtmlTable -Data @($IdentityRows) -Id 'tIdent' -Filters ([ordered]@{ 'Solo gruppi ampi' = 'f-broad' })) 'Chi ha accesso a cosa: per ogni utente/gruppo i percorsi e i diritti assegnati (ACE esplicite e ACE della radice). L''appartenenza ai gruppi non viene espansa.' @($IdentityRows).Count

if ($IncludeFiles) { Add-Section 'sec-files' 'File con permessi propri' (New-HtmlTable -Data $FileExceptions -Id 'tFiles' -EmptyText 'Nessun file con permessi espliciti.') "File con ACE esplicite o ereditarietà disabilitata (controllati: $($script:FileCount)$(if ($script:FileTruncated) { ", limite di $MaxFiles raggiunto" }))." $FileExceptions.Count }

Add-Section 'sec-acl' 'Tutte le ACE esplicite' (New-HtmlTable -Data $AllAces -Id 'tAces' -Filters ([ordered]@{})) 'Elenco piatto di tutte le ACE esplicite e delle ACE della radice di ogni percorso (utile per esportazione e ricerca).' $AllAces.Count

Add-Section 'sec-err' 'Errori e log' ((New-HtmlTable -Data $AccessErrors -Id 'tErr' -EmptyText 'Nessun errore di accesso.') + '<h3>Log di esecuzione</h3>' + (New-HtmlTable -Data $script:ReportLog -Id 'tLog' -EmptyText 'Nessun avviso.')) 'Oggetti non leggibili e avvisi di esecuzione.' ($AccessErrors.Count + $script:ReportLog.Count)

Export-ReportCsv $AllAces 'ACE_esplicite'
Export-ReportCsv $FolderExceptions 'Cartelle_eccezioni'
Export-ReportCsv $ShareRows 'Permessi_condivisione'
Export-ReportCsv @($IdentityRows) 'Accessi_per_identita'
Export-ReportCsv $FileExceptions 'File_eccezioni'
Export-ReportCsv @($FindingRows) 'Rilevazioni'

$css = @'
:root{--bg:#f3f5f9;--card:#fff;--tx:#1e293b;--mu:#64748b;--bd:#e2e8f0;--ac:#1e40af;--hd:#0f172a}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;font:13px/1.45 "Segoe UI",Tahoma,Arial,sans-serif;background:var(--bg);color:var(--tx)}
header{position:fixed;top:0;left:0;right:0;height:58px;background:var(--hd);color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 20px;z-index:20}
header h1{font-size:18px;margin:0;font-weight:600}header .meta{font-size:11.5px;color:#cbd5e1;text-align:right;line-height:1.35}
nav{position:fixed;top:58px;left:0;bottom:0;width:235px;background:#fff;border-right:1px solid var(--bd);overflow-y:auto;padding:10px 0}
nav a{display:flex;justify-content:space-between;gap:8px;padding:7px 18px;color:var(--tx);text-decoration:none;border-left:3px solid transparent}
nav a:hover{background:#eff6ff;border-left-color:var(--ac)}nav a .n{color:var(--mu);font-size:11px}
main{margin:58px 0 0 235px;padding:22px 26px 40px}
section{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:18px 22px;margin-bottom:22px;scroll-margin-top:70px}
section>h2{margin:0 0 4px;font-size:19px;color:var(--ac)}
.intro{color:var(--mu);margin:0 0 12px}h3{font-size:14.5px;margin:22px 0 8px;color:#0f172a}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:10px;margin-bottom:12px}
.card{display:block;border:1px solid var(--bd);border-left:5px solid #94a3b8;border-radius:8px;padding:10px 14px;background:#fafbfc;color:inherit;text-decoration:none}
a.card:hover{background:#eff6ff}.card .v{font-size:24px;font-weight:700}.card .l{color:var(--mu);font-size:12px}
.c-high{border-left-color:#dc2626}.c-med{border-left-color:#d97706}.c-low{border-left-color:#2563eb}.c-info{border-left-color:#64748b}
.tb{display:flex;gap:8px;align-items:center;margin:8px 0;flex-wrap:wrap}
.tb input[type=search]{padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;min-width:260px}
.tb select,.tb button{padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;cursor:pointer;font:inherit}
.tb button:hover{background:#eff6ff}.tb .cnt{color:var(--mu);margin-left:auto}
.tw{overflow:auto;max-height:75vh;border:1px solid var(--bd);border-radius:6px}
table.dt{border-collapse:collapse;width:100%;font-size:12px}
table.dt th{position:sticky;top:0;background:#e8eef7;text-align:left;padding:7px 8px;white-space:nowrap;cursor:pointer;user-select:none;border-bottom:1px solid #cbd5e1;z-index:1}
table.dt th:hover{background:#dbe5f3}table.dt th[data-dir=asc]::after{content:" \25B2";font-size:9px}table.dt th[data-dir=desc]::after{content:" \25BC";font-size:9px}
table.dt td{padding:5px 8px;border-bottom:1px solid #eef2f7;vertical-align:top;white-space:nowrap}
table.dt tbody tr:hover td{background:#f8fafc}tr.f-risk td{background:#fff1f2}
.cl{max-height:130px;overflow:auto;padding-right:6px}.lt{white-space:normal;min-width:260px;max-width:560px}
.bdg{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap;margin:1px 0}
.b-ok{background:#dcfce7;color:#166534}.b-off{background:#e2e8f0;color:#475569}.b-info{background:#e0f2fe;color:#075985}
.b-low{background:#dbeafe;color:#1e40af}.b-med{background:#fef3c7;color:#92400e}.b-warn{background:#ffedd5;color:#9a3412}
.b-high{background:#fee2e2;color:#991b1b}.b-crit{background:#7f1d1d;color:#fff}
table.mini{border-collapse:collapse;margin:6px 0;font-size:12px;background:#fff}
table.mini th{background:#eef2f7;text-align:left;padding:4px 8px}table.mini td{padding:4px 8px;border-top:1px solid #eef2f7}
tr.ace-inh td{color:#64748b}tr.ace-risk td{background:#fee2e2}tr.ace-deny td{background:#fef3c7}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:18px}ul.tree{padding-left:0}
ul.tree ul{border-left:1px dashed #cbd5e1;margin-left:9px}ul.tree li{margin:2px 0}
ul.tree summary{cursor:pointer;padding:3px 6px;border-radius:5px}ul.tree summary:hover{background:#eff6ff}
.node{margin:4px 0 8px 22px;padding:8px 12px;background:#f8fafc;border:1px solid var(--bd);border-radius:6px}
.only-x li.fnode[data-x="0"]{display:none}
.objlist{max-height:260px;overflow:auto;font-family:Consolas,monospace;font-size:11.5px;background:#f8fafc;padding:6px 8px;border-radius:4px;white-space:nowrap}
details>summary{cursor:pointer}
code{font-family:Consolas,monospace;background:#f1f5f9;padding:0 4px;border-radius:3px;font-size:11.5px}
.empty{color:var(--mu);font-style:italic}.err{color:#b91c1c}
.note{background:#fffbeb;border:1px solid #fde68a;padding:8px 12px;border-radius:6px;color:#78350f;margin:10px 0}
footer{color:var(--mu);text-align:center;font-size:11px;padding:10px 0 30px}
@media (max-width:900px){nav{display:none}main{margin-left:0;padding:70px 12px}}
@media print{header,nav{position:static}nav,.tb{display:none}main{margin:0;padding:0}.tw{max-height:none;overflow:visible}}
'@

$js = @'
var _tt={};
function tblQ(id){clearTimeout(_tt[id]);_tt[id]=setTimeout(function(){tblFilter(id)},200);}
function tblFilter(id){var t=document.getElementById(id);if(!t)return;var qi=document.getElementById(id+'-q');var q=qi?qi.value.toLowerCase().trim():'';var s=document.getElementById(id+'-f');var c=s?s.value:'';var rows=t.tBodies[0].rows,n=0;for(var i=0;i<rows.length;i++){var r=rows[i];var ok=(!c||r.classList.contains(c))&&(!q||r.textContent.toLowerCase().indexOf(q)>-1);r.style.display=ok?'':'none';if(ok)n++;}var ce=document.getElementById(id+'-n');if(ce)ce.textContent=n+' / '+rows.length;}
function tblSort(th){var table=th.closest('table');var hs=th.parentNode.children;var idx=Array.prototype.indexOf.call(hs,th);var asc=th.getAttribute('data-dir')!=='asc';for(var i=0;i<hs.length;i++)hs[i].removeAttribute('data-dir');th.setAttribute('data-dir',asc?'asc':'desc');var body=table.tBodies[0];var rows=Array.prototype.slice.call(body.rows);var num=/^-?\d+(?:[.,]\d+)?$/;rows.sort(function(a,b){var x=a.cells[idx].textContent.trim(),y=b.cells[idx].textContent.trim();if(x===''&&y!=='')return 1;if(y===''&&x!=='')return -1;var r;if(num.test(x)&&num.test(y)){r=parseFloat(x.replace(',','.'))-parseFloat(y.replace(',','.'));}else{r=x.localeCompare(y,'it',{numeric:true,sensitivity:'base'});}return asc?r:-r;});var f=document.createDocumentFragment();rows.forEach(function(r){f.appendChild(r)});body.appendChild(f);}
function tblCsv(id){var t=document.getElementById(id);if(!t)return;function q(s){s=(s||'').replace(/\r?\n/g,' | ').replace(/\s+\|\s+/g,' | ').trim();return '"'+s.replace(/"/g,'""')+'"';}var out=[];var h=[];var hc=t.tHead.rows[0].cells;for(var i=0;i<hc.length;i++)h.push(q(hc[i].textContent));out.push(h.join(';'));var rows=t.tBodies[0].rows;for(var j=0;j<rows.length;j++){var r=rows[j];if(r.style.display==='none')continue;var a=[];for(var k=0;k<r.cells.length;k++)a.push(q(r.cells[k].innerText));out.push(a.join(';'));}var blob=new Blob(['\ufeff'+out.join('\r\n')],{type:'text/csv;charset=utf-8'});var l=document.createElement('a');l.href=URL.createObjectURL(blob);l.download=id.replace(/^t/,'')+'.csv';document.body.appendChild(l);l.click();setTimeout(function(){l.remove()},100);}
function treeAll(id,o){var ds=document.getElementById(id).querySelectorAll('details');for(var i=0;i<ds.length;i++)ds[i].open=o;}
function treeX(id,cb){document.getElementById(id).classList.toggle('only-x',cb.checked);}
'@

$runAs = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
$duration = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)
$out = New-Object System.Text.StringBuilder
[void]$out.Append("<!DOCTYPE html><html lang='it'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Report permessi cartelle</title><style>$css</style></head><body>")
[void]$out.Append("<header><h1>Report permessi cartelle e condivisioni</h1><div class='meta'>Generato il $(Format-Date $StartTime) da $(Enc $runAs) su $(Enc $env:COMPUTERNAME)<br>Durata $duration min</div></header><nav>")
foreach ($s in $Sections) {
    $cnt = if ($null -ne $s.Count) { "<span class='n'>$($s.Count)</span>" } else { '' }
    [void]$out.Append("<a href='#$($s.Id)'><span>$(Enc $s.Title)</span>$cnt</a>")
}
[void]$out.Append('</nav><main>')
foreach ($s in $Sections) {
    [void]$out.Append("<section id='$($s.Id)'><h2>$(Enc $s.Title)</h2>")
    if ($s.Intro) { [void]$out.Append("<p class='intro'>$(Enc $s.Intro)</p>") }
    [void]$out.Append($s.Html).Append('</section>')
}
$params = "Depth=$Depth; MaxFolders=$MaxFolders; IncludeFiles=$([bool]$IncludeFiles); IncludeInheritedAces=$([bool]$IncludeInheritedAces)"
[void]$out.Append("<footer>Share Permission Report v$ScriptVersion &middot; Parametri: $(Enc $params) &middot; Report in sola lettura.</footer></main><script>$js</script></body></html>")
[System.IO.File]::WriteAllText($ReportFile, $out.ToString(), (New-Object System.Text.UTF8Encoding($true)))

#endregion

Write-Host ''
Write-Host "Report generato: $ReportFile" -ForegroundColor Green
if ($ExportCsv -and (Test-Path -LiteralPath $CsvFolder)) { Write-Host "CSV esportati in: $CsvFolder" -ForegroundColor Green }
Write-Host ("Cartelle analizzate: {0} - Eccezioni: {1} - ACE a rischio: {2} - Errori: {3}" -f $script:FolderCount, $FolderExceptions.Count, $RiskyAces.Count, $AccessErrors.Count) -ForegroundColor Yellow
if ($OpenReport) { Invoke-Item -LiteralPath $ReportFile }
