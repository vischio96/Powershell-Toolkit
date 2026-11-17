#Requires -Version 5.1
<#
.SYNOPSIS
    Genera un report HTML dettagliato di Active Directory orientato a sicurezza e visibilità.

.DESCRIPTION
    Il report (un unico file HTML autonomo, con ricerca, ordinamento ed esportazione CSV delle tabelle) contiene:
      - Riepilogo e rilevazioni di sicurezza classificate per gravità (Critico / Alto / Medio / Basso / Info)
      - Dominio e foresta: livelli funzionali, ruoli FSMO, schema, cestino AD, MachineAccountQuota, tombstone
      - Domain Controller, stato della replica, siti/subnet, trust
      - Password policy di dominio (con valutazione), Fine-Grained Password Policy, criteri Kerberos,
        criteri di controllo (audit) applicati ai Domain Controller
      - Utenti: stato, ultimo logon, tentativi errati, blocco, password, flag di sicurezza, deleghe,
        SPN, attributi anagrafici, gruppi diretti e annidati
      - Account speciali (Administrator, Guest, krbtgt)
      - Gruppi privilegiati con membri diretti e annidati
      - Tutti i gruppi con conteggio membri
      - Computer: SO e stato del supporto, ultimo logon, LAPS, BitLocker in AD, deleghe, gruppi
      - Deleghe Kerberos (non vincolate, vincolate, resource-based)
      - Account di servizio gestiti (MSA / gMSA / dMSA)
      - Struttura ad albero delle OU con GPO collegate e GPO risultanti (ereditarietà, blocco, imposizione)
      - Elenco GPO con stato, collegamenti, filtri WMI, coerenza SYSVOL
      - Permessi NTFS (e di condivisione, se UNC) di un percorso con struttura ad albero
      - (Opzionale) accessi falliti e blocchi account letti dai registri di sicurezza dei DC

    Lo script è in SOLA LETTURA: non modifica nulla in Active Directory né sul file system.

.PARAMETER OutputFolder
    Cartella in cui salvare il report. Predefinito: cartella dello script.

.PARAMETER Server
    Domain Controller da interrogare. Predefinito: emulatore PDC (dato più preciso per tentativi errati e blocchi).

.PARAMETER FolderPath
    Uno o più percorsi (locali o UNC) di cui analizzare i permessi. Se omesso viene mostrata una finestra
    di selezione della cartella (Annulla = salta l'analisi).

.PARAMETER FolderDepth
    Profondità massima delle sottocartelle da analizzare (predefinito 5).

.PARAMETER MaxFolders
    Numero massimo di cartelle analizzate per evitare report enormi (predefinito 10000).

.PARAMETER IncludeInheritedAces
    Mostra nell'albero anche le ACE ereditate di ogni sottocartella (di default solo quelle esplicite).

.PARAMETER SkipFolderReport
    Non esegue l'analisi dei permessi delle cartelle.

.PARAMETER InactiveDays
    Giorni senza logon oltre i quali un account è considerato inattivo (predefinito 90).

.PARAMETER PasswordAgeDays
    Età della password oltre la quale viene segnalata (predefinito 365).

.PARAMETER QueryAllDCs
    Interroga tutti i DC per l'attributo lastLogon (non replicato) per un ultimo logon preciso.
    Senza questa opzione si usa lastLogonTimestamp (replicato, può avere fino a ~14 giorni di ritardo).

.PARAMETER ResolveComputerIP
    Risolve via DNS l'indirizzo IPv4 dei computer (può rallentare molto con molti oggetti obsoleti).

.PARAMETER IncludeSecurityEvents
    Legge dai registri Security dei DC gli eventi 4625, 4771, 4776 (accessi falliti) e 4740 (blocchi).

.PARAMETER EventHours
    Finestra temporale in ore per gli eventi (predefinito 24).

.PARAMETER MaxEventsPerDC
    Numero massimo di eventi letti per DC e per query (predefinito 20000).

.PARAMETER ExportCsv
    Esporta anche le tabelle principali in file CSV (separatore ';', UTF-8).

.PARAMETER OpenReport
    Apre il report al termine.

.EXAMPLE
    .\Get-ADSecurityReport.ps1

.EXAMPLE
    .\Get-ADSecurityReport.ps1 -FolderPath '\\FS01\Dati','D:\Condivisioni' -FolderDepth 3 -ExportCsv -OpenReport

.EXAMPLE
    .\Get-ADSecurityReport.ps1 -QueryAllDCs -IncludeSecurityEvents -EventHours 48 -SkipFolderReport

.NOTES
    Requisiti: Windows PowerShell 5.1 o PowerShell 7 su Windows, modulo ActiveDirectory (RSAT).
    Consigliato eseguire con un account con ampi diritti di lettura (es. Domain Admin o account delegato):
    con un utente standard alcune informazioni (BitLocker, FGPP, eventi, alcune ACL) potrebbero non essere visibili.
#>
[CmdletBinding()]
param(
    [string]$OutputFolder,
    [string]$Server,
    [string[]]$FolderPath,
    [ValidateRange(0, 50)][int]$FolderDepth = 5,
    [ValidateRange(1, 500000)][int]$MaxFolders = 10000,
    [switch]$IncludeInheritedAces,
    [switch]$SkipFolderReport,
    [ValidateRange(1, 3650)][int]$InactiveDays = 90,
    [ValidateRange(1, 3650)][int]$PasswordAgeDays = 365,
    [switch]$QueryAllDCs,
    [switch]$ResolveComputerIP,
    [switch]$IncludeSecurityEvents,
    [ValidateRange(1, 720)][int]$EventHours = 24,
    [ValidateRange(100, 1000000)][int]$MaxEventsPerDC = 20000,
    [switch]$ExportCsv,
    [switch]$OpenReport
)

Set-StrictMode -Off
$ScriptVersion = '1.0'
$StartTime = Get-Date
$Now = $StartTime
$InactiveLimit = $Now.AddDays(-$InactiveDays)
if (-not $OutputFolder) { $OutputFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }

#region ===================== FUNZIONI DI SUPPORTO =====================

$script:ReportLog = New-Object System.Collections.Generic.List[object]
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:FL = @{}
$script:TableSeq = 0

function Write-Step {
    param([string]$Message)
    Write-Host ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message) -ForegroundColor Cyan
}

function Add-Log {
    param([string]$Area, [string]$Message, [string]$Level = 'Avviso')
    $script:ReportLog.Add([pscustomobject][ordered]@{ 'Livello' = $Level; 'Area' = $Area; 'Messaggio' = $Message })
    if ($Level -ne 'Info') { Write-Warning "[$Area] $Message" }
}

function Invoke-Safe {
    param([string]$Area, [scriptblock]$Script)
    try { & $Script } catch { Add-Log -Area $Area -Message $_.Exception.Message }
}

function Enc {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Format-Date {
    param($Date)
    if ($Date -is [datetime] -and $Date.Year -gt 1601) { return $Date.ToString('yyyy-MM-dd HH:mm') }
    return ''
}

function Convert-FileTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $v = [int64]$Value
        if ($v -le 0 -or $v -ge 2650467743999999999) { return $null }
        return [datetime]::FromFileTime($v)
    } catch { return $null }
}

function Get-DaysSince {
    param($Date)
    if ($Date -is [datetime] -and $Date.Year -gt 1601) { return [int][math]::Floor(($Now - $Date).TotalDays) }
    return $null
}

function Get-List {
    # Restituisce sempre un array (vuoto se il valore è nullo), senza elementi vuoti
    param($Value)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Value) {
        foreach ($v in $Value) { if ($null -ne $v -and "$v" -ne '') { $out.Add($v) } }
    }
    return , $out.ToArray()
}

function Get-ParentDN {
    param([string]$DN)
    return ($DN -replace '^(?:[^,\\]|\\.)+,', '')
}

function Get-RdnName {
    param([string]$DN)
    if ($DN -match '^(?:CN|OU|DC)=((?:[^,\\]|\\.)+)') { return ($matches[1] -replace '\\(.)', '$1') }
    return $DN
}

function ConvertTo-CanonicalPath {
    param([string]$DN)
    if (-not $DN) { return '' }
    $parts = [regex]::Split($DN, '(?<!\\),')
    $dc = @(); $rest = @()
    foreach ($p in $parts) {
        if ($p -match '^DC=(.+)$') { $dc += $matches[1] }
        else { $rest += (($p -replace '^(CN|OU)=', '') -replace '\\(.)', '$1') }
    }
    [array]::Reverse($rest)
    return ((@($dc -join '.') + $rest) -join '/')
}

function New-Raw {
    param([string]$Html, [string]$Text)
    [pscustomobject]@{ PSTypeName = 'RawHtml'; Html = $Html; Text = $Text }
}

function New-Badge {
    param([string]$Text, [string]$Class = 'b-info')
    New-Raw -Html ("<span class='bdg {0}'>{1}</span>" -f $Class, (Enc $Text)) -Text $Text
}

function Get-Flag {
    # Sì evidenziato se vero, "No" altrimenti
    param($Value, [string]$Class = 'b-warn')
    if ($Value) { return (New-Badge 'Sì' $Class) }
    return 'No'
}

function Format-Span {
    param($Span, [string]$ZeroText = 'Nessuno / mai')
    if ($null -eq $Span) { return '' }
    $ts = [timespan]$Span
    if ($ts.Ticks -le 0) { return $ZeroText }
    if ($ts.TotalDays -ge 1) { return ('{0} giorni' -f [math]::Round($ts.TotalDays, 1)) }
    if ($ts.TotalHours -ge 1) { return ('{0} ore' -f [math]::Round($ts.TotalHours, 1)) }
    return ('{0} minuti' -f [math]::Round($ts.TotalMinutes, 0))
}

function Format-Cell {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) {
        if ($Value.Length -gt 70) { return "<div class='lt'>" + (Enc $Value) + '</div>' }
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
    param(
        [object[]]$Data,
        [string]$Id,
        [System.Collections.IDictionary]$Filters,
        [string]$EmptyText = 'Nessun elemento da mostrare.',
        [switch]$NoToolbar
    )
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

function New-KVTable {
    param([System.Collections.IDictionary]$Data)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<table class='kv'>")
    foreach ($k in $Data.Keys) { [void]$sb.Append("<tr><th>$(Enc $k)</th><td>$(Format-Cell $Data[$k])</td></tr>") }
    [void]$sb.Append('</table>')
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
            foreach ($p in $r.PSObject.Properties) {
                if ($p.Name.StartsWith('_')) { continue }
                $o[$p.Name] = ConvertTo-PlainText $p.Value
            }
            [pscustomobject]$o
        }
        $rows | Export-Csv -LiteralPath (Join-Path $CsvFolder "$Name.csv") -NoTypeInformation -Delimiter ';' -Encoding UTF8
    } catch { Add-Log 'Esportazione CSV' "$($Name): $($_.Exception.Message)" }
}

function Add-FL {
    # Accumula oggetti per una rilevazione
    param([string]$Key, [string]$Item)
    if (-not $script:FL.ContainsKey($Key)) { $script:FL[$Key] = New-Object System.Collections.Generic.List[string] }
    $script:FL[$Key].Add($Item)
}

function Get-FLItems {
    param([string]$Key)
    if ($script:FL.ContainsKey($Key)) { return , $script:FL[$Key].ToArray() }
    return , @()
}

function Add-Finding {
    param(
        [ValidateSet('Critico', 'Alto', 'Medio', 'Basso', 'Info')][string]$Severity,
        [string]$Category, [string]$Title, [string]$Description, [string]$Recommendation,
        [object[]]$Objects, [string]$Section
    )
    $script:Findings.Add([pscustomobject]@{
            Severity = $Severity; Category = $Category; Title = $Title; Description = $Description
            Recommendation = $Recommendation; Objects = @(Get-List $Objects); Section = $Section
        })
}

function Add-FindingFromList {
    # Aggiunge la rilevazione solo se la lista di oggetti non è vuota
    param([string]$Key, [string]$Severity, [string]$Category, [string]$Title, [string]$Description, [string]$Recommendation, [string]$Section)
    $items = Get-FLItems $Key
    if ($items.Count -gt 0) {
        Add-Finding -Severity $Severity -Category $Category -Title "$Title ($($items.Count))" -Description $Description -Recommendation $Recommendation -Objects $items -Section $Section
    }
}

function Get-OsSupport {
    # Stato del supporto Microsoft in base a nome e build del SO (date di fine supporto note al 2026)
    param([string]$OS, [string]$Version)
    if (-not $OS) { return [pscustomobject]@{ Status = 'Sconosciuto'; Eol = '' } }
    if ($OS -notmatch 'Windows') { return [pscustomobject]@{ Status = 'N/D (non Windows)'; Eol = '' } }
    $build = $null
    if ($Version -match '\((\d+)\)') { $build = [int]$matches[1] }
    $ent = $OS -match 'Enterprise|Education'
    $eol = $null
    if ($OS -match 'Windows (NT|2000|XP|Vista)|Server 2003') { $eol = '2015-07-14' }
    elseif ($OS -match 'Server 2008') { $eol = '2020-01-14' }
    elseif ($OS -match 'Server 2012') { $eol = '2023-10-10' }
    elseif ($OS -match 'Server 2016') { $eol = '2027-01-12' }
    elseif ($OS -match 'Server 2019') { $eol = '2029-01-09' }
    elseif ($OS -match 'Server 2022') { $eol = '2031-10-14' }
    elseif ($OS -match 'Server 2025') { $eol = '2034-10-10' }
    elseif ($OS -match 'Windows 7') { $eol = '2020-01-14' }
    elseif ($OS -match 'Windows 8') { $eol = '2023-01-10' }
    elseif ($OS -match 'Windows 10') {
        if ($OS -match 'LTS[BC]') {
            switch ($build) { 10240 { $eol = '2025-10-14' } 14393 { $eol = '2026-10-13' } 17763 { $eol = '2029-01-09' } 19044 { $eol = '2027-01-12' } }
        } else { $eol = '2025-10-14' }
    }
    elseif ($OS -match 'Windows 11') {
        if ($OS -match 'LTSC') { if ($build -eq 26100) { $eol = '2029-10-09' } }
        else {
            switch ($build) {
                22000 { $eol = $(if ($ent) { '2024-10-08' } else { '2023-10-10' }) }
                22621 { $eol = $(if ($ent) { '2025-10-14' } else { '2024-10-08' }) }
                22631 { $eol = $(if ($ent) { '2026-11-10' } else { '2025-11-11' }) }
                26100 { $eol = $(if ($ent) { '2027-10-12' } else { '2026-10-13' }) }
                26200 { $eol = $(if ($ent) { '2028-10-10' } else { '2027-10-12' }) }
            }
        }
    }
    if (-not $eol) { return [pscustomobject]@{ Status = 'Da verificare'; Eol = '' } }
    $eolDate = [datetime]::ParseExact($eol, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $status = if ($eolDate -lt $Now) { 'Non supportato' } elseif ($eolDate -lt $Now.AddDays(365)) { 'In scadenza' } else { 'Supportato' }
    return [pscustomobject]@{ Status = $status; Eol = $eol }
}

function Get-OsBadge {
    param($Support)
    switch ($Support.Status) {
        'Non supportato' { return (New-Badge 'Non supportato' 'b-high') }
        'In scadenza' { return (New-Badge 'In scadenza' 'b-med') }
        'Supportato' { return (New-Badge 'Supportato' 'b-ok') }
        default { return (New-Badge $Support.Status 'b-off') }
    }
}

# ---- Gruppi annidati (calcolo in memoria della chiusura transitiva memberOf) ----
$script:GroupParents = @{}
$script:GroupClosureCache = @{}

function Get-GroupClosure {
    param([string]$DN)
    if ($script:GroupClosureCache.ContainsKey($DN)) { return , $script:GroupClosureCache[$DN] }
    $result = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $stack = New-Object System.Collections.Stack
    $stack.Push($DN)
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        foreach ($p in $script:GroupParents[$cur]) { if ($p -and $result.Add($p)) { $stack.Push($p) } }
    }
    $script:GroupClosureCache[$DN] = $result
    return , $result
}

function Get-EffectiveGroupSet {
    param([string[]]$Direct, [string]$Primary)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $all = @($Direct) + @($Primary)
    foreach ($g in $all) {
        if (-not $g) { continue }
        [void]$set.Add($g)
        foreach ($p in (Get-GroupClosure $g)) { [void]$set.Add($p) }
    }
    return , $set
}

# ---- GPO ----
function Get-GpLinks {
    # Analizza l'attributo gPLink; restituisce i collegamenti in ordine di collegamento (1 = precedenza massima)
    param([string]$GpLink)
    if ([string]::IsNullOrWhiteSpace($GpLink)) { return , @() }
    $list = @()
    foreach ($m in [regex]::Matches($GpLink, '\[LDAP://([^;\]]+);(\d+)\]', 'IgnoreCase')) {
        $dn = $m.Groups[1].Value
        $opt = [int]$m.Groups[2].Value
        $guid = ([regex]::Match($dn, '\{[0-9A-Fa-f\-]{36}\}')).Value.ToUpper()
        $list += [pscustomobject]@{ Guid = $guid; Enabled = -not ($opt -band 1); Enforced = [bool]($opt -band 2); Order = 0 }
    }
    [array]::Reverse($list)
    $i = 1
    foreach ($l in $list) { $l.Order = $i; $i++ }
    return , $list
}

# ---- Permessi NTFS ----
$script:SidNameCache = @{}
function Resolve-SidName {
    param([string]$Sid)
    if ($script:SidNameCache.ContainsKey($Sid)) { return $script:SidNameCache[$Sid] }
    $n = $null
    try { $n = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value } catch { $n = $null }
    $script:SidNameCache[$Sid] = $n
    return $n
}

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
        $s = $std -bor 1048576
        $name = switch ($s) {
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
    if (-not $ci -and -not $oi) { $t = 'Solo questa cartella' }
    elseif ($io) { $t = if ($ci -and $oi) { 'Solo sottocartelle e file' } elseif ($ci) { 'Solo sottocartelle' } else { 'Solo file' } }
    else { $t = if ($ci -and $oi) { 'Questa cartella, sottocartelle e file' } elseif ($ci) { 'Questa cartella e sottocartelle' } else { 'Questa cartella e file' } }
    if ($np) { $t += ' (solo primo livello)' }
    return $t
}

#endregion

#region ===================== PREREQUISITI E CONNESSIONE =====================

Write-Step "AD Security Report v$ScriptVersion - avvio"
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Modulo ActiveDirectory non trovato. Installare RSAT: 'Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' (client) oppure 'Install-WindowsFeature RSAT-AD-PowerShell' (server)."
    return
}
Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue -Verbose:$false

$adParams = @{}
if ($Server) { $adParams['Server'] = $Server }
try {
    $Domain = Get-ADDomain @adParams -ErrorAction Stop
    $Forest = Get-ADForest @adParams -ErrorAction Stop
} catch {
    Write-Error "Impossibile contattare il dominio: $($_.Exception.Message)"
    return
}
if (-not $Server) { $Server = $Domain.PDCEmulator; $adParams['Server'] = $Server }
$RootDSE = Get-ADRootDSE @adParams
$DomainDN = $Domain.DistinguishedName
$DomainSID = $Domain.DomainSID.Value
$DnsRoot = $Domain.DNSRoot
$ConfigNC = $RootDSE.configurationNamingContext
$SchemaNC = $RootDSE.schemaNamingContext
Write-Step "Dominio: $DnsRoot - DC interrogato: $Server"

$RootDomainSID = $DomainSID
if ($Forest.RootDomain -ne $DnsRoot) {
    $rs = Invoke-Safe 'Foresta' { (Get-ADDomain -Identity $Forest.RootDomain -Server $Forest.RootDomain -ErrorAction Stop).DomainSID.Value }
    if ($rs) { $RootDomainSID = $rs }
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmm'
if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$ReportFile = Join-Path $OutputFolder ('AD_Report_{0}_{1}.html' -f $DnsRoot, $stamp)
$CsvFolder = Join-Path $OutputFolder ('AD_Report_{0}_{1}_csv' -f $DnsRoot, $stamp)

# Selezione della cartella per il report permessi (all'inizio, per non bloccare a metà esecuzione)
if (-not $SkipFolderReport -and -not $FolderPath -and [Environment]::UserInteractive) {
    $sel = $null
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Seleziona la cartella di cui analizzare i permessi (Annulla per saltare)'
        $dlg.ShowNewFolderButton = $false
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $sel = $dlg.SelectedPath }
    } catch {
        $sel = Read-Host 'Percorso della cartella di cui analizzare i permessi (INVIO per saltare)'
    }
    if ($sel) { $FolderPath = @($sel) }
}

function Test-SchemaAttribute {
    param([string]$Name)
    try { return [bool](Get-ADObject -SearchBase $SchemaNC -LDAPFilter "(lDAPDisplayName=$Name)" @adParams -ErrorAction Stop) } catch { return $false }
}
$HasLegacyLaps = Test-SchemaAttribute 'ms-Mcs-AdmPwdExpirationTime'
$HasWinLaps = Test-SchemaAttribute 'msLAPS-PasswordExpirationTime'
$HasRBCD = Test-SchemaAttribute 'msDS-AllowedToActOnBehalfOfOtherIdentity'

#endregion

#region ===================== DOMINIO, FORESTA, DC =====================

Write-Step 'Raccolta informazioni su dominio, foresta e Domain Controller'
$DomObj = Get-ADObject $DomainDN -Properties 'ms-DS-MachineAccountQuota', gPLink, gPOptions, whenCreated @adParams
$MAQ = $DomObj.'ms-DS-MachineAccountQuota'

$SchemaVersion = Invoke-Safe 'Schema' { (Get-ADObject $SchemaNC -Properties objectVersion @adParams -ErrorAction Stop).objectVersion }
$SchemaMap = @{ 13 = 'Windows 2000'; 30 = 'Windows Server 2003'; 31 = 'Windows Server 2003 R2'; 44 = 'Windows Server 2008'; 47 = 'Windows Server 2008 R2'; 56 = 'Windows Server 2012'; 69 = 'Windows Server 2012 R2'; 87 = 'Windows Server 2016'; 88 = 'Windows Server 2019 / 2022'; 91 = 'Windows Server 2025' }
$SchemaText = if ($SchemaVersion) { "$SchemaVersion ($($SchemaMap[[int]$SchemaVersion]))" } else { 'n/d' }

$RecycleBin = Invoke-Safe 'Cestino AD' { Get-ADOptionalFeature -Filter "Name -like 'Recycle Bin Feature'" @adParams -ErrorAction Stop }
$RecycleEnabled = [bool]($RecycleBin -and @($RecycleBin.EnabledScopes).Count -gt 0)

$Tombstone = Invoke-Safe 'Tombstone' { (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$ConfigNC" -Properties tombstoneLifetime @adParams -ErrorAction Stop).tombstoneLifetime }

$DCs = @(Invoke-Safe 'Domain Controller' { Get-ADDomainController -Filter * @adParams -ErrorAction Stop } | Where-Object { $_ })

$DcRows = foreach ($dc in ($DCs | Sort-Object Name)) {
    $sup = Get-OsSupport $dc.OperatingSystem $dc.OperatingSystemVersion
    if ($sup.Status -eq 'Non supportato') { Add-FL 'dc.eol' "$($dc.HostName) - $($dc.OperatingSystem)" }
    [pscustomobject][ordered]@{
        'Nome'             = $dc.Name
        'Hostname'         = $dc.HostName
        'IPv4'             = $dc.IPv4Address
        'Sito'             = $dc.Site
        'Sistema operativo' = $dc.OperatingSystem
        'Versione'         = $dc.OperatingSystemVersion
        'Supporto SO'      = Get-OsBadge $sup
        'Global Catalog'   = [bool]$dc.IsGlobalCatalog
        'Sola lettura (RODC)' = [bool]$dc.IsReadOnly
        'Ruoli FSMO'       = @($dc.OperationMasterRoles | ForEach-Object { [string]$_ })
    }
}

Write-Step 'Verifica stato della replica'
$ReplRows = @(Invoke-Safe 'Replica' {
        Get-ADReplicationPartnerMetadata -Target $DnsRoot -Scope Domain -ErrorAction Stop | ForEach-Object {
            $ok = ($_.LastReplicationResult -eq 0)
            if (-not $ok) { Add-FL 'repl.fail' "$($_.Server) <- $(Get-RdnName (Get-ParentDN $_.Partner)) - risultato $($_.LastReplicationResult), errori consecutivi $($_.ConsecutiveReplicationFailures)" }
            [pscustomobject][ordered]@{
                'Server'               = $_.Server
                'Partner'              = Get-RdnName (Get-ParentDN $_.Partner)
                'Partizione'           = $_.Partition
                'Ultimo tentativo'     = $_.LastReplicationAttempt
                'Ultimo successo'      = $_.LastReplicationSuccess
                'Esito'                = $(if ($ok) { New-Badge 'OK' 'b-ok' } else { New-Badge "Errore $($_.LastReplicationResult)" 'b-high' })
                'Errori consecutivi'   = $_.ConsecutiveReplicationFailures
            }
        }
    } | Where-Object { $_ })

Write-Step 'Raccolta siti, subnet e trust'
$SitesRaw = @(Invoke-Safe 'Siti' { Get-ADObject -SearchBase "CN=Sites,$ConfigNC" -SearchScope OneLevel -LDAPFilter '(objectClass=site)' -Properties gPLink, description @adParams -ErrorAction Stop } | Where-Object { $_ })
$SubnetsRaw = @(Invoke-Safe 'Subnet' { Get-ADObject -SearchBase "CN=Subnets,CN=Sites,$ConfigNC" -LDAPFilter '(objectClass=subnet)' -Properties siteObject, description, location @adParams -ErrorAction Stop } | Where-Object { $_ })
$TrustsRaw = @(Invoke-Safe 'Trust' { Get-ADTrust -Filter * @adParams -ErrorAction Stop } | Where-Object { $_ })

$TrustRows = foreach ($t in $TrustsRaw) {
    if (-not $t.IntraForest -and -not $t.ForestTransitive -and -not $t.SIDFilteringQuarantined) { Add-FL 'trust.sidfilter' "$($t.Target) ($($t.Direction))" }
    [pscustomobject][ordered]@{
        'Dominio di destinazione'   = $t.Target
        'Direzione'                 = [string]$t.Direction
        'Tipo'                      = [string]$t.TrustType
        'Trust di foresta'          = [bool]$t.ForestTransitive
        'Intra-foresta'             = [bool]$t.IntraForest
        'SID filtering (quarantena)' = [bool]$t.SIDFilteringQuarantined
        'Autenticazione selettiva'  = [bool]$t.SelectiveAuthentication
        'Creato'                    = $t.whenCreated
        'Modificato'                = $t.whenChanged
    }
}

#endregion

#region ===================== GRUPPI (mappe di base) =====================

Write-Step 'Raccolta gruppi'
$RawGroups = @()
try {
    $RawGroups = @(Get-ADGroup -Filter * -Properties member, memberOf, description, managedBy, whenCreated, whenChanged, adminCount, mail @adParams -ErrorAction Stop)
} catch {
    Add-Log 'Gruppi' "Lettura con attributo member non riuscita ($($_.Exception.Message)); nuovo tentativo senza membri."
    $RawGroups = @(Invoke-Safe 'Gruppi' { Get-ADGroup -Filter * -Properties memberOf, description, managedBy, whenCreated, whenChanged, adminCount, mail @adParams -ErrorAction Stop } | Where-Object { $_ })
}

$GroupByDN = @{}; $GroupBySid = @{}; $GroupDnByRid = @{}
foreach ($g in $RawGroups) {
    $GroupByDN[$g.DistinguishedName] = $g
    $sid = $g.SID.Value
    $GroupBySid[$sid] = $g
    if ($sid.StartsWith("$DomainSID-")) { $GroupDnByRid[$sid.Substring($DomainSID.Length + 1)] = $g.DistinguishedName }
    $script:GroupParents[$g.DistinguishedName] = @(Get-List $g.MemberOf)
}

function Get-DnName {
    param([string]$DN)
    $g = $GroupByDN[$DN]
    if ($g) { return $g.Name }
    return (Get-RdnName $DN)
}

# Gruppi privilegiati (individuati tramite SID: indipendenti dalla lingua del dominio)
$PrivDefs = @(
    @{ Sid = "$DomainSID-512"; Label = 'Domain Admins' },
    @{ Sid = "$RootDomainSID-519"; Label = 'Enterprise Admins' },
    @{ Sid = "$RootDomainSID-518"; Label = 'Schema Admins' },
    @{ Sid = 'S-1-5-32-544'; Label = 'Administrators' },
    @{ Sid = 'S-1-5-32-548'; Label = 'Account Operators' },
    @{ Sid = 'S-1-5-32-549'; Label = 'Server Operators' },
    @{ Sid = 'S-1-5-32-550'; Label = 'Print Operators' },
    @{ Sid = 'S-1-5-32-551'; Label = 'Backup Operators' },
    @{ Sid = "$DomainSID-520"; Label = 'Group Policy Creator Owners' },
    @{ Sid = "$DomainSID-526"; Label = 'Key Admins' },
    @{ Sid = "$RootDomainSID-527"; Label = 'Enterprise Key Admins' },
    @{ Sid = 'DnsAdmins'; Label = 'DnsAdmins' }
)
$PrivGroups = [ordered]@{}
$idx = 0
foreach ($d in $PrivDefs) {
    $g = if ($d.Sid -eq 'DnsAdmins') { $RawGroups | Where-Object { $_.SamAccountName -eq 'DnsAdmins' } | Select-Object -First 1 } else { $GroupBySid[$d.Sid] }
    if ($g -and -not $PrivGroups.Contains($g.DistinguishedName)) {
        $display = if ($g.Name -ne $d.Label) { "$($d.Label) ($($g.Name))" } else { $d.Label }
        $PrivGroups[$g.DistinguishedName] = [pscustomobject]@{ Label = $d.Label; Name = $g.Name; Sid = $g.SID.Value; Display = $display; Index = $idx; DN = $g.DistinguishedName }
        $idx++
    }
}
# Gruppi protetti da AdminSDHolder (per verificare adminCount orfani)
$AdminSdDNs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($k in $PrivGroups.Keys) { [void]$AdminSdDNs.Add($k) }
foreach ($s in @('S-1-5-32-552', "$DomainSID-516", "$DomainSID-521")) { if ($GroupBySid[$s]) { [void]$AdminSdDNs.Add($GroupBySid[$s].DistinguishedName) } }
$ProtectedUsersDN = if ($GroupBySid["$DomainSID-525"]) { $GroupBySid["$DomainSID-525"].DistinguishedName } else { $null }

$PrivRows = New-Object System.Collections.Generic.List[object]
$DelegRows = New-Object System.Collections.Generic.List[object]
$CountByContainer = @{}
$PrimaryCount = @{}
function Add-ContainerCount {
    param([string]$DN, [string]$Kind)
    $p = Get-ParentDN $DN
    if (-not $CountByContainer.ContainsKey($p)) { $CountByContainer[$p] = @{ U = 0; C = 0; G = 0 } }
    $CountByContainer[$p][$Kind] = $CountByContainer[$p][$Kind] + 1
}

#endregion

#region ===================== ULTIMO LOGON PRECISO (opzionale) =====================

$PreciseLogon = @{}
if ($QueryAllDCs) {
    foreach ($dc in $DCs) {
        Write-Step "Lettura lastLogon da $($dc.HostName)"
        try {
            Get-ADObject -LDAPFilter '(&(objectClass=user)(lastLogon>=1))' -Properties lastLogon -Server $dc.HostName -ResultPageSize 1000 -ErrorAction Stop | ForEach-Object {
                $k = $_.ObjectGUID.ToString(); $t = [int64]$_.lastLogon
                if (-not $PreciseLogon.ContainsKey($k) -or $PreciseLogon[$k] -lt $t) { $PreciseLogon[$k] = $t }
            }
        } catch { Add-Log "lastLogon $($dc.HostName)" $_.Exception.Message }
    }
}
function Get-BestLastLogon {
    param($Obj)
    $d = $Obj.LastLogonDate
    if ($QueryAllDCs) {
        $k = $Obj.ObjectGUID.ToString()
        if ($PreciseLogon.ContainsKey($k)) {
            $p = [datetime]::FromFileTime($PreciseLogon[$k])
            if (-not $d -or $p -gt $d) { $d = $p }
        }
    }
    return $d
}

#endregion

#region ===================== UTENTI =====================

Write-Step 'Raccolta utenti'
$UserProps = @('DisplayName', 'UserPrincipalName', 'Enabled', 'LastLogonDate', 'badPwdCount', 'LastBadPasswordAttempt', 'LockedOut',
    'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired', 'PasswordExpired', 'CannotChangePassword',
    'AllowReversiblePasswordEncryption', 'AccountExpirationDate', 'msDS-UserPasswordExpiryTimeComputed', 'whenCreated', 'whenChanged',
    'Description', 'Title', 'Department', 'Company', 'Office', 'EmailAddress', 'telephoneNumber', 'Manager', 'MemberOf', 'PrimaryGroupID',
    'adminCount', 'SIDHistory', 'servicePrincipalName', 'msDS-AllowedToDelegateTo', 'TrustedForDelegation', 'TrustedToAuthForDelegation',
    'DoesNotRequirePreAuth', 'UseDESKeyOnly', 'AccountNotDelegated', 'ScriptPath', 'HomeDirectory', 'ProfilePath', 'logonCount')
$RawUsers = @()
try { $RawUsers = @(Get-ADUser -Filter * -Properties $UserProps @adParams -ErrorAction Stop) } catch { Add-Log 'Utenti' $_.Exception.Message }

$PwdInDescPattern = '(?i)(passw(or)?d|pwd|psw|parola\s*chiave|kennwort|mot de passe)\s*[:=]'
$Users = New-Object System.Collections.Generic.List[object]
$Stat = @{}
$i = 0
foreach ($u in $RawUsers) {
    $i++
    if ($i % 250 -eq 0) { Write-Progress -Activity 'Elaborazione utenti' -Status "$i / $($RawUsers.Count)" -PercentComplete ([math]::Min(100, $i * 100 / $RawUsers.Count)) }
    $sam = $u.SamAccountName
    $sid = $u.SID.Value
    $lbl = "$sam ($($u.Name))"
    Add-ContainerCount $u.DistinguishedName 'U'
    $pgKey = [string]$u.PrimaryGroupID
    $PrimaryCount[$pgKey] = 1 + [int]$PrimaryCount[$pgKey]

    $enabled = [bool]$u.Enabled
    $lastLogon = Get-BestLastLogon $u
    $daysLogon = Get-DaysSince $lastLogon
    $pwdAge = Get-DaysSince $u.PasswordLastSet
    $direct = Get-List $u.MemberOf
    $primaryDN = $GroupDnByRid[$pgKey]
    $eff = Get-EffectiveGroupSet -Direct $direct -Primary $primaryDN
    $privHits = @(foreach ($pd in $PrivGroups.Keys) { if ($eff.Contains($pd)) { $PrivGroups[$pd].Display } })
    $isPriv = $privHits.Count -gt 0
    $inPU = [bool]($ProtectedUsersDN -and $eff.Contains($ProtectedUsersDN))
    $isAdminSd = $false
    foreach ($a in $AdminSdDNs) { if ($eff.Contains($a)) { $isAdminSd = $true; break } }
    $spns = Get-List $u.servicePrincipalName
    $delegTo = Get-List $u.'msDS-AllowedToDelegateTo'
    $sidHist = @(Get-List $u.SIDHistory | ForEach-Object { [string]$_ })
    $isKrbtgt = ($sid -eq "$DomainSID-502") -or ($sam -like 'krbtgt_*')
    $never = -not $lastLogon
    $inactive = $enabled -and (($lastLogon -and $lastLogon -lt $InactiveLimit) -or ($never -and $u.whenCreated -lt $InactiveLimit))
    $kerberoast = $enabled -and $spns.Count -gt 0 -and -not $isKrbtgt
    $descPwd = [bool]($u.Description -match $PwdInDescPattern)

    # Scadenza password
    $expRaw = [int64]$u.'msDS-UserPasswordExpiryTimeComputed'
    $pwdExpiry = if ($u.PasswordNeverExpires -or $expRaw -ge 9223372036854775807) { 'Mai' } else { Format-Date (Convert-FileTime $expRaw) }

    # Deleghe
    $deleg = @()
    if ($u.TrustedForDelegation) { $deleg += 'Non vincolata' }
    if ($delegTo.Count) { $deleg += ('Vincolata' + $(if ($u.TrustedToAuthForDelegation) { ' (protocol transition)' } else { '' })) }
    elseif ($u.TrustedToAuthForDelegation) { $deleg += 'Protocol transition' }
    if ($deleg.Count) {
        $DelegRows.Add([pscustomobject][ordered]@{ 'Oggetto' = $sam; 'Tipo oggetto' = 'Utente'; 'Stato' = $(if ($enabled) { 'Attivo' } else { 'Disabilitato' }); 'Tipo delega' = ($deleg -join ', '); 'Destinazioni / principali autorizzati' = $delegTo })
    }

    # Gruppi
    $directNames = @($direct | ForEach-Object { Get-DnName $_ } | Sort-Object)
    if ($primaryDN) { $directNames = @("$(Get-DnName $primaryDN) (primario)") + $directNames }
    $nestedNames = @(@(foreach ($g in $eff) { if (($direct -notcontains $g) -and $g -ne $primaryDN) { Get-DnName $g } }) | Sort-Object)

    # Rischi
    $risks = New-Object System.Collections.Generic.List[string]
    if ($enabled) {
        if ($u.PasswordNotRequired) { $risks.Add('Password non richiesta'); Add-FL 'u.pwdnotreq' $lbl }
        if ($u.AllowReversiblePasswordEncryption) { $risks.Add('Cifratura reversibile'); Add-FL 'u.reversible' $lbl }
        if ($u.DoesNotRequirePreAuth) { $risks.Add('AS-REP roastable'); Add-FL 'u.asrep' $lbl }
        if ($u.UseDESKeyOnly) { $risks.Add('Solo DES'); Add-FL 'u.des' $lbl }
        if ($kerberoast) { $risks.Add('Kerberoastable (SPN)'); Add-FL 'u.kerberoast' "$lbl - $($spns -join ', ')" }
        if ($u.TrustedForDelegation) { $risks.Add('Delega non vincolata'); Add-FL 'u.unconstrained' $lbl }
        if ($delegTo.Count -or $u.TrustedToAuthForDelegation) { Add-FL 'u.constrained' "$lbl -> $($delegTo -join ', ')" }
        if ($u.PasswordNeverExpires -and -not $isKrbtgt) { $risks.Add('Password senza scadenza'); Add-FL 'u.neverexpires' $lbl }
        if ($sidHist.Count) { $risks.Add('SIDHistory'); Add-FL 'u.sidhistory' "$lbl - $($sidHist -join ', ')" }
        if ($inactive -and -not $isKrbtgt) {
            $risks.Add("Inattivo > $InactiveDays gg")
            Add-FL 'u.inactive' "$lbl - ultimo logon: $(if ($lastLogon) { Format-Date $lastLogon } else { 'mai' })"
        }
        if ($never -and -not $isKrbtgt) { Add-FL 'u.never' "$lbl - creato il $(Format-Date $u.whenCreated)" }
        if ($null -ne $pwdAge -and $pwdAge -gt $PasswordAgeDays -and -not $isKrbtgt) { $risks.Add("Password > $PasswordAgeDays gg"); Add-FL 'u.oldpwd' "$lbl - $pwdAge giorni" }
        if ($u.LockedOut) { Add-FL 'u.locked' $lbl }
        if ([int]$u.badPwdCount -ge 3) { Add-FL 'u.badpwd' "$lbl - $($u.badPwdCount) tentativi, ultimo $(Format-Date $u.LastBadPasswordAttempt)" }
        if ($u.PasswordExpired) { Add-FL 'u.pwdexpired' $lbl }
    }
    if ($descPwd) { $risks.Add('Possibile password nella descrizione'); Add-FL 'u.descpwd' "$lbl - `"$($u.Description)`"" }
    if ($isPriv) {
        if (-not $enabled) { Add-FL 'u.priv.disabled' "$lbl - $($privHits -join ', ')" }
        else {
            if ($null -ne $pwdAge -and $pwdAge -gt $PasswordAgeDays) { Add-FL 'u.priv.oldpwd' "$lbl - $pwdAge giorni" }
            if ($u.PasswordNeverExpires) { Add-FL 'u.priv.neverexp' $lbl }
            if ($spns.Count) { Add-FL 'u.priv.spn' "$lbl - $($spns -join ', ')" }
            if (-not $inPU -and -not $u.AccountNotDelegated) { Add-FL 'u.priv.notprotected' $lbl }
            if ($inactive) { Add-FL 'u.priv.inactive' $lbl }
        }
    }
    if ($u.adminCount -eq 1 -and -not $isAdminSd -and -not $isKrbtgt) { Add-FL 'u.admincount' $lbl }

    # Righe gruppi privilegiati
    foreach ($pd in $PrivGroups.Keys) {
        if ($eff.Contains($pd)) {
            $PrivRows.Add([pscustomobject][ordered]@{
                    'Gruppo privilegiato' = $PrivGroups[$pd].Display
                    'Membro'              = $u.Name
                    'Account'             = $sam
                    'Tipo'                = 'Utente'
                    'Appartenenza'        = $(if (($direct -contains $pd) -or $primaryDN -eq $pd) { 'Diretta' } else { 'Annidata' })
                    'Stato'               = $(if ($enabled) { New-Badge 'Attivo' 'b-ok' } else { New-Badge 'Disabilitato' 'b-off' })
                    'Ultimo logon'        = $lastLogon
                    'Età password (gg)'   = $pwdAge
                    'Pwd senza scadenza'  = Get-Flag $u.PasswordNeverExpires
                    'SPN'                 = Get-Flag ($spns.Count -gt 0) 'b-high'
                    'Protected Users'     = $inPU
                    'Sensibile (no delega)' = [bool]$u.AccountNotDelegated
                    '_RowClass'           = "pg-$($PrivGroups[$pd].Index)"
                })
        }
    }

    $cls = @($(if ($enabled) { 'st-on' } else { 'st-off' }))
    if ($inactive) { $cls += 'f-inactive' }
    if ($risks.Count) { $cls += 'f-risk' }
    if ($isPriv) { $cls += 'f-priv' }
    if ($u.LockedOut) { $cls += 'f-locked' }
    if ($never) { $cls += 'f-never' }
    if ([int]$u.badPwdCount -gt 0) { $cls += 'f-badpwd' }
    if ($u.PasswordNeverExpires) { $cls += 'f-nexp' }

    $Users.Add([pscustomobject][ordered]@{
            'Nome'                    = $u.Name
            'Account'                 = $sam
            'UPN'                     = $u.UserPrincipalName
            'Stato'                   = $(if ($enabled) { New-Badge 'Attivo' 'b-ok' } else { New-Badge 'Disabilitato' 'b-off' })
            'Ultimo logon'            = $lastLogon
            'Gg da ultimo logon'      = $daysLogon
            'Tentativi errati'        = $u.badPwdCount
            'Ultimo tentativo errato' = $u.LastBadPasswordAttempt
            'Bloccato'                = Get-Flag $u.LockedOut 'b-high'
            'Password impostata'      = $u.PasswordLastSet
            'Età password (gg)'       = $pwdAge
            'Scadenza password'       = $pwdExpiry
            'Password scaduta'        = Get-Flag $u.PasswordExpired 'b-low'
            'Pwd senza scadenza'      = Get-Flag $u.PasswordNeverExpires
            'Pwd non richiesta'       = Get-Flag $u.PasswordNotRequired 'b-high'
            'Non può cambiare pwd'    = Get-Flag $u.CannotChangePassword 'b-low'
            'Cifratura reversibile'   = Get-Flag $u.AllowReversiblePasswordEncryption 'b-high'
            'No preauth Kerberos'     = Get-Flag $u.DoesNotRequirePreAuth 'b-high'
            'Solo DES'                = Get-Flag $u.UseDESKeyOnly
            'SPN'                     = $spns
            'Delega'                  = $deleg
            'Sensibile (no delega)'   = [bool]$u.AccountNotDelegated
            'Protected Users'         = $inPU
            'AdminCount'              = $u.adminCount
            'Privilegi'               = $privHits
            'SIDHistory'              = $sidHist
            'Scadenza account'        = $u.AccountExpirationDate
            'Creato'                  = $u.whenCreated
            'Modificato'              = $u.whenChanged
            'Descrizione'             = $u.Description
            'Qualifica'               = $u.Title
            'Reparto'                 = $u.Department
            'Società'                 = $u.Company
            'Ufficio'                 = $u.Office
            'Email'                   = $u.EmailAddress
            'Telefono'                = $u.telephoneNumber
            'Manager'                 = $(if ($u.Manager) { Get-RdnName $u.Manager } else { '' })
            'Script di logon'         = $u.ScriptPath
            'Home directory'          = $u.HomeDirectory
            'Profilo'                 = $u.ProfilePath
            'Posizione (OU)'          = ConvertTo-CanonicalPath (Get-ParentDN $u.DistinguishedName)
            'Gruppi diretti'          = $directNames
            'Gruppi annidati'         = $nestedNames
            'Rischi'                  = @($risks | ForEach-Object { New-Badge $_ 'b-warn' })
            '_RowClass'               = ($cls -join ' ')
            '_Enabled'                = $enabled
            '_Inactive'               = $inactive
            '_Priv'                   = $isPriv
        })
}
Write-Progress -Activity 'Elaborazione utenti' -Completed

#endregion

#region ===================== COMPUTER =====================

Write-Step 'Raccolta computer'
$CompProps = @('DNSHostName', 'Enabled', 'OperatingSystem', 'OperatingSystemVersion', 'OperatingSystemServicePack', 'LastLogonDate', 'PasswordLastSet',
    'whenCreated', 'whenChanged', 'Description', 'Location', 'ManagedBy', 'MemberOf', 'PrimaryGroupID', 'TrustedForDelegation',
    'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo', 'servicePrincipalName', 'badPwdCount', 'LastBadPasswordAttempt', 'SIDHistory')
if ($HasLegacyLaps) { $CompProps += 'ms-Mcs-AdmPwdExpirationTime' }
if ($HasWinLaps) { $CompProps += 'msLAPS-PasswordExpirationTime' }
if ($HasRBCD) { $CompProps += 'msDS-AllowedToActOnBehalfOfOtherIdentity' }
if ($ResolveComputerIP) { $CompProps += 'IPv4Address' }
$RawComputers = @()
try { $RawComputers = @(Get-ADComputer -Filter * -Properties $CompProps @adParams -ErrorAction Stop) } catch { Add-Log 'Computer' $_.Exception.Message }

# Chiavi di ripristino BitLocker salvate in AD (richiede permessi di lettura su msFVE-RecoveryInformation)
$BitLockerCount = @{}
$blObjs = @(Invoke-Safe 'BitLocker' { Get-ADObject -SearchBase $DomainDN -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' @adParams -ErrorAction Stop } | Where-Object { $_ })
foreach ($b in $blObjs) { $p = Get-ParentDN $b.DistinguishedName; $BitLockerCount[$p] = 1 + [int]$BitLockerCount[$p] }

$Computers = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($c in $RawComputers) {
    $i++
    if ($i % 250 -eq 0) { Write-Progress -Activity 'Elaborazione computer' -Status "$i / $($RawComputers.Count)" -PercentComplete ([math]::Min(100, $i * 100 / $RawComputers.Count)) }
    $name = $c.Name
    Add-ContainerCount $c.DistinguishedName 'C'
    $pgKey = [string]$c.PrimaryGroupID
    $PrimaryCount[$pgKey] = 1 + [int]$PrimaryCount[$pgKey]
    $enabled = [bool]$c.Enabled
    $os = $c.OperatingSystem
    $isWindows = $os -match 'Windows'
    $type = switch ($c.PrimaryGroupID) {
        516 { 'Domain Controller' }
        521 { 'RODC' }
        default { if ($os -match 'Server') { 'Server' } elseif ($isWindows) { 'Workstation' } elseif ($os) { 'Altro' } else { 'Sconosciuto' } }
    }
    $isDC = $type -in 'Domain Controller', 'RODC'
    $sup = Get-OsSupport $os $c.OperatingSystemVersion
    $lastLogon = Get-BestLastLogon $c
    $never = -not $lastLogon
    $inactive = $enabled -and (($lastLogon -and $lastLogon -lt $InactiveLimit) -or ($never -and $c.whenCreated -lt $InactiveLimit))
    $pwdAge = Get-DaysSince $c.PasswordLastSet
    $direct = Get-List $c.MemberOf
    $primaryDN = $GroupDnByRid[$pgKey]
    $eff = Get-EffectiveGroupSet -Direct $direct -Primary $primaryDN
    $spns = Get-List $c.servicePrincipalName
    $delegTo = Get-List $c.'msDS-AllowedToDelegateTo'
    $sidHist = @(Get-List $c.SIDHistory | ForEach-Object { [string]$_ })

    # LAPS
    $lapsLegacy = if ($HasLegacyLaps) { Convert-FileTime $c.'ms-Mcs-AdmPwdExpirationTime' } else { $null }
    $lapsWin = if ($HasWinLaps) { Convert-FileTime $c.'msLAPS-PasswordExpirationTime' } else { $null }
    $lapsTypes = @()
    if ($lapsWin) { $lapsTypes += 'Windows LAPS' }
    if ($lapsLegacy) { $lapsTypes += 'LAPS legacy' }
    $lapsExp = if ($lapsWin) { $lapsWin } else { $lapsLegacy }
    $lapsNeeded = $enabled -and $isWindows -and -not $isDC
    $lapsCell = if ($lapsTypes.Count) { New-Badge ($lapsTypes -join ' + ') 'b-ok' } elseif ($lapsNeeded) { New-Badge 'No' 'b-high' } else { 'N/D' }

    # Deleghe
    $deleg = @()
    $rbcd = @()
    if ($c.TrustedForDelegation -and -not $isDC) { $deleg += 'Non vincolata' }
    if ($delegTo.Count) { $deleg += ('Vincolata' + $(if ($c.TrustedToAuthForDelegation) { ' (protocol transition)' } else { '' })) }
    elseif ($c.TrustedToAuthForDelegation) { $deleg += 'Protocol transition' }
    if ($HasRBCD -and $c.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
        try { $rbcd = @($c.'msDS-AllowedToActOnBehalfOfOtherIdentity'.Access | ForEach-Object { [string]$_.IdentityReference }) } catch { $rbcd = @('(non decodificabile)') }
        $deleg += 'Resource-based (RBCD)'
    }
    if ($deleg.Count) {
        $DelegRows.Add([pscustomobject][ordered]@{ 'Oggetto' = $name; 'Tipo oggetto' = "Computer ($type)"; 'Stato' = $(if ($enabled) { 'Attivo' } else { 'Disabilitato' }); 'Tipo delega' = ($deleg -join ', '); 'Destinazioni / principali autorizzati' = @($delegTo) + @($rbcd | ForEach-Object { "RBCD: $_" }) })
    }

    $risks = New-Object System.Collections.Generic.List[string]
    $lbl = "$name ($os)"
    if ($enabled) {
        if ($sup.Status -eq 'Non supportato') { $risks.Add('SO non supportato'); Add-FL 'c.eol' "$name - $os $($c.OperatingSystemVersion)" }
        elseif ($sup.Status -eq 'In scadenza') { Add-FL 'c.eolsoon' "$name - $os (fine supporto $($sup.Eol))" }
        if ($lapsNeeded -and -not $lapsTypes.Count) { $risks.Add('LAPS assente'); Add-FL 'c.nolaps' $lbl }
        if ($c.TrustedForDelegation -and -not $isDC) { $risks.Add('Delega non vincolata'); Add-FL 'c.unconstrained' $lbl }
        if ($delegTo.Count -or $c.TrustedToAuthForDelegation) { Add-FL 'c.constrained' "$name -> $($delegTo -join ', ')" }
        if ($rbcd.Count) { $risks.Add('RBCD'); Add-FL 'c.rbcd' "$name <- $($rbcd -join ', ')" }
        if ($inactive) { $risks.Add("Inattivo > $InactiveDays gg"); Add-FL 'c.inactive' "$name - ultimo logon: $(if ($lastLogon) { Format-Date $lastLogon } else { 'mai' })" }
        if ($sidHist.Count) { $risks.Add('SIDHistory'); Add-FL 'c.sidhistory' $name }
    }

    $privHits = @()
    foreach ($pd in $PrivGroups.Keys) {
        if ($eff.Contains($pd)) {
            $privHits += $PrivGroups[$pd].Display
            $PrivRows.Add([pscustomobject][ordered]@{
                    'Gruppo privilegiato' = $PrivGroups[$pd].Display; 'Membro' = $name; 'Account' = $c.SamAccountName; 'Tipo' = 'Computer'
                    'Appartenenza' = $(if (($direct -contains $pd) -or $primaryDN -eq $pd) { 'Diretta' } else { 'Annidata' })
                    'Stato' = $(if ($enabled) { New-Badge 'Attivo' 'b-ok' } else { New-Badge 'Disabilitato' 'b-off' })
                    'Ultimo logon' = $lastLogon; 'Età password (gg)' = $pwdAge; 'Pwd senza scadenza' = 'N/D'; 'SPN' = 'N/D'
                    'Protected Users' = $false; 'Sensibile (no delega)' = $false; '_RowClass' = "pg-$($PrivGroups[$pd].Index)"
                })
        }
    }
    if ($privHits.Count -and -not $isDC) { $risks.Add('In gruppi privilegiati'); Add-FL 'c.priv' "$name - $($privHits -join ', ')" }

    $cls = @($(if ($enabled) { 'st-on' } else { 'st-off' }))
    if ($inactive) { $cls += 'f-inactive' }
    if ($risks.Count) { $cls += 'f-risk' }
    if ($sup.Status -eq 'Non supportato') { $cls += 'f-eol' }
    if ($lapsNeeded -and -not $lapsTypes.Count) { $cls += 'f-nolaps' }
    switch ($type) { 'Domain Controller' { $cls += 'k-dc' } 'RODC' { $cls += 'k-dc' } 'Server' { $cls += 'k-srv' } 'Workstation' { $cls += 'k-ws' } default { $cls += 'k-oth' } }

    $row = [ordered]@{
        'Nome'                = $name
        'DNS'                 = $c.DNSHostName
        'Stato'               = $(if ($enabled) { New-Badge 'Attivo' 'b-ok' } else { New-Badge 'Disabilitato' 'b-off' })
        'Tipo'                = $type
        'Sistema operativo'   = $os
        'Versione SO'         = $c.OperatingSystemVersion
        'Service Pack'        = $c.OperatingSystemServicePack
        'Supporto SO'         = Get-OsBadge $sup
        'Fine supporto'       = $sup.Eol
        'Ultimo logon'        = $lastLogon
        'Gg da ultimo logon'  = Get-DaysSince $lastLogon
        'Password account impostata' = $c.PasswordLastSet
        'Età password (gg)'   = $pwdAge
    }
    if ($ResolveComputerIP) { $row['IPv4'] = $c.IPv4Address }
    $row['LAPS'] = $lapsCell
    $row['Scadenza password LAPS'] = $lapsExp
    $row['Chiavi BitLocker in AD'] = [int]$BitLockerCount[$c.DistinguishedName]
    $row['Delega'] = $deleg
    $row['SPN'] = $spns
    $row['Tentativi errati'] = $c.badPwdCount
    $row['Ultimo tentativo errato'] = $c.LastBadPasswordAttempt
    $row['Creato'] = $c.whenCreated
    $row['Modificato'] = $c.whenChanged
    $row['Descrizione'] = $c.Description
    $row['Ubicazione'] = $c.Location
    $row['Gestito da'] = $(if ($c.ManagedBy) { Get-RdnName $c.ManagedBy } else { '' })
    $row['Posizione (OU)'] = ConvertTo-CanonicalPath (Get-ParentDN $c.DistinguishedName)
    $row['Gruppi'] = @(@($(if ($primaryDN) { "$(Get-DnName $primaryDN) (primario)" })) + @($direct | ForEach-Object { Get-DnName $_ } | Sort-Object))
    $row['Rischi'] = @($risks | ForEach-Object { New-Badge $_ 'b-warn' })
    $row['_RowClass'] = ($cls -join ' ')
    $row['_Enabled'] = $enabled
    $row['_Type'] = $type
    $row['_Eol'] = $sup.Status
    $row['_Inactive'] = $inactive
    $row['_LapsMissing'] = ($lapsNeeded -and -not $lapsTypes.Count)
    $Computers.Add([pscustomobject]$row)
}
Write-Progress -Activity 'Elaborazione computer' -Completed

#endregion

#region ===================== GRUPPI (tabella) =====================

Write-Step 'Elaborazione gruppi'
$Groups = New-Object System.Collections.Generic.List[object]
foreach ($g in $RawGroups) {
    Add-ContainerCount $g.DistinguishedName 'G'
    $members = Get-List $g.member
    $sid = $g.SID.Value
    $rid = if ($sid.StartsWith("$DomainSID-")) { $sid.Substring($DomainSID.Length + 1) } else { '' }
    $pc = if ($rid) { [int]$PrimaryCount[$rid] } else { 0 }
    $total = $members.Count + $pc
    $isPrivGroup = $PrivGroups.Contains($g.DistinguishedName)
    $scope = switch ([string]$g.GroupScope) { 'DomainLocal' { 'Dominio locale' } 'Global' { 'Globale' } 'Universal' { 'Universale' } default { [string]$g.GroupScope } }
    $cat = switch ([string]$g.GroupCategory) { 'Security' { 'Sicurezza' } 'Distribution' { 'Distribuzione' } default { [string]$g.GroupCategory } }
    $memberNames = @($members | Select-Object -First 300 | ForEach-Object { Get-RdnName $_ } | Sort-Object)
    if ($members.Count -gt 300) { $memberNames += "... (+$($members.Count - 300) altri)" }
    if ($total -eq 0 -and -not $g.IsCriticalSystemObject) { Add-FL 'g.empty' $g.Name }

    # Gruppi annidati in gruppi privilegiati
    $geff = Get-GroupClosure $g.DistinguishedName
    $gdirect = Get-List $g.MemberOf
    foreach ($pd in $PrivGroups.Keys) {
        if ($geff.Contains($pd)) {
            $PrivRows.Add([pscustomobject][ordered]@{
                    'Gruppo privilegiato' = $PrivGroups[$pd].Display; 'Membro' = $g.Name; 'Account' = $g.SamAccountName; 'Tipo' = 'Gruppo'
                    'Appartenenza' = $(if ($gdirect -contains $pd) { 'Diretta' } else { 'Annidata' })
                    'Stato' = "$total membri"; 'Ultimo logon' = $null; 'Età password (gg)' = $null; 'Pwd senza scadenza' = 'N/D'; 'SPN' = 'N/D'
                    'Protected Users' = $false; 'Sensibile (no delega)' = $false; '_RowClass' = "pg-$($PrivGroups[$pd].Index)"
                })
        }
    }

    $cls = @()
    if ($total -eq 0) { $cls += 'f-empty' }
    if ($isPrivGroup) { $cls += 'f-priv' }
    $cls += $(if ($cat -eq 'Sicurezza') { 'k-sec' } else { 'k-dist' })
    $Groups.Add([pscustomobject][ordered]@{
            'Nome'          = $g.Name
            'Account'       = $g.SamAccountName
            'Ambito'        = $scope
            'Tipo'          = $cat
            'Membri'        = $total
            'Vuoto'         = Get-Flag ($total -eq 0) 'b-low'
            'Privilegiato'  = Get-Flag $isPrivGroup 'b-high'
            'AdminCount'    = $g.adminCount
            'SID'           = $sid
            'Gestito da'    = $(if ($g.managedBy) { Get-RdnName $g.managedBy } else { '' })
            'Email'         = $g.mail
            'Descrizione'   = $g.description
            'Creato'        = $g.whenCreated
            'Modificato'    = $g.whenChanged
            'Posizione (OU)' = ConvertTo-CanonicalPath (Get-ParentDN $g.DistinguishedName)
            'Membro di'     = @($gdirect | ForEach-Object { Get-DnName $_ } | Sort-Object)
            'Membri diretti' = $memberNames
            '_RowClass'     = ($cls -join ' ')
        })
}

# Riepilogo gruppi privilegiati
$PrivSummary = foreach ($pd in $PrivGroups.Keys) {
    $pg = $PrivGroups[$pd]
    $rows = @($PrivRows | Where-Object { $_.'Gruppo privilegiato' -eq $pg.Display })
    $usersR = @($rows | Where-Object { $_.Tipo -eq 'Utente' })
    $enabledU = @($usersR | Where-Object { $_.Stato.Text -eq 'Attivo' })
    [pscustomobject][ordered]@{
        'Gruppo'                     = $pg.Display
        'SID'                        = $pg.Sid
        'Membri diretti'             = @($rows | Where-Object { $_.Appartenenza -eq 'Diretta' }).Count
        'Utenti effettivi'           = $usersR.Count
        'Utenti abilitati'           = $enabledU.Count
        'Gruppi annidati'            = @($rows | Where-Object { $_.Tipo -eq 'Gruppo' }).Count
        'Computer'                   = @($rows | Where-Object { $_.Tipo -eq 'Computer' }).Count
    }
}

#endregion

#region ===================== GPO =====================

Write-Step 'Raccolta GPO'
$RawGpos = @(Invoke-Safe 'GPO' { Get-ADObject -SearchBase "CN=Policies,CN=System,$DomainDN" -SearchScope OneLevel -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, flags, versionNumber, gPCFileSysPath, whenCreated, whenChanged, gPCWQLFilter, gPCMachineExtensionNames, gPCUserExtensionNames @adParams -ErrorAction Stop } | Where-Object { $_ })
$GpoByGuid = @{}
foreach ($g in $RawGpos) {
    $guid = ([regex]::Match($g.Name, '\{[0-9A-Fa-f\-]{36}\}')).Value.ToUpper()
    if ($guid) { $GpoByGuid[$guid] = $g }
}
function Get-GpoName {
    param([string]$Guid)
    $g = $GpoByGuid[$Guid]
    if ($g) { return [string]$g.displayName }
    return "(GPO non trovata o di altro dominio) $Guid"
}
function Get-GpoStatusText {
    param([string]$Guid)
    $g = $GpoByGuid[$Guid]
    if (-not $g) { return 'n/d' }
    switch ([int]$g.flags) { 0 { 'Abilitata' } 1 { 'Impostazioni utente disabilitate' } 2 { 'Impostazioni computer disabilitate' } 3 { 'Tutte le impostazioni disabilitate' } default { "Flag $($g.flags)" } }
}

$WmiFilters = @{}
$wmiObjs = @(Invoke-Safe 'Filtri WMI' { Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$DomainDN" -LDAPFilter '(objectClass=msWMI-Som)' -Properties 'msWMI-Name', 'msWMI-ID' @adParams -ErrorAction Stop } | Where-Object { $_ })
foreach ($w in $wmiObjs) { if ($w.'msWMI-ID') { $WmiFilters[([string]$w.'msWMI-ID').ToUpper()] = $w.'msWMI-Name' } }

$GpoLinkMap = @{}
function Register-GpoLinks {
    param($Links, [string]$TargetName)
    foreach ($l in $Links) {
        if (-not $GpoLinkMap.ContainsKey($l.Guid)) { $GpoLinkMap[$l.Guid] = New-Object System.Collections.Generic.List[object] }
        $GpoLinkMap[$l.Guid].Add([pscustomobject]@{ Target = $TargetName; Enabled = $l.Enabled; Enforced = $l.Enforced })
    }
}

#endregion

#region ===================== OU E ALBERO =====================

Write-Step 'Raccolta struttura OU'
$RawOUs = @(Invoke-Safe 'OU' { Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions, Description, ProtectedFromAccidentalDeletion, whenCreated, ManagedBy @adParams -ErrorAction Stop } | Where-Object { $_ })

$Nodes = @{}
function New-TreeNode {
    param([string]$DN, [string]$Name, [string]$Type, [string]$GpLink, $GpOptions, [string]$Description, $Protected, $Created, [string]$ManagedBy)
    [pscustomobject]@{
        DN = $DN; Name = $Name; Type = $Type; Links = @(Get-GpLinks $GpLink); Block = (([int]$GpOptions -band 1) -eq 1)
        Description = $Description; Protected = $Protected; Created = $Created; ManagedBy = $ManagedBy
        Children = (New-Object System.Collections.Generic.List[object]); Effective = @()
        U = 0; C = 0; G = 0; TU = 0; TC = 0; TG = 0
    }
}
$Nodes[$DomainDN] = New-TreeNode -DN $DomainDN -Name $DnsRoot -Type 'Dominio' -GpLink $DomObj.gPLink -GpOptions $DomObj.gPOptions -Created $DomObj.whenCreated
Register-GpoLinks $Nodes[$DomainDN].Links "$DnsRoot (dominio)"
foreach ($ou in $RawOUs) {
    $n = New-TreeNode -DN $ou.DistinguishedName -Name $ou.Name -Type 'OU' -GpLink $ou.gPLink -GpOptions $ou.gPOptions -Description $ou.Description -Protected ([bool]$ou.ProtectedFromAccidentalDeletion) -Created $ou.whenCreated -ManagedBy $(if ($ou.ManagedBy) { Get-RdnName $ou.ManagedBy })
    $Nodes[$ou.DistinguishedName] = $n
    Register-GpoLinks $n.Links (ConvertTo-CanonicalPath $ou.DistinguishedName)
    if (-not $ou.ProtectedFromAccidentalDeletion) { Add-FL 'ou.unprotected' (ConvertTo-CanonicalPath $ou.DistinguishedName) }
}
# Contenitori (CN=Users, CN=Computers, ...) che contengono oggetti
foreach ($p in @($CountByContainer.Keys)) {
    $cur = $p
    while ($cur -and -not $Nodes.ContainsKey($cur) -and $cur.EndsWith($DomainDN, [StringComparison]::OrdinalIgnoreCase)) {
        $Nodes[$cur] = New-TreeNode -DN $cur -Name (Get-RdnName $cur) -Type 'Contenitore'
        $cur = Get-ParentDN $cur
    }
}
foreach ($k in @($CountByContainer.Keys)) {
    if ($Nodes.ContainsKey($k)) { $Nodes[$k].U = $CountByContainer[$k].U; $Nodes[$k].C = $CountByContainer[$k].C; $Nodes[$k].G = $CountByContainer[$k].G }
}
foreach ($n in @($Nodes.Values)) {
    if ($n.DN -ne $DomainDN) {
        $pDN = Get-ParentDN $n.DN
        if ($Nodes.ContainsKey($pDN)) { $Nodes[$pDN].Children.Add($n) }
    }
}

# Calcolo GPO risultanti (logica GPMC: le imposte vincono e la più alta nella gerarchia ha precedenza;
# il blocco dell'ereditarietà ferma solo le GPO non imposte)
function Set-TreeEffective {
    param($Node, [object[]]$ParentEnforced, [object[]]$ParentNormal)
    $own = @($Node.Links | Where-Object { $_.Enabled } | ForEach-Object {
            [pscustomobject]@{ Guid = $_.Guid; Name = (Get-GpoName $_.Guid); Enforced = $_.Enforced; Source = $Node.Name }
        })
    $enf = @($ParentEnforced) + @($own | Where-Object { $_.Enforced })
    $norm = @($own | Where-Object { -not $_.Enforced })
    if (-not $Node.Block) { $norm = $norm + @($ParentNormal) }
    $Node.Effective = @($enf + $norm)
    $Node.TU = $Node.U; $Node.TC = $Node.C; $Node.TG = $Node.G
    $sorted = @($Node.Children | Sort-Object Name)
    $Node.Children.Clear()
    foreach ($ch in $sorted) {
        $Node.Children.Add($ch)
        Set-TreeEffective -Node $ch -ParentEnforced $enf -ParentNormal $norm
        $Node.TU += $ch.TU; $Node.TC += $ch.TC; $Node.TG += $ch.TG
    }
}
Set-TreeEffective -Node $Nodes[$DomainDN] -ParentEnforced @() -ParentNormal @()

# Collegamenti GPO a livello di sito
$SiteRows = foreach ($s in ($SitesRaw | Sort-Object Name)) {
    $links = @(Get-GpLinks $s.gPLink)
    Register-GpoLinks $links "Sito: $($s.Name)"
    [pscustomobject][ordered]@{
        'Sito'          = $s.Name
        'Descrizione'   = $s.description
        'Subnet'        = @($SubnetsRaw | Where-Object { $_.siteObject -eq $s.DistinguishedName } | ForEach-Object { $_.Name } | Sort-Object)
        'Domain Controller' = @($DCs | Where-Object { $_.Site -eq $s.Name } | ForEach-Object { $_.Name })
        'GPO collegate' = @($links | ForEach-Object { (Get-GpoName $_.Guid) + $(if ($_.Enforced) { ' [Imposta]' }) + $(if (-not $_.Enabled) { ' [Link disabilitato]' }) })
    }
}
$SubnetRows = foreach ($sn in ($SubnetsRaw | Sort-Object Name)) {
    [pscustomobject][ordered]@{ 'Subnet' = $sn.Name; 'Sito' = $(if ($sn.siteObject) { Get-RdnName $sn.siteObject } else { '(nessun sito)' }); 'Ubicazione' = $sn.location; 'Descrizione' = $sn.description }
}

function ConvertTo-OuTreeHtml {
    param($Node, [int]$Depth)
    $sb = New-Object System.Text.StringBuilder
    $icon = switch ($Node.Type) { 'Dominio' { '&#127760;' } 'OU' { '&#128193;' } default { '&#128451;' } }
    $badges = New-Object System.Collections.Generic.List[string]
    $nLinks = @($Node.Links).Count
    if ($nLinks) { $badges.Add("<span class='bdg b-info'>$nLinks GPO collegate</span>") }
    if ($Node.Block) { $badges.Add("<span class='bdg b-med'>Blocco ereditarietà</span>") }
    if ($Node.Type -eq 'OU' -and -not $Node.Protected) { $badges.Add("<span class='bdg b-low'>Non protetta da eliminazione</span>") }
    $badges.Add("<span class='cnts'>Utenti $($Node.TU) &middot; Computer $($Node.TC) &middot; Gruppi $($Node.TG)</span>")
    $open = if ($Depth -lt 2) { ' open' } else { '' }
    [void]$sb.Append("<li><details$open><summary>$icon <b>$(Enc $Node.Name)</b> <span class='ty'>$(Enc $Node.Type)</span> $($badges -join ' ')</summary><div class='node'>")
    [void]$sb.Append("<div class='dn'><code>$(Enc $Node.DN)</code></div>")
    if ($Node.Description) { [void]$sb.Append("<div>Descrizione: $(Enc $Node.Description)</div>") }
    if ($Node.Type -ne 'Contenitore') {
        if ($nLinks) {
            [void]$sb.Append("<div class='lbl'>GPO collegate direttamente</div><table class='mini'><tr><th>Ordine</th><th>GPO</th><th>Link attivo</th><th>Imposta (Enforced)</th><th>Stato GPO</th></tr>")
            foreach ($l in ($Node.Links | Sort-Object Order)) {
                $st = Get-GpoStatusText $l.Guid
                $stCls = if ($st -eq 'Abilitata') { 'b-ok' } else { 'b-med' }
                [void]$sb.Append("<tr><td>$($l.Order)</td><td>$(Enc (Get-GpoName $l.Guid))</td><td>$(if ($l.Enabled) { 'Sì' } else { "<span class='bdg b-off'>No</span>" })</td><td>$(if ($l.Enforced) { "<span class='bdg b-high'>Sì</span>" } else { 'No' })</td><td><span class='bdg $stCls'>$(Enc $st)</span></td></tr>")
            }
            [void]$sb.Append('</table>')
        } else { [void]$sb.Append("<div class='empty'>Nessuna GPO collegata direttamente.</div>") }
    } else {
        [void]$sb.Append("<div class='empty'>Contenitore predefinito: non può avere GPO collegate, eredita quelle del livello superiore.</div>")
    }
    [void]$sb.Append("<div class='lbl'>GPO applicate (risultanti, in ordine di precedenza)</div>")
    if (@($Node.Effective).Count) {
        [void]$sb.Append("<ol class='eff'>")
        foreach ($e in $Node.Effective) {
            [void]$sb.Append("<li>$(Enc $e.Name) <span class='src'>da: $(Enc $e.Source)</span>$(if ($e.Enforced) { " <span class='bdg b-high'>Imposta</span>" })</li>")
        }
        [void]$sb.Append('</ol>')
    } else { [void]$sb.Append("<div class='empty'>Nessuna GPO applicata (escluse le GPO di sito).</div>") }
    [void]$sb.Append('</div>')
    if ($Node.Children.Count) {
        [void]$sb.Append('<ul>')
        foreach ($ch in $Node.Children) { [void]$sb.Append((ConvertTo-OuTreeHtml -Node $ch -Depth ($Depth + 1))) }
        [void]$sb.Append('</ul>')
    }
    [void]$sb.Append('</details></li>')
    return $sb.ToString()
}

$OuRows = foreach ($n in ($Nodes.Values | Where-Object { $_.Type -ne 'Contenitore' } | Sort-Object { ConvertTo-CanonicalPath $_.DN })) {
    [pscustomobject][ordered]@{
        'Nome'                 = $n.Name
        'Percorso'             = ConvertTo-CanonicalPath $n.DN
        'Tipo'                 = $n.Type
        'Descrizione'          = $n.Description
        'Protetta da eliminazione' = $(if ($n.Type -ne 'OU') { 'N/D' } elseif ($n.Protected) { 'Sì' } else { New-Badge 'No' 'b-low' })
        'Blocco ereditarietà'  = Get-Flag $n.Block 'b-med'
        'GPO collegate'        = @($n.Links | Sort-Object Order | ForEach-Object { "$($_.Order). $(Get-GpoName $_.Guid)" + $(if ($_.Enforced) { ' [Imposta]' }) + $(if (-not $_.Enabled) { ' [Link disabilitato]' }) })
        'GPO risultanti'       = @($n.Effective | ForEach-Object { $_.Name })
        'Utenti (diretti)'     = $n.U
        'Computer (diretti)'   = $n.C
        'Gruppi (diretti)'     = $n.G
        'Utenti (totali)'      = $n.TU
        'Computer (totali)'    = $n.TC
        'Creata'               = $n.Created
        'Gestita da'           = $n.ManagedBy
    }
}

# Tabella GPO
$SysvolPolicies = "\\$DnsRoot\SYSVOL\$DnsRoot\Policies"
$GpoRows = foreach ($g in ($RawGpos | Sort-Object displayName)) {
    $guid = ([regex]::Match($g.Name, '\{[0-9A-Fa-f\-]{36}\}')).Value.ToUpper()
    $flags = [int]$g.flags
    $status = Get-GpoStatusText $guid
    $ver = [int64]$g.versionNumber
    $uVer = $ver -shr 16
    $cVer = $ver -band 65535
    $links = @(if ($GpoLinkMap.ContainsKey($guid)) { $GpoLinkMap[$guid] })
    $activeLinks = @($links | Where-Object { $_.Enabled })
    $sysvolOk = $false
    try { if ($g.gPCFileSysPath) { $sysvolOk = Test-Path -LiteralPath $g.gPCFileSysPath } } catch { $sysvolOk = $false }
    $wmi = ''
    if ($g.gPCWQLFilter) {
        $wg = ([regex]::Match([string]$g.gPCWQLFilter, '\{[0-9A-Fa-f\-]{36}\}')).Value.ToUpper()
        $wmi = if ($WmiFilters.ContainsKey($wg)) { $WmiFilters[$wg] } else { "Filtro $wg" }
    }
    $issues = @()
    if ($activeLinks.Count -eq 0) { $issues += 'Non collegata'; Add-FL 'gpo.unlinked' $g.displayName }
    if ($flags -eq 3) { $issues += 'Tutte le impostazioni disabilitate'; Add-FL 'gpo.disabled' $g.displayName }
    if ($ver -eq 0) { $issues += 'Vuota (versione 0)'; Add-FL 'gpo.empty' $g.displayName }
    if (-not $sysvolOk) { $issues += 'Cartella SYSVOL mancante/inaccessibile'; Add-FL 'gpo.nosysvol' "$($g.displayName) - $($g.gPCFileSysPath)" }
    [pscustomobject][ordered]@{
        'Nome'              = $g.displayName
        'GUID'              = $guid
        'Stato'             = $(if ($flags -eq 0) { New-Badge $status 'b-ok' } else { New-Badge $status 'b-med' })
        'Versione utente'   = $uVer
        'Versione computer' = $cVer
        'Collegamenti attivi' = $activeLinks.Count
        'Collegamenti'      = @($links | ForEach-Object { $_.Target + $(if ($_.Enforced) { ' [Imposta]' }) + $(if (-not $_.Enabled) { ' [Link disabilitato]' }) })
        'Filtro WMI'        = $wmi
        'Creata'            = $g.whenCreated
        'Modificata'        = $g.whenChanged
        'SYSVOL'            = $(if ($sysvolOk) { 'OK' } else { New-Badge 'Mancante' 'b-high' })
        'Problemi'          = @($issues | ForEach-Object { New-Badge $_ 'b-warn' })
        '_RowClass'         = $(if ($issues.Count) { 'f-issue' } else { '' })
    }
}
$SysvolOrphans = @(Invoke-Safe 'SYSVOL' {
        Get-ChildItem -LiteralPath $SysvolPolicies -Directory -ErrorAction Stop |
            Where-Object { $_.Name -match '^\{[0-9A-Fa-f\-]{36}\}$' -and -not $GpoByGuid.ContainsKey($_.Name.ToUpper()) } |
            ForEach-Object { $_.FullName }
    } | Where-Object { $_ })

#endregion

#region ===================== PASSWORD POLICY, KERBEROS, AUDIT =====================

Write-Step 'Raccolta password policy'
$PwdPolicy = Invoke-Safe 'Password policy' { Get-ADDefaultDomainPasswordPolicy @adParams -ErrorAction Stop }
$Fgpp = @(Invoke-Safe 'FGPP' { Get-ADFineGrainedPasswordPolicy -Filter * @adParams -ErrorAction Stop } | Where-Object { $_ })

function New-PolicyRow {
    param([string]$Setting, $Value, [string]$Recommended, [ValidateSet('OK', 'Attenzione', 'Critico', 'Info')][string]$Result)
    $cls = switch ($Result) { 'OK' { 'b-ok' } 'Attenzione' { 'b-med' } 'Critico' { 'b-high' } default { 'b-info' } }
    if ($Result -in 'Attenzione', 'Critico') { Add-FL "pwd.$Result" "$($Setting): $Value (consigliato: $Recommended)" }
    [pscustomobject][ordered]@{ 'Impostazione' = $Setting; 'Valore attuale' = $Value; 'Valore consigliato' = $Recommended; 'Esito' = (New-Badge $Result $cls) }
}

$PwdRows = @()
if ($PwdPolicy) {
    $p = $PwdPolicy
    $minLen = [int]$p.MinPasswordLength
    $PwdRows += New-PolicyRow 'Lunghezza minima password' $minLen '>= 14 (minimo accettabile 12)' $(if ($minLen -ge 12) { 'OK' } elseif ($minLen -ge 8) { 'Attenzione' } else { 'Critico' })
    $PwdRows += New-PolicyRow 'Complessità password' $(if ($p.ComplexityEnabled) { 'Abilitata' } else { 'Disabilitata' }) 'Abilitata' $(if ($p.ComplexityEnabled) { 'OK' } else { 'Attenzione' })
    $hist = [int]$p.PasswordHistoryCount
    $PwdRows += New-PolicyRow 'Cronologia password' $hist '>= 24' $(if ($hist -ge 24) { 'OK' } elseif ($hist -ge 5) { 'Attenzione' } else { 'Critico' })
    $maxAge = [timespan]$p.MaxPasswordAge
    $PwdRows += New-PolicyRow 'Validità massima password' (Format-Span $maxAge 'Mai (nessuna scadenza)') '<= 365 giorni (oppure nessuna scadenza solo con password lunghe + MFA)' $(if ($maxAge.Ticks -le 0 -or $maxAge.TotalDays -gt 365) { 'Attenzione' } else { 'OK' })
    $minAge = [timespan]$p.MinPasswordAge
    $PwdRows += New-PolicyRow 'Validità minima password' (Format-Span $minAge '0 (cambio immediato)') '>= 1 giorno' $(if ($minAge.TotalDays -ge 1) { 'OK' } else { 'Attenzione' })
    $thr = [int]$p.LockoutThreshold
    $PwdRows += New-PolicyRow 'Soglia di blocco account' $(if ($thr -eq 0) { '0 (blocco disabilitato)' } else { "$thr tentativi" }) '5 - 10 tentativi' $(if ($thr -eq 0) { 'Critico' } elseif ($thr -le 10) { 'OK' } else { 'Attenzione' })
    if ($thr -gt 0) {
        $ld = [timespan]$p.LockoutDuration
        $PwdRows += New-PolicyRow 'Durata blocco account' (Format-Span $ld 'Fino a sblocco manuale') '>= 15 minuti' $(if ($ld.Ticks -le 0 -or $ld.TotalMinutes -ge 15) { 'OK' } else { 'Attenzione' })
        $ow = [timespan]$p.LockoutObservationWindow
        $PwdRows += New-PolicyRow 'Reimposta contatore blocchi dopo' (Format-Span $ow) '>= 15 minuti' $(if ($ow.TotalMinutes -ge 15) { 'OK' } else { 'Attenzione' })
    }
    $PwdRows += New-PolicyRow 'Archivia password con crittografia reversibile' $(if ($p.ReversibleEncryptionEnabled) { 'Abilitata' } else { 'Disabilitata' }) 'Disabilitata' $(if ($p.ReversibleEncryptionEnabled) { 'Critico' } else { 'OK' })
}

$FgppRows = foreach ($f in ($Fgpp | Sort-Object Precedence)) {
    [pscustomobject][ordered]@{
        'Nome'                  = $f.Name
        'Precedenza'            = $f.Precedence
        'Si applica a'          = @(Get-List $f.AppliesTo | ForEach-Object { Get-RdnName $_ })
        'Lunghezza minima'      = $f.MinPasswordLength
        'Complessità'           = [bool]$f.ComplexityEnabled
        'Cronologia'            = $f.PasswordHistoryCount
        'Validità massima'      = Format-Span $f.MaxPasswordAge 'Mai'
        'Validità minima'       = Format-Span $f.MinPasswordAge '0'
        'Soglia blocco'         = $f.LockoutThreshold
        'Durata blocco'         = Format-Span $f.LockoutDuration 'Fino a sblocco manuale'
        'Finestra osservazione' = Format-Span $f.LockoutObservationWindow
        'Cifratura reversibile' = Get-Flag $f.ReversibleEncryptionEnabled 'b-high'
    }
}

function Read-GptTmpl {
    param([string]$Guid)
    $path = "$SysvolPolicies\$Guid\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $res = [ordered]@{}
    try { $lines = Get-Content -LiteralPath $path -ErrorAction Stop } catch { Add-Log 'SYSVOL' "Impossibile leggere $($path): $($_.Exception.Message)" 'Info'; return $null }
    $sec = ''
    foreach ($l in $lines) {
        if ($l -match '^\s*\[(.+)\]\s*$') { $sec = $matches[1]; if (-not $res.Contains($sec)) { $res[$sec] = [ordered]@{} }; continue }
        if ($sec -and $l -match '^\s*([^=;]+?)\s*=\s*(.*?)\s*$') { $res[$sec][$matches[1]] = $matches[2] }
    }
    return $res
}

$InfLabels = @{
    'MinimumPasswordAge' = 'Validità minima password (giorni)'; 'MaximumPasswordAge' = 'Validità massima password (giorni)'
    'MinimumPasswordLength' = 'Lunghezza minima password'; 'PasswordComplexity' = 'Complessità password (1 = sì)'
    'PasswordHistorySize' = 'Cronologia password'; 'LockoutBadCount' = 'Soglia blocco account'
    'ResetLockoutCount' = 'Reimposta contatore blocchi dopo (minuti)'; 'LockoutDuration' = 'Durata blocco (minuti)'
    'RequireLogonToChangePassword' = 'Logon richiesto per cambiare password'; 'ForceLogoffWhenHourExpire' = 'Disconnessione forzata alla scadenza orario'
    'ClearTextPassword' = 'Crittografia reversibile (1 = sì)'; 'LSAAnonymousNameLookup' = 'Traduzione anonima SID/nomi (1 = sì)'
    'NewAdministratorName' = 'Nuovo nome account Administrator'; 'NewGuestName' = 'Nuovo nome account Guest'
    'EnableAdminAccount' = 'Account Administrator abilitato'; 'EnableGuestAccount' = 'Account Guest abilitato'
    'MaxTicketAge' = 'Durata massima ticket utente (ore)'; 'MaxRenewAge' = 'Durata massima rinnovo ticket utente (giorni)'
    'MaxServiceAge' = 'Durata massima ticket di servizio (minuti)'; 'MaxClockSkew' = 'Tolleranza sincronizzazione orologi (minuti)'
    'TicketValidateClient' = 'Imponi restrizioni di accesso utente (1 = sì)'
    'AuditSystemEvents' = 'Eventi di sistema'; 'AuditLogonEvents' = 'Eventi di accesso'; 'AuditObjectAccess' = 'Accesso agli oggetti'
    'AuditPrivilegeUse' = 'Uso dei privilegi'; 'AuditPolicyChange' = 'Modifica dei criteri'; 'AuditAccountManage' = 'Gestione account'
    'AuditProcessTracking' = 'Tracciamento processi'; 'AuditDSAccess' = 'Accesso al servizio directory'; 'AuditAccountLogon' = 'Eventi di accesso account'
}
$AuditValueMap = @{ '0' = 'Nessun controllo'; '1' = 'Operazioni riuscite'; '2' = 'Operazioni non riuscite'; '3' = 'Riuscite e non riuscite' }

$DDPGuid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
$DDP = Read-GptTmpl $DDPGuid
$KerbRows = @()
if ($DDP) {
    foreach ($secName in @('Kerberos Policy', 'System Access')) {
        if ($DDP.Contains($secName)) {
            foreach ($k in $DDP[$secName].Keys) {
                $KerbRows += [pscustomobject][ordered]@{ 'Sezione' = $secName; 'Impostazione' = $(if ($InfLabels[$k]) { $InfLabels[$k] } else { $k }); 'Chiave' = $k; 'Valore' = $DDP[$secName][$k] }
            }
        }
    }
} else { Add-Log 'Default Domain Policy' "GptTmpl.inf non leggibile da $SysvolPolicies\$DDPGuid" 'Info' }

# Criteri di controllo (audit) risultanti sull'OU Domain Controllers
$AuditRows = New-Object System.Collections.Generic.List[object]
$dcOuDN = "OU=Domain Controllers,$DomainDN"
$AuditSeen = @{}
if ($Nodes.ContainsKey($dcOuDN)) {
    foreach ($e in $Nodes[$dcOuDN].Effective) {
        $tmpl = Read-GptTmpl $e.Guid
        if ($tmpl -and $tmpl.Contains('Event Audit')) {
            foreach ($k in $tmpl['Event Audit'].Keys) {
                $key = "basic|$k"
                if ($AuditSeen.ContainsKey($key)) { continue }
                $AuditSeen[$key] = $true
                $v = [string]$tmpl['Event Audit'][$k]
                $AuditRows.Add([pscustomobject][ordered]@{ 'Tipo' = 'Criterio base'; 'Categoria / sottocategoria' = $(if ($InfLabels[$k]) { $InfLabels[$k] } else { $k }); 'Impostazione' = $(if ($AuditValueMap[$v]) { $AuditValueMap[$v] } else { $v }); 'GPO di origine' = $e.Name })
            }
        }
        $csv = "$SysvolPolicies\$($e.Guid)\MACHINE\Microsoft\Windows NT\Audit\audit.csv"
        if (Test-Path -LiteralPath $csv) {
            try {
                foreach ($r in (Import-Csv -LiteralPath $csv -ErrorAction Stop)) {
                    if (-not $r.Subcategory) { continue }
                    $key = "adv|$($r.Subcategory)"
                    if ($AuditSeen.ContainsKey($key)) { continue }
                    $AuditSeen[$key] = $true
                    $AuditRows.Add([pscustomobject][ordered]@{ 'Tipo' = 'Criterio avanzato'; 'Categoria / sottocategoria' = $r.Subcategory; 'Impostazione' = $r.'Inclusion Setting'; 'GPO di origine' = $e.Name })
                }
            } catch { Add-Log 'Audit' "$($csv): $($_.Exception.Message)" 'Info' }
        }
    }
}

#endregion

#region ===================== ACCOUNT SPECIALI E SERVICE ACCOUNT =====================

Write-Step 'Analisi account speciali e account di servizio'
$SpecialRows = New-Object System.Collections.Generic.List[object]
$krbtgtAge = $null
foreach ($u in $RawUsers) {
    $sid = $u.SID.Value
    $role = $null; $notes = @()
    $age = Get-DaysSince $u.PasswordLastSet
    if ($sid -eq "$DomainSID-500") {
        $role = 'Administrator predefinito (RID 500)'
        if ($u.SamAccountName -match '^(Administrator|Amministratore|Administrateur|Administrador)$') { $notes += 'Non rinominato' }
        if ($null -ne $age -and $age -gt $PasswordAgeDays) { $notes += "Password più vecchia di $PasswordAgeDays giorni"; Add-FL 'adm.oldpwd' "$($u.SamAccountName) - $age giorni" }
        if ($u.Enabled -and $u.LastLogonDate -and (Get-DaysSince $u.LastLogonDate) -lt 30) { $notes += 'Usato di recente: preferire account amministrativi nominativi' }
    }
    elseif ($sid -eq "$DomainSID-501") {
        $role = 'Guest (RID 501)'
        if ($u.Enabled) { $notes += 'ABILITATO'; Add-FL 'guest.enabled' $u.SamAccountName }
    }
    elseif ($sid -eq "$DomainSID-502") {
        $role = 'krbtgt (RID 502)'
        $krbtgtAge = $age
        if ($null -ne $age -and $age -gt 180) { $notes += 'Password non ruotata da oltre 180 giorni' }
    }
    elseif ($u.SamAccountName -like 'krbtgt_*') {
        $role = 'krbtgt RODC'
        if ($null -ne $age -and $age -gt 180) { $notes += 'Password non ruotata da oltre 180 giorni'; Add-FL 'krbtgt.rodc' "$($u.SamAccountName) - $age giorni" }
    }
    if ($role) {
        $SpecialRows.Add([pscustomobject][ordered]@{
                'Account' = $u.SamAccountName; 'Ruolo' = $role
                'Stato' = $(if ($u.Enabled) { New-Badge 'Attivo' 'b-ok' } else { New-Badge 'Disabilitato' 'b-off' })
                'Ultimo logon' = Get-BestLastLogon $u; 'Password impostata' = $u.PasswordLastSet; 'Età password (gg)' = $age
                'Note' = @($notes | ForEach-Object { New-Badge $_ 'b-warn' })
            })
    }
}

$MsaRaw = @(Invoke-Safe 'Account di servizio gestiti' { Get-ADServiceAccount -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, ServicePrincipalNames, PrincipalsAllowedToRetrieveManagedPassword, whenCreated, Description, objectClass @adParams -ErrorAction Stop } | Where-Object { $_ })
$MsaRows = foreach ($m in ($MsaRaw | Sort-Object Name)) {
    $typeTxt = switch -Wildcard ($m.objectClass) { '*GroupManaged*' { 'gMSA' } '*DelegatedManaged*' { 'dMSA' } '*ManagedServiceAccount*' { 'sMSA' } default { [string]$m.objectClass } }
    [pscustomobject][ordered]@{
        'Nome' = $m.Name; 'Tipo' = $typeTxt
        'Stato' = $(if ($m.Enabled) { New-Badge 'Attivo' 'b-ok' } else { New-Badge 'Disabilitato' 'b-off' })
        'Ultimo logon' = $m.LastLogonDate; 'Password impostata' = $m.PasswordLastSet
        'SPN' = Get-List $m.ServicePrincipalNames
        'Autorizzati a recuperare la password' = @(Get-List $m.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object { Get-RdnName $_ })
        'Creato' = $m.whenCreated; 'Descrizione' = $m.Description
    }
}

#endregion

#region ===================== PERMESSI CARTELLE =====================

$FolderSections = New-Object System.Collections.Generic.List[string]
$FolderExceptions = New-Object System.Collections.Generic.List[object]
$FolderRisky = New-Object System.Collections.Generic.List[object]
$FolderErrors = New-Object System.Collections.Generic.List[object]
$FolderAces = New-Object System.Collections.Generic.List[object]
$script:FolderCount = 0
$script:FolderTruncated = $false
# SID "ampi": Everyone, Anonymous, Authenticated Users, Users, Guests, Domain Users, Domain Guests, Domain Computers
$BroadSids = @('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546', "$DomainSID-513", "$DomainSID-514", "$DomainSID-515")
# Diritti di scrittura/modifica: WriteData, AppendData, WriteEA, DeleteSubdirs, WriteAttributes, Delete, ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE
$RiskyMask = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288 -bor 268435456 -bor 1073741824

function Get-FolderAclNode {
    param([string]$Path, [int]$Level, [bool]$NoRecurse)
    $script:FolderCount++
    if ($script:FolderCount % 200 -eq 0) { Write-Progress -Activity 'Analisi permessi cartelle' -Status "$($script:FolderCount) cartelle - $Path" }
    $name = if ($Level -eq 0) { $Path } else { [System.IO.Path]::GetFileName($Path.TrimEnd('\')) }
    $node = [pscustomobject]@{
        Path = $Path; Name = $name; Level = $Level; Owner = ''; Protected = $false; Aces = @(); ExplicitCount = 0
        Risky = $false; Error = $null; Note = $null; Truncated = $false; Children = (New-Object System.Collections.Generic.List[object])
    }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        try {
            $osid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            $on = Resolve-SidName $osid
            $node.Owner = if ($on) { $on } else { "$osid (non risolto)" }
        } catch { $node.Owner = $acl.Owner }
        $node.Protected = [bool]$acl.AreAccessRulesProtected
        if ($node.Protected -and $Level -gt 0) { $node.Note = 'Ereditarietà disabilitata' }
        $aces = New-Object System.Collections.Generic.List[object]
        foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = $r.IdentityReference.Value
            $rn = Resolve-SidName $sid
            $idName = if ($rn) { $rn } else { "$sid (non risolto)" }
            $mask = [int64][int]$r.FileSystemRights
            $allow = ([string]$r.AccessControlType -eq 'Allow')
            $rights = Get-RightsText $mask
            $applies = Get-AppliesTo ([int]$r.InheritanceFlags) ([int]$r.PropagationFlags)
            $risky = [bool]($allow -and ($BroadSids -contains $sid) -and (($mask -band 4294967295) -band $RiskyMask))
            $orphan = (-not $rn) -and $sid -like 'S-1-5-21-*'
            $ace = [pscustomobject]@{ Identity = $idName; Sid = $sid; Allow = $allow; Rights = $rights; AppliesTo = $applies; Inherited = [bool]$r.IsInherited; Risky = $risky; Orphan = $orphan }
            $aces.Add($ace)
            if (-not $r.IsInherited) { $node.ExplicitCount++ }
            if (-not $r.IsInherited -or $Level -eq 0) {
                $FolderAces.Add([pscustomobject][ordered]@{ 'Percorso' = $Path; 'Identità' = $idName; 'SID' = $sid; 'Tipo' = $(if ($allow) { 'Consenti' } else { 'Nega' }); 'Diritti' = $rights; 'Si applica a' = $applies; 'Ereditata' = [bool]$r.IsInherited })
                if ($risky) {
                    $node.Risky = $true
                    $FolderRisky.Add([pscustomobject][ordered]@{ 'Percorso' = $Path; 'Identità' = $idName; 'Tipo' = 'Consenti'; 'Diritti' = $rights; 'Si applica a' = $applies; 'Ereditata' = [bool]$r.IsInherited })
                }
                if ($orphan) { Add-FL 'fs.orphan' "$Path - $sid" }
            }
        }
        $node.Aces = $aces.ToArray()
        if ($Level -gt 0 -and ($node.Protected -or $node.ExplicitCount -gt 0)) {
            $FolderExceptions.Add([pscustomobject][ordered]@{
                    'Percorso' = $Path; 'Livello' = $Level
                    'Ereditarietà' = $(if ($node.Protected) { New-Badge 'Disabilitata' 'b-med' } else { 'Attiva' })
                    'ACE esplicite' = @($aces | Where-Object { -not $_.Inherited } | ForEach-Object { "$($_.Identity): $($_.Rights) ($(if ($_.Allow) { 'Consenti' } else { 'Nega' }))" })
                    'Proprietario' = $node.Owner
                })
        }
    } catch {
        $node.Error = $_.Exception.Message
        $FolderErrors.Add([pscustomobject][ordered]@{ 'Percorso' = $Path; 'Errore' = $_.Exception.Message })
    }
    if (-not $NoRecurse -and $Level -lt $FolderDepth) {
        try {
            $di = New-Object System.IO.DirectoryInfo -ArgumentList $Path
            $subs = @($di.GetDirectories() | Sort-Object Name)
            foreach ($s in $subs) {
                if ($script:FolderCount -ge $MaxFolders) { $node.Truncated = $true; $script:FolderTruncated = $true; break }
                $isReparse = ($s.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                $child = Get-FolderAclNode -Path $s.FullName -Level ($Level + 1) -NoRecurse $isReparse
                if ($isReparse) { $child.Note = 'Collegamento / junction: non esplorato' }
                $node.Children.Add($child)
            }
        } catch {
            $msg = "Impossibile elencare le sottocartelle: $($_.Exception.Message)"
            if (-not $node.Error) { $node.Error = $msg }
            $FolderErrors.Add([pscustomobject][ordered]@{ 'Percorso' = $Path; 'Errore' = $msg })
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
    $selfSpecial = [bool]($Node.Protected -or $Node.Risky -or $Node.Error -or (-not $isRoot -and $Node.ExplicitCount -gt 0))
    $special = $selfSpecial -or $childSpecial -or $isRoot
    $b = New-Object System.Collections.Generic.List[string]
    if ($Node.Protected -and -not $isRoot) { $b.Add("<span class='bdg b-med'>Ereditarietà disabilitata</span>") }
    if ($Node.ExplicitCount -gt 0 -and -not $isRoot) { $b.Add("<span class='bdg b-info'>$($Node.ExplicitCount) ACE esplicite</span>") }
    if ($Node.Risky) { $b.Add("<span class='bdg b-high'>Permessi ampi in scrittura</span>") }
    if ($Node.Error) { $b.Add("<span class='bdg b-high'>Errore</span>") }
    if ($Node.Note -and -not $Node.Protected) { $b.Add("<span class='bdg b-off'>$(Enc $Node.Note)</span>") }
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
    if (-not $isRoot -and -not $IncludeInheritedAces -and $inhCount -gt 0) { [void]$body.Append("<div class='empty'>$inhCount ACE ereditate non mostrate (identiche alla cartella superiore).</div>") }
    [void]$body.Append('</div>')
    $open = if ($isRoot) { ' open' } else { '' }
    $html = "<li class='fnode' data-x='$([int]$special)'><details$open><summary>&#128193; $(Enc $Node.Name) $($b -join ' ')</summary>$($body.ToString())"
    if ($Node.Children.Count) { $html += "<ul>$($childSb.ToString())</ul>" }
    $html += '</details></li>'
    return [pscustomobject]@{ Html = $html; Special = $special }
}

$ShareRows = New-Object System.Collections.Generic.List[object]
if (-not $SkipFolderReport -and $FolderPath) {
    $treeIdx = 0
    foreach ($fp in $FolderPath) {
        $treeIdx++
        Write-Step "Analisi permessi: $fp (profondità $FolderDepth)"
        if (-not (Test-Path -LiteralPath $fp -PathType Container)) {
            Add-Log 'Permessi cartelle' "Percorso non trovato o non accessibile: $fp"
            $FolderSections.Add("<h3>$(Enc $fp)</h3><p class='err'>Percorso non trovato o non accessibile.</p>")
            continue
        }
        if ($fp -match '^\\\\([^\\]+)\\([^\\]+)') {
            $srv = $matches[1]; $share = $matches[2]
            try {
                foreach ($sa in (Get-SmbShareAccess -Name $share -CimSession $srv -ErrorAction Stop)) {
                    $ShareRows.Add([pscustomobject][ordered]@{ 'Condivisione' = "\\$srv\$share"; 'Account' = $sa.AccountName; 'Tipo' = [string]$sa.AccessControlType; 'Diritto' = [string]$sa.AccessRight })
                    if ([string]$sa.AccessControlType -eq 'Allow' -and [string]$sa.AccessRight -in 'Full', 'Change' -and $sa.AccountName -match '^(Everyone|Tutti|Jeder|Tout le monde)$') { Add-FL 'fs.share.everyone' "\\$srv\$share - $($sa.AccountName): $($sa.AccessRight)" }
                }
            } catch { Add-Log 'Permessi condivisione' "\\$srv\$($share): $($_.Exception.Message)" 'Info' }
        }
        $countBefore = $script:FolderCount
        $root = Get-FolderAclNode -Path $fp -Level 0 -NoRecurse $false
        $analyzed = $script:FolderCount - $countBefore
        $tid = "ftree$treeIdx"
        $tree = (ConvertTo-FolderTreeHtml $root).Html
        $FolderSections.Add(@"
<h3>&#128194; $(Enc $fp)</h3>
<p class='intro'>Cartelle analizzate: <b>$analyzed</b> &middot; Profondità massima: <b>$FolderDepth</b> &middot; Proprietario radice: <b>$(Enc $root.Owner)</b></p>
<div class='tb'><button type='button' onclick="treeAll('$tid',true)">Espandi tutto</button><button type='button' onclick="treeAll('$tid',false)">Comprimi tutto</button>
<label><input type='checkbox' onchange="treeX('$tid',this)"> Mostra solo cartelle con eccezioni (permessi espliciti, ereditarietà disabilitata, rischi, errori)</label></div>
<ul class='tree' id='$tid'>$tree</ul>
"@)
    }
    Write-Progress -Activity 'Analisi permessi cartelle' -Completed
}

#endregion

#region ===================== EVENTI DI SICUREZZA (opzionale) =====================

$EventAgg = @{}
$LockoutRows = New-Object System.Collections.Generic.List[object]
$StatusMap = @{
    '0xc000006a' = 'Password errata'; '0xc0000064' = 'Utente inesistente'; '0xc000006d' = 'Credenziali errate'; '0xc000006e' = 'Restrizione account'
    '0xc000006f' = 'Fuori dall''orario consentito'; '0xc0000070' = 'Workstation non autorizzata'; '0xc0000071' = 'Password scaduta'
    '0xc0000072' = 'Account disabilitato'; '0xc0000193' = 'Account scaduto'; '0xc0000224' = 'Cambio password obbligatorio'
    '0xc0000234' = 'Account bloccato'; '0xc0000133' = 'Orologio non sincronizzato'; '0xc000015b' = 'Tipo di accesso non concesso'
    '0xc0000413' = 'Authentication firewall'; '0x18' = 'Password errata (Kerberos)'; '0x12' = 'Account disabilitato/bloccato/scaduto (Kerberos)'
    '0x6' = 'Utente inesistente (Kerberos)'; '0x17' = 'Password scaduta (Kerberos)'; '0x25' = 'Differenza orologio (Kerberos)'; '0xc' = 'Restrizione di policy (Kerberos)'
}
if ($IncludeSecurityEvents) {
    Write-Step "Lettura eventi di sicurezza dai DC (ultime $EventHours ore)"
    $ms = [int64]$EventHours * 3600000
    $queries = @(
        "*[System[(EventID=4625 or EventID=4771 or EventID=4740) and TimeCreated[timediff(@SystemTime) <= $ms]]]",
        "*[System[(EventID=4776) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='Status']!='0x0']]"
    )
    foreach ($dc in $DCs) {
        foreach ($q in $queries) {
            $evs = @()
            try { $evs = @(Get-WinEvent -ComputerName $dc.HostName -LogName Security -FilterXPath $q -MaxEvents $MaxEventsPerDC -ErrorAction Stop) }
            catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Add-Log "Eventi $($dc.HostName)" $_.Exception.Message } }
            if ($evs.Count -ge $MaxEventsPerDC) { Add-Log "Eventi $($dc.HostName)" "Raggiunto il limite di $MaxEventsPerDC eventi: i dati potrebbero essere parziali." 'Info' }
            foreach ($e in $evs) {
                try { $x = [xml]$e.ToXml() } catch { continue }
                $d = @{}
                foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
                $id = [int]$e.Id
                $acct = $d['TargetUserName']
                if ($id -eq 4740) {
                    $LockoutRows.Add([pscustomobject][ordered]@{ 'Data/ora' = $e.TimeCreated; 'Account bloccato' = $acct; 'Computer di origine' = $d['TargetDomainName']; 'DC' = $dc.Name })
                    continue
                }
                $dom = ''; $src = ''; $st = ''; $evName = ''
                if ($id -eq 4625) {
                    $dom = $d['TargetDomainName']; $src = $d['IpAddress']
                    if (-not $src -or $src -eq '-') { $src = $d['WorkstationName'] }
                    $st = ([string]$d['Status']).ToLower()
                    if ($st -in '0xc000006d', '0xc000006e' -and $d['SubStatus']) { $st = ([string]$d['SubStatus']).ToLower() }
                    $evName = '4625 - Accesso non riuscito'
                } elseif ($id -eq 4771) {
                    $src = ([string]$d['IpAddress']) -replace '^::ffff:', ''
                    $st = ([string]$d['Status']).ToLower()
                    $evName = '4771 - Pre-autenticazione Kerberos non riuscita'
                } elseif ($id -eq 4776) {
                    $src = $d['Workstation']
                    $st = ([string]$d['Status']).ToLower()
                    $evName = '4776 - Convalida credenziali NTLM non riuscita'
                } else { continue }
                $key = "$acct|$src|$id|$st"
                if (-not $EventAgg.ContainsKey($key)) {
                    $EventAgg[$key] = [pscustomobject]@{ Account = $acct; Domain = $dom; Source = $src; EventName = $evName; Status = $st; Hits = 0; First = $e.TimeCreated; Last = $e.TimeCreated; DCs = (New-Object 'System.Collections.Generic.HashSet[string]') }
                }
                $a = $EventAgg[$key]
                $a.Hits++
                if ($e.TimeCreated -lt $a.First) { $a.First = $e.TimeCreated }
                if ($e.TimeCreated -gt $a.Last) { $a.Last = $e.TimeCreated }
                [void]$a.DCs.Add($dc.Name)
            }
        }
    }
}
$EventRows = foreach ($a in ($EventAgg.Values | Sort-Object Hits -Descending)) {
    [pscustomobject][ordered]@{
        'Account' = $a.Account; 'Dominio' = $a.Domain; 'Origine (IP / host)' = $a.Source; 'Evento' = $a.EventName
        'Motivo' = $(if ($StatusMap[$a.Status]) { "$($StatusMap[$a.Status]) ($($a.Status))" } else { $a.Status })
        'Tentativi' = $a.Hits; 'Primo' = $a.First; 'Ultimo' = $a.Last; 'DC' = @($a.DCs)
    }
}
if ($IncludeSecurityEvents -and $EventAgg.Count) {
    # Possibile password spray: stessa origine contro molti account
    $EventAgg.Values | Where-Object { $_.Source -and $_.Source -ne '-' } | Group-Object Source | ForEach-Object {
        $accts = @($_.Group | Select-Object -ExpandProperty Account -Unique)
        if ($accts.Count -ge 10) { Add-FL 'ev.spray' "$($_.Name) - $($accts.Count) account diversi, $(($_.Group | Measure-Object Hits -Sum).Sum) tentativi" }
    }
    $EventAgg.Values | Group-Object Account | ForEach-Object {
        $sum = ($_.Group | Measure-Object Hits -Sum).Sum
        if ($sum -ge 20) { Add-FL 'ev.brute' "$($_.Name) - $sum tentativi falliti" }
    }
}

#endregion

#region ===================== RILEVAZIONI =====================

Write-Step 'Valutazione dei controlli di sicurezza'

# Dominio / foresta
if ([string]$Domain.DomainMode -notmatch '2016|2025') { Add-Finding -Severity 'Basso' -Category 'Dominio' -Title "Livello funzionale del dominio datato ($($Domain.DomainMode))" -Description 'Livelli funzionali inferiori a Windows Server 2016 non abilitano alcune funzionalità di sicurezza (es. rotazione automatica dei segreti NTLM per smart card, miglioramenti PAM/Kerberos).' -Recommendation 'Dopo aver dismesso i DC più vecchi, innalzare i livelli funzionali di dominio e foresta.' -Section 'sec-domain' }
if (-not $RecycleEnabled) { Add-Finding -Severity 'Medio' -Category 'Dominio' -Title 'Cestino di Active Directory non abilitato' -Description 'Senza il cestino AD il ripristino di oggetti eliminati per errore richiede un ripristino autorevole da backup.' -Recommendation 'Abilitare il Recycle Bin: Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target <foresta>.' -Section 'sec-domain' }
if ([int]$MAQ -gt 0) { Add-Finding -Severity 'Medio' -Category 'Dominio' -Title "ms-DS-MachineAccountQuota = $MAQ" -Description 'Qualsiasi utente autenticato può aggiungere fino a questo numero di computer al dominio; è un prerequisito di diversi attacchi (es. RBCD, noPac).' -Recommendation 'Impostare ms-DS-MachineAccountQuota a 0 e delegare il join al dominio solo ad account/gruppi specifici.' -Section 'sec-domain' }
Add-FindingFromList 'dc.eol' 'Critico' 'Domain Controller' 'Domain Controller con sistema operativo non supportato' 'I DC con SO fuori supporto non ricevono aggiornamenti di sicurezza e compromettono l''intero dominio.' 'Migrare con priorità i ruoli su DC con sistema operativo supportato.' 'sec-dc'
Add-FindingFromList 'repl.fail' 'Alto' 'Domain Controller' 'Errori di replica tra Domain Controller' 'Errori di replica causano incoerenze (password, GPO, appartenenze) e possono portare a oggetti persistenti.' 'Analizzare con repadmin /replsummary e repadmin /showrepl e risolvere le cause (DNS, rete, tempo, USN rollback).' 'sec-dc'
Add-FindingFromList 'trust.sidfilter' 'Medio' 'Trust' 'Trust esterni senza SID filtering' 'Senza quarantena SID un dominio fidato potrebbe iniettare SID privilegiati tramite SIDHistory.' 'Abilitare il SID filtering: netdom trust <dominio> /domain:<fidato> /quarantine:yes.' 'sec-sites'

# Password policy
$pwdCrit = Get-FLItems 'pwd.Critico'; $pwdWarn = Get-FLItems 'pwd.Attenzione'
if ($pwdCrit.Count) { Add-Finding -Severity 'Alto' -Category 'Password policy' -Title 'Password policy di dominio con impostazioni critiche' -Description 'La policy di dominio predefinita presenta impostazioni gravemente deboli.' -Recommendation 'Allineare la Default Domain Policy ai valori consigliati (vedi sezione Password policy) e valutare FGPP più restrittive per gli account privilegiati.' -Objects $pwdCrit -Section 'sec-pwd' }
if ($pwdWarn.Count) { Add-Finding -Severity 'Medio' -Category 'Password policy' -Title 'Password policy di dominio migliorabile' -Description 'Alcune impostazioni non rispettano le raccomandazioni (CIS / Microsoft).' -Recommendation 'Rivedere le impostazioni indicate.' -Objects $pwdWarn -Section 'sec-pwd' }
if ($krbtgtAge -gt 180) { Add-Finding -Severity 'Alto' -Category 'Account speciali' -Title "Password dell'account krbtgt non ruotata da $krbtgtAge giorni" -Description 'Una password krbtgt vecchia prolunga la validità di eventuali Golden Ticket in caso di compromissione passata.' -Recommendation 'Ruotare la password krbtgt due volte (attendendo la replica completa tra le due rotazioni), ad es. con lo script ufficiale New-KrbtgtKeys.ps1.' -Section 'sec-special' }
Add-FindingFromList 'krbtgt.rodc' 'Basso' 'Account speciali' 'Account krbtgt RODC con password non ruotata' 'Le chiavi krbtgt dei RODC vanno ruotate periodicamente.' 'Ruotare le password degli account krbtgt_xxxxx.' 'sec-special'
Add-FindingFromList 'guest.enabled' 'Alto' 'Account speciali' 'Account Guest abilitato' 'L''account Guest consente accessi non autenticati/anonimi.' 'Disabilitare l''account Guest.' 'sec-special'
Add-FindingFromList 'adm.oldpwd' 'Medio' 'Account speciali' 'Password dell''Administrator predefinito non cambiata da tempo' 'L''account RID 500 non è soggetto a blocco ed è il primo bersaglio degli attacchi.' 'Impostare una password lunga e casuale, custodita in cassaforte, e usare account amministrativi nominativi.' 'sec-special'

# Gruppi privilegiati
foreach ($pd in $PrivGroups.Keys) {
    $pg = $PrivGroups[$pd]
    $members = @($PrivRows | Where-Object { $_.'Gruppo privilegiato' -eq $pg.Display -and $_.Tipo -ne 'Gruppo' } | ForEach-Object { "$($_.Account) ($($_.Tipo), $($_.Appartenenza))" })
    if ($pg.Label -in 'Schema Admins', 'Enterprise Admins' -and $members.Count -gt 0) {
        Add-Finding -Severity 'Medio' -Category 'Gruppi privilegiati' -Title "$($pg.Display) contiene $($members.Count) membri" -Description 'Questo gruppo dovrebbe essere vuoto e popolato solo temporaneamente quando necessario.' -Recommendation 'Rimuovere i membri permanenti e adottare un processo di accesso just-in-time.' -Objects $members -Section 'sec-priv'
    }
    if ($pg.Label -in 'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators', 'DnsAdmins' -and $members.Count -gt 0) {
        Add-Finding -Severity 'Medio' -Category 'Gruppi privilegiati' -Title "$($pg.Display) non è vuoto ($($members.Count))" -Description 'I gruppi operatori/DnsAdmins hanno privilegi che consentono l''escalation fino a Domain Admin.' -Recommendation 'Svuotare il gruppo e delegare i permessi in modo granulare.' -Objects $members -Section 'sec-priv'
    }
    if ($pg.Label -eq 'Domain Admins') {
        $enabledDA = @($PrivRows | Where-Object { $_.'Gruppo privilegiato' -eq $pg.Display -and $_.Tipo -eq 'Utente' -and $_.Stato.Text -eq 'Attivo' })
        if ($enabledDA.Count -gt 5) { Add-Finding -Severity 'Basso' -Category 'Gruppi privilegiati' -Title "Numero elevato di Domain Admins abilitati ($($enabledDA.Count))" -Description 'Ogni account Domain Admin aumenta la superficie di attacco del dominio.' -Recommendation 'Ridurre al minimo i membri (idealmente 2-4 account dedicati) e usare deleghe granulari.' -Objects @($enabledDA | ForEach-Object { $_.Account }) -Section 'sec-priv' }
    }
}
$preW2k = $GroupBySid['S-1-5-32-554']
if ($preW2k) {
    $pm = @(Get-List $preW2k.member)
    if (@($pm | Where-Object { $_ -match '^CN=(S-1-1-0|S-1-5-7),' }).Count) { Add-Finding -Severity 'Alto' -Category 'Gruppi privilegiati' -Title 'Pre-Windows 2000 Compatible Access contiene Everyone/Anonymous' -Description 'Consente la lettura anonima di molte informazioni di AD.' -Recommendation 'Rimuovere Everyone e Anonymous Logon dal gruppo.' -Objects $pm -Section 'sec-groups' }
    elseif (@($pm | Where-Object { $_ -match '^CN=S-1-5-11,' }).Count) { Add-Finding -Severity 'Basso' -Category 'Gruppi privilegiati' -Title 'Pre-Windows 2000 Compatible Access contiene Authenticated Users' -Description 'Configurazione legacy che concede ampi diritti di lettura su utenti e gruppi.' -Recommendation 'Valutare la rimozione dopo verifica di compatibilità con applicazioni legacy.' -Objects $pm -Section 'sec-groups' }
}
Add-FindingFromList 'u.priv.spn' 'Alto' 'Account privilegiati' 'Account privilegiati con SPN (kerberoastable)' 'Un attaccante può richiedere un ticket di servizio e tentare il cracking offline della password di un account privilegiato.' 'Rimuovere gli SPN dagli account privilegiati o sostituirli con gMSA.' 'sec-priv'
Add-FindingFromList 'u.priv.oldpwd' 'Alto' 'Account privilegiati' "Account privilegiati con password più vecchia di $PasswordAgeDays giorni" 'Password vecchie su account privilegiati aumentano il rischio di compromissione.' 'Cambiare le password e applicare una FGPP dedicata agli amministratori.' 'sec-priv'
Add-FindingFromList 'u.priv.neverexp' 'Medio' 'Account privilegiati' 'Account privilegiati con password senza scadenza' 'Gli account privilegiati non dovrebbero avere password senza scadenza.' 'Rimuovere il flag e gestire la rotazione (o usare gMSA per i servizi).' 'sec-priv'
Add-FindingFromList 'u.priv.notprotected' 'Medio' 'Account privilegiati' 'Account privilegiati non protetti contro la delega' 'Non sono membri di Protected Users né marcati come "Account sensibile e non delegabile": le loro credenziali possono essere delegate/esposte.' 'Aggiungere gli account amministrativi a Protected Users (dopo test) o impostare "Account is sensitive and cannot be delegated".' 'sec-priv'
Add-FindingFromList 'u.priv.inactive' 'Medio' 'Account privilegiati' 'Account privilegiati inattivi' "Account privilegiati abilitati senza logon da oltre $InactiveDays giorni." 'Disabilitare o rimuovere dai gruppi privilegiati gli account non utilizzati.' 'sec-priv'
Add-FindingFromList 'u.priv.disabled' 'Basso' 'Account privilegiati' 'Account disabilitati ancora membri di gruppi privilegiati' 'Se riabilitati otterrebbero immediatamente privilegi elevati.' 'Rimuovere gli account disabilitati dai gruppi privilegiati.' 'sec-priv'
Add-FindingFromList 'u.admincount' 'Basso' 'Account privilegiati' 'Account con adminCount=1 non più privilegiati (orfani AdminSDHolder)' 'Mantengono ACL protette non ereditate e potrebbero indicare ex amministratori.' 'Azzerare adminCount e ripristinare l''ereditarietà dei permessi sugli oggetti.' 'sec-users'
Add-FindingFromList 'c.priv' 'Alto' 'Account privilegiati' 'Computer (non DC) membri di gruppi privilegiati' 'Chi controlla questi computer ottiene i privilegi del gruppo.' 'Rimuovere gli account computer dai gruppi privilegiati.' 'sec-priv'

# Utenti
Add-FindingFromList 'u.pwdnotreq' 'Alto' 'Utenti' 'Utenti abilitati con flag "Password non richiesta"' 'Il flag PASSWD_NOTREQD consente password vuote indipendentemente dalla policy.' 'Rimuovere il flag: Set-ADUser <utente> -PasswordNotRequired $false.' 'sec-users'
Add-FindingFromList 'u.reversible' 'Alto' 'Utenti' 'Utenti con password memorizzata con crittografia reversibile' 'La password è recuperabile in chiaro da chi ottiene il database di AD.' 'Disabilitare l''opzione e forzare il cambio password.' 'sec-users'
Add-FindingFromList 'u.asrep' 'Alto' 'Utenti' 'Utenti senza pre-autenticazione Kerberos (AS-REP roasting)' 'Chiunque può ottenere materiale crittografico per il cracking offline della password.' 'Abilitare la pre-autenticazione Kerberos per questi account.' 'sec-users'
Add-FindingFromList 'u.descpwd' 'Alto' 'Utenti' 'Possibili password nel campo Descrizione' 'La descrizione è leggibile da tutti gli utenti autenticati.' 'Rimuovere le password dalla descrizione e cambiarle immediatamente.' 'sec-users'
Add-FindingFromList 'u.unconstrained' 'Alto' 'Deleghe' 'Utenti con delega Kerberos non vincolata' 'Il servizio può impersonare qualsiasi utente verso qualsiasi servizio.' 'Sostituire con delega vincolata o RBCD.' 'sec-deleg'
Add-FindingFromList 'u.kerberoast' 'Medio' 'Utenti' 'Utenti con SPN (kerberoastable)' 'I ticket di servizio di questi account possono essere sottoposti a cracking offline.' 'Usare gMSA o password di almeno 25 caratteri; abilitare AES e disabilitare RC4.' 'sec-users'
Add-FindingFromList 'u.des' 'Medio' 'Utenti' 'Utenti con "Usa solo cifratura DES"' 'DES è obsoleto e facilmente violabile.' 'Rimuovere il flag e usare AES.' 'sec-users'
Add-FindingFromList 'u.constrained' 'Medio' 'Deleghe' 'Utenti con delega vincolata / protocol transition' 'La delega con protocol transition permette di impersonare utenti senza la loro autenticazione.' 'Verificare la necessità di ogni delega e limitarne le destinazioni.' 'sec-deleg'
Add-FindingFromList 'u.sidhistory' 'Medio' 'Utenti' 'Utenti con SIDHistory valorizzato' 'SIDHistory può essere abusato per ottenere privilegi nascosti.' 'Ripulire SIDHistory al termine delle migrazioni.' 'sec-users'
Add-FindingFromList 'u.neverexpires' 'Medio' 'Utenti' 'Utenti abilitati con password senza scadenza' 'Password mai cambiate restano valide indefinitamente se compromesse.' 'Limitare il flag ad account di servizio controllati (meglio gMSA).' 'sec-users'
Add-FindingFromList 'u.inactive' 'Medio' 'Utenti' "Utenti abilitati inattivi da oltre $InactiveDays giorni" 'Account non utilizzati sono bersagli ideali perché il loro uso improprio passa inosservato.' 'Disabilitare gli account inattivi e spostarli in un''OU dedicata prima dell''eliminazione.' 'sec-users'
Add-FindingFromList 'u.oldpwd' 'Basso' 'Utenti' "Utenti abilitati con password più vecchia di $PasswordAgeDays giorni" 'Password molto vecchie hanno maggiore probabilità di essere state esposte.' 'Forzare il cambio password.' 'sec-users'
Add-FindingFromList 'u.never' 'Basso' 'Utenti' 'Utenti abilitati che non hanno mai effettuato l''accesso' 'Account creati e mai usati.' 'Verificare e disabilitare se non necessari.' 'sec-users'
Add-FindingFromList 'u.locked' 'Info' 'Utenti' 'Utenti attualmente bloccati' 'Account bloccati per troppi tentativi errati.' 'Verificare l''origine dei tentativi (sezione eventi / evento 4740 sul PDC).' 'sec-users'
Add-FindingFromList 'u.badpwd' 'Info' 'Utenti' 'Utenti con 3 o più tentativi di password errati (contatore attuale)' 'Contatore badPwdCount letto dal DC interrogato.' 'Verificare eventuali tentativi di attacco o credenziali salvate obsolete.' 'sec-users'
Add-FindingFromList 'u.pwdexpired' 'Info' 'Utenti' 'Utenti abilitati con password scaduta' 'Account che dovranno cambiare password al prossimo accesso.' 'Verificare se gli account sono ancora necessari.' 'sec-users'

# Computer
Add-FindingFromList 'c.eol' 'Alto' 'Computer' 'Computer abilitati con sistema operativo non supportato' 'Sistemi senza aggiornamenti di sicurezza (per Windows 10 verificare l''eventuale adesione al programma ESU).' 'Aggiornare o dismettere; nel frattempo isolarli in rete.' 'sec-computers'
Add-FindingFromList 'c.eolsoon' 'Medio' 'Computer' 'Computer con sistema operativo in scadenza di supporto (entro 12 mesi)' 'Il supporto terminerà entro un anno.' 'Pianificare l''aggiornamento.' 'sec-computers'
Add-FindingFromList 'c.nolaps' 'Alto' 'Computer' 'Computer Windows senza LAPS' 'Senza LAPS la password dell''amministratore locale è spesso uguale su più macchine, permettendo il movimento laterale.' 'Distribuire Windows LAPS su tutti i client e server membri.' 'sec-computers'
Add-FindingFromList 'c.unconstrained' 'Alto' 'Deleghe' 'Computer (non DC) con delega Kerberos non vincolata' 'Un attaccante che compromette il computer può catturare i TGT di chi vi si autentica (inclusi i DC tramite coercion).' 'Sostituire con delega vincolata o RBCD.' 'sec-deleg'
Add-FindingFromList 'c.rbcd' 'Medio' 'Deleghe' 'Computer con Resource-Based Constrained Delegation' 'Verificare che i principali autorizzati siano legittimi.' 'Rimuovere le configurazioni RBCD non necessarie.' 'sec-deleg'
Add-FindingFromList 'c.constrained' 'Info' 'Deleghe' 'Computer con delega vincolata' 'Elenco a scopo di verifica.' 'Verificare la necessità di ogni delega.' 'sec-deleg'
Add-FindingFromList 'c.inactive' 'Medio' 'Computer' "Computer abilitati inattivi da oltre $InactiveDays giorni" 'Oggetti computer obsoleti.' 'Disabilitare e poi eliminare gli oggetti non più in uso.' 'sec-computers'
Add-FindingFromList 'c.sidhistory' 'Medio' 'Computer' 'Computer con SIDHistory valorizzato' 'SIDHistory residuo da migrazioni.' 'Ripulire SIDHistory.' 'sec-computers'

# OU / GPO
Add-FindingFromList 'ou.unprotected' 'Basso' 'OU' 'OU non protette da eliminazione accidentale' 'Un errore può eliminare l''OU e tutto il suo contenuto.' 'Abilitare ProtectedFromAccidentalDeletion sulle OU.' 'sec-ou'
Add-FindingFromList 'gpo.unlinked' 'Basso' 'GPO' 'GPO non collegate (o con soli link disabilitati)' 'GPO inutilizzate complicano la gestione.' 'Verificare ed eliminare le GPO non necessarie (dopo backup).' 'sec-gpo'
Add-FindingFromList 'gpo.nosysvol' 'Medio' 'GPO' 'GPO con cartella SYSVOL mancante o inaccessibile' 'La GPO non può essere applicata correttamente.' 'Verificare la replica SYSVOL (DFSR) e i permessi.' 'sec-gpo'
Add-FindingFromList 'gpo.empty' 'Info' 'GPO' 'GPO vuote (versione 0)' 'GPO senza impostazioni.' 'Eliminare se non utilizzate.' 'sec-gpo'
Add-FindingFromList 'gpo.disabled' 'Info' 'GPO' 'GPO con tutte le impostazioni disabilitate' 'GPO presenti ma senza effetto.' 'Eliminare se non utilizzate.' 'sec-gpo'
if ($SysvolOrphans.Count) { Add-Finding -Severity 'Basso' -Category 'GPO' -Title "Cartelle GPO orfane in SYSVOL ($($SysvolOrphans.Count))" -Description 'Cartelle di policy in SYSVOL senza oggetto GPO corrispondente in AD.' -Recommendation 'Verificare ed eliminare le cartelle orfane dopo un backup.' -Objects $SysvolOrphans -Section 'sec-gpo' }
if ($Nodes.ContainsKey($dcOuDN)) {
    if ($AuditRows.Count -eq 0) {
        Add-Finding -Severity 'Medio' -Category 'Audit' -Title 'Nessun criterio di controllo (audit) configurato tramite GPO sui Domain Controller' -Description 'Senza audit non è possibile rilevare accessi falliti, modifiche ai gruppi o agli account. (Verificare con auditpol /get /category:* su un DC: potrebbe essere configurato localmente.)' -Recommendation 'Configurare i criteri di controllo avanzati nella Default Domain Controllers Policy o in una GPO dedicata.' -Section 'sec-pwd'
    } else {
        $needed = @('Credential Validation', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations', 'Logon', 'Account Lockout', 'User Account Management', 'Security Group Management', 'Directory Service Changes')
        $advSet = @($AuditRows | Where-Object { $_.Tipo -eq 'Criterio avanzato' -and $_.Impostazione -and $_.Impostazione -notmatch 'No Auditing' } | ForEach-Object { $_.'Categoria / sottocategoria' })
        $missing = @($needed | Where-Object { $n = $_; -not ($advSet | Where-Object { $_ -match [regex]::Escape($n) }) })
        if ($advSet.Count -and $missing.Count) { Add-Finding -Severity 'Basso' -Category 'Audit' -Title 'Sottocategorie di audit consigliate non configurate sui DC' -Description 'Sottocategorie di controllo avanzato raccomandate da Microsoft non presenti nelle GPO applicate ai DC.' -Recommendation 'Abilitare le sottocategorie elencate (Success/Failure come da baseline Microsoft).' -Objects $missing -Section 'sec-pwd' }
    }
}

# File system
if ($FolderRisky.Count) { Add-Finding -Severity 'Alto' -Category 'Permessi cartelle' -Title "Permessi di scrittura concessi a gruppi ampi ($($FolderRisky.Count))" -Description 'Everyone / Authenticated Users / Users / Domain Users hanno diritti di modifica: rischio di diffusione ransomware e manomissione dati.' -Recommendation 'Sostituire con gruppi di sicurezza specifici (modello AGDLP) con il minimo privilegio.' -Objects @($FolderRisky | ForEach-Object { "$($_.Percorso) - $($_.'Identità'): $($_.Diritti)" }) -Section 'sec-folders' }
Add-FindingFromList 'fs.share.everyone' 'Medio' 'Permessi cartelle' 'Condivisioni con Everyone in modifica/controllo completo' 'I permessi di condivisione non limitano l''accesso.' 'Limitare i permessi di condivisione (es. Authenticated Users: Modifica) e gestire il dettaglio con NTFS.' 'sec-folders'
Add-FindingFromList 'fs.orphan' 'Basso' 'Permessi cartelle' 'ACE con SID orfani (account eliminati)' 'Permessi assegnati ad account/gruppi non più esistenti.' 'Rimuovere le ACE orfane.' 'sec-folders'
if ($FolderErrors.Count) { Add-Finding -Severity 'Info' -Category 'Permessi cartelle' -Title "Cartelle non analizzabili ($($FolderErrors.Count))" -Description 'Accesso negato o percorso non leggibile con l''account in uso.' -Recommendation 'Eseguire lo script con un account con diritti di lettura (o privilegio di backup).' -Objects @($FolderErrors | ForEach-Object { "$($_.Percorso) - $($_.Errore)" }) -Section 'sec-folders' }

# Eventi
Add-FindingFromList 'ev.spray' 'Alto' 'Eventi' 'Possibile password spray: stessa origine con errori su molti account' "Rilevate origini con tentativi falliti su 10 o più account distinti nelle ultime $EventHours ore." 'Indagare le origini indicate, bloccarle se malevole e verificare gli account coinvolti.' 'sec-events'
Add-FindingFromList 'ev.brute' 'Medio' 'Eventi' 'Account con numerosi accessi falliti' "Account con almeno 20 tentativi falliti nelle ultime $EventHours ore." 'Verificare se si tratta di credenziali memorizzate obsolete o di attacchi.' 'sec-events'
if ($LockoutRows.Count) { Add-Finding -Severity 'Info' -Category 'Eventi' -Title "Blocchi account registrati ($($LockoutRows.Count))" -Description "Eventi 4740 nelle ultime $EventHours ore." 'Verificare i computer di origine dei blocchi.' -Objects @($LockoutRows | ForEach-Object { "$(Format-Date $_.'Data/ora') - $($_.'Account bloccato') da $($_.'Computer di origine')" }) -Section 'sec-events' }

$Findings = @($script:Findings | Sort-Object @{ Expression = { @{ 'Critico' = 0; 'Alto' = 1; 'Medio' = 2; 'Basso' = 3; 'Info' = 4 }[$_.Severity] } }, Category, Title)

#endregion

#region ===================== COSTRUZIONE HTML =====================

Write-Step 'Generazione del report HTML'

$SevClass = @{ 'Critico' = 'b-crit'; 'Alto' = 'b-high'; 'Medio' = 'b-med'; 'Basso' = 'b-low'; 'Info' = 'b-info' }
$SectionNames = @{ 'sec-domain' = 'Dominio'; 'sec-dc' = 'Domain Controller'; 'sec-sites' = 'Siti e trust'; 'sec-pwd' = 'Policy'; 'sec-users' = 'Utenti'; 'sec-special' = 'Account speciali'; 'sec-priv' = 'Gruppi privilegiati'; 'sec-groups' = 'Gruppi'; 'sec-computers' = 'Computer'; 'sec-deleg' = 'Deleghe'; 'sec-ou' = 'OU'; 'sec-gpo' = 'GPO'; 'sec-folders' = 'Permessi'; 'sec-events' = 'Eventi' }

$FindingRows = foreach ($f in $Findings) {
    $objHtml = ''
    if ($f.Objects.Count) {
        $shown = @($f.Objects | Select-Object -First 1000 | ForEach-Object { Enc $_ })
        $more = if ($f.Objects.Count -gt 1000) { "<br>... e altri $($f.Objects.Count - 1000)" } else { '' }
        $objHtml = "<details><summary>$($f.Objects.Count) oggetti</summary><div class='objlist'>$($shown -join '<br>')$more</div></details>"
    }
    [pscustomobject][ordered]@{
        'Gravità'         = New-Badge $f.Severity $SevClass[$f.Severity]
        'Categoria'       = $f.Category
        'Controllo'       = New-Raw "<b>$(Enc $f.Title)</b>" $f.Title
        'Descrizione'     = New-Raw "<div class='lt'>$(Enc $f.Description)</div>" $f.Description
        'Raccomandazione' = New-Raw "<div class='lt'>$(Enc $f.Recommendation)</div>" $f.Recommendation
        'Oggetti'         = New-Raw $objHtml (($f.Objects | Select-Object -First 1000) -join ' | ')
        'Sezione'         = $(if ($f.Section) { New-Raw "<a href='#$($f.Section)'>$(Enc $SectionNames[$f.Section])</a>" $SectionNames[$f.Section] } else { '' })
        '_RowClass'       = "sev-$($f.Severity)"
    }
}

# Statistiche
$uEnabled = @($Users | Where-Object { $_._Enabled }).Count
$cEnabled = @($Computers | Where-Object { $_._Enabled }).Count
$sevCount = @{}
foreach ($s in 'Critico', 'Alto', 'Medio', 'Basso', 'Info') { $sevCount[$s] = @($Findings | Where-Object { $_.Severity -eq $s }).Count }

$Sections = New-Object System.Collections.Generic.List[object]
function Add-Section {
    param([string]$Id, [string]$Title, [string]$Html, [string]$Intro, $Count)
    $Sections.Add([pscustomobject]@{ Id = $Id; Title = $Title; Html = $Html; Intro = $Intro; Count = $Count })
}

# --- Riepilogo ---
$sb = New-Object System.Text.StringBuilder
[void]$sb.Append("<h3>Rilevazioni per gravità</h3><div class='cards'>")
[void]$sb.Append((New-Card 'Critico' $sevCount['Critico'] 'c-crit' '#sec-findings'))
[void]$sb.Append((New-Card 'Alto' $sevCount['Alto'] 'c-high' '#sec-findings'))
[void]$sb.Append((New-Card 'Medio' $sevCount['Medio'] 'c-med' '#sec-findings'))
[void]$sb.Append((New-Card 'Basso' $sevCount['Basso'] 'c-low' '#sec-findings'))
[void]$sb.Append((New-Card 'Info' $sevCount['Info'] 'c-info' '#sec-findings'))
[void]$sb.Append("</div><h3>Oggetti</h3><div class='cards'>")
[void]$sb.Append((New-Card 'Utenti totali' $Users.Count '' '#sec-users'))
[void]$sb.Append((New-Card 'Utenti abilitati' $uEnabled))
[void]$sb.Append((New-Card 'Utenti disabilitati' ($Users.Count - $uEnabled)))
[void]$sb.Append((New-Card "Utenti inattivi (> $InactiveDays gg)" @($Users | Where-Object { $_._Inactive }).Count 'c-med'))
[void]$sb.Append((New-Card 'Utenti bloccati' (Get-FLItems 'u.locked').Count))
[void]$sb.Append((New-Card 'Utenti privilegiati' @($Users | Where-Object { $_._Priv }).Count 'c-high' '#sec-priv'))
[void]$sb.Append((New-Card 'Computer totali' $Computers.Count '' '#sec-computers'))
[void]$sb.Append((New-Card 'Computer abilitati' $cEnabled))
[void]$sb.Append((New-Card 'Server' @($Computers | Where-Object { $_._Type -eq 'Server' }).Count))
[void]$sb.Append((New-Card 'Workstation' @($Computers | Where-Object { $_._Type -eq 'Workstation' }).Count))
[void]$sb.Append((New-Card 'SO non supportato (abilitati)' (Get-FLItems 'c.eol').Count 'c-high'))
[void]$sb.Append((New-Card 'Senza LAPS (abilitati)' (Get-FLItems 'c.nolaps').Count 'c-high'))
[void]$sb.Append((New-Card "Computer inattivi (> $InactiveDays gg)" (Get-FLItems 'c.inactive').Count 'c-med'))
[void]$sb.Append((New-Card 'Domain Controller' $DCs.Count '' '#sec-dc'))
[void]$sb.Append((New-Card 'Gruppi' $Groups.Count '' '#sec-groups'))
[void]$sb.Append((New-Card 'Gruppi vuoti' (Get-FLItems 'g.empty').Count))
[void]$sb.Append((New-Card 'OU' $RawOUs.Count '' '#sec-ou'))
[void]$sb.Append((New-Card 'GPO' $RawGpos.Count '' '#sec-gpo'))
[void]$sb.Append((New-Card 'GPO non collegate' (Get-FLItems 'gpo.unlinked').Count))
[void]$sb.Append('</div>')
if (-not $QueryAllDCs) { [void]$sb.Append("<div class='note'>Ultimo logon basato su <b>lastLogonTimestamp</b> (replicato, ritardo fino a ~14 giorni). Per il valore preciso eseguire con <code>-QueryAllDCs</code>.</div>") }
[void]$sb.Append("<div class='note'>Tentativi di password errati e stato di blocco letti dal DC <b>$(Enc $Server)</b>$(if ($Server -eq $Domain.PDCEmulator) { ' (emulatore PDC: valore più affidabile)' }). Il contatore badPwdCount si azzera dopo un accesso riuscito o allo scadere della finestra di osservazione.</div>")
Add-Section 'sec-summary' 'Riepilogo' $sb.ToString() "Panoramica del dominio $DnsRoot al $(Format-Date $Now)."

Add-Section 'sec-findings' 'Rilevazioni di sicurezza' (New-HtmlTable -Data $FindingRows -Id 'tFindings' -Filters ([ordered]@{ 'Critico' = 'sev-Critico'; 'Alto' = 'sev-Alto'; 'Medio' = 'sev-Medio'; 'Basso' = 'sev-Basso'; 'Info' = 'sev-Info' }) -EmptyText 'Nessuna rilevazione.') 'Controlli automatici ordinati per gravità. Espandere "oggetti" per l''elenco degli elementi coinvolti.' $Findings.Count

# --- Dominio ---
$fsmo = [ordered]@{
    'Nome DNS dominio'           = $DnsRoot
    'Nome NetBIOS'               = $Domain.NetBIOSName
    'Distinguished Name'         = $DomainDN
    'SID dominio'                = $DomainSID
    'Livello funzionale dominio' = [string]$Domain.DomainMode
    'Foresta'                    = $Forest.Name
    'Livello funzionale foresta' = [string]$Forest.ForestMode
    'Domini della foresta'       = @($Forest.Domains)
    'Versione schema'            = $SchemaText
    'Schema Master'              = $Forest.SchemaMaster
    'Domain Naming Master'       = $Forest.DomainNamingMaster
    'PDC Emulator'               = $Domain.PDCEmulator
    'RID Master'                 = $Domain.RIDMaster
    'Infrastructure Master'      = $Domain.InfrastructureMaster
    'Global Catalog'             = @($Forest.GlobalCatalogs)
    'Siti'                       = @($Forest.Sites)
    'Suffissi UPN aggiuntivi'    = @($Forest.UPNSuffixes)
    'Cestino AD'                 = $(if ($RecycleEnabled) { New-Badge 'Abilitato' 'b-ok' } else { New-Badge 'Non abilitato' 'b-med' })
    'Tombstone lifetime'         = $(if ($Tombstone) { "$Tombstone giorni" } else { 'Non impostato (predefinito)' })
    'ms-DS-MachineAccountQuota'  = $(if ([int]$MAQ -gt 0) { New-Badge ([string]$MAQ) 'b-med' } else { [string]$MAQ })
    'Dominio creato il'          = $DomObj.whenCreated
    'Container utenti predefinito' = $Domain.UsersContainer
    'Container computer predefinito' = $Domain.ComputersContainer
    'LAPS legacy (schema)'       = $HasLegacyLaps
    'Windows LAPS (schema)'      = $HasWinLaps
}
Add-Section 'sec-domain' 'Dominio e foresta' (New-KVTable $fsmo) 'Informazioni generali, ruoli FSMO e configurazioni di dominio.'

# --- DC ---
$h = "<h3>Domain Controller</h3>" + (New-HtmlTable -Data @($DcRows) -Id 'tDC') + "<h3>Stato della replica</h3>" + (New-HtmlTable -Data $ReplRows -Id 'tRepl' -EmptyText 'Dati di replica non disponibili.')
Add-Section 'sec-dc' 'Domain Controller e replica' $h 'Elenco dei DC, sistema operativo, ruoli e stato delle repliche.' $DCs.Count

# --- Siti e trust ---
$h = "<h3>Siti</h3>" + (New-HtmlTable -Data @($SiteRows) -Id 'tSites') + "<h3>Subnet</h3>" + (New-HtmlTable -Data @($SubnetRows) -Id 'tSubnets' -EmptyText 'Nessuna subnet definita.') + "<h3>Trust</h3>" + (New-HtmlTable -Data @($TrustRows) -Id 'tTrusts' -EmptyText 'Nessun trust configurato.')
Add-Section 'sec-sites' 'Siti, subnet e trust' $h 'Topologia dei siti e relazioni di trust.'

# --- Policy ---
$h = "<h3>Password policy di dominio (Default Domain Policy)</h3>" + (New-HtmlTable -Data $PwdRows -Id 'tPwd' -NoToolbar -EmptyText 'Password policy non leggibile.')
$h += "<h3>Fine-Grained Password Policy</h3>" + (New-HtmlTable -Data @($FgppRows) -Id 'tFgpp' -EmptyText 'Nessuna FGPP trovata (o permessi insufficienti per leggerle).')
$h += "<h3>Criteri account e Kerberos (GptTmpl.inf della Default Domain Policy)</h3>" + (New-HtmlTable -Data $KerbRows -Id 'tKerb' -EmptyText 'File GptTmpl.inf non leggibile.')
$h += "<h3>Criteri di controllo (audit) risultanti sull'OU Domain Controllers</h3>" + (New-HtmlTable -Data $AuditRows -Id 'tAudit' -EmptyText 'Nessun criterio di audit trovato nelle GPO applicate all''OU Domain Controllers.')
Add-Section 'sec-pwd' 'Password policy, Kerberos e audit' $h 'Valutazione rispetto alle raccomandazioni CIS / Microsoft Security Baseline.'

# --- Utenti ---
$userFilters = [ordered]@{ 'Solo abilitati' = 'st-on'; 'Solo disabilitati' = 'st-off'; "Inattivi (> $InactiveDays gg)" = 'f-inactive'; 'Mai connessi' = 'f-never'; 'Con rischi' = 'f-risk'; 'Privilegiati' = 'f-priv'; 'Bloccati' = 'f-locked'; 'Con tentativi errati' = 'f-badpwd'; 'Password senza scadenza' = 'f-nexp' }
Add-Section 'sec-users' 'Utenti' (New-HtmlTable -Data $Users -Id 'tUsers' -Filters $userFilters) 'Tutti gli account utente con stato, accessi, password, flag di sicurezza, attributi e gruppi (diretti e annidati). Clic sull''intestazione per ordinare.' $Users.Count
Export-ReportCsv $Users 'Utenti'

Add-Section 'sec-special' 'Account speciali' (New-HtmlTable -Data $SpecialRows -Id 'tSpecial' -NoToolbar) 'Administrator predefinito, Guest e account krbtgt.'

# --- Privilegiati ---
$pgFilters = [ordered]@{}
foreach ($pd in $PrivGroups.Keys) { $pgFilters[$PrivGroups[$pd].Display] = "pg-$($PrivGroups[$pd].Index)" }
$h = "<h3>Riepilogo</h3>" + (New-HtmlTable -Data @($PrivSummary) -Id 'tPrivSum' -NoToolbar) + "<h3>Membri (diretti e annidati)</h3>" + (New-HtmlTable -Data $PrivRows -Id 'tPriv' -Filters $pgFilters -EmptyText 'Nessun membro.')
Add-Section 'sec-priv' 'Gruppi privilegiati' $h 'Gruppi individuati tramite SID noti (indipendenti dalla lingua). L''appartenenza annidata è calcolata ricorsivamente.' $PrivRows.Count
Export-ReportCsv $PrivRows 'Membri_gruppi_privilegiati'

Add-Section 'sec-groups' 'Gruppi' (New-HtmlTable -Data $Groups -Id 'tGroups' -Filters ([ordered]@{ 'Sicurezza' = 'k-sec'; 'Distribuzione' = 'k-dist'; 'Vuoti' = 'f-empty'; 'Privilegiati' = 'f-priv' })) 'Tutti i gruppi. "Membri" include anche gli utenti che hanno il gruppo come gruppo primario.' $Groups.Count
Export-ReportCsv $Groups 'Gruppi'

# --- Computer ---
$compFilters = [ordered]@{ 'Solo abilitati' = 'st-on'; 'Solo disabilitati' = 'st-off'; 'Domain Controller' = 'k-dc'; 'Server' = 'k-srv'; 'Workstation' = 'k-ws'; 'Altri' = 'k-oth'; 'SO non supportato' = 'f-eol'; 'Senza LAPS' = 'f-nolaps'; "Inattivi (> $InactiveDays gg)" = 'f-inactive'; 'Con rischi' = 'f-risk' }
$compIntro = 'Tutti gli oggetti computer con sistema operativo, stato del supporto, LAPS, BitLocker, deleghe e gruppi.'
if ($blObjs.Count -eq 0) { $compIntro += ' Nota: nessuna chiave BitLocker trovata in AD (non configurato o permessi di lettura insufficienti).' }
Add-Section 'sec-computers' 'Computer' (New-HtmlTable -Data $Computers -Id 'tComputers' -Filters $compFilters) $compIntro $Computers.Count
Export-ReportCsv $Computers 'Computer'

Add-Section 'sec-deleg' 'Deleghe Kerberos' (New-HtmlTable -Data $DelegRows -Id 'tDeleg' -EmptyText 'Nessuna delega configurata (esclusi i DC).') 'Account con delega non vincolata, vincolata, protocol transition o resource-based (i DC hanno delega non vincolata per progettazione e sono esclusi).' $DelegRows.Count
Add-Section 'sec-msa' 'Account di servizio gestiti' (New-HtmlTable -Data @($MsaRows) -Id 'tMsa' -EmptyText 'Nessun account di servizio gestito.') 'Managed Service Account (sMSA), Group Managed Service Account (gMSA) e Delegated MSA.'

# --- OU ---
$tree = ConvertTo-OuTreeHtml -Node $Nodes[$DomainDN] -Depth 0
$h = "<div class='tb'><button type='button' onclick=""treeAll('outree',true)"">Espandi tutto</button><button type='button' onclick=""treeAll('outree',false)"">Comprimi tutto</button></div><ul class='tree' id='outree'>$tree</ul>"
$h += "<h3>Elenco OU</h3>" + (New-HtmlTable -Data @($OuRows) -Id 'tOU')
$h += "<div class='note'>Le GPO risultanti seguono la logica di GPMC (link abilitati, ordine di collegamento, blocco ereditarietà, imposizione). Non sono considerati filtri di sicurezza, filtri WMI, loopback né GPO collegate ai siti (elencate nella sezione Siti).</div>"
Add-Section 'sec-ou' 'Struttura OU e GPO applicate' $h 'Albero di OU e contenitori con GPO collegate e GPO risultanti per ciascun livello.' $RawOUs.Count
Export-ReportCsv @($OuRows) 'OU'

$h = (New-HtmlTable -Data @($GpoRows) -Id 'tGPO' -Filters ([ordered]@{ 'Con problemi' = 'f-issue' }))
if ($SysvolOrphans.Count) { $h += "<h3>Cartelle orfane in SYSVOL</h3><div class='objlist'>$(($SysvolOrphans | ForEach-Object { Enc $_ }) -join '<br>')</div>" }
Add-Section 'sec-gpo' 'Group Policy Object' $h 'Tutte le GPO del dominio con stato, versioni, collegamenti, filtri WMI e coerenza SYSVOL.' $RawGpos.Count
Export-ReportCsv @($GpoRows) 'GPO'

# --- Permessi cartelle ---
if (-not $SkipFolderReport -and $FolderPath) {
    $h = "<div class='note'>Per le sottocartelle sono mostrate solo le ACE <b>esplicite</b>$(if ($IncludeInheritedAces) { ' e quelle ereditate' }); la radice mostra tutte le ACE effettive. In rosso le ACE che concedono scrittura a gruppi ampi (Everyone, Authenticated Users, Users, Domain Users...).$(if ($script:FolderTruncated) { " <b>Raggiunto il limite di $MaxFolders cartelle: analisi parziale.</b>" })</div>"
    if ($ShareRows.Count) { $h += "<h3>Permessi di condivisione</h3>" + (New-HtmlTable -Data $ShareRows -Id 'tShare' -NoToolbar) }
    $h += ($FolderSections -join "`n")
    $h += "<h3>Cartelle con permessi espliciti o ereditarietà disabilitata</h3>" + (New-HtmlTable -Data $FolderExceptions -Id 'tFoldEx' -EmptyText 'Nessuna eccezione: tutte le sottocartelle ereditano i permessi.')
    $h += "<h3>Permessi di scrittura a gruppi ampi</h3>" + (New-HtmlTable -Data $FolderRisky -Id 'tFoldRisk' -EmptyText 'Nessuna ACE a rischio trovata.')
    if ($FolderErrors.Count) { $h += "<h3>Errori di accesso</h3>" + (New-HtmlTable -Data $FolderErrors -Id 'tFoldErr') }
    Add-Section 'sec-folders' 'Permessi cartelle' $h "Struttura ad albero dei permessi NTFS di: $(($FolderPath | ForEach-Object { $_ }) -join ', ')" $script:FolderCount
    Export-ReportCsv $FolderAces 'Permessi_cartelle_ACE_esplicite'
    Export-ReportCsv $FolderExceptions 'Permessi_cartelle_eccezioni'
}

# --- Eventi ---
if ($IncludeSecurityEvents) {
    $h = "<h3>Accessi falliti aggregati per account e origine</h3>" + (New-HtmlTable -Data @($EventRows) -Id 'tEvents' -EmptyText 'Nessun accesso fallito trovato nel periodo.')
    $h += "<h3>Blocchi account (4740)</h3>" + (New-HtmlTable -Data $LockoutRows -Id 'tLockouts' -EmptyText 'Nessun blocco nel periodo.')
    Add-Section 'sec-events' 'Accessi falliti (eventi)' $h "Eventi 4625, 4771, 4776 e 4740 letti dai registri Security dei DC nelle ultime $EventHours ore. Richiede che l'audit sia attivo e che i registri non siano già stati sovrascritti." @($EventRows).Count
    Export-ReportCsv @($EventRows) 'Accessi_falliti'
}

Add-Section 'sec-log' 'Log di raccolta' (New-HtmlTable -Data $script:ReportLog -Id 'tLog' -EmptyText 'Nessun avviso durante la raccolta.') 'Avvisi ed errori riscontrati durante l''esecuzione (dati eventualmente incompleti).' $script:ReportLog.Count
Export-ReportCsv $FindingRows 'Rilevazioni'

$css = @'
:root{--bg:#f3f5f9;--card:#fff;--tx:#1e293b;--mu:#64748b;--bd:#e2e8f0;--ac:#1e40af;--hd:#0f172a}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;font:13px/1.45 "Segoe UI",Tahoma,Arial,sans-serif;background:var(--bg);color:var(--tx)}
header{position:fixed;top:0;left:0;right:0;height:58px;background:var(--hd);color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 20px;z-index:20}
header h1{font-size:18px;margin:0;font-weight:600}header h1 span{color:#93c5fd}
header .meta{font-size:11.5px;color:#cbd5e1;text-align:right;line-height:1.35}
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
.c-crit{border-left-color:#7f1d1d}.c-high{border-left-color:#dc2626}.c-med{border-left-color:#d97706}.c-low{border-left-color:#2563eb}.c-info{border-left-color:#64748b}
.tb{display:flex;gap:8px;align-items:center;margin:8px 0;flex-wrap:wrap}
.tb input[type=search]{padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;min-width:260px}
.tb select,.tb button{padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;cursor:pointer;font:inherit}
.tb button:hover{background:#eff6ff}.tb .cnt{color:var(--mu);margin-left:auto}
.tw{overflow:auto;max-height:75vh;border:1px solid var(--bd);border-radius:6px}
table.dt{border-collapse:collapse;width:100%;font-size:12px}
table.dt th{position:sticky;top:0;background:#e8eef7;text-align:left;padding:7px 8px;white-space:nowrap;cursor:pointer;user-select:none;border-bottom:1px solid #cbd5e1;z-index:1}
table.dt th:hover{background:#dbe5f3}table.dt th[data-dir=asc]::after{content:" \25B2";font-size:9px}table.dt th[data-dir=desc]::after{content:" \25BC";font-size:9px}
table.dt td{padding:5px 8px;border-bottom:1px solid #eef2f7;vertical-align:top;white-space:nowrap}
table.dt tbody tr:hover td{background:#f8fafc}
tr.st-off td{color:#94a3b8}
.cl{max-height:110px;overflow:auto;padding-right:6px}.lt{white-space:normal;min-width:260px;max-width:520px}
.bdg{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap;margin:1px 0}
.b-ok{background:#dcfce7;color:#166534}.b-off{background:#e2e8f0;color:#475569}.b-info{background:#e0f2fe;color:#075985}
.b-low{background:#dbeafe;color:#1e40af}.b-med{background:#fef3c7;color:#92400e}.b-warn{background:#ffedd5;color:#9a3412}
.b-high{background:#fee2e2;color:#991b1b}.b-crit{background:#7f1d1d;color:#fff}
table.kv{border-collapse:collapse;min-width:60%}table.kv th{text-align:left;background:#f1f5f9;padding:6px 12px;width:280px;vertical-align:top;border-bottom:1px solid #fff}
table.kv td{padding:6px 12px;border-bottom:1px solid #eef2f7}
table.mini{border-collapse:collapse;margin:6px 0;font-size:12px;background:#fff}
table.mini th{background:#eef2f7;text-align:left;padding:4px 8px}table.mini td{padding:4px 8px;border-top:1px solid #eef2f7}
tr.ace-inh td{color:#64748b}tr.ace-risk td{background:#fee2e2}tr.ace-deny td{background:#fef3c7}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:18px}ul.tree{padding-left:0}
ul.tree ul{border-left:1px dashed #cbd5e1;margin-left:9px}ul.tree li{margin:2px 0}
ul.tree summary{cursor:pointer;padding:3px 6px;border-radius:5px}ul.tree summary:hover{background:#eff6ff}
ul.tree .ty{color:var(--mu);font-size:11px}ul.tree .cnts{color:var(--mu);font-size:11px;margin-left:6px}
.node{margin:4px 0 8px 22px;padding:8px 12px;background:#f8fafc;border:1px solid var(--bd);border-radius:6px}
.node .lbl{font-weight:600;margin-top:8px}.node .dn{margin-bottom:4px}
ol.eff{margin:4px 0 0;padding-left:22px}ol.eff .src{color:var(--mu);font-size:11px}
.only-x li.fnode[data-x="0"]{display:none}
.objlist{max-height:260px;overflow:auto;font-family:Consolas,monospace;font-size:11.5px;background:#f8fafc;padding:6px 8px;border-radius:4px;white-space:nowrap}
details>summary{cursor:pointer}
code{font-family:Consolas,monospace;background:#f1f5f9;padding:0 4px;border-radius:3px;font-size:11.5px}
.empty{color:var(--mu);font-style:italic}.err{color:#b91c1c}
.note{background:#fffbeb;border:1px solid #fde68a;padding:8px 12px;border-radius:6px;color:#78350f;margin:10px 0}
footer{color:var(--mu);text-align:center;font-size:11px;padding:10px 0 30px}
@media (max-width:900px){nav{display:none}main{margin-left:0;padding:70px 12px}}
@media print{header,nav{position:static}nav,.tb{display:none}main{margin:0;padding:0}.tw{max-height:none;overflow:visible}section{break-inside:auto}}
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
[void]$out.Append("<!DOCTYPE html><html lang='it'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Report AD - $(Enc $DnsRoot)</title><style>$css</style></head><body>")
[void]$out.Append("<header><h1>Report Active Directory &middot; <span>$(Enc $DnsRoot)</span></h1><div class='meta'>Generato il $(Format-Date $Now) da $(Enc $runAs) su $(Enc $env:COMPUTERNAME)<br>DC interrogato: $(Enc $Server) &middot; durata $duration min</div></header><nav>")
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
$params = "InactiveDays=$InactiveDays; PasswordAgeDays=$PasswordAgeDays; QueryAllDCs=$([bool]$QueryAllDCs); FolderDepth=$FolderDepth; IncludeSecurityEvents=$([bool]$IncludeSecurityEvents)"
[void]$out.Append("<footer>AD Security Report v$ScriptVersion &middot; Parametri: $(Enc $params) &middot; Report in sola lettura: nessuna modifica è stata effettuata.</footer></main><script>$js</script></body></html>")

[System.IO.File]::WriteAllText($ReportFile, $out.ToString(), (New-Object System.Text.UTF8Encoding($true)))

#endregion

Write-Host ''
Write-Host "Report generato: $ReportFile" -ForegroundColor Green
if ($ExportCsv -and (Test-Path -LiteralPath $CsvFolder)) { Write-Host "CSV esportati in: $CsvFolder" -ForegroundColor Green }
Write-Host ("Rilevazioni -> Critico: {0}  Alto: {1}  Medio: {2}  Basso: {3}  Info: {4}" -f $sevCount['Critico'], $sevCount['Alto'], $sevCount['Medio'], $sevCount['Basso'], $sevCount['Info']) -ForegroundColor Yellow
if ($script:ReportLog.Count) { Write-Host "Avvisi durante la raccolta: $($script:ReportLog.Count) (vedi sezione 'Log di raccolta')" -ForegroundColor Yellow }
if ($OpenReport) { Invoke-Item -LiteralPath $ReportFile }
