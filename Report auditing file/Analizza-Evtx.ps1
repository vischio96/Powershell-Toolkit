<#
.SYNOPSIS
    Analizza un file EVTX di sicurezza (auditing file server) e genera un report HTML interattivo.

.DESCRIPTION
    Estrae gli eventi 4663 (accesso a oggetto file) e 4660 (eliminazione oggetto),
    classifica le operazioni (lettura, scrittura/modifica, eliminazione/rinomina,
    modifica attributi/permessi), correla gli eventi 4660 al percorso tramite HandleId
    e produce un report HTML autonomo con ricerca, filtri per utente/azione/data,
    timeline ed export CSV.

    Gli eventi identici (stesso utente, percorso, azione, processo) nello stesso
    minuto vengono raggruppati in una riga sola con il conteggio.

.PARAMETER PercorsoEvtx
    Percorso del file .evtx da analizzare. Se omesso si apre una finestra che
    permette di scegliere tra il log di sicurezza attivo del server
    (C:\Windows\System32\winevt\Logs\Security.evtx, richiede amministratore)
    e un file .evtx selezionato manualmente.

.PARAMETER PercorsoReport
    Percorso del report HTML da generare. Predefinito: .\Report_FileAudit.html

.PARAMETER IncludiMetadati
    Include anche le letture di metadati/permessi (AccessMask 0x80 ReadAttributes,
    0x8 ReadEA, 0x20000 ReadControl). Sono la gran parte del volume e di solito
    non interessano: esclusi per impostazione predefinita.

.PARAMETER EscludiLetture
    Esclude anche le letture dei dati (0x1 ReadData), lasciando solo le modifiche.

.PARAMETER ApriReport
    Apre il report nel browser al termine.

.EXAMPLE
    .\Analizza-Evtx.ps1 -ApriReport       # apre la finestra di selezione del log

.EXAMPLE
    .\Analizza-Evtx.ps1 -PercorsoEvtx .\log.evtx -ApriReport

.EXAMPLE
    .\Analizza-Evtx.ps1 -EscludiLetture   # solo scritture, eliminazioni, modifiche
#>
[CmdletBinding()]
param(
    [string]$PercorsoEvtx,
    [string]$PercorsoReport = ".\Report_FileAudit.html",
    [switch]$IncludiMetadati,
    [switch]$EscludiLetture,
    [switch]$ApriReport
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0'

$LOG_SICUREZZA_ATTIVO = Join-Path $env:SystemRoot 'System32\winevt\Logs\Security.evtx'

# ---------------------------------------------------------------------------
# Finestra di selezione della sorgente (mostrata se -PercorsoEvtx non e' indicato)
# ---------------------------------------------------------------------------
function Select-SorgenteEvtx {
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw "La finestra di selezione richiede una sessione STA. Avvia con 'powershell.exe -STA -File .\Analizza-Evtx.ps1' oppure indica -PercorsoEvtx."
    }
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form -Property @{
        Text = 'Analisi auditing file - selezione log di sicurezza'
        StartPosition = 'CenterScreen'; FormBorderStyle = 'FixedDialog'
        MaximizeBox = $false; MinimizeBox = $false; TopMost = $true
        ClientSize = New-Object System.Drawing.Size(560, 215)
        Font = New-Object System.Drawing.Font('Segoe UI', 9)
    }

    $lblTitolo = New-Object System.Windows.Forms.Label -Property @{
        Text = 'Scegli il file di log di sicurezza da analizzare:'
        Location = '15,12'; AutoSize = $true
    }

    $rbAttivo = New-Object System.Windows.Forms.RadioButton -Property @{
        Text = "Log di sicurezza attuale di questo server`r`n$LOG_SICUREZZA_ATTIVO"
        Location = '20,38'; Size = '520,38'; Checked = $true
    }
    $rbFile = New-Object System.Windows.Forms.RadioButton -Property @{
        Text = 'File .evtx selezionato manualmente (es. log esportato o archiviato):'
        Location = '20,82'; Size = '520,22'
    }
    $txtFile = New-Object System.Windows.Forms.TextBox -Property @{
        Location = '38,108'; Size = '410,23'; Enabled = $false
    }
    $btnSfoglia = New-Object System.Windows.Forms.Button -Property @{
        Text = 'Sfoglia...'; Location = '455,107'; Size = '90,25'; Enabled = $false
    }
    $btnOk = New-Object System.Windows.Forms.Button -Property @{
        Text = 'Analizza'; Location = '370,170'; Size = '85,28'
    }
    $btnAnnulla = New-Object System.Windows.Forms.Button -Property @{
        Text = 'Annulla'; Location = '460,170'; Size = '85,28'
        DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    }

    # se nella cartella dello script c'e' un log.evtx lo propongo come predefinito
    $predefinito = Join-Path $PSScriptRoot 'log.evtx'
    if (Test-Path $predefinito) { $txtFile.Text = $predefinito }

    $rbFile.Add_CheckedChanged({
        $txtFile.Enabled = $rbFile.Checked; $btnSfoglia.Enabled = $rbFile.Checked
    })

    $btnSfoglia.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title  = 'Seleziona il file di log di sicurezza'
            Filter = 'Log eventi di Windows (*.evtx)|*.evtx|Tutti i file (*.*)|*.*'
            CheckFileExists = $true
        }
        if ($txtFile.Text -and (Test-Path (Split-Path $txtFile.Text -Parent) -ErrorAction SilentlyContinue)) {
            $dlg.InitialDirectory = Split-Path $txtFile.Text -Parent
        } else { $dlg.InitialDirectory = $PSScriptRoot }
        if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) { $txtFile.Text = $dlg.FileName }
        $dlg.Dispose()
    })

    $btnOk.Add_Click({
        if ($rbFile.Checked) {
            $f = $txtFile.Text.Trim('"', ' ')
            if (-not $f -or -not (Test-Path -LiteralPath $f -PathType Leaf)) {
                [void][System.Windows.Forms.MessageBox]::Show($form, 'Seleziona un file .evtx esistente.',
                    'File non valido', 'OK', 'Warning')
                return
            }
            $txtFile.Text = $f
        }
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })

    $form.Controls.AddRange(@($lblTitolo, $rbAttivo, $rbFile, $txtFile, $btnSfoglia, $btnOk, $btnAnnulla))
    $form.AcceptButton = $btnOk
    $form.CancelButton = $btnAnnulla

    $esito = $form.ShowDialog()
    $scelta = if ($rbAttivo.Checked) { $LOG_SICUREZZA_ATTIVO } else { $txtFile.Text }
    $form.Dispose()

    if ($esito -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    return $scelta
}

if ([string]::IsNullOrWhiteSpace($PercorsoEvtx)) {
    $PercorsoEvtx = Select-SorgenteEvtx
    if (-not $PercorsoEvtx) { Write-Host "Operazione annullata dall'utente."; return }
}

if (-not (Test-Path -LiteralPath $PercorsoEvtx)) { throw "File non trovato: $PercorsoEvtx" }
$PercorsoEvtx = (Resolve-Path -LiteralPath $PercorsoEvtx).Path

# Il Security.evtx attivo e' bloccato dal servizio Registro eventi: lo leggo tramite il
# canale 'Security' (richiede privilegi di amministratore) invece che come file.
$UsaLogAttivo = [string]::Equals($PercorsoEvtx, $LOG_SICUREZZA_ATTIVO, [System.StringComparison]::OrdinalIgnoreCase)
if ($UsaLogAttivo) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw "La lettura del log di sicurezza attivo richiede una sessione PowerShell avviata come amministratore." }
}

# ---------------------------------------------------------------------------
# Classificazione AccessMask -> indice azione
# ---------------------------------------------------------------------------
# 0 Lettura | 1 Scrittura/Modifica | 2 Eliminazione/Rinomina | 3 Modifica attributi
# 4 Eliminazione (4660) | 5 Modifica permessi | 6 Esecuzione | 7 Lettura metadati
$MASK_DELETE    = 0x10000
$MASK_WRITE     = 0x2 -bor 0x4          # WriteData | AppendData
$MASK_WRITEMETA = 0x100 -bor 0x10       # WriteAttributes | WriteEA
$MASK_ACL       = 0x40000 -bor 0x80000  # WriteDAC | WriteOwner
$MASK_EXEC      = 0x20
$MASK_READ      = 0x1

$epoch0 = [datetime]::new(1970,1,1,0,0,0,[System.DateTimeKind]::Utc)

Write-Host "Report auditing file v$ScriptVersion"
Write-Host "Analisi di: $PercorsoEvtx"
Write-Host ("Filtri: letture dati {0}, metadati/permessi {1}" -f `
    ($(if ($EscludiLetture)  {'ESCLUSE'} else {'incluse'})), `
    ($(if ($IncludiMetadati) {'inclusi'} else {'esclusi'})))

if ($UsaLogAttivo) {
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        'Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        "*[System[(EventID=4663 or EventID=4660)]]")
} else {
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        $PercorsoEvtx, [System.Diagnostics.Eventing.Reader.PathType]::FilePath,
        "*[System[(EventID=4663 or EventID=4660)]]")
}
$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

$righe    = [System.Collections.Generic.Dictionary[string,object[]]]::new()
$utenti   = [System.Collections.Generic.Dictionary[string,int]]::new()
$processi = [System.Collections.Generic.Dictionary[string,int]]::new()
$mappaHandle = [System.Collections.Generic.Dictionary[string,string]]::new()

$totLetti = 0; $totTenuti = 0
$primoEvento = $null; $ultimoEvento = $null
$sw = [System.Diagnostics.Stopwatch]::StartNew()

function Get-Indice([System.Collections.Generic.Dictionary[string,int]]$dict, [string]$chiave) {
    $idx = 0
    if (-not $dict.TryGetValue($chiave, [ref]$idx)) { $idx = $dict.Count; $dict[$chiave] = $idx }
    return $idx
}

while ($null -ne ($ev = $reader.ReadEvent())) {
    $totLetti++
    if ($totLetti % 100000 -eq 0) { Write-Host ("  {0:N0} eventi letti..." -f $totLetti) }

    $p = $ev.Properties
    $t = $ev.TimeCreated.ToUniversalTime()
    if ($null -eq $primoEvento) { $primoEvento = $ev.TimeCreated }
    $ultimoEvento = $ev.TimeCreated
    $ts = [int64]($t - $epoch0).TotalSeconds

    $azione = -1; $percorso = ''; $utente = ''; $proc = ''

    if ($ev.Id -eq 4663) {
        if ($p.Count -lt 12) { $ev.Dispose(); continue }
        $percorso = [string]$p[6].Value
        $handle   = [string]$p[7].Value
        # la mappa handle->percorso serve a risolvere i 4660, va sempre aggiornata
        $mappaHandle[$handle] = $percorso

        $mv = $p[9].Value
        if ($mv -is [string]) { $mask = [convert]::ToInt64($mv, 16) } else { $mask = [int64]$mv }

        if     ($mask -band $MASK_DELETE)    { $azione = 2 }
        elseif ($mask -band $MASK_WRITE)     { $azione = 1 }
        elseif ($mask -band $MASK_WRITEMETA) { $azione = 3 }
        elseif ($mask -band $MASK_ACL)       { $azione = 5 }
        elseif ($mask -band $MASK_EXEC)      { $azione = 6 }
        elseif ($mask -band $MASK_READ)      { $azione = 0 }
        else                                 { $azione = 7 }

        if ($azione -eq 7 -and -not $IncludiMetadati) { $ev.Dispose(); continue }
        if ($azione -eq 0 -and $EscludiLetture)       { $ev.Dispose(); continue }

        $utente = "$($p[2].Value)\$($p[1].Value)"
        $proc   = [string]$p[11].Value
    }
    elseif ($ev.Id -eq 4660) {
        $azione = 4
        $handle = [string]$p[5].Value
        if (-not $mappaHandle.TryGetValue($handle, [ref]$percorso)) { $percorso = '(percorso non risolto)' }
        $utente = "$($p[2].Value)\$($p[1].Value)"
        $proc   = [string]$p[7].Value
    }
    $ev.Dispose()
    if ($azione -lt 0) { continue }

    if ([string]::IsNullOrEmpty($proc)) { $proc = 'Rete (SMB)' }
    else { $proc = $proc.Substring($proc.LastIndexOf('\') + 1) }

    $u = Get-Indice $utenti $utente
    $pr = Get-Indice $processi $proc

    $totTenuti++
    $chiave = "$u`t$azione`t$pr`t$($ts - ($ts % 60))`t$percorso"
    $riga = $null
    if ($righe.TryGetValue($chiave, [ref]$riga)) { $riga[5] = [int]$riga[5] + 1 }
    else { $righe[$chiave] = @($ts, $u, $azione, $percorso, $pr, 1) }
}
$sw.Stop()
Write-Host ("Lettura completata: {0:N0} eventi, {1:N0} operazioni tenute, {2:N0} righe dopo il raggruppamento ({3:N0}s)" -f `
    $totLetti, $totTenuti, $righe.Count, $sw.Elapsed.TotalSeconds)

if ($righe.Count -eq 0) { throw "Nessun evento 4663/4660 corrispondente ai filtri trovato nel file." }

# ---------------------------------------------------------------------------
# Serializzazione dati -> JSON
# ---------------------------------------------------------------------------
Write-Host "Generazione del report..."
$ordinate = [System.Collections.Generic.List[object[]]]::new($righe.Values)
$ordinate.Sort({ param($a, $b) ([int64]$b[0]).CompareTo([int64]$a[0]) })  # piu' recenti prima

$sb = [System.Text.StringBuilder]::new(($ordinate.Count * 110))
[void]$sb.Append('[')
foreach ($r in $ordinate) {
    $path = ([string]$r[3]).Replace('\', '\\').Replace('"', '\"')
    [void]$sb.Append('[').Append([int64]$r[0]).Append(',').Append([int]$r[1]).Append(',').
        Append([int]$r[2]).Append(',"').Append($path).Append('",').
        Append([int]$r[4]).Append(',').Append([int]$r[5]).Append('],')
}
if ($sb[$sb.Length-1] -eq ',') { $sb.Length-- }
[void]$sb.Append(']')
$jsonRighe = $sb.ToString()

function ConvertTo-JsonStringArray($dict) {
    $arr = New-Object string[] $dict.Count
    foreach ($kv in $dict.GetEnumerator()) { $arr[$kv.Value] = $kv.Key }
    $parti = foreach ($s in $arr) { '"' + $s.Replace('\', '\\').Replace('"', '\"') + '"' }
    return '[' + ($parti -join ',') + ']'
}
$jsonUtenti   = ConvertTo-JsonStringArray $utenti
$jsonProcessi = ConvertTo-JsonStringArray $processi

$nomeFile = if ($UsaLogAttivo) { "Security (log attivo di $env:COMPUTERNAME)" }
            else { [System.IO.Path]::GetFileName($PercorsoEvtx) }
$meta = ('{{"file":"{0}","generato":"{1}","dal":"{2}","al":"{3}","eventiTotali":{4},"note":"{5}"}}' -f `
    $nomeFile.Replace('\','\\').Replace('"','\"'),
    (Get-Date -Format 'dd/MM/yyyy HH:mm'),
    $primoEvento.ToString('dd/MM/yyyy HH:mm'),
    $ultimoEvento.ToString('dd/MM/yyyy HH:mm'),
    $totLetti,
    ("v$ScriptVersion · letture dati: {0} · letture metadati/permessi: {1}" -f `
        $(if ($EscludiLetture)  {'escluse'} else {'incluse'}),
        $(if ($IncludiMetadati) {'incluse'} else {'escluse'})))

# ---------------------------------------------------------------------------
# Template HTML (segnaposto: __META__ __UTENTI__ __PROCESSI__ __RIGHE__)
# ---------------------------------------------------------------------------
$template = @'
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Report auditing file</title>
<style>
:root{
  --surface:#fcfcfb; --page:#f9f9f7; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --border:rgba(11,11,11,.10); --accent:#2a78d6;
  --hover:rgba(11,11,11,.04);
}
@media (prefers-color-scheme: dark){
  :root{ --surface:#1a1a19; --page:#0d0d0d; --ink:#ffffff; --ink2:#c3c2b7;
         --grid:#2c2c2a; --axis:#383835; --border:rgba(255,255,255,.10); --accent:#3987e5;
         --hover:rgba(255,255,255,.06); }
}
*{box-sizing:border-box; margin:0}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif; background:var(--page);
     color:var(--ink); font-size:14px; line-height:1.45; padding:24px}
.wrap{max-width:1400px; margin:0 auto}
h1{font-size:20px; font-weight:600}
.sub{color:var(--ink2); font-size:13px; margin-top:4px}
.card{background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:16px; margin-top:16px}
.kpis{display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-top:16px}
.kpi{background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:12px 16px}
.kpi .lbl{font-size:12px; color:var(--ink2)}
.kpi .val{font-size:26px; font-weight:600; margin-top:2px}
.filters{display:flex; flex-wrap:wrap; gap:10px; align-items:flex-end}
.filters label{display:flex; flex-direction:column; gap:4px; font-size:12px; color:var(--ink2)}
.filters input,.filters select{font:inherit; font-size:13px; color:var(--ink);
  background:var(--page); border:1px solid var(--axis); border-radius:6px; padding:6px 8px}
.filters input[type=search]{width:280px}
button{font:inherit; font-size:13px; padding:7px 14px; border-radius:6px; cursor:pointer;
  border:1px solid var(--axis); background:var(--surface); color:var(--ink)}
button:hover{background:var(--hover)}
button.primary{background:var(--accent); border-color:var(--accent); color:#fff}
.count{font-size:13px; color:var(--ink2); margin-left:auto; align-self:center}
/* timeline */
.chart-title{font-size:13px; font-weight:600; margin-bottom:2px}
.chart-sub{font-size:12px; color:var(--muted); margin-bottom:10px}
.chart{position:relative; height:140px; display:flex; align-items:flex-end; gap:2px;
  border-bottom:1px solid var(--axis); padding-bottom:1px}
.chart .bar{flex:1; max-width:24px; min-width:2px; background:var(--accent);
  border-radius:4px 4px 0 0; cursor:pointer}
.chart .bar:hover{opacity:.75}
.xlabels{display:flex; gap:2px; margin-top:4px}
.xlabels span{flex:1; max-width:24px; min-width:2px; font-size:10px; color:var(--muted);
  overflow:visible; white-space:nowrap}
#tooltip{position:fixed; display:none; background:var(--ink); color:var(--page);
  font-size:12px; padding:6px 10px; border-radius:6px; pointer-events:none; z-index:10;
  max-width:420px}
/* tabella */
table{width:100%; border-collapse:collapse; font-size:13px}
th{font-size:12px; color:var(--ink2); text-align:left; font-weight:600; cursor:pointer;
   padding:8px 10px; border-bottom:1px solid var(--axis); white-space:nowrap; user-select:none}
th:hover{background:var(--hover)}
td{padding:6px 10px; border-bottom:1px solid var(--grid); vertical-align:top}
tr:hover td{background:var(--hover)}
td.dt{white-space:nowrap; font-variant-numeric:tabular-nums; color:var(--ink2)}
td.n{text-align:right; font-variant-numeric:tabular-nums}
th.n{text-align:right}
td.path{word-break:break-all; max-width:640px}
.badge{display:inline-flex; align-items:center; gap:6px; white-space:nowrap}
.badge i{width:9px; height:9px; border-radius:50%; display:inline-block}
.pager{display:flex; gap:10px; align-items:center; justify-content:center; margin-top:12px}
.empty{text-align:center; color:var(--muted); padding:32px}
footer{color:var(--muted); font-size:12px; margin-top:16px; text-align:center}
</style>
</head>
<body>
<div class="wrap">
  <h1>Report auditing file &mdash; movimenti sui file</h1>
  <div class="sub" id="sottotitolo"></div>

  <div class="kpis" id="kpis"></div>

  <div class="card">
    <div class="filters">
      <label>Cerca (percorso, utente, processo)
        <input type="search" id="f-q" placeholder="es. \Dati\UffPersonale oppure .pdf">
      </label>
      <label>Utente
        <select id="f-utente"><option value="">Tutti</option></select>
      </label>
      <label>Azione
        <select id="f-azione"><option value="">Tutte</option></select>
      </label>
      <label>Dal
        <input type="datetime-local" id="f-dal">
      </label>
      <label>Al
        <input type="datetime-local" id="f-al">
      </label>
      <button id="btn-reset">Azzera filtri</button>
      <button id="btn-csv" class="primary">Esporta CSV</button>
      <span class="count" id="conteggio"></span>
    </div>
  </div>

  <div class="card">
    <div class="chart-title">Operazioni nel tempo</div>
    <div class="chart-sub" id="chart-sub"></div>
    <div class="chart" id="chart"></div>
    <div class="xlabels" id="xlabels"></div>
  </div>

  <div class="card" style="padding:0">
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th data-c="0">Data e ora</th>
        <th data-c="1">Utente</th>
        <th data-c="2">Azione</th>
        <th data-c="3">Percorso</th>
        <th data-c="4">Processo</th>
        <th data-c="5" class="n">N. eventi</th>
      </tr></thead>
      <tbody id="corpo"></tbody>
    </table>
    </div>
    <div class="pager">
      <button id="pg-prev">&#8249; Precedente</button>
      <span id="pg-info"></span>
      <button id="pg-next">Successiva &#8250;</button>
    </div>
  </div>

  <footer id="pie"></footer>
</div>
<div id="tooltip"></div>

<script>
const META = __META__;
const UTENTI = __UTENTI__;
const PROCESSI = __PROCESSI__;
const AZIONI = [
  {n:"Lettura",              c:"#2a78d6"},
  {n:"Scrittura / modifica", c:"#1baf7a"},
  {n:"Eliminazione / rinomina", c:"#eb6834"},
  {n:"Modifica attributi",   c:"#eda100"},
  {n:"Eliminazione (4660)",  c:"#e34948"},
  {n:"Modifica permessi",    c:"#4a3aa7"},
  {n:"Esecuzione",           c:"#e87ba4"},
  {n:"Lettura metadati",     c:"#898781"}
];
const RIGHE = __RIGHE__;
// riga: [epoch, idxUtente, idxAzione, percorso, idxProcesso, conteggio]

const PER_PAGINA = 100;
let filtrate = RIGHE, pagina = 1, ordCol = 0, ordAsc = false;

const $ = id => document.getElementById(id);
const fmtN = n => n.toLocaleString("it-IT");
const fmtData = ts => {
  const d = new Date(ts*1000);
  return d.toLocaleDateString("it-IT") + " " +
         d.toLocaleTimeString("it-IT", {hour:"2-digit", minute:"2-digit", second:"2-digit"});
};

document.title = "Report auditing file - " + META.file;
$("sottotitolo").textContent = "File: " + META.file + " · periodo: " + META.dal + " – " + META.al +
  " · " + fmtN(META.eventiTotali) + " eventi analizzati · generato il " + META.generato;
$("pie").textContent = "Righe raggruppate per utente + percorso + azione + minuto · " + META.note;

// popola i menu
const selU = $("f-utente");
UTENTI.map((u,i)=>[u,i]).sort((a,b)=>a[0].localeCompare(b[0])).forEach(([u,i])=>{
  const o = document.createElement("option"); o.value = i; o.textContent = u; selU.appendChild(o);
});
const selA = $("f-azione");
AZIONI.forEach((a,i)=>{
  if (RIGHE.some(r=>r[2]===i)) {
    const o = document.createElement("option"); o.value = i; o.textContent = a.n; selA.appendChild(o);
  }
});

function applicaFiltri(){
  const q = $("f-q").value.trim().toLowerCase();
  const fu = $("f-utente").value, fa = $("f-azione").value;
  const dal = $("f-dal").value ? new Date($("f-dal").value).getTime()/1000 : null;
  const al  = $("f-al").value  ? new Date($("f-al").value).getTime()/1000  : null;
  filtrate = RIGHE.filter(r=>{
    if (fu !== "" && r[1] !== +fu) return false;
    if (fa !== "" && r[2] !== +fa) return false;
    if (dal !== null && r[0] < dal) return false;
    if (al  !== null && r[0] > al)  return false;
    if (q && !(r[3].toLowerCase().includes(q) ||
               UTENTI[r[1]].toLowerCase().includes(q) ||
               PROCESSI[r[4]].toLowerCase().includes(q))) return false;
    return true;
  });
  ordina();
  pagina = 1;
  render();
}

function ordina(){
  const c = ordCol, asc = ordAsc ? 1 : -1;
  const chiave = r => c===1 ? UTENTI[r[1]] : c===2 ? AZIONI[r[2]].n : c===4 ? PROCESSI[r[4]] : r[c];
  filtrate.sort((a,b)=>{
    const x = chiave(a), y = chiave(b);
    return (x<y ? -1 : x>y ? 1 : 0) * asc;
  });
}

function render(){
  // KPI
  let tot=0, scritture=0, elim=0;
  const fileSet = new Set(), utentiSet = new Set();
  for (const r of filtrate){
    tot += r[5]; fileSet.add(r[3]); utentiSet.add(r[1]);
    if (r[2]===1 || r[2]===3) scritture += r[5];
    if (r[2]===2 || r[2]===4) elim += r[5];
  }
  $("kpis").innerHTML =
    kpi("Operazioni", tot) + kpi("File coinvolti", fileSet.size) +
    kpi("Utenti", utentiSet.size) + kpi("Scritture / modifiche", scritture) +
    kpi("Eliminazioni / rinomine", elim);
  $("conteggio").textContent = fmtN(filtrate.length) + " righe";

  renderChart();
  renderTabella();
}
const kpi = (l,v)=>'<div class="kpi"><div class="lbl">'+l+'</div><div class="val">'+fmtN(v)+'</div></div>';

function renderChart(){
  const chart = $("chart"), xl = $("xlabels");
  chart.innerHTML = ""; xl.innerHTML = "";
  if (!filtrate.length){ $("chart-sub").textContent = "Nessun dato"; return; }
  let min = Infinity, max = -Infinity;
  for (const r of filtrate){ if (r[0]<min) min=r[0]; if (r[0]>max) max=r[0]; }
  const oraria = (max-min) <= 72*3600;
  const passo = oraria ? 3600 : 86400;
  $("chart-sub").textContent = oraria ? "Totale per ora · clic su una barra per filtrare quell'ora"
                                      : "Totale per giorno · clic su una barra per filtrare quel giorno";
  const b0 = Math.floor(min/passo)*passo, b1 = Math.floor(max/passo)*passo;
  const nb = (b1-b0)/passo + 1;
  const buckets = new Array(nb).fill(0);
  for (const r of filtrate) buckets[Math.floor((r[0]-b0)/passo)] += r[5];
  const picco = Math.max(...buckets);
  const tip = $("tooltip");
  const etichettaOgni = Math.ceil(nb / 16);
  buckets.forEach((v,i)=>{
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.style.height = (v ? Math.max(2, v/picco*130) : 0) + "px";
    const t0 = b0 + i*passo;
    bar.onmousemove = e => {
      const d = new Date(t0*1000);
      const lbl = oraria
        ? d.toLocaleDateString("it-IT",{day:"2-digit",month:"2-digit"}) + " " + d.toLocaleTimeString("it-IT",{hour:"2-digit"}) + ":00"
        : d.toLocaleDateString("it-IT");
      tip.textContent = lbl + " — " + fmtN(v) + " operazioni";
      tip.style.display = "block";
      tip.style.left = Math.min(e.clientX+12, innerWidth-240) + "px";
      tip.style.top = (e.clientY+14) + "px";
    };
    bar.onmouseleave = ()=> tip.style.display = "none";
    bar.onclick = ()=>{
      const toLocal = ts => { const d = new Date(ts*1000);
        const p = n => String(n).padStart(2,"0");
        return d.getFullYear()+"-"+p(d.getMonth()+1)+"-"+p(d.getDate())+"T"+p(d.getHours())+":"+p(d.getMinutes()); };
      $("f-dal").value = toLocal(t0); $("f-al").value = toLocal(t0+passo-60);
      applicaFiltri();
    };
    chart.appendChild(bar);
    const sp = document.createElement("span");
    if (i % etichettaOgni === 0){
      const d = new Date(t0*1000);
      sp.textContent = oraria ? d.toLocaleTimeString("it-IT",{hour:"2-digit"})+"h"
                              : d.toLocaleDateString("it-IT",{day:"2-digit",month:"2-digit"});
    }
    xl.appendChild(sp);
  });
}

function renderTabella(){
  const corpo = $("corpo");
  const nPag = Math.max(1, Math.ceil(filtrate.length / PER_PAGINA));
  if (pagina > nPag) pagina = nPag;
  const inizio = (pagina-1)*PER_PAGINA;
  const fetta = filtrate.slice(inizio, inizio+PER_PAGINA);
  if (!fetta.length){
    corpo.innerHTML = '<tr><td colspan="6" class="empty">Nessun risultato con i filtri correnti</td></tr>';
  } else {
    corpo.innerHTML = fetta.map(r=>{
      const a = AZIONI[r[2]];
      return '<tr><td class="dt">'+fmtData(r[0])+'</td>'+
        '<td>'+esc(UTENTI[r[1]])+'</td>'+
        '<td><span class="badge"><i style="background:'+a.c+'"></i>'+a.n+'</span></td>'+
        '<td class="path" title="'+esc(r[3])+'">'+esc(r[3])+'</td>'+
        '<td>'+esc(PROCESSI[r[4]])+'</td>'+
        '<td class="n">'+fmtN(r[5])+'</td></tr>';
    }).join("");
  }
  $("pg-info").textContent = "Pagina " + fmtN(pagina) + " di " + fmtN(nPag);
  $("pg-prev").disabled = pagina <= 1;
  $("pg-next").disabled = pagina >= nPag;
}
const esc = s => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

// eventi UI
let debounce;
$("f-q").addEventListener("input", ()=>{ clearTimeout(debounce); debounce = setTimeout(applicaFiltri, 250); });
["f-utente","f-azione","f-dal","f-al"].forEach(id => $(id).addEventListener("change", applicaFiltri));
$("btn-reset").onclick = ()=>{
  ["f-q","f-dal","f-al"].forEach(id=>$(id).value="");
  ["f-utente","f-azione"].forEach(id=>$(id).value="");
  applicaFiltri();
};
$("pg-prev").onclick = ()=>{ pagina--; renderTabella(); };
$("pg-next").onclick = ()=>{ pagina++; renderTabella(); };
document.querySelectorAll("th").forEach(th=>{
  th.onclick = ()=>{
    const c = +th.dataset.c;
    if (ordCol === c) ordAsc = !ordAsc; else { ordCol = c; ordAsc = (c===1||c===2||c===3||c===4); }
    ordina(); pagina = 1; renderTabella();
  };
});
$("btn-csv").onclick = ()=>{
  const testa = "Data e ora;Utente;Azione;Percorso;Processo;N. eventi\r\n";
  const corpo = filtrate.map(r =>
    '"'+fmtData(r[0])+'";"'+UTENTI[r[1]]+'";"'+AZIONI[r[2]].n+'";"'+
    r[3].replace(/"/g,'""')+'";"'+PROCESSI[r[4]]+'";'+r[5]).join("\r\n");
  const blob = new Blob(["﻿"+testa+corpo], {type:"text/csv;charset=utf-8"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "file_audit_filtrato.csv";
  a.click();
  URL.revokeObjectURL(a.href);
};

applicaFiltri();
</script>
</body>
</html>
'@

$html = $template.Replace('__META__', $meta).Replace('__UTENTI__', $jsonUtenti).
    Replace('__PROCESSI__', $jsonProcessi).Replace('__RIGHE__', $jsonRighe)

$PercorsoReport = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $PercorsoReport))
[System.IO.File]::WriteAllText($PercorsoReport, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host ("Report generato: {0} ({1:N1} MB)" -f $PercorsoReport, ((Get-Item $PercorsoReport).Length / 1MB))

# riepilogo a console
$perAzione = @{}
foreach ($r in $ordinate) { $perAzione[[int]$r[2]] = $perAzione[[int]$r[2]] + [int]$r[5] }
$nomiAzioni = 'Lettura','Scrittura/modifica','Eliminazione/rinomina','Modifica attributi','Eliminazione (4660)','Modifica permessi','Esecuzione','Lettura metadati'
Write-Host "`nOperazioni per tipo:"
$perAzione.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
    Write-Host ("  {0,-22} {1,10:N0}" -f $nomiAzioni[$_.Key], $_.Value)
}

if ($ApriReport) { Start-Process $PercorsoReport }
