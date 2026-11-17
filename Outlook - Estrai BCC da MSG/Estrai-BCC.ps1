<#
.SYNOPSIS
    Estrae i destinatari in copia nascosta (BCC / CCN) da uno o piu' file .msg di Outlook
    e li esporta in CSV, con interfaccia grafica.

.DESCRIPTION
    Apre una finestra in cui:
      1. si caricano i file .msg (pulsanti "Aggiungi file" / "Aggiungi cartella" oppure
         trascinando file e cartelle nella finestra);
      2. si sceglie il percorso del file CSV da generare;
      3. con "Estrai ed esporta" i messaggi vengono letti tramite Outlook, i destinatari
         BCC vengono esportati nel CSV e mostrati a video.

    Per ogni destinatario BCC vengono riportati file, oggetto, data, nome e indirizzo
    e-mail (per i destinatari Exchange viene ricavato l'indirizzo SMTP primario).
    Con l'opzione "un indirizzo per riga" gli indirizzi duplicati vengono uniti e viene
    indicato in quanti messaggi compaiono.

    Lo script e' in sola lettura: i file .msg non vengono modificati e nessun messaggio
    viene inviato.

.PARAMETER Path
    File .msg o cartelle da caricare all'avvio (facoltativo).

.PARAMETER OutputCsv
    Percorso del file CSV proposto (predefinito: Documenti\Destinatari_BCC_<data>.csv).

.PARAMETER Recurse
    Con le cartelle indicate in -Path include anche le sottocartelle.

.PARAMETER Univoci
    Esporta un indirizzo per riga, rimuovendo i duplicati.

.PARAMETER NoGui
    Esecuzione senza interfaccia (es. da script pianificato): richiede -Path; il CSV
    viene salvato in -OutputCsv e il risultato mostrato a console.

.EXAMPLE
    .\Estrai-BCC.ps1
    Apre l'interfaccia grafica.

.EXAMPLE
    .\Estrai-BCC.ps1 -Path 'D:\Messaggi' -Recurse
    Apre l'interfaccia con gia' caricati i file .msg della cartella e delle sottocartelle.

.EXAMPLE
    .\Estrai-BCC.ps1 -Path 'D:\Messaggi' -OutputCsv 'D:\Export\BCC.csv' -Univoci -NoGui
    Esecuzione senza interfaccia.
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string]$OutputCsv,
    [switch]$Recurse,
    [switch]$Univoci,
    [switch]$NoGui
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0'

# Costanti Outlook
$OL_BCC         = 3   # OlMailRecipientType.olBCC
$OL_DISCARD     = 1   # OlInspectorClose.olDiscard
$PR_SMTP_ADDRESS = 'http://schemas.microsoft.com/mapi/proptag/0x39FE001E'

# ---------------------------------------------------------------------------
# Funzioni di elaborazione
# ---------------------------------------------------------------------------
function Get-MsgFileList {
    <# Espande file e cartelle in un elenco univoco di file .msg #>
    param([string[]]$Path, [switch]$Recurse)
    $set = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Path) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $p = $p.Trim('"', ' ')
        if (Test-Path -LiteralPath $p -PathType Container) {
            $found = Get-ChildItem -LiteralPath $p -Filter '*.msg' -File -Recurse:$Recurse -ErrorAction SilentlyContinue
            foreach ($f in $found) { if (-not $set.Contains($f.FullName)) { $set.Add($f.FullName) } }
        }
        elseif ((Test-Path -LiteralPath $p -PathType Leaf) -and $p -match '\.msg$') {
            $full = (Resolve-Path -LiteralPath $p).ProviderPath
            if (-not $set.Contains($full)) { $set.Add($full) }
        }
    }
    return $set.ToArray()
}

function Get-RecipientSmtp {
    <# Restituisce l'indirizzo SMTP di un destinatario (anche Exchange) #>
    param($Recipient)
    $addr = [string]$Recipient.Address
    try {
        $entry = $Recipient.AddressEntry
        if ($entry -and $entry.Type -eq 'EX') {
            $exUser = $entry.GetExchangeUser()
            if ($exUser -and $exUser.PrimarySmtpAddress) { return [string]$exUser.PrimarySmtpAddress }
            $exList = $entry.GetExchangeDistributionList()
            if ($exList -and $exList.PrimarySmtpAddress) { return [string]$exList.PrimarySmtpAddress }
        }
    } catch { Write-Verbose "AddressEntry non leggibile: $_" }
    if ($addr -notmatch '@') {
        try {
            $smtp = [string]$Recipient.PropertyAccessor.GetProperty($PR_SMTP_ADDRESS)
            if ($smtp) { return $smtp }
        } catch { Write-Verbose "PR_SMTP_ADDRESS non disponibile: $_" }
    }
    return $addr
}

function Invoke-BccExtraction {
    <#
        Legge i file .msg tramite Outlook e restituisce un oggetto con:
        Rows (destinatari BCC), Errors (file non leggibili), SenzaBcc (n. messaggi senza BCC)
    #>
    param([string[]]$Files, [scriptblock]$OnProgress)

    $rows   = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $senzaBcc = 0

    $giaAperto = [bool](Get-Process -Name OUTLOOK -ErrorAction SilentlyContinue)
    try {
        $outlook   = New-Object -ComObject Outlook.Application
        $namespace = $outlook.GetNamespace('MAPI')
    }
    catch {
        throw "Impossibile avviare Outlook: verificare che Outlook (versione desktop) sia installato e configurato. Dettaglio: $($_.Exception.Message)"
    }

    try {
        $i = 0
        foreach ($file in $Files) {
            $i++
            if ($OnProgress) { & $OnProgress $i $Files.Count ([System.IO.Path]::GetFileName($file)) }
            $mail = $null
            try {
                $mail = $namespace.OpenSharedItem($file)
                $oggetto = [string]$mail.Subject
                $data = $null
                try {
                    $data = [datetime]$mail.SentOn
                    if ($data.Year -ge 4500) { $data = [datetime]$mail.CreationTime }
                } catch { $data = $null }

                $trovati = 0
                $recips = $mail.Recipients
                for ($r = 1; $r -le $recips.Count; $r++) {
                    $rec = $recips.Item($r)
                    if ($rec.Type -eq $OL_BCC) {
                        $trovati++
                        $rows.Add([pscustomobject]@{
                            File    = [System.IO.Path]::GetFileName($file)
                            Oggetto = $oggetto
                            Data    = if ($data) { $data.ToString('dd/MM/yyyy HH:mm') } else { '' }
                            Nome    = [string]$rec.Name
                            Email   = Get-RecipientSmtp $rec
                        })
                    }
                    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($rec)
                }
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($recips)
                if ($trovati -eq 0) { $senzaBcc++ }
            }
            catch {
                $errors.Add("$([System.IO.Path]::GetFileName($file)): $($_.Exception.Message)")
            }
            finally {
                if ($mail) {
                    try { $mail.Close($OL_DISCARD) } catch { Write-Verbose "Close: $_" }
                    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($mail)
                }
            }
        }
    }
    finally {
        if ($namespace) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($namespace) }
        if ($outlook) {
            # chiude Outlook solo se e' stato avviato dallo script
            if (-not $giaAperto) { try { $outlook.Quit() } catch { Write-Verbose "Quit: $_" } }
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook)
        }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }

    return [pscustomobject]@{ Rows = $rows.ToArray(); Errors = $errors.ToArray(); SenzaBcc = $senzaBcc }
}

function ConvertTo-UniqueRecipient {
    <# Un indirizzo per riga, con il numero di messaggi in cui compare #>
    param([object[]]$Rows)
    $Rows | Group-Object { ([string]$_.Email).ToLowerInvariant() } | ForEach-Object {
        $first = $_.Group[0]
        [pscustomobject]@{
            Nome      = $first.Nome
            Email     = $first.Email
            Messaggi  = @($_.Group | Select-Object -ExpandProperty File -Unique).Count
        }
    } | Sort-Object Email
}

function Export-BccCsv {
    param([object[]]$Rows, [string]$Path)
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # UTF-8 con BOM: Excel riconosce correttamente gli accenti
    $enc = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
    $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Delimiter ';' -Encoding $enc
}

function Get-DefaultCsvPath {
    $docs = [Environment]::GetFolderPath('MyDocuments')
    return Join-Path $docs ("Destinatari_BCC_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmm'))
}

# ---------------------------------------------------------------------------
# Interfaccia grafica
# ---------------------------------------------------------------------------
function Show-BccForm {
    param([string[]]$Files, [string]$OutputCsv, [scriptblock]$OnShown)

    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form = New-Object System.Windows.Forms.Form -Property @{
        Text = "Estrai destinatari BCC da file MSG  -  v$ScriptVersion"
        StartPosition = 'CenterScreen'; Font = $font; AllowDrop = $true
        ClientSize = New-Object System.Drawing.Size(920, 680)
        MinimumSize = New-Object System.Drawing.Size(760, 560)
    }

    # --- 1. file MSG ---------------------------------------------------------
    $grpFile = New-Object System.Windows.Forms.GroupBox -Property @{
        Text = '1. File MSG da analizzare'; Location = '12,10'; Size = '896,176'; Anchor = 'Top,Left,Right'
    }
    $lstFile = New-Object System.Windows.Forms.ListBox -Property @{
        Location = '12,24'; Size = '720,118'; Anchor = 'Top,Left,Right'
        SelectionMode = 'MultiExtended'; HorizontalScrollbar = $true; IntegralHeight = $false
    }
    $lblDrop = New-Object System.Windows.Forms.Label -Property @{
        Text = 'Trascina qui file .msg o cartelle, oppure usa i pulsanti a destra.'
        Location = '12,148'; Size = '720,20'; Anchor = 'Top,Left,Right'; ForeColor = [System.Drawing.SystemColors]::GrayText
    }
    $btnAddFile = New-Object System.Windows.Forms.Button -Property @{ Text = 'Aggiungi file...';      Location = '744,24';  Size = '140,28'; Anchor = 'Top,Right' }
    $btnAddDir  = New-Object System.Windows.Forms.Button -Property @{ Text = 'Aggiungi cartella...'; Location = '744,58';  Size = '140,28'; Anchor = 'Top,Right' }
    $btnRemove  = New-Object System.Windows.Forms.Button -Property @{ Text = 'Rimuovi selezionati';  Location = '744,92';  Size = '140,28'; Anchor = 'Top,Right' }
    $btnClear   = New-Object System.Windows.Forms.Button -Property @{ Text = 'Svuota elenco';        Location = '744,126'; Size = '140,28'; Anchor = 'Top,Right' }
    $grpFile.Controls.AddRange(@($lstFile, $lblDrop, $btnAddFile, $btnAddDir, $btnRemove, $btnClear))

    # --- 2. esportazione -----------------------------------------------------
    $grpCsv = New-Object System.Windows.Forms.GroupBox -Property @{
        Text = '2. Esportazione CSV'; Location = '12,194'; Size = '896,92'; Anchor = 'Top,Left,Right'
    }
    $lblCsv = New-Object System.Windows.Forms.Label -Property @{ Text = 'File CSV:'; Location = '12,28'; AutoSize = $true }
    $txtCsv = New-Object System.Windows.Forms.TextBox -Property @{ Location = '80,25'; Size = '556,23'; Anchor = 'Top,Left,Right' }
    $btnBrowse = New-Object System.Windows.Forms.Button -Property @{ Text = 'Sfoglia...'; Location = '644,23'; Size = '92,27'; Anchor = 'Top,Right' }
    $chkUnique = New-Object System.Windows.Forms.CheckBox -Property @{
        Text = 'Un indirizzo per riga (rimuove i duplicati e indica in quanti messaggi compare)'
        Location = '80,56'; Size = '556,24'; Anchor = 'Top,Left,Right'
    }
    $btnRun = New-Object System.Windows.Forms.Button -Property @{
        Text = 'Estrai ed esporta'; Location = '746,22'; Size = '138,58'; Anchor = 'Top,Right'
        Font = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
    }
    $grpCsv.Controls.AddRange(@($lblCsv, $txtCsv, $btnBrowse, $chkUnique, $btnRun))

    # --- avanzamento ---------------------------------------------------------
    $progress = New-Object System.Windows.Forms.ProgressBar -Property @{ Location = '12,296'; Size = '896,16'; Anchor = 'Top,Left,Right' }
    $lblStatus = New-Object System.Windows.Forms.Label -Property @{
        Text = 'Pronto.'; Location = '12,316'; Size = '896,20'; Anchor = 'Top,Left,Right'; AutoEllipsis = $true
    }

    # --- 3. risultati --------------------------------------------------------
    $grpRes = New-Object System.Windows.Forms.GroupBox -Property @{
        Text = '3. Indirizzi BCC trovati'; Location = '12,340'; Size = '896,328'; Anchor = 'Top,Bottom,Left,Right'
    }
    $grid = New-Object System.Windows.Forms.DataGridView -Property @{
        Location = '12,24'; Size = '872,256'; Anchor = 'Top,Bottom,Left,Right'
        ReadOnly = $true; AllowUserToAddRows = $false; AllowUserToDeleteRows = $false
        AutoSizeColumnsMode = 'Fill'; SelectionMode = 'FullRowSelect'; RowHeadersVisible = $false
        BackgroundColor = [System.Drawing.SystemColors]::Window; BorderStyle = 'FixedSingle'
        ClipboardCopyMode = 'EnableAlwaysIncludeHeaderText'
    }
    $btnCopy    = New-Object System.Windows.Forms.Button -Property @{ Text = 'Copia indirizzi'; Location = '12,288';  Size = '130,28'; Anchor = 'Bottom,Left'; Enabled = $false }
    $btnOpenCsv = New-Object System.Windows.Forms.Button -Property @{ Text = 'Apri CSV';        Location = '150,288'; Size = '100,28'; Anchor = 'Bottom,Left'; Enabled = $false }
    $btnOpenDir = New-Object System.Windows.Forms.Button -Property @{ Text = 'Apri cartella';   Location = '258,288'; Size = '110,28'; Anchor = 'Bottom,Left'; Enabled = $false }
    $lblCount = New-Object System.Windows.Forms.Label -Property @{
        Text = ''; Location = '384,294'; Size = '500,20'; Anchor = 'Bottom,Left,Right'; TextAlign = 'MiddleRight'
    }
    $grpRes.Controls.AddRange(@($grid, $btnCopy, $btnOpenCsv, $btnOpenDir, $lblCount))

    $form.Controls.AddRange(@($grpFile, $grpCsv, $progress, $lblStatus, $grpRes))
    $form.AcceptButton = $btnRun

    $script:Ui = @{
        Form = $form; List = $lstFile; Group = $grpFile; Csv = $txtCsv; Unique = $chkUnique; Run = $btnRun
        Progress = $progress; Status = $lblStatus; Grid = $grid; Count = $lblCount
        Copy = $btnCopy; OpenCsv = $btnOpenCsv; OpenDir = $btnOpenDir
        Buttons = @($btnAddFile, $btnAddDir, $btnRemove, $btnClear, $btnBrowse, $btnRun)
        LastCsv = $null; LastRows = @()
    }

    # --- gestori -------------------------------------------------------------
    $script:AddPaths = {
        param([string[]]$Paths, [bool]$Sub)
        $nuovi = @(Get-MsgFileList -Path $Paths -Recurse:$Sub)
        foreach ($f in $nuovi) { if (-not $script:Ui.List.Items.Contains($f)) { [void]$script:Ui.List.Items.Add($f) } }
        $script:Ui.Group.Text = "1. File MSG da analizzare ($($script:Ui.List.Items.Count))"
        if ($Paths.Count -gt 0 -and $nuovi.Count -eq 0) { $script:Ui.Status.Text = 'Nessun file .msg trovato nei percorsi indicati.' }
    }

    $btnAddFile.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title = 'Seleziona i file MSG'; Filter = 'Messaggi Outlook (*.msg)|*.msg|Tutti i file (*.*)|*.*'; Multiselect = $true
        }
        if ($dlg.ShowDialog($script:Ui.Form) -eq 'OK') { & $script:AddPaths $dlg.FileNames $false }
        $dlg.Dispose()
    })
    $btnAddDir.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog -Property @{
            Description = 'Seleziona la cartella con i file MSG'; ShowNewFolderButton = $false
        }
        if ($dlg.ShowDialog($script:Ui.Form) -eq 'OK') {
            $sub = $false
            $hasSub = @(Get-ChildItem -LiteralPath $dlg.SelectedPath -Directory -ErrorAction SilentlyContinue).Count -gt 0
            if ($hasSub) {
                $ans = [System.Windows.Forms.MessageBox]::Show($script:Ui.Form, 'Includere anche le sottocartelle?',
                    'Aggiungi cartella', 'YesNo', 'Question')
                $sub = ($ans -eq 'Yes')
            }
            & $script:AddPaths @($dlg.SelectedPath) $sub
        }
        $dlg.Dispose()
    })
    $btnRemove.Add_Click({
        $sel = @($script:Ui.List.SelectedItems)
        foreach ($s in $sel) { $script:Ui.List.Items.Remove($s) }
        $script:Ui.Group.Text = "1. File MSG da analizzare ($($script:Ui.List.Items.Count))"
    })
    $btnClear.Add_Click({
        $script:Ui.List.Items.Clear()
        $script:Ui.Group.Text = '1. File MSG da analizzare'
    })
    $lstFile.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Delete') { $btnRemove.PerformClick() } })

    $form.Add_DragEnter({
        param($s, $e)
        if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = 'Copy' }
    })
    $form.Add_DragDrop({
        param($s, $e)
        $items = [string[]]$e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
        & $script:AddPaths $items $true
    })

    $btnBrowse.Add_Click({
        $cur = $script:Ui.Csv.Text
        $dlg = New-Object System.Windows.Forms.SaveFileDialog -Property @{
            Title = 'Salva il file CSV'; Filter = 'File CSV (*.csv)|*.csv'; DefaultExt = 'csv'
            AddExtension = $true; OverwritePrompt = $true
            FileName = if ($cur) { [System.IO.Path]::GetFileName($cur) } else { 'Destinatari_BCC.csv' }
        }
        if ($cur) {
            $d = Split-Path -Path $cur -Parent
            if ($d -and (Test-Path -LiteralPath $d)) { $dlg.InitialDirectory = $d }
        }
        if ($dlg.ShowDialog($script:Ui.Form) -eq 'OK') { $script:Ui.Csv.Text = $dlg.FileName }
        $dlg.Dispose()
    })

    $btnRun.Add_Click({
        $ui = $script:Ui
        $files = @($ui.List.Items | ForEach-Object { [string]$_ })
        if ($files.Count -eq 0) {
            [void][System.Windows.Forms.MessageBox]::Show($ui.Form, 'Aggiungi almeno un file .msg.', 'Nessun file', 'OK', 'Warning'); return
        }
        $csv = $ui.Csv.Text.Trim('"', ' ')
        if (-not $csv) {
            [void][System.Windows.Forms.MessageBox]::Show($ui.Form, 'Indica il percorso del file CSV.', 'Percorso mancante', 'OK', 'Warning'); return
        }
        if ($csv -notmatch '\.csv$') { $csv += '.csv' }
        $ui.Csv.Text = $csv

        foreach ($b in $ui.Buttons) { $b.Enabled = $false }
        $ui.Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $ui.Progress.Maximum = $files.Count; $ui.Progress.Value = 0
        try {
            $res = Invoke-BccExtraction -Files $files -OnProgress {
                param($i, $n, $name)
                $script:Ui.Progress.Value = $i
                $script:Ui.Status.Text = "Analisi $i di ${n}: $name"
                [System.Windows.Forms.Application]::DoEvents()
            }
            $rows = @($res.Rows)
            if ($ui.Unique.Checked -and $rows.Count -gt 0) { $rows = @(ConvertTo-UniqueRecipient -Rows $rows) }

            $table = New-Object System.Data.DataTable
            if ($rows.Count -gt 0) {
                foreach ($p in $rows[0].PSObject.Properties.Name) { [void]$table.Columns.Add($p) }
                foreach ($r in $rows) { [void]$table.Rows.Add(@($r.PSObject.Properties.Value)) }
            }
            $ui.Grid.DataSource = $table
            $ui.LastRows = $rows

            $note = @()
            if ($res.SenzaBcc -gt 0) { $note += "messaggi senza BCC: $($res.SenzaBcc)" }
            if ($res.Errors.Count -gt 0) { $note += "file non leggibili: $($res.Errors.Count)" }
            $suffix = if ($note) { ' (' + ($note -join ', ') + ')' } else { '' }

            if ($rows.Count -gt 0) {
                Export-BccCsv -Rows $rows -Path $csv
                $ui.LastCsv = $csv
                $ui.Status.Text = "Esportati $($rows.Count) destinatari in $csv$suffix"
                $nEmail = @($rows | ForEach-Object { ([string]$_.Email).ToLowerInvariant() } | Select-Object -Unique).Count
                $ui.Count.Text = "$($rows.Count) righe - $nEmail indirizzi univoci - $($files.Count) file analizzati"
            } else {
                $ui.LastCsv = $null
                $ui.Status.Text = "Nessun destinatario BCC trovato: CSV non creato$suffix"
                $ui.Count.Text = ''
            }
            $ui.Copy.Enabled = $rows.Count -gt 0
            $ui.OpenCsv.Enabled = [bool]$ui.LastCsv
            $ui.OpenDir.Enabled = [bool]$ui.LastCsv

            if ($res.Errors.Count -gt 0) {
                $msg = "Alcuni file non sono stati letti:`r`n`r`n" + (($res.Errors | Select-Object -First 15) -join "`r`n")
                if ($res.Errors.Count -gt 15) { $msg += "`r`n... e altri $($res.Errors.Count - 15)" }
                [void][System.Windows.Forms.MessageBox]::Show($ui.Form, $msg, 'File non letti', 'OK', 'Warning')
            }
        }
        catch {
            $ui.Status.Text = 'Errore: ' + $_.Exception.Message
            [void][System.Windows.Forms.MessageBox]::Show($ui.Form, $_.Exception.Message, 'Errore', 'OK', 'Error')
        }
        finally {
            foreach ($b in $ui.Buttons) { $b.Enabled = $true }
            $ui.Form.Cursor = [System.Windows.Forms.Cursors]::Default
        }
    })

    $btnCopy.Add_Click({
        $mails = @($script:Ui.LastRows | ForEach-Object { [string]$_.Email } | Select-Object -Unique)
        if ($mails.Count) {
            [System.Windows.Forms.Clipboard]::SetText(($mails -join '; '))
            $script:Ui.Status.Text = "Copiati negli appunti $($mails.Count) indirizzi (separati da ';')."
        }
    })
    $btnOpenCsv.Add_Click({ if ($script:Ui.LastCsv) { Start-Process -FilePath $script:Ui.LastCsv } })
    $btnOpenDir.Add_Click({ if ($script:Ui.LastCsv) { Start-Process -FilePath 'explorer.exe' -ArgumentList "/select,`"$($script:Ui.LastCsv)`"" } })

    # --- valori iniziali -----------------------------------------------------
    $txtCsv.Text = if ($OutputCsv) { $OutputCsv } else { Get-DefaultCsvPath }
    $chkUnique.Checked = [bool]$Univoci
    if ($Files) { & $script:AddPaths $Files $false }
    if ($OnShown) { $form.Add_Shown($OnShown) }

    [void]$form.ShowDialog()
    $form.Dispose()
}

# ---------------------------------------------------------------------------
# Avvio
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -eq '.') { return }   # dot-source: carica solo le funzioni

if ($NoGui) {
    if (-not $Path) { throw 'Con -NoGui indicare i file o le cartelle con -Path.' }
    if (-not $OutputCsv) { $OutputCsv = Get-DefaultCsvPath }
    $files = @(Get-MsgFileList -Path $Path -Recurse:$Recurse)
    if ($files.Count -eq 0) { throw 'Nessun file .msg trovato nei percorsi indicati.' }
    Write-Host "Estrazione BCC v$ScriptVersion - $($files.Count) file"
    $res = Invoke-BccExtraction -Files $files -OnProgress {
        param($i, $n, $name) Write-Host ("[{0}/{1}] {2}" -f $i, $n, $name) -ForegroundColor Cyan
    }
    foreach ($e in $res.Errors) { Write-Warning $e }
    $rows = @($res.Rows)
    if ($Univoci -and $rows.Count) { $rows = @(ConvertTo-UniqueRecipient -Rows $rows) }
    if ($rows.Count -eq 0) { Write-Warning 'Nessun destinatario BCC trovato.'; return }
    Export-BccCsv -Rows $rows -Path $OutputCsv
    $rows | Format-Table -AutoSize | Out-Host
    Write-Host "Esportati $($rows.Count) destinatari in $OutputCsv" -ForegroundColor Green
    return
}

# L'interfaccia grafica richiede un thread STA
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
    $cmd = '& ' + (& $q $PSCommandPath)
    if ($Path)      { $cmd += ' -Path ' + (($Path | ForEach-Object { & $q $_ }) -join ',') }
    if ($OutputCsv) { $cmd += ' -OutputCsv ' + (& $q $OutputCsv) }
    if ($Recurse)   { $cmd += ' -Recurse' }
    if ($Univoci)   { $cmd += ' -Univoci' }
    Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList "-NoProfile -STA -ExecutionPolicy Bypass -Command `"$cmd`""
    return
}

$startFiles = if ($Path) { @(Get-MsgFileList -Path $Path -Recurse:$Recurse) } else { @() }
Show-BccForm -Files $startFiles -OutputCsv $OutputCsv
