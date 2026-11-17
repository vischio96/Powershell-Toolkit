#Requires -Version 7
<#
.SYNOPSIS
    Verifica la coerenza del toolkit e (opzionale) prepara il pacchetto di rilascio di uno script.

.DESCRIPTION
    Per ogni script elencato in toolkit.json controlla che:
      - la cartella contenga lo script, README.md e CHANGELOG.md;
      - lo script non abbia errori di sintassi;
      - la variabile $ScriptVersion sia presente e la versione abbia una sezione "## [x.y]" nel CHANGELOG;
      - (se disponibile) PSScriptAnalyzer non riporti errori.
    Con -Tag (formato "<slug>-v<versione>", es. "ad-security-report-v2.0") verifica inoltre che il tag
    corrisponda alla versione dichiarata nello script e prepara in -OutDir lo zip e le note di rilascio.
#>
[CmdletBinding()]
param(
    [string]$Tag,
    [string]$OutDir = (Join-Path $PWD 'release-out')
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$manifest = Get-Content -LiteralPath (Join-Path $root 'toolkit.json') -Raw | ConvertFrom-Json
$errors = [System.Collections.Generic.List[string]]::new()
$hasAnalyzer = [bool](Get-Module -ListAvailable PSScriptAnalyzer)
$info = @{}

foreach ($s in $manifest.scripts) {
    $dir = Join-Path $root $s.folder
    $ps1 = Join-Path $dir $s.script
    foreach ($f in @($ps1, (Join-Path $dir 'README.md'), (Join-Path $dir 'CHANGELOG.md'))) {
        if (-not (Test-Path -LiteralPath $f)) { $errors.Add("[$($s.slug)] File mancante: $f") }
    }
    if (-not (Test-Path -LiteralPath $ps1)) { continue }

    $tokens = $null; $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($ps1, [ref]$tokens, [ref]$parseErrors)
    foreach ($e in $parseErrors) { $errors.Add("[$($s.slug)] Errore di sintassi riga $($e.Extent.StartLineNumber): $($e.Message)") }

    $m = Select-String -LiteralPath $ps1 -Pattern "^\s*\`$ScriptVersion\s*=\s*'([0-9]+\.[0-9]+(?:\.[0-9]+)?)'" | Select-Object -First 1
    if (-not $m) { $errors.Add("[$($s.slug)] `$ScriptVersion non trovato in $($s.script)"); continue }
    $version = $m.Matches[0].Groups[1].Value

    $changelog = Join-Path $dir 'CHANGELOG.md'
    $notes = $null
    if (Test-Path -LiteralPath $changelog) {
        $text = Get-Content -LiteralPath $changelog -Raw
        $rx = '(?ms)^## \[' + [regex]::Escape($version) + '\][^\n]*\n(.*?)(?=^## \[|\z)'
        $cm = [regex]::Match($text, $rx)
        if (-not $cm.Success) { $errors.Add("[$($s.slug)] Il CHANGELOG non contiene la sezione '## [$version]'") }
        else { $notes = $cm.Groups[1].Value.Trim() }
    }

    if ($hasAnalyzer) {
        $res = @(Invoke-ScriptAnalyzer -Path $ps1 -Severity Error)
        foreach ($r in $res) { $errors.Add("[$($s.slug)] PSScriptAnalyzer $($r.RuleName) riga $($r.Line): $($r.Message)") }
    }

    $info[$s.slug] = [pscustomobject]@{ Slug = $s.slug; Name = $s.name; Folder = $dir; Version = $version; Notes = $notes }
    Write-Host ("OK  {0,-28} v{1}" -f $s.slug, $version)
}

if ($Tag) {
    if ($Tag -notmatch '^(?<slug>[a-z0-9-]+)-v(?<ver>[0-9]+\.[0-9]+(?:\.[0-9]+)?)$') {
        $errors.Add("Tag '$Tag' non valido: formato atteso <slug>-v<versione> (es. ad-security-report-v2.0)")
    } elseif (-not $info.ContainsKey($Matches.slug)) {
        $errors.Add("Tag '$Tag': nessuno script con slug '$($Matches.slug)' in toolkit.json")
    } else {
        $i = $info[$Matches.slug]
        if ($i.Version -ne $Matches.ver) {
            $errors.Add("Tag '$Tag': la versione nel tag ($($Matches.ver)) non coincide con `$ScriptVersion dello script ($($i.Version))")
        } elseif ($errors.Count -eq 0) {
            New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
            $zip = Join-Path $OutDir "$Tag.zip"
            $files = Get-ChildItem -LiteralPath $i.Folder -File | Where-Object { $_.Extension -in '.ps1', '.md' }
            Compress-Archive -LiteralPath $files.FullName -DestinationPath $zip -Force
            $repo = if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { 'OWNER/REPO' }
            $readme = "https://github.com/$repo/blob/$Tag/$([uri]::EscapeDataString([IO.Path]::GetFileName($i.Folder)))/README.md"
            $body = "## $($i.Name) v$($i.Version)`n`n$($i.Notes)`n`nGuida completa: [README]($readme)"
            Set-Content -LiteralPath (Join-Path $OutDir 'notes.md') -Value $body -Encoding utf8
            if ($env:GITHUB_OUTPUT) {
                Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "zip=$zip"
                Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "notes=$(Join-Path $OutDir 'notes.md')"
                Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "title=$($i.Name) v$($i.Version)"
            }
            Write-Host "Pacchetto di rilascio pronto: $zip"
        }
    }
}

if ($errors.Count) {
    $errors | ForEach-Object { Write-Host "::error::$_" }
    throw "Verifica non superata: $($errors.Count) errori."
}
Write-Host 'Verifica completata senza errori.'
