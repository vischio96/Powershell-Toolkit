# PowerShell Toolkit

Raccolta di script PowerShell per amministratori di sistema Windows / Active Directory.
Ogni script vive nella propria cartella con **guida** (`README.md`), **registro revisioni** (`CHANGELOG.md`) ed eventuali screenshot, e viene versionato e rilasciato in modo indipendente.

## Script disponibili

| Script | Versione | Descrizione |
| --- | --- | --- |
| [Active Directory security report](Active%20Directory%20security%20report/) | 2.0 | Report HTML di sicurezza e inventario di Active Directory: rilevazioni per gravità, utenti, gruppi privilegiati, computer, GPO, hardening dei protocolli sui DC (LDAP/LDAPS, NTLM, SMB, TLS, Kerberos), DCSync, AD CS |
| [Report permessi cartelle e condivisioni](Report%20permessi%20cartelle%20e%20condivisioni/) | 1.2 | Report HTML dei permessi NTFS e SMB con struttura ad albero, rilevazioni e accessi effettivi per utente (gruppi espansi dal Domain Controller) |

Tutti gli script sono **in sola lettura** e producono un report HTML autonomo (apribile offline) con ricerca, filtri, ordinamento ed esportazione CSV.

## Download

Scaricare la versione desiderata dalla pagina [Release](https://github.com/vischio96/Powershell-Toolkit/releases): ogni release contiene lo zip della sola cartella dello script.
Dopo il download può essere necessario sbloccare il file: `Unblock-File .\<script>.ps1`.

## Versioni e rilasci

- Ogni script dichiara la propria versione nella variabile `$ScriptVersion` e la documenta nel proprio `CHANGELOG.md` (sezione `## [x.y] - data`).
- I rilasci usano tag nel formato **`<slug>-v<versione>`**, ad esempio `ad-security-report-v2.0` o `share-permission-report-v1.1`. Gli slug sono definiti in [`toolkit.json`](toolkit.json).
- Al push di un tag, la GitHub Action [Rilascio script](.github/workflows/release.yml) verifica che:
  - lo slug esista in `toolkit.json`;
  - la versione del tag coincida con `$ScriptVersion` nello script;
  - il `CHANGELOG.md` contenga la sezione della versione;
  - lo script non abbia errori di sintassi né errori PSScriptAnalyzer;

  e solo allora pubblica la release con lo zip della cartella e le note prese dal changelog.
- Ad ogni push su `main` la Action [Verifica script](.github/workflows/ci.yml) esegue gli stessi controlli su tutti gli script.

Verifica locale (PowerShell 7):

```powershell
./.github/scripts/Test-Toolkit.ps1                                   # tutti gli script
./.github/scripts/Test-Toolkit.ps1 -Tag ad-security-report-v2.0      # come in fase di rilascio
```

## Aggiungere un nuovo script

1. Creare una cartella con lo script, `README.md` (guida) e `CHANGELOG.md`; eventuali immagini in `screenshots/` (sempre **oscurate**: nessun nome di dominio, server, utente, IP o SID reale).
2. Dichiarare `$ScriptVersion = 'x.y'` nello script.
3. Aggiungere la voce in [`toolkit.json`](toolkit.json) e nella tabella qui sopra.
4. Commit, poi tag e push del tag:

   ```powershell
   git tag -a nuovo-script-v1.0 -m "Nuovo script v1.0"
   git push origin main nuovo-script-v1.0
   ```

   > GitHub non avvia i workflow se si inviano più di 3 tag con un solo push: pubblicare i tag uno alla volta.

## Sicurezza dei dati

I report generati contengono informazioni sensibili sull'infrastruttura e **non devono essere caricati nel repository** (sono esclusi tramite `.gitignore`).
