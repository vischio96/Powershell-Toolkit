# Active Directory security report

Script PowerShell **in sola lettura** che genera un unico report HTML di Active Directory orientato a sicurezza e visibilità: rilevazioni classificate per gravità, inventario completo e verifica dell'hardening dei protocolli sui Domain Controller.

> Versione corrente: **2.0** – [registro revisioni](CHANGELOG.md)

## Contenuto del report

| Sezione | Cosa contiene |
| --- | --- |
| Riepilogo | Conteggi per gravità e indicatori principali (utenti, computer, LAPS, SO non supportati, protocolli, AD CS...) |
| Rilevazioni di sicurezza | Tutti i controlli falliti, con descrizione, raccomandazione ed elenco degli oggetti coinvolti |
| Dominio e foresta | Livelli funzionali, ruoli FSMO, schema, cestino AD, tombstone, MachineAccountQuota, LAPS |
| Domain Controller e replica | DC, SO e supporto, GC/RODC, ruoli FSMO, stato della replica |
| Siti, subnet e trust | Topologia dei siti, GPO di sito, trust e SID filtering |
| Password policy, Kerberos e audit | Default Domain Policy valutata (CIS / Microsoft), FGPP, criteri Kerberos, audit sui DC |
| Utenti | Stato, ultimo logon, tentativi errati, blocco, password, flag di sicurezza, deleghe, SPN, gruppi diretti e annidati |
| Account speciali | Administrator (RID 500), Guest, krbtgt e krbtgt dei RODC |
| Gruppi privilegiati | Membri diretti e annidati dei gruppi amministrativi (individuati per SID, indipendenti dalla lingua) |
| Gruppi / Computer | Inventario completo; per i computer: supporto del SO, LAPS, chiavi BitLocker, deleghe |
| Deleghe Kerberos / MSA | Deleghe non vincolate, vincolate, RBCD; sMSA, gMSA, dMSA |
| Struttura OU e GPO | Albero delle OU con GPO collegate e risultanti (ereditarietà, blocco, imposizione); elenco GPO e coerenza SYSVOL |
| **Protocolli e hardening** | LDAPS, firma LDAP, channel binding, NTLM/LM, SMB, TLS, Kerberos, Netlogon, WDigest, LSA, Spooler, LLMNR, DNS, DCSync, GPP |
| **Servizi certificati (AD CS)** | Modelli pubblicati sulle CA Enterprise e configurazioni ESC1–ESC4 |
| Accessi falliti (opzionale) | Eventi 4625/4771/4776/4740 e accessi NTLMv1 (4624) dai registri Security dei DC |

Tutte le tabelle hanno ricerca, filtri, ordinamento per colonna ed esportazione CSV direttamente dal browser.

### Controlli di protocollo e hardening

Per ogni Domain Controller vengono letti registro, servizi e configurazione (via WinRM, con fallback sul Registro remoto) e confrontati con i valori consigliati:

| Area | Controlli |
| --- | --- |
| LDAP | Firma obbligatoria (`LDAPServerIntegrity` = 2), channel binding (`LdapEnforceChannelBinding` = 2), client con bind non firmati / in chiaro (evento 2887) |
| LDAPS | Test attivo sulla porta 636: certificato, emittente, scadenza, catena attendibile, protocollo negoziato, accettazione di TLS 1.0 / 1.1 |
| Accesso anonimo | Ricerca LDAP anonima (test attivo), `dSHeuristics`, `RestrictAnonymous`, `RestrictAnonymousSAM`, `EveryoneIncludesAnonymous` |
| NTLM / LM | `LmCompatibilityLevel` = 5, `NoLMHash`, `NtlmMinServerSec`, audit e restrizioni NTLM nel dominio |
| SMB | Firma obbligatoria, SMBv1 disabilitato, crittografia |
| TLS | SSL 3.0, TLS 1.0 e TLS 1.1 lato server (SCHANNEL) |
| Kerberos | Tipi di crittografia consentiti (RC4 / DES), crittografia degli account dei DC e di krbtgt, account con SPN senza AES |
| Netlogon | Eccezioni Zerologon (`VulnerableChannelAllowList`), `RequireSignOrSeal`, `RequireStrongKey` |
| Credenziali | WDigest (`UseLogonCredential`), LSA protection (`RunAsPPL`), Credential Guard |
| Servizi / rete | Print Spooler sui DC, LLMNR, sorgente oraria dell'emulatore PDC, zone DNS con aggiornamenti non sicuri |
| Permessi AD | Diritti DCSync a principali non standard, WriteDacl/WriteOwner/controllo completo su radice del dominio e AdminSDHolder |
| GPO | Password nelle Group Policy Preferences (`cpassword`) in SYSVOL |

I valori non configurati vengono interpretati secondo i predefiniti di Windows (indicati nel report).

## Requisiti

- Windows PowerShell 5.1 o PowerShell 7 su Windows.
- Modulo **ActiveDirectory** (RSAT):
  - client: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
  - server: `Install-WindowsFeature RSAT-AD-PowerShell`
- Sessione **elevata** e account con ampi diritti di lettura (es. Domain Admin o account delegato). Se la sessione non è elevata lo script si riavvia chiedendo l'elevazione UAC.
- Per i controlli di protocollo sui DC: **WinRM** raggiungibile (predefinito su Windows Server) oppure servizio **Registro remoto**. In alternativa eseguire lo script direttamente su un DC.
- Per gli eventi (`-IncludeSecurityEvents`): accesso remoto ai registri eventi dei DC (regola firewall "Gestione remota registro eventi").

## Utilizzo

```powershell
# Report completo, apertura automatica al termine
.\Get-ADSecurityReport.ps1 -OpenReport

# Report con esportazione CSV in una cartella specifica
.\Get-ADSecurityReport.ps1 -OutputFolder 'D:\Report' -ExportCsv

# Ultimo logon preciso (interroga tutti i DC) e accessi falliti / NTLMv1 delle ultime 48 ore
.\Get-ADSecurityReport.ps1 -QueryAllDCs -IncludeSecurityEvents -EventHours 48

# Senza controlli che leggono registro e servizi dei DC
.\Get-ADSecurityReport.ps1 -SkipProtocolChecks
```

Se lo script è stato scaricato da Internet potrebbe essere necessario sbloccarlo: `Unblock-File .\Get-ADSecurityReport.ps1`.

### Parametri

| Parametro | Predefinito | Descrizione |
| --- | --- | --- |
| `-OutputFolder` | cartella dello script | Cartella in cui salvare report e CSV |
| `-Server` | emulatore PDC | Domain Controller da interrogare |
| `-SkipProtocolChecks` | – | Salta i controlli che leggono registro e servizi dei DC (i controlli LDAP restano attivi) |
| `-NoElevation` | – | Non richiede l'elevazione UAC (sconsigliato: dati incompleti) |
| `-InactiveDays` | 90 | Giorni senza logon oltre i quali un account è inattivo |
| `-PasswordAgeDays` | 365 | Età della password oltre la quale viene segnalata |
| `-QueryAllDCs` | – | Legge `lastLogon` da tutti i DC per un ultimo logon preciso |
| `-ResolveComputerIP` | – | Risolve via DNS l'IPv4 dei computer |
| `-IncludeSecurityEvents` | – | Legge gli eventi di sicurezza dai DC |
| `-EventHours` | 24 | Finestra temporale degli eventi |
| `-MaxEventsPerDC` | 20000 | Numero massimo di eventi letti per DC e per query |
| `-ExportCsv` | – | Esporta le tabelle principali in CSV (separatore `;`, UTF-8) |
| `-OpenReport` | – | Apre il report al termine |

Guida integrata: `Get-Help .\Get-ADSecurityReport.ps1 -Full`.

## Output

- `AD_Report_<dominio>_<data>.html` – report autonomo (nessuna dipendenza esterna, apribile offline).
- `AD_Report_<dominio>_<data>_csv\` – con `-ExportCsv`.

> Il report contiene informazioni sensibili sul dominio: conservarlo in un percorso protetto e non pubblicarlo.

## Note

- Lo script **non modifica nulla**: esegue solo letture LDAP, letture di registro/servizi sui DC e handshake TLS verso la porta 636.
- **Antivirus**: lo script esegue controlli tipici degli strumenti di audit di Active Directory (DCSync, AD CS, GPP, Kerberoasting...). Alcuni antivirus/EDR, incluso Microsoft Defender tramite AMSI, possono classificarlo come potenzialmente pericoloso e bloccarne l'esecuzione (`Questo script include contenuto dannoso ed è stato bloccato dal software antivirus`). In tal caso verificare l'integrità del file (hash della release) e gestire l'eccezione secondo le policy aziendali.
- Se WinRM e Registro remoto non rispondono, il DC compare nella rilevazione "Domain Controller non interrogabili" e nella tabella "Metodo di raccolta per DC".
- Per individuare i client che usano bind LDAP non firmati abilitare la registrazione diagnostica `16 LDAP Interface Events` = 2 (eventi 2889).

## Revisioni

Vedi [CHANGELOG.md](CHANGELOG.md). Le versioni pubblicate sono disponibili nelle [release](https://github.com/vischio96/Powershell-Toolkit/releases) con tag `ad-security-report-v<versione>`.
