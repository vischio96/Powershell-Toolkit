# Registro revisioni – Active Directory security report

Formato basato su [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/). Ogni versione corrisponde al tag `ad-security-report-v<versione>`.

## [2.0] - 2026-11-17

### Aggiunto
- **Elevazione automatica**: se la sessione non è amministrativa lo script si riavvia chiedendo l'elevazione UAC (con gli stessi parametri). Parametro `-NoElevation` per disattivarla (sconsigliato).
- **Nuova sezione "Protocolli e hardening"** con controlli per ogni Domain Controller:
  - LDAP: firma obbligatoria (`LDAPServerIntegrity`), channel binding (`LdapEnforceChannelBinding`), client con bind non firmati / in chiaro (evento 2887);
  - LDAPS: test attivo sulla porta 636 (certificato, emittente, scadenza, catena attendibile, protocollo negoziato, accettazione di TLS 1.0 / 1.1);
  - ricerca LDAP anonima (test attivo) e `dSHeuristics`;
  - NTLM / LM: `LmCompatibilityLevel`, `NoLMHash`, `NtlmMinServerSec`, audit e restrizioni NTLM;
  - accesso anonimo: `RestrictAnonymous`, `RestrictAnonymousSAM`, `EveryoneIncludesAnonymous`;
  - SMB: firma obbligatoria, SMBv1, crittografia;
  - SCHANNEL: SSL 3.0, TLS 1.0, TLS 1.1;
  - Kerberos: tipi di crittografia consentiti (RC4 / DES) e crittografia degli account dei DC e di krbtgt;
  - Netlogon: eccezioni Zerologon (`VulnerableChannelAllowList`), `RequireSignOrSeal`, `RequireStrongKey`;
  - protezione credenziali: WDigest, LSA protection (`RunAsPPL`), Credential Guard;
  - Print Spooler sui DC, LLMNR, sorgente oraria dell'emulatore PDC, zone DNS con aggiornamenti dinamici non sicuri.
- Controlli a livello di dominio: principali non standard con diritti **DCSync**, permessi di modifica su radice del dominio e **AdminSDHolder**, password nelle **Group Policy Preferences** (`cpassword`) in SYSVOL.
- **Nuova sezione "Servizi certificati (AD CS)"**: modelli pubblicati vulnerabili a ESC1, ESC2, ESC3, ESC4.
- Utenti con SPN senza crittografia AES (Kerberoasting in RC4).
- Con `-IncludeSecurityEvents`: accessi con autenticazione **NTLMv1** (evento 4624).
- Parametro `-SkipProtocolChecks` per saltare i controlli che leggono registro e servizi dei DC.
- Raccolta della configurazione dei DC via WinRM, con fallback sul Registro remoto e indicazione del metodo usato.

### Corretto
- Errore `Eccezione durante la chiamata di "Add" con "1" argomento/i: "La raccolta è a dimensione fissa"` nella raccolta della struttura OU quando più GPO sono collegate allo stesso contenitore. La stessa causa (array annidati prodotti da `return , $array` dentro `@()`) alterava anche:
  - le GPO risultanti e il conteggio dei collegamenti delle OU con più GPO;
  - il calcolo dell'appartenenza annidata dei gruppi con più gruppi padre (gruppi privilegiati incompleti);
  - l'elenco degli oggetti delle rilevazioni (mostrato come un unico elemento);
  - SIDHistory, deleghe, SPN e "Si applica a" delle FGPP con più valori.
- Errore su PowerShell 7 nel ciclo dei computer (assegnazione alla variabile automatica di sola lettura `$IsWindows`).

### Rimosso
- Analisi dei permessi NTFS / di condivisione delle cartelle (parametri `-FolderPath`, `-FolderDepth`, `-MaxFolders`, `-IncludeInheritedAces`, `-SkipFolderReport` e relativa sezione). Per questa analisi usare lo script **Report permessi cartelle e condivisioni**.

## [1.0] - 2026-11-05

### Aggiunto
- Prima versione pubblica.
- Report HTML unico (ricerca, filtri, ordinamento, esportazione CSV) con rilevazioni classificate per gravità.
- Dominio e foresta, Domain Controller, replica, siti, subnet e trust.
- Password policy, FGPP, criteri Kerberos e criteri di audit applicati ai DC.
- Utenti, account speciali, gruppi privilegiati (membri diretti e annidati), gruppi, computer (SO, supporto, LAPS, BitLocker), deleghe Kerberos, MSA/gMSA/dMSA.
- Albero delle OU con GPO collegate e risultanti; elenco GPO con coerenza SYSVOL.
- Analisi dei permessi NTFS / di condivisione di un percorso.
- (Opzionale) accessi falliti e blocchi letti dai registri Security dei DC.
