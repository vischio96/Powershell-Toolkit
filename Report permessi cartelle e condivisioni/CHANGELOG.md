# Registro revisioni – Report permessi cartelle e condivisioni

Formato basato su [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/). Ogni versione corrisponde al tag `share-permission-report-v<versione>`.

## [1.2] - 2026-11-17

### Modificato
- Rimosso il limite predefinito di 20000 cartelle: vengono analizzate **tutte** le cartelle fino alla profondità impostata con `-Depth`. `-MaxFolders` resta disponibile come limite facoltativo (predefinito 0 = nessun limite).

## [1.1] - 2026-11-17

### Aggiunto
- **Espansione dei gruppi**: per ogni gruppo presente nelle ACL NTFS e nei permessi di condivisione vengono letti gli utenti effettivi:
  - gruppi di dominio interrogando il Domain Controller via LDAP (ADSI, non serve il modulo ActiveDirectory), con appartenenza annidata risolta dal DC e utenti che hanno il gruppo come gruppo primario;
  - gruppi locali del file server (es. `BUILTIN\Administrators`) tramite il provider WinNT, espandendo anche i gruppi di dominio che contengono;
  - membri di altri domini (foreign security principal) risolti tramite Global Catalog quando possibile.
- Nuova sezione **Accessi per utente**: per ogni utente i percorsi e i diritti, con indicazione se l'accesso è diretto o "tramite" un gruppo, stato abilitato/disabilitato e filtri.
- Nuova sezione **Membri dei gruppi**: utenti effettivi, utenti abilitati, gruppi annidati e altri membri di ogni gruppo.
- Colonna "Utenti effettivi" nella vista **Accessi per identità**.
- Rilevazioni: utenti disabilitati che mantengono accessi, gruppi con permessi ma senza utenti.
- Parametri `-SkipGroupExpansion`, `-DomainController`, `-ExpandBroadGroups`.
- Esportazione CSV `Accessi_per_utente.csv` e `Membri_gruppi.csv`.

### Note
- I gruppi "ampi" (Everyone, Authenticated Users, Domain Users, Users, ...) non vengono espansi per impostazione predefinita.
- Se nessun Domain Controller è raggiungibile vengono espansi solo i gruppi locali e le identità di dominio sono indicate come "Non risolto".

## [1.0] - 2026-11-05

### Aggiunto
- Prima versione pubblica.
- Report HTML unico (ricerca, filtri, ordinamento, esportazione CSV) dei permessi NTFS e di condivisione SMB.
- Analisi di percorsi locali/UNC o di tutte le condivisioni di uno o più file server.
- Albero delle cartelle con proprietario e ACE, elenco delle eccezioni (permessi espliciti, ereditarietà disabilitata).
- Rilevazioni: scrittura a gruppi ampi, lettura a Everyone, SID orfani, ACE di negazione, errori di accesso.
- Vista "chi ha accesso a cosa" per identità; controllo opzionale dei file.
