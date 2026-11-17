# Registro revisioni – Report permessi cartelle e condivisioni

Formato basato su [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/). Ogni versione corrisponde al tag `share-permission-report-v<versione>`.

## [1.0] - 2026-11-05

### Aggiunto
- Prima versione pubblica.
- Report HTML unico (ricerca, filtri, ordinamento, esportazione CSV) dei permessi NTFS e di condivisione SMB.
- Analisi di percorsi locali/UNC o di tutte le condivisioni di uno o più file server.
- Albero delle cartelle con proprietario e ACE, elenco delle eccezioni (permessi espliciti, ereditarietà disabilitata).
- Rilevazioni: scrittura a gruppi ampi, lettura a Everyone, SID orfani, ACE di negazione, errori di accesso.
- Vista "chi ha accesso a cosa" per identità; controllo opzionale dei file.
