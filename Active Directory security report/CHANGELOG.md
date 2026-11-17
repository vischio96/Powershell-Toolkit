# Registro revisioni – Active Directory security report

Formato basato su [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/). Ogni versione corrisponde al tag `ad-security-report-v<versione>`.

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
