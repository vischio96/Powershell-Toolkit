# Registro revisioni – Report auditing file

Formato basato su [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/). Ogni versione corrisponde al tag `file-audit-report-v<versione>`.

## [1.0] - 2026-11-17

### Aggiunto
- Prima versione pubblica.
- Analisi degli eventi 4663 e 4660 da file `.evtx` o dal log Security attivo (con finestra di selezione della sorgente).
- Classificazione delle operazioni in base all'`AccessMask`: lettura, scrittura/modifica, eliminazione/rinomina, modifica attributi, modifica permessi, esecuzione, lettura metadati; risoluzione del percorso degli eventi 4660 tramite `HandleId`.
- Raggruppamento degli eventi identici per utente, percorso, azione, processo e minuto.
- Report HTML autonomo con indicatori, ricerca, filtri per utente/azione/data, timeline cliccabile, tabella ordinabile e paginata, esportazione CSV.
- Parametri `-IncludiMetadati`, `-EscludiLetture`, `-PercorsoReport`, `-ApriReport`.
