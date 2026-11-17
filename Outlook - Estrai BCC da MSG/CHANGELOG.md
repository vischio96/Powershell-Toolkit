# Registro revisioni – Outlook - Estrai BCC da MSG

Formato basato su [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/). Ogni versione corrisponde al tag `outlook-bcc-extract-v<versione>`.

## [1.0] - 2026-11-17

### Aggiunto
- Prima versione pubblica.
- Interfaccia grafica: caricamento di file `.msg` e cartelle (pulsanti o trascinamento), scelta del percorso del CSV, tabella dei risultati, copia degli indirizzi negli appunti, apertura del CSV e della cartella.
- Estrazione dei destinatari BCC tramite Outlook con file, oggetto, data, nome e indirizzo; indirizzo SMTP primario per i destinatari Exchange.
- Opzione "un indirizzo per riga" (rimozione dei duplicati con numero di messaggi).
- Esportazione CSV (separatore `;`, UTF-8 con BOM).
- Parametri `-Path`, `-Recurse`, `-OutputCsv`, `-Univoci`, `-NoGui` per l'uso da riga di comando.
- Conteggio dei messaggi senza BCC e dei file non leggibili.

### Modificato rispetto allo script originale
- Rimossi cartella e percorso del CSV fissi (`C:\MSG`) e riferimenti personali.
- Outlook viene chiuso al termine solo se è stato avviato dallo script; i messaggi vengono chiusi senza salvare.
