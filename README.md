# SSH Sentinel – Mini-SIEM für SSH-Logs

SSH Sentinel ist eine kleine FastAPI-Webanwendung für eine Cyber-Security-Modularbeit. Sie analysiert hochgeladene OpenSSH-Logs oder überwacht eine lokale Logdatei fortlaufend. Erkannte Events und zeitbasierte Brute-Force-Alarme werden lokal in SQLite gespeichert und im Dashboard angezeigt.

> Die Anwendung ist eine nachvollziehbare Demo-Analyse. Sie ersetzt weder ein produktives SIEM noch Intrusion-Detection- oder andere Sicherheitswerkzeuge.

## Funktionsumfang

- Drag-and-drop oder Dateiauswahl für UTF-8-Dateien mit `.log` oder `.txt` (maximal 2 MB)
- Parser für fehlgeschlagene und erfolgreiche SSH-Anmeldungen sowie ungültige Benutzernamen
- Unterstützung für IPv4, IPv6, Syslog- und ISO-Zeitstempel
- regelbasierte Erkennung verdächtiger IP-Adressen und Benutzernamen
- Risiko-Score von 0 bis 100 mit detaillierter Punkteaufschlüsselung
- markierte Originalzeilen inklusive Markierungsgrund
- HTML-Oberfläche und JSON-API mit derselben Analyse-Logik
- polling-basierte Live-Ingestion mit Rotation- und Truncation-Erkennung
- persistente Events, Brute-Force-Alarme, Status und Untersuchungsnotizen
- Live-Dashboard mit Betriebsstatus und Aktualisierung im Vier-Sekunden-Takt
- einheitlicher Start von Webanwendung und Logüberwachung
- Beispieldateien und automatisierte Tests
- eigenständiger PyInstaller-Build für Linux und Windows
- lokaler Launcher mit automatischem Browserstart und Portprüfung

## Schnellstart unter Linux

```bash
git clone https://github.com/ribpaulo/ssh-sentinel-live.git
cd ssh-sentinel-live

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python launcher.py
```

Anschliessend ist SSH Sentinel unter `http://127.0.0.1:8000` erreichbar.

## Projektstruktur

```text
ssh-sentinel-live/
├── main.py                     # Einstiegspunkt und FastAPI-Konfiguration
├── launcher.py                 # Startet den bisherigen lokalen Upload-/Dashboard-Modus
├── run_live.py                 # Einheitlicher Start von Webserver und Live-Ingestion
├── live_ingest.py              # Separater Kommandozeilenstart der Live-Ingestion
├── live_ingestion.py           # Parser-Anbindung und persistente Event-Ingestion
├── file_tailer.py              # Polling-Tailer für Append, Truncation und Rotation
├── brute_force_detection.py    # Zeitbasierte Live-Detection
├── database.py                 # SQLite-Schema und parametrisierte Datenzugriffe
├── runtime_status.py           # Thread-sicherer Status des integrierten Live-Betriebs
├── routes.py                   # HTML-Routen, JSON-API und Upload-Validierung
├── service.py                  # Verbindet Parser, Detektor und Scoring
├── parser.py                   # Wandelt SSH-Logzeilen in strukturierte Events um
├── detector.py                 # Erkennungsregeln und definierte Schwellenwerte
├── scorer.py                   # Berechnet Risiko-Score und Risiko-Level
├── ssh-sentinel.spec           # Gemeinsame PyInstaller-Konfiguration für Linux und Windows
│
├── models/
│   ├── __init__.py             # Exportiert die verwendeten Datenmodelle
│   ├── analysis.py             # Pydantic-Modelle für Upload-Analyse
│   └── dashboard.py            # Pydantic-Modelle der Dashboard-API
│
├── templates/
│   ├── base.html               # Gemeinsames HTML-Grundgerüst
│   ├── index.html              # Startseite mit Datei-Upload
│   ├── result.html             # Darstellung des Analyseergebnisses
│   └── dashboard.html          # Events, Alarme und Betriebsstatus
│
├── static/
│   ├── style.css               # Responsives Design der Weboberfläche
│   ├── upload.js               # Drag-and-drop und Browser-Validierung
│   └── dashboard.js            # Sicheres Polling und Alarmverwaltung
│
├── examples/
│   ├── auth_good.log           # Beispiel ohne auffälliges Angriffsmuster
│   ├── auth_short_bad.log      # Kurzes Beispiel mit verdächtigen SSH-Events
│   └── auth_long_bad.log       # Umfangreicheres Angriffsszenario
│
├── tests/
│   ├── test_parser.py          # Tests der unterstützten Logformate
│   ├── test_analysis.py        # Tests der Regeln und Risikoauswertung
│   ├── test_api.py             # Tests der HTML-Seiten und JSON-API
│   └── test_launcher.py        # Tests für Startparameter und Portprüfung
│
├── scripts/
│   ├── build_linux.sh          # Erstellt das Linux-Executable
│   ├── build_windows.ps1       # Erstellt die Windows-EXE
│   └── demo_brute_force.sh     # Hängt synthetische Demo-Events an
│
├── requirements.txt            # Python-Abhängigkeiten mit festen Versionen
├── README.md                   # Installation, Nutzung und Dokumentation
└── .gitignore                  # Von Git ausgeschlossene lokale Dateien
```

### Architektur und Datenfluss

Die Verantwortlichkeiten sind bewusst getrennt. Eine hochgeladene Datei durchläuft die Anwendung in folgender Reihenfolge:

```text
Browser / JSON-Client
        │
        ▼
routes.py      Datei empfangen und validieren
        │
        ▼
service.py     Analyse koordinieren
        │
        ├── parser.py      Logzeilen in SSH-Events umwandeln
        ├── detector.py    verdächtige Muster erkennen
        └── scorer.py      Risiko-Score berechnen
        │
        ▼
AnalysisResult
        │
        ├── result.html    Ausgabe als Ergebnisseite
        └── FastAPI       Ausgabe als JSON
```

Im Live-Betrieb ist die Verarbeitungskette ebenfalls bewusst linear:

```text
Logdatei
  → File-Tailer
  → bestehender Parser
  → SQLite Events
  → Brute-Force-Detection
  → SQLite Alerts
  → FastAPI
  → Dashboard und Alarmverwaltung
```

## Entwicklungsumgebung einrichten

Voraussetzung ist Python 3.10 oder neuer.

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -3.10 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Die Änderung der Execution Policy gilt nur für die aktuelle PowerShell-Sitzung und wird nach dem Schliessen des Fensters nicht dauerhaft übernommen.

## Manueller Upload-Modus

Mit automatischem Browserstart:

```bash
python launcher.py
```

Alternativ als normaler Uvicorn-Entwicklungsserver mit automatischem Reload:

```bash
python -m uvicorn main:app --reload
```

Danach ist die Oberfläche unter [http://127.0.0.1:8000](http://127.0.0.1:8000) erreichbar. Die interaktive FastAPI-Dokumentation liegt unter [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

Optionen des Launchers:

```bash
python launcher.py --port 8001
python launcher.py --no-browser
python launcher.py --help
```

Die Anwendung wird absichtlich nur an `127.0.0.1` gebunden und ist damit standardmässig nicht aus dem Netzwerk erreichbar. Falls Port 8000 bereits belegt ist, beendet sich der Launcher mit einer verständlichen Meldung und schlägt einen anderen Port vor.

## Empfohlener einheitlicher Live-Betrieb

Für Demonstration und lokalen Betrieb startet ein Befehl Dashboard und
Live-Ingestion mit garantiert derselben SQLite-Datenbank:

```bash
python run_live.py --log-file /var/log/auth.log
```

Standardmässig bindet der Server an `127.0.0.1:8000`, liest ab dem aktuellen
Dateiende, pollt alle 0,5 Sekunden und verwendet `data/ssh_sentinel.db`. Der
vollständige Aufruf ist beispielsweise:

```bash
python run_live.py \
  --log-file /tmp/ssh-sentinel-demo.log \
  --database data/ssh_sentinel.db \
  --host 127.0.0.1 \
  --port 8000 \
  --poll-interval 0.5 \
  --brute-force-threshold 5 \
  --brute-force-window 60 \
  --from-start
```

`--poll-interval` und `--brute-force-window` müssen positiv und endlich sein,
der Schwellenwert mindestens 2 und der Port zwischen 1 und 65535 liegen. Die
Logdatei muss beim Start als reguläre, lesbare Datei existieren. `Ctrl+C`
beendet Webserver und Tailer kontrolliert. Der integrierte Start verwendet
absichtlich weder Auto-Reload noch mehrere Worker. `--reload` darf nicht mit
einem eingebetteten Watcher kombiniert werden, weil der Entwicklungsserver
zusätzliche Prozesse und damit eine doppelte Ingestion starten kann.

## Lokale Logdatei fortlaufend einlesen

Der bisherige separate Modus bleibt für Betriebskonzepte erhalten, bei denen
Webserver und Ingestion bewusst getrennte Prozesse sind:

```bash
python live_ingest.py --log-file /var/log/auth.log
```

Standardmässig beginnt die Überwachung am aktuellen Dateiende und speichert nur
neu angehängte, unterstützte SSH-Ereignisse in `data/ssh_sentinel.db`. Für eine
andere Datenbank, ein anderes Polling-Intervall oder das Einlesen vorhandener
Zeilen stehen folgende Optionen bereit:

```bash
python live_ingest.py \
  --log-file examples/auth_short_bad.log \
  --database data/ssh_sentinel.db \
  --poll-interval 0.5 \
  --brute-force-threshold 5 \
  --brute-force-window 60 \
  --from-start
```

Die Überwachung wird mit `Ctrl+C` kontrolliert beendet. Zeitstempel ohne Jahr
werden in der lokalen Systemzeitzone interpretiert und vor dem Speichern nach
UTC umgerechnet.

Die Live-Ingestion aktiviert standardmässig die Regel `SSH_BRUTE_FORCE`. Sie
erzeugt bei mindestens fünf fehlgeschlagenen SSH-Anmeldungen derselben
IP-Adresse innerhalb von 60 Sekunden einen persistenten Alarm und verknüpft die
auslösenden Events. Weitere Fehlversuche eines laufenden Angriffs erweitern den
aktiven Alarm. Der Score beträgt 70 von 100: Wiederholte Authentifizierungsfehler
werden als hohes Risiko bewertet, ohne bereits einen erfolgreichen Zugriff zu
unterstellen. Schwellenwert und Fenster können mit `--brute-force-threshold`
beziehungsweise `--brute-force-window` angepasst werden.

## Live-Dashboard

Das Live-Dashboard ist nach dem Start der FastAPI-Anwendung unter
[http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) erreichbar.
Es zeigt die zuletzt gespeicherten SSH-Events, persistente Brute-Force-Alarme
und die mit einem Alarm verknüpften Events. Die Daten werden im sichtbaren
Browserfenster ungefähr alle vier Sekunden aktualisiert.

Die Alarmliste kann nach `OPEN`, `ACKNOWLEDGED`, `FALSE_POSITIVE` und `CLOSED`
gefiltert werden. Im Alarmdialog lassen sich Status und eine optionale
Untersuchungsnotiz bearbeiten:

- `OPEN`: neuer oder weiterhin unbehandelter Alarm
- `ACKNOWLEDGED`: Alarm wurde zur Kenntnis genommen und wird untersucht
- `FALSE_POSITIVE`: Aktivität wurde als Fehlalarm bewertet
- `CLOSED`: Untersuchung ist abgeschlossen

`OPEN` und `ACKNOWLEDGED` gelten für die Live-Detection weiterhin als aktiv und
können durch neue passende Events erweitert werden. `FALSE_POSITIVE` und
`CLOSED` werden nicht mehr erweitert. Gespeicherte Untersuchungsnotizen bleiben
bei einer späteren Erweiterung erhalten.

Standardmässig liest das Dashboard `data/ssh_sentinel.db`. Ein anderer Pfad kann
für die Web-Anwendung über die Umgebungsvariable `SSH_SENTINEL_DATABASE`
konfiguriert werden:

```bash
SSH_SENTINEL_DATABASE=/tmp/ssh_sentinel.db python -m uvicorn main:app --reload
```

Beim normalen `launcher.py`- oder `main:app`-Start ist die integrierte
Live-Ingestion inaktiv. Soll sie als separater Prozess laufen, muss dort derselbe
Datenbankpfad angegeben werden:

```bash
python live_ingest.py --log-file /var/log/auth.log --database /tmp/ssh_sentinel.db
```

Das Dashboard zeigt zusätzlich, ob die integrierte Überwachung aktiv, inaktiv
oder fehlgeschlagen ist. Der read-only Endpunkt `GET /api/system/status` liefert
dieselben knappen Betriebsinformationen ohne Datenbankpfad, Stacktrace oder
interne Fehlerdetails. Die stabile JSON-Antwort enthält
`database_ready`, `live_ingestion`, `log_file`, `started_at`,
`last_event_id`, `last_event_at` und `last_error`.

## Reproduzierbare Brute-Force-Demo

Die Demo verwendet ausschliesslich synthetische Logzeilen und führt weder
Loginversuche noch Netzwerkaktionen aus:

```bash
touch /tmp/ssh-sentinel-demo.log
python run_live.py --log-file /tmp/ssh-sentinel-demo.log
```

In einem zweiten Terminal werden sechs Fehlversuche von der reservierten
Dokumentations-IP `203.0.113.50` angehängt:

```bash
scripts/demo_brute_force.sh /tmp/ssh-sentinel-demo.log
```

Das Skript überschreibt keine vorhandenen Inhalte. Beim fünften Event entsteht
mit den Standardwerten ein Alarm; das sechste Event erweitert ihn. Das Ergebnis
ist unter [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
sichtbar.

## Eigenständige ausführbare Datei erstellen

Die Anwendung wird mit PyInstaller als einzelne ausführbare Datei verpackt. Für die Ausführung des mit PyInstaller erstellten Programms ist auf dem Zielsystem keine separate Python-Installation und keine manuelle Installation der in requirements.txt aufgeführten Python-Pakete erforderlich. Die Jinja2-Templates, das CSS und das Drag-and-drop-JavaScript sind im Executable enthalten.

Das Programm bleibt technisch eine lokale Webanwendung: Beim Start wird im Hintergrund ein lokaler FastAPI-Server geöffnet und anschliessend die Oberfläche im Standardbrowser angezeigt.

### Linux-Build

Der Build muss auf einem Linux-System erstellt werden:

```bash
source .venv/bin/activate
python -m pytest -q
chmod +x scripts/build_linux.sh
./scripts/build_linux.sh
```

Das Ergebnis befindet sich danach hier:

```text
dist/ssh-sentinel
```

Starten:

```bash
./dist/ssh-sentinel
```

Falls die Ausführungsberechtigung beim Kopieren verloren gegangen ist:

```bash
chmod +x dist/ssh-sentinel
```

### Windows-Build

Der Windows-Build muss unter Windows ausgeführt werden. In PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest -q
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
```

Das Ergebnis befindet sich danach hier:

```text
dist\ssh-sentinel.exe
```

Starten:

```powershell
.\dist\ssh-sentinel.exe
```

Die EXE kann auch per Doppelklick gestartet werden. Zum Beenden wird im Konsolenfenster `Ctrl+C` gedrückt oder das Fenster geschlossen.

### Optionen des fertigen Programms

Linux:

```bash
./dist/ssh-sentinel --port 8001
./dist/ssh-sentinel --no-browser
```

Windows:

```powershell
.\dist\ssh-sentinel.exe --port 8001
.\dist\ssh-sentinel.exe --no-browser
```

### Wichtiger Hinweis zum Betriebssystem

PyInstaller ist kein Cross-Compiler. Die ausführbare Datei muss auf dem Zielbetriebssystem gebaut werden:

| Build-System | Ergebnis |
|---|---|
| Linux | `ssh-sentinel` für Linux |
| Windows | `ssh-sentinel.exe` für Windows |

Ein unter Linux erstelltes Programm kann nicht direkt unter Windows ausgeführt werden und umgekehrt. Für beide Varianten werden daher derselbe `ssh-sentinel.spec` und zwei betriebssystemspezifische Build-Skripte bereitgestellt.

Die Verzeichnisse `build/` und `dist/` werden automatisch erzeugt und sind in `.gitignore` eingetragen. Sie können jederzeit gelöscht und durch einen neuen Build wiederhergestellt werden.

## Beispieldateien

Zum Ausprobieren stehen drei Dateien zur Verfügung:

- `examples/auth_good.log` für eine weitgehend unauffällige Analyse
- `examples/auth_short_bad.log` für ein kurzes Angriffsszenario
- `examples/auth_long_bad.log` für eine umfangreichere verdächtige Aktivität

## JSON-API

`POST /api/analyze` erwartet die Datei als Multipart-Feld `log_file`:

```bash
curl -X POST \
  -F "log_file=@examples/auth_short_bad.log" \
  http://127.0.0.1:8000/api/analyze
```

Ein Health-Check steht unter `GET /api/health`, der Betriebsstatus unter
`GET /api/system/status` zur Verfügung.

## Erkennungsregeln und Punkte

Die manuelle Upload-Analyse betrachtet alle erkannten Ereignisse innerhalb einer
hochgeladenen Datei. Sie bleibt bewusst von der persistenten Live-Detection
getrennt. Für Live-Events wertet `SSH_BRUTE_FORCE` mindestens fünf
`failed_login`-Events derselben IP innerhalb eines inklusiven 60-Sekunden-
Fensters aus. Der Alarm hat Severity `HIGH` und einen dokumentierten Score von
70/100. Schwellenwert und Fenster sind über die Live-CLI konfigurierbar.

| Regel | Auslösung | Punkte pro Treffer |
|---|---|---:|
| Mehrfache Fehlversuche je IP | mindestens 5 fehlgeschlagene Logins | 25 Basis + 2 je weiterem Fehler, maximal 40 |
| Hohes Volumen je IP | mindestens 10 Login-Events | 15 Basis + 1 je weiterem Event, maximal 25 |
| Häufig angegriffener Benutzer | mindestens 6 Login-Events für ein Konto | 15 Basis + 2 je weiterem Event, maximal 25 |
| Erfolg nach Fehlversuchen | erfolgreicher Login nach mindestens 3 Fehlern derselben IP | 30 je Sequenz |

Die Punkte aller Treffer werden addiert. Der ausgegebene Gesamtscore wird bei 100 begrenzt. Die Aufschlüsselung zeigt die ungekürzten Beiträge der Regeln, damit die Bewertung überprüfbar bleibt.

| Gesamtscore | Risiko-Level |
|---:|---|
| 0–19 | NIEDRIG |
| 20–49 | MITTEL |
| 50–74 | HOCH |
| 75–100 | KRITISCH |

Hinweis: Die verwendeten Schwellenwerte und Risikopunkte sind Heuristiken für diese Demonstrationsanwendung und entsprechen keinem offiziellen Cybersecurity- oder SIEM-Standard.

Der Alarmstatus ist aktiv, sobald mindestens eine Regel ausgelöst wurde. Deshalb kann ein einzelner Regel-Treffer mit weniger als 20 Punkten bereits einen Alarm bei niedrigem Gesamtrisiko erzeugen.

### Erfolgreicher Login nach Fehlversuchen

Diese Regel verfolgt die Ereignisse jeder IP in Dateireihenfolge. Sobald nach drei oder mehr fehlgeschlagenen Versuchen ein erfolgreicher Login derselben IP folgt, werden die Fehler und der Erfolg gemeinsam markiert. Nach dem Erfolg beginnt für diese IP eine neue Sequenz. Das ist bewusst eine einfache Korrelation für Demonstrationszwecke.

## Unterstützte Logmuster

Beispiele:

```text
Jul 31 09:12:10 host sshd[1110]: Failed password for invalid user admin from 203.0.113.45 port 41101 ssh2
Jul 31 09:12:20 host sshd[1111]: Accepted publickey for deploy from 2001:db8::10 port 41102 ssh2
Jul 31 09:12:30 host sshd[1112]: Invalid user test from 198.51.100.77 port 50201
2026-07-31T09:12:40+02:00 host sshd[1113]: Failed password for root from 198.51.100.22 port 50202 ssh2
```

Nicht erkannte Zeilen bleiben unberücksichtigt, zählen aber in der Anzeige der gesamten Dateizeilen mit.

## Tests

```bash
python -m pytest -q
```

Die Tests decken Parser, Upload-Analyse, Persistenz, File-Tailer, Live-Ingestion,
Detection, Alarmverwaltung, Dashboard, Betriebsstatus, Start-/Stop-Lebenszyklus
und das synthetische Demo-Skript ab.

## Datenschutz und lokale Datenhaltung

Events, rohe erkannte Logzeilen, Alarmnotizen und Zuordnungen liegen in der
lokalen SQLite-Datei. Sie werden nicht an externe Dienste übertragen. Betreiber
sind selbst dafür verantwortlich, Dateirechte, Aufbewahrung und Löschung an die
Schutzbedürftigkeit ihrer Logdaten anzupassen. Datenbankdateien unter `data/`
werden von Git ausgeschlossen.

## Sicherheitsgrenzen und bekannte Limitationen

- Das lokale Dashboard besitzt keine Authentifizierung oder Rollenverwaltung.
  Es sollte nicht ungeschützt an eine öffentliche Netzwerkschnittstelle gebunden
  werden.
- Die Anwendung ist kein vollständiger produktiver SIEM-Ersatz. Es fehlen unter
  anderem zentrale Logübertragung, Hochverfügbarkeit, Benachrichtigungen,
  Mandantentrennung und manipulationssichere Langzeitarchivierung.
- Der Tailer speichert keinen dauerhaften Offset. Nach einem Prozessneustart
  beginnt er standardmässig am aktuellen Dateiende; `--from-start` importiert
  die gesamte vorhandene Datei bewusst erneut.
- SQLite passt zum lokalen Demo-Betrieb, ist aber nicht für hohe parallele
  Schreibraten oder verteilte Instanzen ausgelegt.
- Syslog-Zeitstempel ohne Jahr und Zeitzone werden anhand der lokalen
  Systemzeitzone und einer Jahreswechsel-Heuristik normalisiert.
- Ein Fehler im Hintergrundthread wird sichtbar gemeldet und im Dashboard als
  Fehlerstatus angezeigt; ein automatischer Neustart des Tailers ist nicht Teil
  dieses Projekts.

Parser, Detektor und Scorer sind absichtlich getrennt. Eine neue Logsyntax wird in `parser.py`, eine neue Regel in `detector.py` und eine andere Klassifizierung in `scorer.py` ergänzt, ohne die Webrouten ändern zu müssen.
