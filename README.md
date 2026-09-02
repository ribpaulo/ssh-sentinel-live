# SSH Sentinel – Mini-SIEM für SSH-Logs

SSH Sentinel ist eine kleine FastAPI-Webanwendung für eine Cyber-Security-Modularbeit. Sie liest typische OpenSSH-Einträge aus `auth.log`, erkennt einfache verdächtige Muster und zeigt das Ergebnis als übersichtliche HTML-Seite oder als JSON an.

> Die Anwendung ist eine nachvollziehbare Demo-Analyse. Sie ersetzt weder ein produktives SIEM noch Intrusion-Detection- oder andere Sicherheitswerkzeuge.

## Funktionsumfang

- Drag-and-drop oder Dateiauswahl für UTF-8-Dateien mit `.log` oder `.txt` (maximal 2 MB)
- Parser für fehlgeschlagene und erfolgreiche SSH-Anmeldungen sowie ungültige Benutzernamen
- Unterstützung für IPv4, IPv6, Syslog- und ISO-Zeitstempel
- regelbasierte Erkennung verdächtiger IP-Adressen und Benutzernamen
- Risiko-Score von 0 bis 100 mit detaillierter Punkteaufschlüsselung
- markierte Originalzeilen inklusive Markierungsgrund
- HTML-Oberfläche und JSON-API mit derselben Analyse-Logik
- Beispieldateien und automatisierte Tests
- eigenständiger PyInstaller-Build für Linux und Windows
- lokaler Launcher mit automatischem Browserstart und Portprüfung

## Schnellstart unter Linux

```bash
git clone https://github.com/ribpaulo/mini-siem-web-app.git
cd mini-siem-web-app

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python launcher.py
```

Anschliessend ist SSH Sentinel unter `http://127.0.0.1:8000` erreichbar.

## Projektstruktur

```text
mini-siem-web-app/
├── main.py                     # Einstiegspunkt und FastAPI-Konfiguration
├── launcher.py                 # Startet den lokalen Server und Browser
├── routes.py                   # HTML-Routen, JSON-API und Upload-Validierung
├── service.py                  # Verbindet Parser, Detektor und Scoring
├── parser.py                   # Wandelt SSH-Logzeilen in strukturierte Events um
├── detector.py                 # Erkennungsregeln und definierte Schwellenwerte
├── scorer.py                   # Berechnet Risiko-Score und Risiko-Level
├── ssh-sentinel.spec           # Gemeinsame PyInstaller-Konfiguration für Linux und Windows
│
├── models/
│   ├── __init__.py             # Exportiert die verwendeten Datenmodelle
│   └── analysis.py             # Pydantic-Modelle für Events und Ergebnisse
│
├── templates/
│   ├── base.html               # Gemeinsames HTML-Grundgerüst
│   ├── index.html              # Startseite mit Datei-Upload
│   └── result.html             # Darstellung des Analyseergebnisses
│
├── static/
│   ├── style.css               # Responsives Design der Weboberfläche
│   └── upload.js               # Drag-and-drop und Browser-Validierung
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
│   └── build_windows.ps1       # Erstellt die Windows-EXE
│
├── requirements.txt            # Python-Abhängigkeiten mit festen Versionen
├── README.md                   # Installation, Nutzung und Dokumentation
└── .gitignore                  # Von Git ausgeschlossene lokale Dateien
```

### Verarbeitungskette

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

## Anwendung während der Entwicklung starten

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

## Lokale Logdatei fortlaufend einlesen

Die Live-Ingestion läuft bewusst als separater Prozess und verändert den
bestehenden Upload-Ablauf nicht:

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

Ein Health-Check steht unter `GET /api/health` zur Verfügung.

## Erkennungsregeln und Punkte

Die Demo betrachtet alle erkannten Ereignisse innerhalb einer hochgeladenen Datei. Sie besitzt noch kein gleitendes Zeitfenster. Die Schwellenwerte stehen als Konstanten oben in `detector.py` und lassen sich leicht ändern.

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

Die Tests decken Parser-Varianten, die Beispielanalyse, einen unauffälligen Log, HTML- und JSON-Endpunkte sowie den lokalen Launcher ab.

## Erweiterungsmöglichkeiten

- Zeitfenster pro Regel statt dateiweiter Zählung
- zusätzliche Muster wie Port-Scans, ungewöhnliche Uhrzeiten oder Geo-IP-Anreicherung
- persistente Speicherung von Analysen
- Export als CSV/PDF oder Versand von Alarmen
- konfigurierbare Schwellenwerte über Umgebungsvariablen
- Datei-Streaming für grössere Logs

Parser, Detektor und Scorer sind absichtlich getrennt. Eine neue Logsyntax wird in `parser.py`, eine neue Regel in `detector.py` und eine andere Klassifizierung in `scorer.py` ergänzt, ohne die Webrouten ändern zu müssen.
