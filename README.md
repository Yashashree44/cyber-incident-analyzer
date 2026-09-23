# Cyber Incident Investigation & Evidence Analyzer

A digital forensics and incident response (DFIR) tool that parses Windows event logs, builds a unified investigation timeline, automatically detects suspicious attack patterns, and generates a formatted incident report — with hash-verified chain of custody for every piece of evidence.

## Why this project

Real incident response involves collecting scattered evidence (event logs, network captures, etc.), reconstructing a timeline of what happened, spotting attacker behavior, and writing it all up in a report. This tool automates that workflow end-to-end for Windows Event Log (EVTX) evidence.

## Features

- **Evidence intake with chain of custody** — every evidence file is SHA-256 hashed on intake; re-running intake detects if a file has been modified since it was first registered
- **EVTX parsing** — extracts structured events (timestamp, host, event ID, channel) from raw Windows Event Log files
- **Unified timeline** — all events from multiple evidence files are merged and sorted chronologically in a DuckDB database
- **MITRE ATT&CK mapping** — known event IDs are mapped to human-readable descriptions and their corresponding MITRE ATT&CK technique
- **Detection engine** — flags suspicious patterns automatically; current rule detects reconnaissance activity (group/share enumeration) followed by an audit log clear on the same host, a classic anti-forensics pattern
- **Automated reporting** — generates a formatted HTML report with a summary, highlighted findings, and the full timeline
- **Interactive dashboard** — Streamlit UI to browse evidence, findings, and the timeline, and to generate reports on demand

## Tech stack

Python, DuckDB, Jinja2, Streamlit, [python-evtx](https://github.com/omerbenamram/evtx)

## Architecture
Evidence (.evtx files)
|
v
Evidence Intake -> SHA-256 hash + chain of custody log
|
v
EVTX Parser -> structured events (timestamp, host, event ID, channel)
|
v
Timeline Builder (DuckDB) -> all events merged, sorted by time
|
v
MITRE Mapping -> readable description + ATT&CK technique per event
|
v
Detection Engine -> flags suspicious patterns (e.g. recon + log clear)
|
v
Report Generator / Streamlit Dashboard -> findings + timeline, HTML report

## Project structure
core/ - timeline, MITRE mapping, detections, evidence/chain of custody
parsers/ - EVTX parser (syslog and PCAP parsers planned)
reports/ - HTML report template and generator
data/
evidence/ - sample evidence files (not committed - see below)
working/ - DuckDB database, chain of custody log (generated)
output/ - generated reports (generated)
app.py - Streamlit dashboard


## Sample data

This project is tested using public DFIR sample evidence from the [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) repository, which contains real Windows Event Logs captured during simulated attacks. These are used purely for demonstration and are not included in this repo — download them from the source above and place `.evtx` files in `data/evidence/`.

**Note:** the sample files used come from different simulated environments/years, so the demo timeline mixes unrelated hosts. This is expected for a demo using public samples; in a real engagement, all evidence would come from the same incident.

## Setup

```bash
git clone https://github.com/Yashashree44/cyber-incident-analyzer.git
cd cyber-incident-analyzer
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Add `.evtx` sample files to `data/evidence/`, then:

```bash
# build the timeline from evidence
python core\timeline.py

# run detections
python core\detections.py

# generate an HTML report
python reports\generator.py

# or launch the interactive dashboard
streamlit run app.py
```

## Example finding

> **[High]** 9 recon event(s) on WIN-77LTAPHIQ1R.example.corp were followed by a log clear within 30 minutes — possible anti-forensic activity
>
> Mapped to MITRE ATT&CK: T1069.001 (Permission Groups Discovery), T1135 (Network Share Discovery), T1070.001 (Indicator Removal: Clear Windows Event Logs)

## Roadmap

- [ ] Syslog / auth.log parser
- [ ] PCAP parser
- [ ] IOC extraction (IPs, hashes, domains)
- [ ] Additional detection rules

## Disclaimer

This project is for educational and portfolio purposes. It is designed to analyze evidence you own or have explicit authorization to investigate.