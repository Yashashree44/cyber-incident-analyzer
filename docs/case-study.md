# Case Study: Detecting Reconnaissance and Anti-Forensic Activity

## Scenario

This case study demonstrates the investigation workflow using public DFIR sample evidence (Windows Event Logs) representing a host that was reconnoitered by an attacker who then attempted to cover their tracks.

## Evidence Collected

Three Windows Security Event Log (`.evtx`) files were used as evidence:

| File | Description |
|---|---|
| `discovery_psloggedon.evtx` | Logged-on user enumeration activity |
| `discovery_bloodhound.evtx` | BloodHound-style Active Directory enumeration |
| `4799_remote_local_groups_enumeration.evtx` | Remote local group membership enumeration |

Each file was hashed (SHA-256) on intake and logged in a chain-of-custody record before any analysis, so the evidence's integrity could be verified at any later point.

## Investigation Process

1. **Intake** — all three files were registered via the evidence intake module; hashes were recorded.
2. **Parsing** — the EVTX parser extracted 19 structured events across the three files (timestamp, host, event ID, channel).
3. **Timeline construction** — all 19 events were merged into a single chronological timeline in DuckDB, regardless of which file they came from.
4. **Enrichment** — each event ID was mapped to a human-readable description and, where applicable, a MITRE ATT&CK technique.
5. **Detection** — the timeline was run through a detection rule that looks for reconnaissance activity followed by an audit log clear within a 30-minute window on the same host.

## Finding

The detection engine flagged the following:

> **[High]** 9 recon event(s) on `WIN-77LTAPHIQ1R.example.corp` were followed by a log clear within 30 minutes — possible anti-forensic activity

Specifically, the timeline shows:
- Multiple `Event ID 5145` (network share access checks) on the host between 07:00 and 07:02
- An `Event ID 1102` (audit log cleared) at 07:29:57 — roughly 27 minutes after the recon activity

This sequence — enumerate, then clear the log — is a well-documented attacker pattern for covering tracks after reconnaissance, mapped to:
- **T1135** — Network Share Discovery
- **T1069.001** — Permission Groups Discovery: Local Groups
- **T1070.001** — Indicator Removal: Clear Windows Event Logs

## Why This Matters

Log clearing alone is a strong signal, but correlating it with what happened *before* the log was cleared turns a single ambiguous event into a much higher-confidence finding. An analyst manually reviewing thousands of raw events might miss this connection; automating the correlation surfaces it immediately.

## Output

A full HTML report (including the finding above, evidence hashes, and the complete 19-event timeline) is generated automatically and available via the Streamlit dashboard or as a standalone report file.

## Limitations

- The three evidence files originate from different public sample sets (different hosts, different years), so this timeline combines unrelated data for demonstration purposes only. In a real engagement, all evidence would originate from the same incident.
- Currently only Windows Event Logs (EVTX) are supported. Syslog and PCAP parsing are planned but not yet implemented.
- The detection engine currently implements one rule; a production system would include a broader rule set.