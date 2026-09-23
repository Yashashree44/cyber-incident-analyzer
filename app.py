# Streamlit dashboard: shows the evidence, timeline, findings, and
# lets you download the report — all in one page.

import streamlit as st
import os
import sys

sys.path.append(os.path.dirname(__file__))

from core.timeline import create_timeline_db, get_timeline
from core.mitre import enrich_event
from core.detections import detect_log_clear_after_recon
from core.evidence import register_evidence
from reports.generator import build_report


st.set_page_config(page_title="Cyber Incident Investigator", layout="wide")

st.title("Cyber Incident Investigation & Evidence Analyzer")
st.caption("Loads evidence, builds a timeline, flags suspicious patterns, and generates a report.")

evidence_folder = "data/evidence"
evidence_files = [f for f in os.listdir(evidence_folder) if f.endswith(".evtx")]

st.header("Evidence")
for filename in evidence_files:
    path = os.path.join(evidence_folder, filename)
    entry = register_evidence(path)
    st.text(f"{filename}  —  SHA-256: {entry['sha256']}")

con = create_timeline_db()
rows = get_timeline(con)

st.header("Summary")
col1, col2 = st.columns(2)
col1.metric("Total events", len(rows))

findings = detect_log_clear_after_recon(rows, window_minutes=30)
col2.metric("Findings", len(findings))

st.header("Findings")
if findings:
    for f in findings:
        st.error(f"[{f['severity']}] {f['description']}")
else:
    st.success("No suspicious patterns detected.")

st.header("Timeline")
table_data = []
for row in rows:
    timestamp, host, event_id, channel, source = row
    enriched = enrich_event({"event_id": event_id})
    table_data.append({
        "Timestamp": timestamp,
        "Host": host,
        "Event ID": event_id,
        "Description": enriched["description"],
        "MITRE Technique": enriched["mitre_technique"] or "-"
    })

st.dataframe(table_data, use_container_width=True)

st.header("Report")
if st.button("Generate HTML Report"):
    build_report()
    st.success("Report generated at data/output/report.html")