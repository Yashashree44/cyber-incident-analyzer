# Fills the HTML report template with real data from the timeline
# and detection findings, and saves it as a file we can open in a browser.

import os
import sys
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from core.timeline import create_timeline_db, get_timeline
from core.mitre import enrich_event
from core.detections import detect_log_clear_after_recon


def build_report(output_path="data/output/report.html"):
    con = create_timeline_db()
    rows = get_timeline(con)

    # enrich every event with its readable description + MITRE mapping
    timeline = []
    for row in rows:
        timestamp, host, event_id, channel, source = row
        enriched = enrich_event({"event_id": event_id})
        timeline.append({
            "timestamp": timestamp,
            "host": host,
            "event_id": event_id,
            "description": enriched["description"],
            "mitre_technique": enriched["mitre_technique"]
        })

    findings = detect_log_clear_after_recon(rows, window_minutes=30)

    evidence_files = sorted(os.listdir("data/evidence"))

    env = Environment(loader=FileSystemLoader("reports/templates"))
    template = env.get_template("report.html")

    html = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_events=len(timeline),
        evidence_files=evidence_files,
        findings=findings,
        timeline=timeline
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report saved to {output_path}")


if __name__ == "__main__":
    build_report()