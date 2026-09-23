# Looks at the sorted timeline and flags suspicious patterns.
# Right now it checks for one classic pattern: enumeration activity
# happening close to a log-clearing event (possible anti-forensics).

from datetime import timedelta

# event IDs we treat as "recon" / enumeration activity
RECON_EVENT_IDS = {"4799", "5145"}

# event ID for clearing the audit log
LOG_CLEAR_EVENT_ID = "1102"


def detect_log_clear_after_recon(timeline_rows, window_minutes=10):
    """
    timeline_rows: list of tuples (timestamp, host, event_id, channel, source),
    already sorted by timestamp — this is what get_timeline() returns.

    Flags any log-clear event that happened within `window_minutes`
    of recon activity on the same host.
    """
    findings = []

    for i, row in enumerate(timeline_rows):
        timestamp, host, event_id, channel, source = row

        if event_id != LOG_CLEAR_EVENT_ID:
            continue

        window_start = timestamp - timedelta(minutes=window_minutes)

        # look backwards for recon events on the same host, within the window
        recon_before = [
            r for r in timeline_rows[:i]
            if r[1] == host
            and r[2] in RECON_EVENT_IDS
            and r[0] >= window_start
        ]

        if recon_before:
            findings.append({
                "host": host,
                "log_clear_time": timestamp,
                "recon_events_before": len(recon_before),
                "severity": "High",
                "description": (
                    f"{len(recon_before)} recon event(s) on {host} were followed "
                    f"by a log clear within {window_minutes} minutes — "
                    f"possible anti-forensic activity"
                )
            })

    return findings


# quick test using the real timeline
if __name__ == "__main__":
    import sys
    import os

    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from core.timeline import create_timeline_db, get_timeline

    con = create_timeline_db()
    rows = get_timeline(con)

    results = detect_log_clear_after_recon(rows, window_minutes=30)

    if not results:
        print("No suspicious log-clear pattern found.")
    else:
        print(f"Found {len(results)} suspicious finding(s):\n")
        for f in results:
            print(f["description"])
            print(f"  severity: {f['severity']}\n")