# Takes parsed events (from any parser) and stores them in DuckDB
# so we can sort, filter, and query them like a real investigation timeline.

import duckdb


def create_timeline_db(db_path="data/working/timeline.duckdb"):
    con = duckdb.connect(db_path)

    con.execute("""
        CREATE TABLE IF NOT EXISTS events (
            timestamp TIMESTAMP,
            host VARCHAR,
            event_id VARCHAR,
            channel VARCHAR,
            source VARCHAR
        )
    """)

    return con


def reset_timeline(con):
    """Clears existing events before a fresh load. Call this only when re-loading evidence."""
    con.execute("DELETE FROM events")


def add_events(con, events):
    for e in events:
        con.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?)",
            [e.get("timestamp"), e.get("host"), str(e.get("event_id")),
             e.get("channel"), e.get("source")]
        )


def get_timeline(con):
    return con.execute("SELECT * FROM events ORDER BY timestamp").fetchall()


# quick test: loads all 3 evtx files we have and prints the sorted timeline
if __name__ == "__main__":
    import sys
    import os

    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from parsers.evtx_parser import parse_evtx
    from core.mitre import enrich_event

    con = create_timeline_db()
    reset_timeline(con)

    evidence_folder = "data/evidence"
    for filename in os.listdir(evidence_folder):
        if filename.endswith(".evtx"):
            path = os.path.join(evidence_folder, filename)
            print(f"loading {filename}...")
            events = parse_evtx(path)
            add_events(con, events)

    print("\ntimeline (sorted by time):")
    for row in get_timeline(con):
        timestamp, host, event_id, channel, source = row
        enriched = enrich_event({"event_id": event_id})
        print(f"{timestamp} | {host} | {event_id} - {enriched['description']}")
        if enriched["mitre_technique"]:
            print(f"    -> MITRE: {enriched['mitre_technique']} ({enriched['mitre_name']})")