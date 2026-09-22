# Parses Windows Event Log (.evtx) files and pulls out the fields we need
# for the timeline: when it happened, which machine, and what event.

import evtx
import json


def parse_evtx(file_path):
    events = []
    parser = evtx.PyEvtxParser(file_path)

    for record in parser.records_json():
        try:
            data = json.loads(record["data"])
        except Exception as e:
            print("could not parse a record, skipping:", e)
            continue

        system = data.get("Event", {}).get("System", {})

        event = {
            "timestamp": system.get("TimeCreated", {}).get("#attributes", {}).get("SystemTime"),
            "host": system.get("Computer"),
            "event_id": system.get("EventID"),
            "channel": system.get("Channel"),
            "source": "evtx",
            "raw": data
        }

        events.append(event)

    return events


# quick way to test this file on its own:
# python evtx_parser.py path\to\file.evtx
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("give me a file path: python evtx_parser.py <file.evtx>")
        sys.exit(1)

    result = parse_evtx(sys.argv[1])
    print(f"parsed {len(result)} events")

    print("\nfirst 3:")
    for e in result[:3]:
        print(e["timestamp"], "|", e["channel"], "| event id:", e["event_id"])