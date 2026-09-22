# Maps raw Windows Event IDs to something a human can actually read,
# plus the matching MITRE ATT&CK technique where one applies.

EVENT_ID_MAP = {
    "4799": {
        "description": "Security-enabled local group membership was enumerated",
        "mitre_technique": "T1069.001",
        "mitre_name": "Permission Groups Discovery: Local Groups"
    },
    "5145": {
        "description": "A network share object was checked for access permissions",
        "mitre_technique": "T1135",
        "mitre_name": "Network Share Discovery"
    },
    "1102": {
        "description": "The audit log was cleared",
        "mitre_technique": "T1070.001",
        "mitre_name": "Indicator Removal: Clear Windows Event Logs"
    },
}


def enrich_event(event):
    """
    Takes one event dict (from the timeline) and adds a readable
    description + MITRE mapping, if we know about that event ID.
    """
    event_id = str(event.get("event_id"))
    info = EVENT_ID_MAP.get(event_id)

    if info:
        event["description"] = info["description"]
        event["mitre_technique"] = info["mitre_technique"]
        event["mitre_name"] = info["mitre_name"]
    else:
        event["description"] = "No description available for this event ID"
        event["mitre_technique"] = None
        event["mitre_name"] = None

    return event


# quick test
if __name__ == "__main__":
    sample = {"event_id": "4799", "host": "test-machine"}
    print(enrich_event(sample))