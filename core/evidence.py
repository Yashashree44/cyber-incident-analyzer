# Handles evidence intake: hashing each file and logging it so we
# have a basic chain of custody (when it was added, what its hash was).

import hashlib
import json
import os
from datetime import datetime

CUSTODY_LOG_PATH = "data/working/chain_of_custody.json"


def hash_file(file_path):
    """Returns the SHA-256 hash of a file, read in chunks so big files are fine too."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def load_custody_log():
    if os.path.exists(CUSTODY_LOG_PATH):
        with open(CUSTODY_LOG_PATH, "r") as f:
            return json.load(f)
    return []


def save_custody_log(log):
    os.makedirs(os.path.dirname(CUSTODY_LOG_PATH), exist_ok=True)
    with open(CUSTODY_LOG_PATH, "w") as f:
        json.dump(log, f, indent=2)


def register_evidence(file_path):
    """
    Hashes the file and adds an entry to the custody log.
    If the file was already registered, checks the hash still matches
    (catches accidental or intentional changes to the evidence).
    """
    file_hash = hash_file(file_path)
    file_name = os.path.basename(file_path)

    log = load_custody_log()

    existing = next((e for e in log if e["file"] == file_name), None)

    if existing:
        if existing["sha256"] != file_hash:
            print(f"WARNING: hash mismatch for {file_name} — file may have been modified since intake")
        else:
            print(f"{file_name} already registered, hash matches")
        return existing

    entry = {
        "file": file_name,
        "sha256": file_hash,
        "registered_at": datetime.now().isoformat()
    }
    log.append(entry)
    save_custody_log(log)

    print(f"Registered {file_name}")
    print(f"  SHA-256: {file_hash}")

    return entry


# quick test: register every evidence file we have
if __name__ == "__main__":
    evidence_folder = "data/evidence"
    for filename in os.listdir(evidence_folder):
        path = os.path.join(evidence_folder, filename)
        register_evidence(path)