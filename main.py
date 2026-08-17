import json
import re
from datetime import datetime
import os

REGISTRY_PATH = "canonical.json"
DEGRADED_THRESHOLD = 0.5
REQUIRED_FIELDS = {"asset_id", "status", "location", "timestamp", "source"} #required fields in each record
ALLOWED_STATUSES = {"maintenance", "active", "inactive", "decommissioned"} #allowed statues in status field
MAX_LOCATION_LENGTH = 100
SCREENED_FIELDS = ["location", "source"] #no need to check other fields as they are closed e.g., by Enums, timestamp etc.
INJECTION_PATTERNS = [
    r"ignore (previous|all|the)\s+(instructions|directives|rules)",
    r"disregard (the )?(above|previous|prior)",
    r"system prompt",
    r"you are now",
    r"new instructions?:",
    r"act as (a|an)\b",
    r"\bexec\(",
    r"\beval\(",
    r"<\s*script",
    r"\{\{.*\}\}",              #template injection, e.g. Jinja
    r";\s*(DROP|DELETE|UPDATE|INSERT)\s+",  #SQL injection
    r"\bsudo\b",
    r"admin(istrator)?\s+(override|access|mode)",
]
SOURCE_PRIORITY = { #lower number = higher trust
    "scada": 1,
    "facilities": 2,
    "iot_backup": 3,
}
DEFAULT_PRIORITY = 99  #unknown sources are trusted least
#sources priority is only a tiebreaker when timestamps are equal or when a source is known to be lower confidence like legacy sources

def log_decision(source, outcome, reason):
    entry = {"source": source, "outcome": outcome, "reason": reason}
    with open("log.txt", "a") as log:
        log.write(json.dumps(entry) + "\n")

def check_for_dupli(pairs): 
    """due to the way JSON parsing works, my validate_schema function could accept a record that has all the
    REQUIRED_FIELDS, but with one of these fields duplicated - the most recent one would be accepted. This could 
    lead to data tampering, so I check for duplicates. 
    """
    seen = set()
    duplicates = set()

    for key, value in pairs:
        if key in seen:
            duplicates.add(key)
        else:
            seen.add(key)

    if duplicates:
        raise ValueError(f"Duplicate keys detected: {duplicates}")

    return dict(pairs)

def fetch_source(source_path: str) -> list[dict]:
    try:
        with open(source_path, "r") as f:
            data = json.load(f, object_pairs_hook=check_for_dupli)
    except FileNotFoundError:
        log_decision(source=source_path, outcome="source_unreachable", reason = "File path not valid or found.")
        return []
    except json.JSONDecodeError as e:
        log_decision(source = source_path, outcome="json_syntax_error", reason = "JSON file syntax invalid.")
        return[]
    except ValueError as e:
        log_decision(source=source_path, outcome="source_rejected", reason=str(e))
        return []

    if not isinstance(data, list): #if it is not a list return an empty list
        log_decision(source=source_path, outcome="source_rejected", reason="Expected a JSON array of records, got something else.")
        return []

    valid_records = [] #ensures that items inside list are dict 
    for i, item in enumerate(data):
        if isinstance(item, dict):
            valid_records.append(item)
        else:
            log_decision(source=source_path, outcome="record_rejected", reason=f"Item at index {i} is not a JSON object, got {type(item).__name__}.")

    return valid_records

def validate_schema(data: list[dict]) -> list[dict]:
    valid_records = []
    for i in data:
        missing = REQUIRED_FIELDS - i.keys()
        if missing:
            log_decision(source=i.get("source", "unknown"), outcome="record_rejected", reason=f"Missing fields: {missing}")
            continue

        is_valid, problems = validate_record(i)
        if not is_valid:
            log_decision(source=i.get('source', "unknown"), outcome="record_rejected", reason="; ".join(problems))
            continue

        clean, flags = check_injection(i)
        if not clean:
            log_decision(source=i.get("source", "unknwon"), outcome = "record_quarantined", reason="; ".join(flags))
            print(f"  QUARANTINED {i.get('asset_id', 'unknown')}: {'; '.join(flags)}")
            continue

        valid_records.append(i) 

    return valid_records
        #this function only checks all required fields are present, but types and input must be checked separately

def validate_record(record): #checks the fields and type of a single record
    problems = []

    #1. asset_id must be a string made only of safe characters
    asset_id = record["asset_id"]
    if not isinstance(asset_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", asset_id):
        problems.append(f"Invalid asset_id format: {asset_id!r}")

    raw_status = record["status"]
    if not isinstance(raw_status, str):
        problems.append(f"Invalid status type: {raw_status!r}")
    else:
        status = raw_status.lower()
        if status not in ALLOWED_STATUSES:
            problems.append(f"Invalid status: {status!r}")

    location = record["location"] #
    if not isinstance(location, str) or len(location) == 0 or len(location) > MAX_LOCATION_LENGTH:
        problems.append(f"Invalid location: too long, empty, or wrong type.")

    timestamp = record["timestamp"] #timestamp must valid ISO 8601
    if not isinstance(timestamp, str):
        problems.append(f"Invalid timestamp type: {timestamp!r}")
    else:
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            problems.append(f"Invalid timestamp format: {timestamp!r}")

    source = record["source"]
    if not isinstance(source, str) or len(source) == 0:
        problems.append(f"Invalid source: {source!r}")

    return len(problems) == 0, problems

def check_injection(record: dict) -> tuple[bool, list[str]]:
    #this will scan free text fields for known injection patterns
    #it does not modify or internpet the record in any way, it returns which patterns triggered a match
    flags = []
    for field in SCREENED_FIELDS:
        value = record.get(field, "")
        if not isinstance(value, str):
            continue
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                flags.append(f"Field '{field}' matched suspicious pattern: {pattern!r}")
    return len(flags) == 0, flags

def detect_conflict(incoming: dict, registry: dict) -> dict | None:
    incoming_id = incoming["asset_id"]

    if incoming_id not in registry: #check if the record exists
        return None 

    current = registry[incoming_id] #otherwise pull the matching in record

    if current.get("source") == incoming.get("source"):
        return None #feed updating its own info


    status_differs = current.get("status") != incoming.get("status")
    location_differs = current.get("location") != incoming.get("location")

    if not status_differs and not location_differs:
        return None #different source but agrees

    return { #on case of a conflict, return the new and old records, along with the id and a description of their disagreement
        "asset_id": incoming_id,
        "current": current,
        "incoming": incoming,
        "status_differs": status_differs,
        "location_differs": location_differs,
    }

def is_newer(incoming: dict, current: dict) -> bool:
    incoming_ts = datetime.fromisoformat(incoming["timestamp"].replace("Z", "+00:00"))
    current_ts = datetime.fromisoformat(current["timestamp"].replace("Z", "+00:00"))
    return incoming_ts >= current_ts

def resolve_conflict(conflict: dict) -> dict: #takes the dictionary of the conflict, and returns the updated record to be put into the registry
    """takes current and incoming record from the conflict dictionary and uses timestamps to resolve conflicts,
    but if theyre exactly equal, a fixe trust ranking is used to break the tie. full decision is logged"""

    current = conflict["current"]
    incoming = conflict["incoming"]
    asset_id = conflict["asset_id"]

    current_ts = datetime.fromisoformat(current["timestamp"].replace("Z", "+00:00"))
    incoming_ts = datetime.fromisoformat(incoming["timestamp"].replace("Z", "+00:00"))

    if incoming_ts > current_ts:
        winner, loser, rule = incoming, current, "Incoming record has a more recent timestamp."
    elif current_ts > incoming_ts:
        winner, loser, rule = current, incoming, "Current record has a more recent timestamp."
    else:
        #exact tie on timestamp, fall back to source priority
        current_priority = SOURCE_PRIORITY.get(current["source"], DEFAULT_PRIORITY)
        incoming_priority = SOURCE_PRIORITY.get(incoming["source"], DEFAULT_PRIORITY)

        if incoming_priority < current_priority:
            winner, loser, rule = incoming, current, "Timestamps tied; incoming source has higher priority."
        else:
            winner, loser, rule = current, incoming, "Timestamps tied; current source has equal or higher priority."

    return {
        "asset_id": asset_id,
        "winning_record": winner,
        "losing_record": loser,
        "reason": rule,
    }

def save_registry(registry: dict):
    #writes registry to disk, creates path if needed
    dir_path = os.path.dirname(REGISTRY_PATH)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)

def load_registry() -> dict:
    #loads current registry from disk into memory, returns empty state if no registry file exists
    if not os.path.exists(REGISTRY_PATH):
        return {}

    try:
        with open(REGISTRY_PATH, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        log_decision(source=REGISTRY_PATH, outcome="registry_unreadable", reason=f"Registry file is corrupt: {e}")
        return {}

    if not isinstance(data, dict):
        log_decision(source=REGISTRY_PATH, outcome="registry_unreadable", reason="Registry file did not contain a JSON object.")
        return {}

    return data

def assess_source_quality(source_path: str, raw_count: int, valid_count: int) -> float | None:
    #computes how much of a source's records failed vaildation and screening this run
    #if it exceeds the degraded threshold, it logs the source as degraded; returns none if source does not look degrade

    if raw_count == 0:
        return None

    rejection_rate = 1 - (valid_count / raw_count)

    if rejection_rate > DEGRADED_THRESHOLD:
        log_decision(
            source=source_path,
            outcome="source_flagged_degraded",
            reason=f"{rejection_rate:.0%} of records from this source failed validation/screening this run",
        )
        return rejection_rate

    return None

def orchestrator(sources: list[str]) -> dict:
    """for each source, decides what to do based on what it finds, not a fixed sequance of actions.
    1. a missing/corrupt source is skipped, not fatal to the whole run
    2. a source with an unusually high rejection rate is flagged as
        degraded for this run (its records are still processed, but the
        agent's assessment of it is recorded)
    3. each record is individually accepted, rejected, quarantined,
        or routed into conflict resolution, depending on what it is
    4. conflicting updates are resolved by timestamp precedence, falling
        back to source priority only on an exact tie
    Returns the final registry state after processing every source
    """
    registry = load_registry()

    for source_path in sources:
        print(f"\n=== Processing source: {source_path} ===")

        raw_records = fetch_source(source_path)
        if not raw_records:
            print(f"No usable records from this source, moving on")
            continue

        valid_records = validate_schema(raw_records)

        degraded_rate = assess_source_quality(source_path, len(raw_records), len(valid_records))
        if degraded_rate is not None:
            print(f"WARNING: source flagged as degraded this run ({degraded_rate:.0%} rejected)")

        for record in valid_records:
            asset_id = record["asset_id"]
            conflict = detect_conflict(record, registry)

            if conflict:
                resolution = resolve_conflict(conflict)
                registry[resolution["asset_id"]] = resolution["winning_record"]
                log_decision(
                    source=resolution["winning_record"]["source"],
                    outcome="conflict_resolved",
                    reason=(
                        f"{asset_id}: {resolution['reason']} "
                        f"Winner: {resolution['winning_record']}. "
                        f"Loser: {resolution['losing_record']}."
                    ),
                )
                print(f"CONFLICT on {asset_id}: {resolution['reason']} -> kept {resolution['winning_record']['source']}'s version")
            else:
                if asset_id not in registry or is_newer(record, registry[asset_id]):
                    registry[asset_id] = record
                    print(f"  {asset_id}: added/updated")
                else:
                    log_decision(
                        source=record["source"],
                        outcome="update_ignored",
                        reason=f"{asset_id}: incoming record is older than current registry entry",
                    )
                    print(f"  {asset_id}: ignored (older than current registry entry)")

    save_registry(registry)
    return registry


if __name__ == "__main__":
    SOURCES = [
        "feeds/feed_scada.json",
        "feeds/feed_facilities.json",
        "feeds/feed_iot_backup.json",
    ]
    final_registry = orchestrator(SOURCES)

    print("\n=== FINAL REGISTRY ===")
    for asset_id, rec in final_registry.items():
        print(f"  {asset_id}: {rec['status']} @ {rec['location']} (source={rec['source']}, ts={rec['timestamp']})")
    