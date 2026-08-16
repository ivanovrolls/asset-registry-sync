import json
import re
from datetime import datetime

REQUIRED_FIELDS = {"asset_id", "status", "location", "timestamp", "source"} #required fields in each record
ALLOWED_STATUSES = {"maintenance", "active", "inactive", "decommissioned"} #allowed statues in status field
MAX_LOCATION_LENGTH = 100

def log_decision(source, outcome, reason):
    entry = {"source": source, "outcome": outcome, "reason": reason}
    with open("log.txt", "a") as log:
        log.write(json.dumps(entry) + "\n")


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