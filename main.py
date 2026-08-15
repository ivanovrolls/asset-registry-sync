import json

def log_decision(source, outcome, reason):
    entry = {"source": source, "outcome": outcome, "reason": reason}
    with open("log.txt", "a") as log:
        log.write(entry)


def fetch_source(source_path: str) -> list[dict]:
    try:
        with open(source_path, "r") as f:
            data = json.load(f, object_pairs_hook=check_for_dupli)
    except FileNotFoundError:
        log_decision(source=source_path, outcome="source_unreachable", reason = "File path not valid or found.")
    except json.JSONDecodeError as e:
        log_decision(source = source_path, outcome="json_syntax_error", reason = "JSON file syntax invalid.")
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
    REQUIRED_FIELDS = {"asset_id", "status", "location", "timestamp", "source"}

    valid_records = []
    for i in data:
        missing = REQUIRED_FIELDS - i.keys()
        if missing:
            log_decision(source=i.get("source", "unknown"), outcome="record_rejected", reason=f"Missing fields: {missing}")
            continue
        valid_records.append(i) 
    return valid_records
        #this function only checks all required fields are present, but types and input must be checked separately

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