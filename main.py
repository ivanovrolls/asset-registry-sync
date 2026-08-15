import json

def log_decision(source, outcome, reason):
    entry = {"source": source, "outcome": outcome, "reason": reason}
    with open("log.txt", "a") as log:
        log.write(entry)


def fetch_source(source_path: str) -> list[dict]:
    try:
        with open(source_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        log_decision(source=source_path, outcome="source_unreachable", reason = "File path not valid or found.")
    except json.JSONDecodeError as e:
        log_decision(source = source_path, outcome="json_syntax_error", reason = "JSON file syntax invalid.")

    if not isinstance(data, list): #if it is not a list return an empty list
        log_decision(source=source_path, outcome="source_rejected", reason="Expected a JSON array of records, got something else.")
        return []

    valid_records = [] #ensures that items inside list are dict 
    for i, item in enumerate(data):
        if isinstance(item, dict):
            valid_records.append(item)
        else:
            log_decision(source=source_path, outcome="record_rejected", reason=f"Item at index {i} is not a JSON object, got {type(item).__name__}.")

    return data