# asset-registry-sync

A reconciliation agent that maintains a canonical asset registry from multiple untrusted operational feeds. It fetches from each source, validates and sanitises every field, detects conflicts when sources disagree about the same asset, resolves those conflicts using a documented strategy, and persists the result with a full audit trail explaining every decision.

## How to run it

No external dependencies, standard library only (`json`, `re`, `datetime`, `os`).

```
asset-registry-sync/
├── main.py
└── feeds/
    ├── feed_scada.json
    ├── feed_facilities.json
    └── feed_iot_backup.json
```

```bash
python3 main.py
```

This will:
- Print each source being processed and the outcome for every record it contains
- Print the final registry state
- Write the persisted registry to `canonical.json`
- Append every decision (accepted, rejected, quarantined, conflict resolved, ignored) to `log.txt`, one JSON object per line

Run it again and it picks up where it left off — the registry is loaded from disk at the start of every run, not rebuilt from scratch. To reset to a clean slate: `rm -f log.txt && rm -rf registry`.

## Architecture

Each record moves through a fixed pipeline of increasingly specific checks, but the **agent's actions are not a fixed sequence**; what happens next depends entirely on what's found at each stage:

```
fetch_source        → reads one feed, quarantines it if unreadable/malformed
validate_schema      → per-record: presence, type, format, enum checks
check_injection       → per-record: pattern screen on free-text fields
assess_source_quality → per-source: flags a feed as degraded if most of it failed
detect_conflict       → per-record: compares against the current registry entry
resolve_conflict      → applies timestamp precedence, source priority as tiebreak
orchestrator           → ties all of the above together, decides what runs next
```

Checks are ordered cheapest-to-most-expensive: structural checks (type, presence, enum membership) run before the more expensive regex-based injection screen, so malformed records never reach the most expensive check. A record is only ever compared against other records once it has already been proven safe and well-formed.

## Handling untrusted input

Every field from every feed is treated as untrusted, including the feed's own claim about its `source`. Three layers of defence, in order:

**1. Structural validation is the primary defence, not the pattern screen.** `status` is constrained to a fixed enum (`active`, `inactive`, `maintenance`, `decommissioned`); `asset_id` must match `[A-Za-z0-9_-]+`; `timestamp` must parse as valid ISO 8601; `location` is capped at 100 characters. These constraints mean a field like `status` has no room for injected text at all; an enum is complete by construction, whereas a denylist of suspicious phrases can never be exhaustive against novel wording. This is why `location` (over-length, over-100-char payloads) got rejected by the length cap alone in testing, before the injection screen even ran.

**2. Pattern-based injection screening is secondary and best-effort** `check_injection` scans only the genuinely free-text fields (`location`, `source`) against a list of known injection-style phrases (`"ignore previous instructions"`, `"disregard the above"`, script/eval/exec patterns, SQL-injection shapes, etc.), case-insensitively. This is explicitly a denylist and is known to be incomplete — an attacker who avoids these exact phrasings would slip past it. It exists to catch obvious, unsophisticated attempts and to give the audit log something concrete to point at.

**Per-record, not per-file, rejection.** A malformed or malicious record only disqualifies itself, never the rest of its source file. Rejecting an entire feed over one bad record would discard good data unnecessarily.

**No partial-field acceptance.** If a record is missing a required field, the whole record is rejected rather than accepted with a gap. A registry entry should always trace back to one complete claim from one source at one point in time; accepting partial records would let entries become an untraceable patchwork of fields from different sources and different times, which undermines the audit trail's honesty.

**Duplicate JSON keys are detected and rejected at parse time.** Python's `json` module silently resolves duplicate keys in an object by keeping the last value and discarding the earlier one - this happens before any application code sees the data, so it can't be detected after the fact. `fetch_source` uses `object_pairs_hook` to inspect the raw key-value pairs during parsing and reject any record containing a duplicate key outright, closing an otherwise-invisible route for a field to be silently overwritten.

## Conflict resolution strategy

A conflict is only raised when two **different sources** report **different** `status` or `location` for the same `asset_id`. Two related situations are deliberately *not* treated as conflicts:
- The same source updating its own earlier claim over time (an asset genuinely changing state) this is normal data not  dispute.
- Two different sources agreeing — this is corroboration, and is treated as a confidence signal rather than logged as an event.

**Primary rule: most recent timestamp wins.** An asset registry's job is to reflect current reality. A source-priority-first rule would let a stale claim from a "trusted" source override a fresher, accurate claim from elsewhere — actively working against the registry's purpose. Timestamp precedence keeps the registry current by default.

**Tiebreak: fixed source priority**, used only when both records report the exact same timestamp:

| Source | Priority |
|---|---|
| `scada` | 1 (highest trust) |
| `facilities` | 2 |
| `iot_backup` | 3 |
| unknown source | 99 (lowest trust) |

This ranking is a placeholder reflecting plausible operational roles (a live telemetry system ranked above an explicitly-named backup feed) rather than a rigorously derived trust model. In a real deployment this would be set with actual domain input on each system's reliability.

**Nothing is silently discarded.** `resolve_conflict` returns both the winning and losing record, and both are written to the decision log with the specific rule that decided the outcome (e.g. `"A101: Incoming record has a more recent timestamp. Winner: {...}. Loser: {...}."`) — satisfying the requirement to explain why every update was accepted or rejected, including the losing side of a conflict.

**Winners are always one complete, unmodified record — never a merge.** The registry never combines fields from two sources into a synthetic record. A merged entry couldn't honestly be attributed to any single source's actual claim, which would break the audit trail's core guarantee: every field in the registry traces back to one real claim from one real source.

**Stale replays are rejected even without a "conflict."** If a source resends an older record for an asset with no other source involved, `is_newer` prevents it from silently overwriting a more recent registry entry — this is the same recency principle as conflict resolution, applied even in the no-conflict path, so replaying old data can never roll the registry backward in time. Verified across two separate runs: re-feeding an already-superseded SCADA claim on a second run correctly lost against the persisted, newer Facilities entry.

## The agent deciding what to do next

"Agent" here means the program branches its behaviour based on what it actually encounters at runtime, not that it calls an LLM. Concrete examples in this codebase:

- A missing or corrupt source file is skipped, not fatal to the run — the agent continues to the next source.
- Each record is independently routed to one of: accepted, rejected (malformed), quarantined (injection-like), routed to conflict resolution, or ignored (stale update) — the path taken depends entirely on the record's content.
- `assess_source_quality` computes, per source, what fraction of its records failed validation/screening this run. If more than half fail, the source is flagged as degraded for this run and logged — a decision made about the *source* as a whole, based on an aggregate of what was found, not hardcoded per feed.

## Known limitations and what I'd do next

- **`assess_source_quality` currently only flags a degraded source; it doesn't yet act on the flag.** A natural next step is feeding this signal back into `resolve_conflict`, temporarily lowering a degraded source's priority for the remainder of the run.
- **Registry writes happen once, at the end of a run.** Simpler to reason about, but a crash mid-run loses that run's progress (though nothing already persisted from prior runs is affected). A production version would persist incrementally or use a transactional store (e.g. SQLite) for crash-safety.
- **`location` is free text with a length cap and pattern screen, not a closed enum**, unlike `status`. This was a deliberate choice: real facility location strings are often multi-part and too varied for a small fixed vocabulary. Bu it is the weaker-guarantee field in the schema. A production system covering a known, finite set of physical sites could tighten this to an enum the same way `status` is handled.
- **The injection pattern list is a denylist and is known to be incomplete by construction.** A production system would likely add further layers like rate-limiting or reputation tracking per source over time, not just within a single run.
- **Currently a single file.** Given the scope, this keeps the whole pipeline readable top-to-bottom in one pass, which matters for review. With more time this would split into modules (`validation.py`, `registry.py`, `conflict.py`, `main.py`).
- **Source priority ranking is illustrative, not derived from real reliability data** — see the conflict resolution section above.
