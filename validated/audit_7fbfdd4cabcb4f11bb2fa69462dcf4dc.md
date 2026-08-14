### Title
Byte-position diff truncation in `cap_diff_for_prompt` lets an attacker who controls diff size/ordering push the security-relevant hunk past the cap, silently defeating the LLM review - (File: `plugins/security-guidance/hooks/review_api.py`)

### Summary
`cap_diff_for_prompt` truncates each file's diff purely by byte offset (`content[:DIFF_PER_FILE_BYTES]` / `content[:room]`), keeping only the first N bytes of a file's diff and appending a generic truncation marker for everything past that point. Since the function is content-agnostic and preserves whatever order the diff lines arrive in, an attacker who authors the diff (e.g. a malicious contributor whose PR/commit is reviewed via `review_api`'s importable prompts) can pad the beginning of a changed file with benign filler to push the actual malicious hunk past the 80,000-byte (`DIFF_PER_FILE_BYTES`) or 400,000-byte (`DIFF_TOTAL_BYTES`) cutoff, causing the reviewer LLM to never see the dangerous lines at all.

### Finding Description
`cap_diff_for_prompt` is called directly inside `build_investigate_prompt` [1](#0-0)  to build the exact text sent to the investigate-stage model. The capping logic itself is purely positional: [2](#0-1) 

For a single file, only the first `DIFF_PER_FILE_BYTES` (80,000) bytes of `content` are kept; anything beyond that is replaced with a static string `"... [truncated by security-guidance: file exceeds per-file byte cap]"` that carries no information about what was cut. The same front-wins/rest-dropped pattern applies at the aggregate level via `DIFF_TOTAL_BYTES` (400,000).

This is exactly the "cap defeat" pattern the tool's own investigate-stage system prompt tells the model to look for in *other* code (`RESOURCE-BOUND PLACEMENT: ... first-element-only invariant. The finding is the cap defeat, not the DoS itself` [3](#0-2) ), but the same class of flaw exists in the tool's own diff-preparation code: there is no content-aware prioritization (no hunk selection by risk keyword, no interleaving of head/tail, no per-hunk budgeting) — it is a first-N-bytes-only invariant.

`review_api.py`'s own docstring states it is meant to be imported by "external agentic harnesses so their commit reviewer uses the exact prompts... the plugin uses" [4](#0-3) , i.e. it is explicitly designed to review diffs whose content is not necessarily authored by the reviewing party (contributor PRs, external commits). An attacker who authors such a diff fully controls both its size and internal ordering, and can therefore:
1. Modify one file with a large, innocuous-looking prefix (generated code, a big data table, repeated whitespace/comments) exceeding 80,000 bytes.
2. Place the actual dangerous change (e.g. a backdoor, command-injection sink, secret exfiltration) after that offset.
3. `cap_diff_for_prompt` truncates the file at byte 80,000, dropping the dangerous hunk from the prompt entirely, and the investigate-stage model only ever sees the generic truncation marker with no indication that a security-relevant hunk was excised.

No existing check mitigates this: the function has no hunk-boundary awareness, no keyword/heuristic prioritization, and the resulting marker text gives the model no signal that specific lines (rather than incidental bulk) were cut.

### Impact Explanation
This defeats the security-guidance review's core invariant — that the reviewer sees the attacker's actual change — for any file large enough to trigger per-file truncation. Since the Stop-hook / commit-review flow is the acting security control gating whether Claude is told to "continue and address findings," an attacker who can get a sufficiently padded, malicious diff reviewed (their own contribution, or content that ends up in the session diff) can ship a dangerous change with the review silently reporting no relevant finding for that hunk. This is a trust-boundary bypass of the review tool itself, matching "direct user/project compromise" impact: the project's security-review control fails open for attacker-controlled content specifically shaped to exploit the truncation boundary.

### Likelihood Explanation
Feasibility is straightforward and fully repeatable: the attacker only needs to control the diff content of a single file and pad it past 80,000 bytes (easily done with a large embedded data blob, vendor-bundled/minified code, or verbose auto-generated content — none of which look inherently suspicious) before adding the malicious edit. No timing, race, or privilege escalation is required — the outcome is deterministic given the fixed byte offset.

### Recommendation
Make truncation content-aware and order-independent instead of strictly front-truncating:
- Prioritize hunks touching Phase-1/Phase-2c sink patterns (shell/exec, SQL, filesystem, network, deserialization, template render) when deciding what to keep within the per-file/-total budget.
- When a file must be truncated, keep a bounded sample from both the head and tail of the diff (not just the head) so a padded prefix cannot hide a suffix payload, and vice versa.
- Emit a truncation marker that states how many diff hunks/lines were dropped and lets the caller decide to run a follow-up pass over the omitted portion, rather than an opaque byte-count message.

### Proof of Concept
Unit test plan for `cap_diff_for_prompt` / `build_investigate_prompt`:
1. Construct `content = ("# padding line\n" * N)` sized to exactly exceed `DIFF_PER_FILE_BYTES` (80,000 bytes), followed by a marker string representing a dangerous sink, e.g. `+os.system(user_input)`.
2. Call `cap_diff_for_prompt([("evil.py", content)])` and assert that `"os.system(user_input)"` is **not** present in the returned capped content (demonstrating the dangerous line is dropped).
3. Call `build_investigate_prompt(["evil.py"], [("evil.py", content)])` and assert `"os.system(user_input)"` is absent from the final prompt text sent to the model — confirming the reviewer never receives the dangerous line, only the generic `"[truncated by security-guidance: file exceeds per-file byte cap]"` marker.
4. Repeat with the payload placed at the very start (pre-cap) and assert it IS present — showing the asymmetry: front-anchored payloads survive, tail-anchored ones are dropped, proving the truncation is positionally exploitable rather than risk-aware.

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L1-13)
```python
"""Public review API for the security-guidance agentic commit reviewer.

This module is the importable surface for callers that want to run the
same two-stage agentic security review as the CC plugin (investigate →
self-refute) without going through the CC hook protocol.  External
agentic harnesses can import this directly so their commit reviewer uses
the exact prompts, schemas, and filters the plugin uses.

``security_reminder_hook.py`` imports every symbol below; the hook
script's own underscored names are aliases.  Keep this file free of CC
hook-event coupling (no stdin parsing, no env-var feature gates, no
``debug_log``/state-file IO) so non-CC callers can import it without
side effects.
```

**File:** plugins/security-guidance/hooks/review_api.py (L42-64)
```python
    for fp, content in files:
        if len(content) > DIFF_PER_FILE_BYTES:
            dropped += len(content) - DIFF_PER_FILE_BYTES
            content = (
                content[:DIFF_PER_FILE_BYTES]
                + "\n... [truncated by security-guidance: file exceeds per-file byte cap]"
            )
        room = DIFF_TOTAL_BYTES - total
        if room <= 0:
            dropped += len(content)
            out.append(
                (fp, "[omitted by security-guidance: total diff byte cap reached]")
            )
            continue
        if len(content) > room:
            dropped += len(content) - room
            content = (
                content[:room]
                + "\n... [truncated by security-guidance: total diff byte cap reached]"
            )
        total += len(content)
        out.append((fp, content))
    return out, dropped
```

**File:** plugins/security-guidance/hooks/review_api.py (L101-101)
```python
  - RESOURCE-BOUND PLACEMENT: when + lines parse/decompress/fetch/loop over attacker-influenced input, verify size/time/count caps guard the ACTUAL peak allocation — not a post-flush output, post-decompress buffer, per-iteration (not total) timeout, unclamped arithmetic (subtraction underflow, multiplication overflow), or first-element-only invariant. The finding is the cap defeat, not the DoS itself.
```

**File:** plugins/security-guidance/hooks/review_api.py (L156-176)
```python
def build_investigate_prompt(
    touched_paths: list[str],
    diff_files: list[tuple[str, str]],
    *,
    context_note: str = "",
) -> str:
    capped, _ = cap_diff_for_prompt(diff_files)
    diff_text = "\n\n".join(
        f"=== DIFF: {fp} ===\n{content}" for fp, content in capped
    )
    return (
        "Review this change for security vulnerabilities.\n\n"
        "Changed files (you may Read these and any other file in the repo):\n"
        + "\n".join(f"  - {p}" for p in touched_paths[:50])
        + context_note
        + "\n\nUnified diff (only + lines are new):\n\n"
        + diff_text
        + extensibility.guidance_block()
        + "\n\nInvestigate per the method in your instructions, then return "
        "the findings list."
    )
```
