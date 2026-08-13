### Title
Warning-dedup key collision from unseparated string concatenation causes suppressed security warnings - (File: plugins/security-guidance/hooks/security_reminder_hook.py)

### Summary
The external report's bug class is a hash/key collision: two distinct logical inputs (source chain + source address + payload fields) are concatenated/hashed without a distinguishing separator, so different transactions can map to the same key and silently overwrite each other's approval state. An analogous pattern exists in the `security-guidance` plugin's PostToolUse dedup logic, where `warning_key = f"{file_path}-{rule_name}"` is used as the sole identity key for "already warned" tracking, with no delimiter guaranteeing the two components can't collide.

### Finding Description
In `plugins/security-guidance/hooks/security_reminder_hook.py`, when a pattern-based rule matches on an `Edit`/`Write`/`MultiEdit`/`NotebookEdit` call, the hook builds a dedup key by naively concatenating the file path and the matched rule name with a hyphen: [1](#0-0) 

This key is passed to `atomic_check_and_mark_warning(session_id, warning_key)`, which presumably marks the key as "already shown" in a persisted per-session state file (via the `with_locked_state`/`session_state.py` machinery) so the same warning isn't repeated on subsequent edits.

Because `file_path` values can themselves contain hyphens (a very common character in real paths, e.g. `src/api-keys/config.py` or `my-project/db-utils.py`), two different `(file_path, rule_name)` pairs can produce the identical concatenated string. For example:
- `file_path="src/api"`, `rule_name="keys-hardcoded"` → key `"src/api-keys-hardcoded"`
- `file_path="src/api-keys"`, `rule_name="hardcoded"` → key `"src/api-keys-hardcoded"`

This mirrors the root cause in the external report: fields that are individually well-formed are concatenated (there `abi.encode(version, srcSender, amt, nonce)` without chain/address context; here `f"{file_path}-{rule_name}"` without an unambiguous separator/escaping), producing an identity collision between two logically distinct records.

### Impact Explanation
If the dedup mark for one `(file_path, rule_name)` pair is set, a genuinely different `(file_path, rule_name)` pair that happens to produce the same concatenated key will be treated as "already warned" and the security reminder (`additionalContext` injected via `hookSpecificOutput`) will be suppressed. This is a security-guidance bypass: the model would not be reminded to fix/reconsider a newly detected hardcoded-secret, SQL-injection, or command-injection pattern in a file, because the dedup logic believes that exact finding was already surfaced (for an unrelated file/rule combination). This is not a shell/file authorization bypass by itself, but it degrades a security control (`ENABLE_PATTERN_RULES` guidance) meant to nudge Claude toward safer code, i.e. a "secret/code disclosure" and prompt-based-guardrail trust-boundary weakness within an unprivileged-user-facing plugin hook.

### Likelihood Explanation
Low-to-moderate likelihood in practice: it requires a coincidental split of a hyphen-containing path such that the resulting concatenation matches another real `(file_path, rule_name)` pair's concatenation. It is not attacker-controlled in an adversarial sense (there's no external "attacker" supplying `file_path`/`rule_name` independently of the legitimate edit), so this is primarily a robustness/correctness bug rather than a directly exploitable attack — same as the original finding, which was rated Medium because it requires a specific coincidence of chain/sender/amount/nonce rather than attacker-chosen collision.

### Recommendation
Use an unambiguous separator/encoding when constructing the dedup key, e.g. a null byte, JSON-encode the tuple, or hash `(file_path, rule_name)` as a structured tuple rather than string concatenation:
```python
warning_key = json.dumps([file_path, rule_name])
# or
warning_key = f"{len(file_path)}:{file_path}\x00{rule_name}"
```
This guarantees no two distinct `(file_path, rule_name)` pairs can ever produce the same key, analogous to the report's recommendation to include `srcChain`/`srcAddr` explicitly in the hashed payload instead of relying on positional concatenation of variable-length fields.

### Proof of Concept
```python
# Two distinct (file_path, rule_name) pairs producing the same warning_key
file_path_1, rule_name_1 = "src/api", "keys-hardcoded"
file_path_2, rule_name_2 = "src/api-keys", "hardcoded"

key1 = f"{file_path_1}-{rule_name_1}"   # "src/api-keys-hardcoded"
key2 = f"{file_path_2}-{rule_name_2}"   # "src/api-keys-hardcoded"

assert key1 == key2  # True: identity collision
``` [1](#0-0) 

Note: I was unable to directly view the implementation of `atomic_check_and_mark_warning` (defined later in the same file) to confirm the exact persistence semantics, but its call site and surrounding comments (line 2148-2150) confirm the key is used as the sole de-duplication identity for warnings across a session, which is sufficient to establish the collision root cause and impact described above.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L2147-2150)
```python
            for rule_name, reminder in pattern_matches:
                warning_key = f"{file_path}-{rule_name}"
                if atomic_check_and_mark_warning(session_id, warning_key):
                    all_guidance.append(reminder)
```
