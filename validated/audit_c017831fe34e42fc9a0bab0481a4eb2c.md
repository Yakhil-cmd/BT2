### Title
Pattern-warning dedup keyed only on `(file_path, rule_name)` permanently suppresses future, potentially more severe, security findings for the rest of the session - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
The `security-guidance` plugin's `PostToolUse` handler tracks whether a security pattern warning has already been shown using `atomic_check_and_mark_warning`, keyed solely on `f"{file_path}-{rule_name}"`. Once any match for a given rule on a given file fires once, that key is permanently marked "shown" in session-lifetime state, and no future warning for that same file+rule will ever be displayed again for the rest of the session — regardless of how the offending code changes afterward. This is structurally analogous to the reported Tokemak issue: a single (possibly minor/incidental) event permanently locks a high-water-mark-like state (`shown_warnings`), after which the protective mechanism (fee collection / security warning) silently stops functioning for that dimension, even though the underlying risk condition may later become far worse.

### Finding Description
`atomic_check_and_mark_warning` implements a one-shot latch per session: [1](#0-0) 

It is invoked from the `Edit`/`Write`/`MultiEdit`/`NotebookEdit` `PostToolUse` handler with a warning key built only from the file path and the matched rule name — not from the matched code snippet, line number, or severity: [2](#0-1) 

The `shown_warnings` list is stored in on-disk session state and is only cleaned up after 30 days of inactivity, i.e., it persists for the entire session: [3](#0-2) 

Because the key only distinguishes `(file_path, rule_name)` and not the actual vulnerable content, the very first trigger of a given rule on a given file "uses up" that warning permanently — much like the first NAV/Share spike in the Tokemak bug permanently raised (and locked) `navPerShareHighMark`, after which subsequent smaller-but-still-real fee-generating events (or here, subsequent genuinely dangerous edits matching the same rule in the same file) produce no signal at all.

### Impact Explanation
If Claude (driven by the user or by content it reads, including attacker-controlled/prompt-injected content) makes a trivial or low-risk edit to a file that happens to match a given static pattern rule (e.g., a benign use of `eval`-adjacent syntax, or a placeholder credential pattern), that rule is permanently suppressed for that file for the rest of the session. Any later edit — including one that introduces a genuinely severe, exploitable instance of the same vulnerability class in that same file — will not surface a warning to the user, because the `PostToolUse` guidance is gated entirely on this one-shot key. This defeats the purpose of the pattern-based security reminder for the remainder of the session, silently degrading the plugin's protection exactly like the original bug silently degraded the protocol's fee collection after the high-water mark was set too early.

### Likelihood Explanation
This is easily reachable by an unprivileged user or by content Claude reads/edits during ordinary operation — no special privileges are required, only that two edits touching the same rule/file pair occur in one session, with the second being the one that matters. This is a realistic and plausible sequence in normal coding sessions (e.g., iterative editing of the same file), and it can also be deliberately induced by an attacker who controls repository content or prompt-injected instructions, by forcing a low-severity match to fire first in order to "poison" the warning key before a real vulnerability is introduced.

### Recommendation
Include content-sensitive information in the warning key (e.g., a hash of the matched snippet, or the matched line/content itself) rather than only `file_path` + `rule_name`, so that a new distinct occurrence of the same rule in the same file (different code, different location, different severity) is not silently suppressed by an earlier, unrelated match. Alternatively, only suppress re-warning when the underlying matched content is byte-identical to a prior warned instance (similar to how `previous_findings` dedup in the LLM-based findings path is already content-aware via `(filePath, category)` plus stored `vulnerableCode`), and consider re-arming the warning if intervening edits to the file occurred between the first and second match.

### Proof of Concept
1. In a fresh Claude Code session with the `security-guidance` plugin active, have Claude `Write`/`Edit` a file introducing a low-risk match for a given `rule_name` (e.g., a pattern rule such as an unsafe-deserialization marker used in an innocuous/test context). The `PostToolUse` hook calls `atomic_check_and_mark_warning(session_id, f"{file_path}-{rule_name}")`, which returns `True` the first time, shows the warning, and appends the key to `state["shown_warnings"]`.
2. Later in the same session, edit the same file again to introduce a genuinely dangerous instance of the same vulnerability class (same `rule_name`, different/worse code).
3. `atomic_check_and_mark_warning` is called again with the identical key `f"{file_path}-{rule_name}"`; since it is already present in `shown_warnings`, the function returns `False` and no warning/guidance is emitted for this clearly more severe finding, even though `check_patterns` matched it.
4. The dangerous code change proceeds with no security-guidance signal for the rest of the session, confirmed by the fact that `all_guidance` stays empty and no `hookSpecificOutput.additionalContext` is produced for that file/rule pair again — mirroring the original bug's permanent loss of fee/signal after a one-time high-water-mark lock.

Note: I was unable to fully inspect `plugins/security-guidance/hooks/patterns.py` (rule definitions and their granularity/severity mapping) due to a tool error in the final iteration, so the precise breadth of `rule_name` granularity (how many distinct vulnerability types share one `rule_name`) could not be fully confirmed from source; this is based on the `security_reminder_hook.py` and `session_state.py` code paths that were successfully reviewed.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L237-251)
```python
def atomic_check_and_mark_warning(session_id, warning_key):
    """
    Atomically check if a warning has been shown and mark it as shown if not.
    Returns True if this is the first time seeing this warning (should show it),
    False if it was already shown (should skip it).
    """
    def _check(state):
        warnings = state["shown_warnings"]
        if warning_key in warnings:
            return False
        warnings.append(warning_key)
        return True

    result = with_locked_state(session_id, _check)
    return result if result is not None else True
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L2147-2150)
```python
            for rule_name, reminder in pattern_matches:
                warning_key = f"{file_path}-{rule_name}"
                if atomic_check_and_mark_warning(session_id, warning_key):
                    all_guidance.append(reminder)
```

**File:** plugins/security-guidance/hooks/session_state.py (L49-69)
```python
def cleanup_old_state_files():
    """Remove state files and lock files older than 30 days."""
    try:
        state_dir = os.environ.get("SECURITY_WARNINGS_STATE_DIR", os.path.expanduser("~/.claude/security"))
        if not os.path.exists(state_dir):
            return

        current_time = datetime.now().timestamp()
        thirty_days_ago = current_time - (30 * 24 * 60 * 60)

        for filename in os.listdir(state_dir):
            if filename.startswith("security_warnings_state_") and (
                filename.endswith(".json") or filename.endswith(".lock")
            ):
                file_path = os.path.join(state_dir, filename)
                try:
                    file_mtime = os.path.getmtime(file_path)
                    if file_mtime < thirty_days_ago:
                        os.remove(file_path)
                except (OSError, IOError):
                    pass
```
