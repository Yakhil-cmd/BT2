Confirmed: the code at [1](#0-0)  performs a raw `str.startswith(plans_dir)` check without a path-separator boundary.

### Title
Prefix-matching plan-file exemption allows security-pattern bypass via sibling-named paths - (File: plugins/security-guidance/hooks/security_reminder_hook.py)

### Summary
`main()`'s PostToolUse Edit/Write handler exempts "plan files" from all pattern-based security checks using `file_path.startswith(plans_dir)` where `plans_dir = os.path.expanduser("~/.claude/plans")`, with no separator boundary check. A file path that merely starts with the same string prefix (e.g. `~/.claude/plansXYZ.py` or `~/.claude/plans_backdoor/evil.py`) satisfies the check even though it is not inside the `~/.claude/plans/` directory, causing `sys.exit(0)` to fire before `check_patterns` ever runs.

### Finding Description
In `main()`, for `tool_name in ["Edit", "Write", "MultiEdit", "NotebookEdit"]`, the file path from `tool_input` is compared against `plans_dir` via a bare string prefix test: [1](#0-0) . Because this is a lexical prefix comparison rather than a directory-boundary check (e.g. `file_path == plans_dir or file_path.startswith(plans_dir + os.sep)`), any path that textually begins with `~/.claude/plans` — even `~/.claude/plansEvil/x.py` or `~/.claude/plans-backdoor/evil.py` — satisfies the condition and causes the hook to `sys.exit(0)` immediately, skipping `record_touched_path`, `check_patterns`, and all downstream pattern-based warnings for hardcoded secrets, command injection, eval usage, SQL injection, etc. A prompt-injected instruction that directs Claude to write attacker-controlled content to such a path (which requires no special privilege — just an ordinary `Write`/`Edit` tool call with a crafted `file_path`) fully bypasses PostToolUse pattern-based detection with zero warnings emitted.

### Impact Explanation
This defeats the "plan-file exemption" invariant that pattern-based security checks apply to everything except genuine files under `~/.claude/plans/`. An attacker steering Claude (via prompt injection in repo content, issue text, or tool output) to write malicious code to a specially-crafted sibling path evades all Edit/Write-time security pattern warnings, silently allowing insecure code (hardcoded secrets, `eval`, command injection, etc.) to land without any Claude Code guidance/interruption. This is a security-control bypass in the plugin's own defense-in-depth layer, not privilege escalation or code execution in Claude Code itself — impact is limited to loss of this specific detection coverage for the maliciously-placed file.

### Likelihood Explanation
Highly feasible and repeatable: the attacker only needs to influence the `file_path` argument passed to `Edit`/`Write`/`MultiEdit`, which is a normal, unprivileged capability reachable through prompt injection from any untrusted content Claude reads. No authentication, elevated privilege, or race condition is required — a single crafted path deterministically triggers the bypass every time.

### Recommendation
Change the check to require a path-separator boundary (or resolve/normalize both paths and use `os.path.commonpath`), e.g.:
```python
plans_dir = os.path.expanduser("~/.claude/plans")
if file_path == plans_dir or file_path.startswith(plans_dir + os.sep):
    sys.exit(0)
```
Additionally consider normalizing `file_path` (resolving `..`, symlinks, and case on case-insensitive filesystems) before the comparison to prevent related traversal tricks.

### Proof of Concept
Unit test `main()`'s plan-file gate:
1. Construct `input_data` with `hook_event_name="PostToolUse"`, `tool_name="Write"`, and `tool_input={"file_path": os.path.expanduser("~/.claude/plansEvil/x.py"), "content": "os.system(user_input)"}` (a pattern that should trigger the command-injection rule).
2. Feed as stdin JSON to `main()` (or call the equivalent internal logic directly).
3. Assert the hook does NOT `sys.exit(0)` before calling `check_patterns` — i.e., assert that `check_patterns` is invoked (mock/spy it) and that pattern-based `additionalContext` guidance is emitted for the injected content.
4. Repeat with `file_path=os.path.expanduser("~/.claude/plans/x.py")` (a real plan file) and assert the hook DOES skip pattern checking, confirming the fix preserves the legitimate exemption while closing the prefix-bypass gap.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L2117-2120)
```python
        # Skip plan files
        plans_dir = os.path.expanduser("~/.claude/plans")
        if file_path.startswith(plans_dir):
            sys.exit(0)
```
