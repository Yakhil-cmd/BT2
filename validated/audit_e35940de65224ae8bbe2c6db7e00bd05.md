## Title
Predictable PID-based temp-file name in the Ralph Wiggum `Stop` hook enables a symlink/TOCTOU race that lets any local writer hijack or corrupt state-file updates - (File: `plugins/ralph-wiggum/hooks/stop-hook.sh`)

### Summary
The external report describes a Gnosis Safe deployment that uses a fully deterministic/guessable `create2` salt, letting any unprivileged party front-run or collide with the address, blocking or hijacking a privileged governance action. The equivalent bug class - a privileged, security-relevant filesystem operation performed against a predictable, non-exclusive path that an unprivileged writer can pre-occupy - exists in the bundled `ralph-wiggum` plugin's `Stop` hook, which builds its atomic-update temp file name from the shell PID alone.

### Finding Description
`plugins/ralph-wiggum/hooks/stop-hook.sh` implements the loop-control logic that fires on every `Stop` event while a Ralph loop is active. To persist the incremented iteration counter it does: [1](#0-0) 

`TEMP_FILE="${RALPH_STATE_FILE}.tmp.$$"` derives the "unique" filename solely from the current process's PID, with no `mktemp`, no `O_EXCL`, and no verification that the resulting path is not already a symlink or pre-existing file before the `sed ... > "$TEMP_FILE"` redirection creates/overwrites it. This is the same class of flaw the report calls out for `EnableFastConfirmAction.sol`: a "unique" identifier used for a security/state-relevant deterministic operation (there, a `create2` salt; here, a filename) that is actually guessable/collidable by anyone with write access to the same working directory.

Because PIDs are small, sequential, and reused within a bounded namespace (especially in sandboxes/containers), an unprivileged writer in the same workspace — e.g., a script the agent itself runs via the `Bash` tool, a build/test dependency, or another local process sharing the worktree — can pre-create `.claude/ralph-loop.local.md.tmp.<guessed-pid>` as a symlink pointing at an arbitrary file before the hook fires. When the hook subsequently does `sed "..." "$RALPH_STATE_FILE" > "$TEMP_FILE"`, the shell redirection follows the symlink and writes the rewritten frontmatter content through it into whatever target the attacker chose, and the following `mv "$TEMP_FILE" "$RALPH_STATE_FILE"` then unlinks the attacker's symlink from the intended location, replacing it with the loop's state file — masking that the earlier write went somewhere else. Alternatively, pre-creating the path as a directory or unwritable file causes the `sed` redirection to fail under `set -euo pipefail` at line 7, aborting the hook mid-update and potentially leaving the loop's state inconsistent or the loop uncontrollably blocked/unblocked depending on when the failure occurs. [2](#0-1) 

Notably, the plugin's own security-guidance sibling code is aware of this exact bug class and explicitly avoids it elsewhere: `plugins/security-guidance/hooks/_base.py` documents why `/tmp`-based, PID-suffixed files are dangerous ("TOCTOU / symlink-attack surface") and deliberately moves its debug log under a fixed, mode-0700 state directory instead: [3](#0-2) 

showing the codebase's own security guidance flags this pattern as unsafe, yet `stop-hook.sh` still relies on it for a real state-mutating write.

### Impact Explanation
An unprivileged local writer able to place a file/symlink in the project's `.claude/` directory before the `Stop` hook runs can (a) redirect the hook's write to an arbitrary file it has permission to reach through the symlink, effecting an unauthorized local file write/overwrite outside the intended workspace file, and/or (b) reliably disrupt the Ralph loop's state tracking (denial of service on the automation feature, or silent corruption of the iteration counter), mirroring the report's "any user can... block the usage" and front-run/collision impact on a security-relevant deterministic identifier.

### Likelihood Explanation
Exploitation requires only ordinary filesystem write access to the same project directory the loop operates in (no elevated privilege) and predicting/guessing a small-range PID, which is realistic in constrained sandbox/container PID namespaces or via brute-force pre-creation of a spread of candidate filenames. The hook runs automatically and unconditionally on every `Stop` event while any Ralph loop is active, making the race window recurrent and easy to line up.

### Recommendation
- Short term: Replace `TEMP_FILE="${RALPH_STATE_FILE}.tmp.$$"` with `mktemp` in the same directory (or `mktemp --tmpdir=.claude`), and refuse to write if the resulting path is a symlink (`[ -L "$TEMP_FILE" ]` check) before the `sed` redirection; verify ownership/permissions of `RALPH_STATE_FILE`'s parent directory before trusting it.
- Long term: Apply the same non-predictable, symlink-safe temp-file discipline already documented/justified in `plugins/security-guidance/hooks/_base.py` consistently across all bundled hooks/plugins that perform "temp file + atomic `mv`" updates, and add a lint/test check across the plugin set for `.tmp.$$`-style patterns.

### Proof of Concept
1. Start a Ralph loop so `.claude/ralph-loop.local.md` exists and the `Stop` hook is armed (per `plugins/ralph-wiggum/hooks/stop-hook.sh`, lines 1-18).
2. In the same working directory, run a script (e.g., via a spawned `Bash` tool call or any co-located process) that repeatedly creates `ln -s /path/to/target .claude/ralph-loop.local.md.tmp.<pid>` for a range of plausible PIDs around the expected hook process ID.
3. Trigger a `Stop` event; when the hook's PID matches a pre-created symlink, `sed ... > "$TEMP_FILE"` (`stop-hook.sh` line 155) writes the rewritten frontmatter through the symlink into `/path/to/target`, and the subsequent `mv` (line 156) silently replaces the symlink with the real state file, hiding the redirected write.
4. Observe that `/path/to/target` now contains attacker-influenced content, or, if the pre-created path is instead an unwritable file/directory, observe the hook aborting under `set -euo pipefail`, blocking/corrupting the loop's iteration tracking.

### Citations

**File:** plugins/ralph-wiggum/hooks/stop-hook.sh (L1-18)
```shellscript
#!/bin/bash

# Ralph Wiggum Stop Hook
# Prevents session exit when a ralph-loop is active
# Feeds Claude's output back as input to continue the loop

set -euo pipefail

# Read hook input from stdin (advanced stop hook API)
HOOK_INPUT=$(cat)

# Check if ralph-loop is active
RALPH_STATE_FILE=".claude/ralph-loop.local.md"

if [[ ! -f "$RALPH_STATE_FILE" ]]; then
  # No active loop - allow exit
  exit 0
fi
```

**File:** plugins/ralph-wiggum/hooks/stop-hook.sh (L152-156)
```shellscript
# Update iteration in frontmatter (portable across macOS and Linux)
# Create temp file, then atomically replace
TEMP_FILE="${RALPH_STATE_FILE}.tmp.$$"
sed "s/^iteration: .*/iteration: $NEXT_ITERATION/" "$RALPH_STATE_FILE" > "$TEMP_FILE"
mv "$TEMP_FILE" "$RALPH_STATE_FILE"
```

**File:** plugins/security-guidance/hooks/_base.py (L13-22)
```python
# Debug log file. Lives under the plugin state dir (default ~/.claude/security/)
# rather than /tmp because /tmp is world-writable on multi-user hosts (TOCTOU /
# symlink-attack surface, cross-user log leakage). Overridable per-process via
# SECURITY_GUIDANCE_DEBUG_LOG, or per-state-dir via SECURITY_WARNINGS_STATE_DIR.
_DEFAULT_STATE_DIR = os.path.expanduser(
    os.environ.get("SECURITY_WARNINGS_STATE_DIR") or "~/.claude/security"
)
DEBUG_LOG_FILE = os.environ.get("SECURITY_GUIDANCE_DEBUG_LOG") or os.path.join(
    _DEFAULT_STATE_DIR, "log.txt"
)
```
