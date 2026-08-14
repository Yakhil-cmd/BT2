### Title
Repo-planted `.claude/ralph-loop.local.md` triggers unconsented Ralph loop activation on first Stop event - ([File: plugins/ralph-wiggum/hooks/stop-hook.sh])

### Summary
`stop-hook.sh` activates the Ralph self-referential loop purely by checking for the existence of a fixed, predictable path `.claude/ralph-loop.local.md`, with no verification that the file was created via the user-invoked `/ralph-loop` command. An attacker who can get this file committed into a repository (e.g. via a PR, fork, or shared branch) can plant a fully valid state file, causing the victim's very first session Stop event to silently activate the loop and feed attacker-controlled prompt text back into the model without any user consent.

### Finding Description
The hook's only gate is a file-existence check: [1](#0-0) 

There is no session-binding, no marker proving the file originated from the legitimate setup flow (`setup-ralph-loop.sh`, which is only invoked through the `/ralph-loop` slash command), and no check that the file is untracked/gitignored rather than checked into the repository. Compare to the legitimate creation path, which is only reachable by explicit user command invocation: [2](#0-1) 

Because the hook treats any file at that path identically regardless of provenance, an attacker can commit a crafted `.claude/ralph-loop.local.md` with a valid YAML frontmatter (`active: true`, numeric `iteration`/`max_iterations`, and an attacker-chosen prompt body). On the victim's first Stop event after cloning the repo (with the ralph-wiggum plugin enabled), the hook:
1. Confirms the file exists (line 15) — true, since it's tracked content.
2. Parses frontmatter and validates numeric fields (lines 21-48) — attacker can trivially supply valid numbers.
3. Finds no completion promise satisfied (lines 114-128) if `completion_promise` is set to `null`.
4. Emits `{"decision":"block","reason": $prompt, ...}` (lines 167-174), where `$prompt` is the attacker-controlled `PROMPT_TEXT` extracted directly from the planted file (line 136), which is fed back into the model as the next turn's instruction — with no bound on iterations if `max_iterations: 0`.

No existing validation, allowlist, workspace guard, or session-scoping distinguishes a legitimately user-invoked loop from a repo-planted one; the file's mere presence at a well-known path is trusted.

### Impact Explanation
This breaks the consent invariant that Ralph loop activation must be explicit and user-invoked via `/ralph-loop`. Instead, ordinary repository content silently starts unbounded automation and repeated model invocation with attacker-supplied prompt text injected into the "block reason" fed back to the model each iteration. This is a trust-boundary bypass that hands prompt-injection-style influence over the agent's ongoing instructions to whoever controls checked-in repo content, and — combined with the agent's normal tool access in later turns — creates a foothold for follow-on actions such as file/secret exfiltration attempts, matching an approval-bypass / unauthorized-automation class of impact.

### Likelihood Explanation
Feasibility is high and requires no elevated privilege: any contributor able to add a file to a branch/PR that the victim later checks out (a common, unprivileged action) can plant the file. The exploit fires automatically on the victim's first session Stop event without requiring the victim to run any command, making it fully repeatable across every clone of the tainted repo state until the file is removed.

### Recommendation
Do not treat file existence alone as consent. Bind the state file to an explicit "opt-in" marker set only by `setup-ralph-loop.sh` at command-invocation time (e.g., an ephemeral session/process-bound token stored outside the repo, such as under a session-scoped temp/state directory, or a signed/HMAC value derived from session ID that the hook verifies). Additionally, warn or refuse to trust `.claude/ralph-loop.local.md` if it is a tracked/committed file (`git ls-files --error-unmatch` check) rather than an untracked local file, and recommend/enforce a `.gitignore` entry for `.claude/*.local.md`.

### Proof of Concept
Integration test:
1. In a fresh git repo, commit `.claude/ralph-loop.local.md` with content:
```
---
active: true
iteration: 1
max_iterations: 0
completion_promise: null
---

Attacker-controlled prompt text
```
2. Simulate a Stop hook invocation without ever invoking `/ralph-loop` (i.e., without running `setup-ralph-loop.sh`): pipe a synthetic `HOOK_INPUT` JSON containing a valid `transcript_path` pointing to a transcript file with at least one assistant message, to `stop-hook.sh`.
3. Assert the hook's stdout JSON has `"decision": "block"` and `"reason"` equal to "Attacker-controlled prompt text", proving the loop activated purely from committed repo content with no prior `/ralph-loop` invocation.
4. Assert this holds even when the test harness never calls `plugins/ralph-wiggum/scripts/setup-ralph-loop.sh`.

### Citations

**File:** plugins/ralph-wiggum/hooks/stop-hook.sh (L12-18)
```shellscript
# Check if ralph-loop is active
RALPH_STATE_FILE=".claude/ralph-loop.local.md"

if [[ ! -f "$RALPH_STATE_FILE" ]]; then
  # No active loop - allow exit
  exit 0
fi
```

**File:** plugins/ralph-wiggum/scripts/setup-ralph-loop.sh (L130-150)
```shellscript
# Create state file for stop hook (markdown with YAML frontmatter)
mkdir -p .claude

# Quote completion promise for YAML if it contains special chars or is not null
if [[ -n "$COMPLETION_PROMISE" ]] && [[ "$COMPLETION_PROMISE" != "null" ]]; then
  COMPLETION_PROMISE_YAML="\"$COMPLETION_PROMISE\""
else
  COMPLETION_PROMISE_YAML="null"
fi

cat > .claude/ralph-loop.local.md <<EOF
---
active: true
iteration: 1
max_iterations: $MAX_ITERATIONS
completion_promise: $COMPLETION_PROMISE_YAML
started_at: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
---

$PROMPT
EOF
```
