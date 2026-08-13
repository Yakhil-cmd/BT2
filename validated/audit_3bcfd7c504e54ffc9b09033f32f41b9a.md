### Title
Workspace escape via attacker-committed `.claude` symlink in `setup-ralph-loop.sh` / `stop-hook.sh` - ([File: plugins/ralph-wiggum/scripts/setup-ralph-loop.sh])

### Summary
`setup-ralph-loop.sh` runs `mkdir -p .claude` followed by `cat > .claude/ralph-loop.local.md` without ever checking whether `.claude` is a symlink. If a cloned repository contains a committed symlink named `.claude` pointing outside the workspace, `mkdir -p` silently succeeds (no-op on an existing directory-like path) and the subsequent `cat >` write is redirected through the symlink to an attacker-chosen location outside the workspace root. `hooks/stop-hook.sh` then reads/writes/deletes that same `.claude/ralph-loop.local.md` path on every subsequent Stop-hook invocation, repeatedly operating outside the intended workspace boundary.

### Finding Description
Both scripts reference the state file purely by the relative, unresolved path `.claude/ralph-loop.local.md`:

- `setup-ralph-loop.sh` line 131: `mkdir -p .claude` [1](#0-0)  followed by the heredoc write at line 140: `cat > .claude/ralph-loop.local.md <<EOF ... EOF` [2](#0-1) .
- `stop-hook.sh` sets `RALPH_STATE_FILE=".claude/ralph-loop.local.md"` and performs reads (`-f` test), `sed`/`mv` atomic updates, and `rm` on that path across the entire hook lifecycle [3](#0-2) [4](#0-3) .

Neither script calls `readlink`, `realpath -e`, `test -L`, or performs any check that `.claude` resolves inside the workspace root — a repo-wide `grep` for `symlink|realpath|readlink` shows no such checks exist in either the `ralph-wiggum` plugin's scripts or hooks. If an attacker commits `.claude` as a symlink to an out-of-workspace directory (e.g., `/tmp/outside` or a relative `../../etc`-style escape) in a repository that a user later clones and opens with Claude Code, invoking `/ralph-loop` causes:
1. `mkdir -p .claude` to be a no-op because the symlink target already exists as a directory (or `mkdir -p` simply tolerates the existing path).
2. `cat > .claude/ralph-loop.local.md` to write the loop state file through the symlink, landing at the attacker-controlled external path.
3. Every following Stop-hook invocation in `stop-hook.sh` to transparently follow the same symlink for reads, atomic `sed`/`mv` rewrites, and eventual `rm`, all operating outside the approved workspace root for the lifetime of the loop.

### Impact Explanation
This breaks workspace confinement: file creation, modification, and deletion driven by a "safe" relative path silently escape to a location chosen by repository content rather than the user or the tool's sandbox boundary. Scoped impact is limited to file writes/reads/deletes redirected outside the workspace (matching the "workspace escape" / file mutation boundary bypass bounty category), reachable purely from ordinary repository content (a committed symlink) with no privileged access, key leakage, or social engineering required.

### Likelihood Explanation
Feasibility is high and fully repeatable: the only precondition is that the victim clones/opens a repository containing a committed symlink named `.claude` pointing outside the workspace, then invokes `/ralph-loop` (a normal, documented plugin command). Git supports committing symlinks natively, so this is trivially achievable by anyone who can get a user to open an attacker-authored repository — a common trust boundary in Claude Code's plugin/command flow. The bug reproduces deterministically every time the command runs against such a repo.

### Recommendation
Before creating or writing `.claude/ralph-loop.local.md`, resolve and validate the path stays within the workspace root:
- Use `test -L .claude` (or `readlink -f .claude`) to detect a symlink before `mkdir -p`, and refuse to proceed (exit with an error) if `.claude` is a symlink pointing outside the workspace root (compare `realpath -e .claude` against `realpath "$PWD"`/workspace root prefix).
- Apply the same guard in `stop-hook.sh` before any read/write/`rm` of `RALPH_STATE_FILE`.
- Consider creating state files with `O_NOFOLLOW`-equivalent semantics (e.g., `set -o noclobber` plus explicit symlink checks, or writing to a resolved absolute path validated against the workspace boundary).

### Proof of Concept
Integration test outline:
1. Create a temporary "workspace" directory `WORKSPACE`.
2. Inside `WORKSPACE`, create `ln -s /tmp/outside_target .claude` (create `/tmp/outside_target` empty beforehand, simulating a committed symlink checked out from a malicious repo).
3. `cd $WORKSPACE` and run `bash plugins/ralph-wiggum/scripts/setup-ralph-loop.sh "test prompt"`.
4. Assert that `/tmp/outside_target/ralph-loop.local.md` now exists (proving the write escaped the workspace) and that `WORKSPACE/.claude` remains a symlink (proving `mkdir -p` did not fail/detect it).
5. Simulate a Stop-hook call: pipe a minimal `{"transcript_path": "..."}` JSON into `plugins/ralph-wiggum/hooks/stop-hook.sh` from within `WORKSPACE`, and assert it reads/mutates `/tmp/outside_target/ralph-loop.local.md` rather than refusing to operate through the symlink.
6. Expected (fixed) behavior: step 3 should fail with an explicit error ("`.claude` is a symlink, refusing to write state file outside workspace") and no file should be created at `/tmp/outside_target/ralph-loop.local.md`.

### Citations

**File:** plugins/ralph-wiggum/scripts/setup-ralph-loop.sh (L130-131)
```shellscript
# Create state file for stop hook (markdown with YAML frontmatter)
mkdir -p .claude
```

**File:** plugins/ralph-wiggum/scripts/setup-ralph-loop.sh (L140-150)
```shellscript
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

**File:** plugins/ralph-wiggum/hooks/stop-hook.sh (L13-18)
```shellscript
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
