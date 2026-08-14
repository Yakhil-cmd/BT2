### Title
Symlinked `.claude` directory in a cloned repo allows `setup-ralph-loop.sh` to write the Ralph loop state file outside the workspace - (File: `plugins/ralph-wiggum/scripts/setup-ralph-loop.sh`)

### Summary
`setup-ralph-loop.sh` runs `mkdir -p .claude` followed by `cat > .claude/ralph-loop.local.md` with no check that `.claude` is a real directory rather than a symlink. If a cloned repository contains a committed symlink named `.claude` pointing outside the workspace, `mkdir -p` silently succeeds (no-op on an existing path) and the subsequent `cat >` write is redirected through the symlink to the attacker-chosen external location. `stop-hook.sh` then reads and rewrites the same path (`.claude/ralph-loop.local.md`) on every loop iteration, perpetuating file I/O outside the intended workspace boundary.

### Finding Description
In `plugins/ralph-wiggum/scripts/setup-ralph-loop.sh`: [1](#0-0) 
`mkdir -p .claude` does not fail or warn if `.claude` already exists as a symlink to a directory - it is a documented no-op for existing paths of any type that resolves to a directory. The following `cat > .claude/ralph-loop.local.md <<EOF ... EOF` then writes through that symlink to wherever it points, because the shell's redirection follows the symlinked directory component transparently.

Nowhere in the script (nor in `stop-hook.sh`) is there a check with `[[ -L .claude ]]`, `readlink`, or `realpath` to detect that `.claude` is a symlink or to verify the resolved path stays within the repository root; the `grep_search` for `symlink|-L |readlink|realpath` returns no hits in either `setup-ralph-loop.sh` or `hooks/stop-hook.sh`. [2](#0-1) 
`stop-hook.sh` performs the identical unguarded path resolution (`RALPH_STATE_FILE=".claude/ralph-loop.local.md"`), so once the symlink exists, every subsequent hook invocation reads/writes through it as well, including the atomic-update `sed`/`mv` sequence: [3](#0-2) 

Attack flow: attacker commits a symlink `.claude -> /tmp/outside` (or any absolute/relative out-of-workspace target) into a repository. Victim clones the repo and invokes `/ralph-loop <prompt>`, which invokes `setup-ralph-loop.sh`. `mkdir -p .claude` is a no-op on the pre-existing symlink, and the `cat >` write lands in `/tmp/outside/ralph-loop.local.md` instead of the workspace. Every following Stop-hook cycle continues to read/update that external file.

### Impact Explanation
This is a workspace-confinement bypass: file creation and iterative read/write/atomic-replace operations that are assumed to be scoped to the project's `.claude/` directory instead target a location outside the approved workspace root, chosen entirely by attacker-controlled repository content. Depending on the symlink target, this can overwrite or corrupt arbitrary writable files/directories that the running user has access to (e.g. other project directories, home-directory config, `/tmp` shared paths used by other tools), and it does so repeatedly and automatically (once per Stop-hook iteration) with no confirmation prompt.

### Likelihood Explanation
Requires only that: (1) the attacker can get a symlinked `.claude` entry into a repository the victim clones (trivial - just a git commit containing a symlink), and (2) the victim runs `/ralph-loop` in that workspace. No admin privileges, credentials, or social engineering beyond "use a plugin command in a cloned repo" are needed. Git preserves symlinks by default on POSIX systems, and `mkdir -p`/`cat >` follow them without any warning, making this fully reproducible.

### Recommendation
Before writing to `.claude/ralph-loop.local.md`, in both `setup-ralph-loop.sh` and `hooks/stop-hook.sh`:
- Check `[[ -L .claude ]]` and refuse to proceed (print an error and exit non-zero) if `.claude` is a symlink.
- Alternatively/also, resolve the real path with `realpath -e .claude` (or Python/`readlink -f`) and verify it is still inside the current working directory / workspace root before performing `mkdir -p` or writing/reading the state file.
- Apply the same guard to the final resolved path of `ralph-loop.local.md` itself, not just the parent directory, in case `.claude` is a real directory but the file itself is a symlink.

### Proof of Concept
Integration test:
1. Create a temp "workspace" directory `ws/`.
2. Inside `ws/`, create a symlink: `ln -s /tmp/outside-target .claude` (create `/tmp/outside-target` first, it must resolve to a directory).
3. `cd ws && bash plugins/ralph-wiggum/scripts/setup-ralph-loop.sh "test prompt"`.
4. Assert that `/tmp/outside-target/ralph-loop.local.md` was created (demonstrating escape) while `ws/.claude` remains a symlink (not replaced with a real directory) — this confirms the write escaped the workspace.
5. Expected behavior after fix: the script should detect `.claude` is a symlink, print an error, and exit non-zero without creating any file in `/tmp/outside-target`.
6. Follow-up: invoke `hooks/stop-hook.sh` with a minimal `HOOK_INPUT` while `.claude` is still the malicious symlink and assert it likewise refuses to operate through the symlinked path.

### Citations

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

**File:** plugins/ralph-wiggum/hooks/stop-hook.sh (L13-21)
```shellscript
RALPH_STATE_FILE=".claude/ralph-loop.local.md"

if [[ ! -f "$RALPH_STATE_FILE" ]]; then
  # No active loop - allow exit
  exit 0
fi

# Parse markdown frontmatter (YAML between ---) and extract values
FRONTMATTER=$(sed -n '/^---$/,/^---$/{ /^---$/d; p; }' "$RALPH_STATE_FILE")
```

**File:** plugins/ralph-wiggum/hooks/stop-hook.sh (L152-156)
```shellscript
# Update iteration in frontmatter (portable across macOS and Linux)
# Create temp file, then atomically replace
TEMP_FILE="${RALPH_STATE_FILE}.tmp.$$"
sed "s/^iteration: .*/iteration: $NEXT_ITERATION/" "$RALPH_STATE_FILE" > "$TEMP_FILE"
mv "$TEMP_FILE" "$RALPH_STATE_FILE"
```
