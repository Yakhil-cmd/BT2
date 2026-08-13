### Title
Symlink following in `.claude` directory allows `setup-ralph-loop.sh` to write the Ralph loop state file outside the intended workspace - ([File: plugins/ralph-wiggum/scripts/setup-ralph-loop.sh])

### Summary
`setup-ralph-loop.sh`, invoked by `/ralph-loop` (`plugins/ralph-wiggum/commands/ralph-loop.md`), unconditionally runs `mkdir -p .claude` followed by `cat > .claude/ralph-loop.local.md` without verifying that `.claude` is a real directory rather than a symlink. If a cloned repository ships `.claude` as a symlink to a path outside the workspace root, both the directory creation (no-op, since `mkdir -p` succeeds when the target already resolves to an existing directory) and the state-file write transparently follow the symlink, causing the state file to be created/overwritten at an attacker-chosen location.

### Finding Description
- `plugins/ralph-wiggum/commands/ralph-loop.md` restricts the allowed tool to `Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)` [1](#0-0) , but that restriction only limits which *command* can be run — it does not constrain what paths the script itself touches.
- Inside the script, `mkdir -p .claude` and `cat > .claude/ralph-loop.local.md <<EOF ... EOF` are executed relative to CWD with no symlink check (`-L`/`readlink`) beforehand [2](#0-1) .
- `mkdir -p` treats an existing symlink-to-directory as satisfying the "directory exists" condition and does nothing further, and the subsequent shell redirection (`cat >`) follows the symlink when opening the target file for writing.
- `plugins/ralph-wiggum/hooks/stop-hook.sh` also references the state file via the same relative path `.claude/ralph-loop.local.md` [3](#0-2) , so all subsequent reads/updates (including the iteration counter rewrite via `sed`/`mv` at lines 152-156) also transparently traverse the same symlink.
- No code path in this plugin performs `realpath`/`readlink -f` validation or checks that resolved paths remain under the workspace root; the only symlink-aware code in the repo is unrelated (`plugins/security-guidance/hooks/gitutil.py`, `_base.py`, `review_api.py`), confirming this plugin has no such guard.

### Impact Explanation
This allows a malicious repository to redirect where Claude Code writes/updates loop-state content once the victim runs `/ralph-loop` in that checkout. The direct consequence is an out-of-workspace file write/overwrite at a location fully chosen by the attacker (wherever `.claude` symlinks to), and all subsequent hook reads/writes for the Ralph loop lifecycle operate on that external path instead of the intended workspace-scoped file. This is a workspace-confinement bypass (arbitrary file write/overwrite via symlink, with content controlled indirectly by the invoking user's prompt and the script's fixed YAML template) rather than a secret-exfiltration primitive, since the file's contents are simply what the script itself generates. The impact aligns with "unauthorized file action / workspace escape" categories rather than credential leakage.

### Likelihood Explanation
Requires the victim to clone/checkout an attacker-supplied repository that contains `.claude` as a symlink to a path outside the workspace, and then invoke `/ralph-loop` from that workspace. This is a plausible but non-trivial precondition — Claude Code users routinely operate inside arbitrary cloned repos, and git can store symlinks as tracked entries, making the setup reproducible. Exploitation is deterministic once the symlink and invocation occur, with no user interaction or approval step interposed at the file-write layer.

### Recommendation
Before creating or writing to `.claude` and `.claude/ralph-loop.local.md`, verify that `.claude` (if it exists) is a real directory and not a symlink (e.g., `[[ -L .claude ]] && { echo "refusing: .claude is a symlink" >&2; exit 1; }`), and additionally resolve the final state-file path with `realpath`/`readlink -f` and confirm it is still contained within the workspace root (`$(pwd)`) before writing. Apply the same guard in `stop-hook.sh` and `cancel-ralph.md` since they consume the same relative path.

### Proof of Concept
Integration test:
1. Create a temporary "workspace" directory `WS` and an external target directory `EXT` outside `WS`.
2. Inside `WS`, create `ln -s "$EXT" .claude` (symlinked directory).
3. `cd "$WS"` and run `setup-ralph-loop.sh "test prompt"`.
4. Assert that `EXT/ralph-loop.local.md` now exists (demonstrating escape) while `WS` still only contains the symlink (no real `.claude` directory was created), OR — after the fix — assert the script exits non-zero with an error and no file is created in `EXT`.
5. Repeat by invoking `stop-hook.sh` with a crafted `transcript_path` to show it also reads/mutates `EXT/ralph-loop.local.md` through the symlink, confirming the entire lifecycle operates outside the intended workspace root.

### Citations

**File:** plugins/ralph-wiggum/commands/ralph-loop.md (L4-4)
```markdown
allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)"]
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
