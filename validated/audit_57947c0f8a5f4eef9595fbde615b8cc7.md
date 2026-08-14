### Title
`.claude` symlink pre-created by malicious repo causes `setup-ralph-loop.sh` to write state file outside the workspace - ([File: plugins/ralph-wiggum/scripts/setup-ralph-loop.sh])

### Summary
The `/ralph-loop` slash command runs `setup-ralph-loop.sh` in the current working directory (the cloned repo), which does `mkdir -p .claude` and then `cat > .claude/ralph-loop.local.md <<EOF`. Neither call checks whether `.claude` is a symlink, so a malicious repository can ship `.claude` as a symlink to an external directory and have the loop-control state file written there instead of inside the workspace.

### Finding Description
`setup-ralph-loop.sh` is invoked by the `ralph-loop` command directly against the current directory (`plugins/ralph-wiggum/commands/ralph-loop.md`, which runs `"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS` with `allowed-tools: ["Bash(...)"]`) [1](#0-0) . The script itself performs:

```
mkdir -p .claude
...
cat > .claude/ralph-loop.local.md <<EOF
...
EOF
``` [2](#0-1) 

`mkdir -p` treats an existing symlink to a directory as success (it does not create a new directory and does not error), and the subsequent `cat >` redirection follows the symlink and writes through it to whatever target the symlink points to. There is no `-L`/`readlink`/`realpath` check anywhere in the script or elsewhere in the repo guarding `.claude` creation (confirmed via search — no symlink/realpath checks exist in `plugins/ralph-wiggum/**`), so an attacker who controls repository content (e.g., commits a `.claude` symlink pointing to `/tmp/attacker-dir` or another path outside the repo) can cause the loop state file to be written outside the intended workspace directory when the victim clones the repo and runs `/ralph-loop`.

### Impact Explanation
Scoped impact is confined to writing the Ralph loop's automation/state file (`ralph-loop.local.md`, which contains the loop's iteration count, completion promise, and prompt text) to an attacker-chosen directory outside the cloned workspace. This is a workspace-confinement violation for automation state files — it does not itself grant arbitrary file content control (the file content is loop metadata, not attacker-controlled arbitrary bytes beyond the prompt/promise text), but it demonstrates that filesystem writes performed by this script are not constrained to the project directory when `.claude` is attacker-supplied as a symlink.

### Likelihood Explanation
The precondition is that the victim clones/opens a malicious repository that contains a `.claude` symlink and then runs the `/ralph-loop` command in that workspace. No additional privileges, key leaks, or social engineering beyond "clone this repo and use ralph-loop" are required, and the write path (`mkdir -p` + `cat >`) is deterministic and reproducible every time.

### Recommendation
Before creating/writing to `.claude`, verify it is not a symlink (e.g., `if [ -L .claude ]; then echo "refusing to use symlinked .claude" >&2; exit 1; fi`), or resolve the path with `realpath` and confirm it is contained within the intended project root before performing `mkdir -p` and the heredoc write. Apply the same guard to any other scripts in the repo that blindly `mkdir -p .claude` (e.g., `plugins/hookify/commands/hookify.md`).

### Proof of Concept
Integration test:
1. In a temp workspace, create an external temp directory `EXT=$(mktemp -d)`.
2. `ln -s "$EXT" .claude` in the workspace root (simulating a malicious repo shipping `.claude` as a symlink).
3. Run `setup-ralph-loop.sh "test prompt" --max-iterations 1`.
4. Assert that `ls -l .claude` still shows a symlink (i.e., the script refused to replace/traverse it) OR assert the script exits non-zero with an error, and that `EXT/ralph-loop.local.md` does NOT exist.
5. Currently (pre-fix), the test would show `EXT/ralph-loop.local.md` created with loop state content, proving the write escaped the workspace root via the symlink.

### Citations

**File:** plugins/ralph-wiggum/commands/ralph-loop.md (L12-14)
```markdown
```!
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS
```
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
