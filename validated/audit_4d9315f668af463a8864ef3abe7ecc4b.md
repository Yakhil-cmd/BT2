### Title
Arbitrary file overwrite via symlink-following write in setup-ralph-loop.sh - ([File: plugins/ralph-wiggum/scripts/setup-ralph-loop.sh])

### Summary
`setup-ralph-loop.sh` writes the Ralph loop state directly to `.claude/ralph-loop.local.md` using shell `>` redirection without checking whether that path is a symlink. A malicious repository can pre-populate `.claude/ralph-loop.local.md` as a symlink pointing to an attacker-chosen file, so that when a victim runs `/ralph-loop` from that checkout, the script clobbers the symlink target instead of the intended state file.

### Finding Description
The setup script creates the `.claude` directory and then writes the loop state with a plain output redirection: [1](#0-0) 

`mkdir -p .claude` is a no-op if `.claude` already exists (e.g., checked into the attacker's repo), and `cat > .claude/ralph-loop.local.md <<EOF ... EOF` is standard bash redirection, which opens the target for writing and **follows symlinks** rather than truncating/replacing the symlink itself. There is no `-f`/`-L` check, `readlink`, or `test -L` guard anywhere in the script to detect that `.claude/ralph-loop.local.md` is a symlink before writing.

Exploit flow:
1. Attacker crafts a repository containing `.claude/ralph-loop.local.md` as a symlink (e.g., pointing to `~/.bashrc`, another project's config, or any file writable by the victim's user).
2. Victim clones/checks out the repo and runs `/ralph-loop <prompt>` from that directory.
3. `setup-ralph-loop.sh` executes `cat > .claude/ralph-loop.local.md <<EOF ... EOF`, which follows the symlink and overwrites the real target file with the Ralph loop YAML frontmatter + prompt content.
4. The victim's chosen file outside the intended `.claude` directory is silently corrupted/overwritten.

No existing validation, allowlist, or workspace guard intercepts this: the script only validates CLI argument formats (`--max-iterations`, `--completion-promise`) and never inspects the filesystem state of the target path before writing through it.

### Impact Explanation
This is a scoped arbitrary file overwrite: any file the victim's OS user has write permission to (via the symlink target) can be overwritten with attacker-influenced content (the Ralph state template, with iteration count/promise/prompt text), purely by the victim running the documented `/ralph-loop` slash command from a malicious checkout. This breaks workspace confinement — a plugin operation nominally scoped to `.claude/` inside the project can be redirected to mutate files anywhere the user has write access, including files outside the repository (e.g., dotfiles, shared configs), leading to corruption or potential follow-on compromise if the overwritten file is later trusted/executed (e.g., a shell rc file or another tool's config).

### Likelihood Explanation
Feasible and repeatable: the attacker only needs to commit a symlink into a git repository (git supports symlinks natively) and get the victim to run `/ralph-loop` from that checkout — a normal, documented usage flow requiring no special privileges, no social engineering beyond "use this repo," and no reliance on hooks/mocks. It is fully reproducible: the same symlink triggers the overwrite every time `/ralph-loop` is invoked from that directory.

### Recommendation
Before writing, explicitly check that `.claude/ralph-loop.local.md` is not a symlink (e.g., `if [[ -L .claude/ralph-loop.local.md ]]; then echo "refusing to write through symlink" >&2; exit 1; fi`), or write to a temp file within `.claude/` and atomically `mv` it into place only after confirming the destination is a regular file or does not exist, using `ln`-safe patterns (e.g., `rm -f` a detected symlink first, or use `install`/`cp --no-dereference` semantics). Apply the same symlink check to `.claude` itself in case it is also a symlink to an unexpected directory.

### Proof of Concept
Integration test:
1. In a temp directory, run `mkdir -p .claude`.
2. Create a sentinel file `sentinel.txt` with known content outside `.claude` (e.g., in the parent directory or elsewhere writable).
3. Create `ln -s ../sentinel.txt .claude/ralph-loop.local.md` (or an absolute path to any writable file).
4. Run `setup-ralph-loop.sh "test prompt"`.
5. Assert: `sentinel.txt` content has been overwritten with the Ralph loop YAML frontmatter (proving the symlink was followed and the target file was clobbered), and/or assert the script does NOT detect/refuse the symlink.
6. Expected secure behavior (currently failing): the script should detect `-L .claude/ralph-loop.local.md`, print an error, and exit non-zero without modifying `sentinel.txt`.

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
