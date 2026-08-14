### Title
Unconditional overwrite of active ralph-loop.local.md allows silent state/prompt hijack without re-consent - ([File: plugins/ralph-wiggum/scripts/setup-ralph-loop.sh])

### Summary
`setup-ralph-loop.sh` unconditionally writes `.claude/ralph-loop.local.md` via `cat > ... <<EOF` with no check for a pre-existing active loop, so a second invocation of `/ralph-loop` silently replaces the previously consented prompt/iteration-limit/completion-promise binding with new attacker-influenced content. The `stop-hook.sh` then trusts this file as-is on the very next Stop event and feeds its `PROMPT_TEXT` back to the model as the blocking `reason`, without ever re-validating that the current session's approved task matches the file's contents.

### Finding Description
In `plugins/ralph-wiggum/scripts/setup-ralph-loop.sh`, after parsing `$ARGUMENTS` into `PROMPT`, `MAX_ITERATIONS`, and `COMPLETION_PROMISE`, the script does: [1](#0-0) 

There is no read of the existing `.claude/ralph-loop.local.md`, no check of its `active:` field, and no confirmation prompt before the `cat >` (truncating redirect) replaces it. If a ralph loop is already active (state file exists with `active: true`, some `iteration`, `max_iterations`, and `completion_promise` bound to an originally-approved task), a second `/ralph-loop <new prompt>` invocation — however triggered — overwrites the file with `iteration: 1` and the new `PROMPT`/`MAX_ITERATIONS`/`COMPLETION_PROMISE`, with no diffing, warning, or explicit re-consent step.

`stop-hook.sh` has no way to detect this drift: it only checks that `.claude/ralph-loop.local.md` exists and that `iteration`/`max_iterations` are well-formed integers before extracting `PROMPT_TEXT` via `awk` and feeding it back to the model through the `"decision":"block","reason":$prompt` JSON output: [2](#0-1) 

Because the hook treats whatever is currently in the file as ground truth, any content written by the second `setup-ralph-loop.sh` run — regardless of who or what triggered it — becomes the next prompt injected back into the model's context on the next Stop event.

### Impact Explanation
This allows silent replacement of a user-approved, scoped ralph-loop task (prompt, iteration cap, completion condition) with different content chosen by whatever triggered the second invocation, without any confirmation step. Since `stop-hook.sh` re-feeds `PROMPT_TEXT` to the model as a blocking `reason` on every Stop event, the new content is guaranteed to reach the model's context on the next loop iteration — effectively an unauthorized prompt/state-binding change that persists and auto-repeats. This matches an approval-bypass / trust-boundary weakening pattern: the file is meant to represent a single explicitly-consented loop configuration, but the script provides no session/task binding check to prevent it from being silently swapped out.

### Likelihood Explanation
This requires an active ralph loop already running and a mechanism to trigger `/ralph-loop` a second time with attacker-influenced `$ARGUMENTS`. `/ralph-loop` is a user-invoked slash command; whether "crafted PR automation" can cause the model to autonomously re-invoke it depends on separate trust boundaries (e.g., whether the model can be prompt-injected into re-running slash commands from repository/PR content), which I could not fully verify within this repo's indexed context — the command definition (`plugins/ralph-wiggum/commands/ralph-loop.md`) content was not retrievable in this session. Setting that external precondition aside, the setup script itself has zero idempotency/overwrite protection, which is a concrete, verifiable gap independent of how the second invocation is sourced.

### Recommendation
Before overwriting, have `setup-ralph-loop.sh` check for an existing `.claude/ralph-loop.local.md` with `active: true`; if found, either refuse to proceed and instruct the user to run `/cancel-ralph` first, or require an explicit `--force`/re-confirmation flag surfaced back to the user before truncating the file. Optionally have `stop-hook.sh` bind the state file to a session identifier so a mismatched rewrite is detectable.

### Proof of Concept
Integration test plan:
1. Run `setup-ralph-loop.sh "Task A" --completion-promise 'DONE A' --max-iterations 5`; capture resulting `.claude/ralph-loop.local.md` contents (prompt "Task A", promise "DONE A").
2. Without cancelling, run `setup-ralph-loop.sh "Task B (attacker prompt)" --completion-promise 'DONE B'`.
3. Assert (current behavior, demonstrating the bug): the file now contains "Task B" and `iteration: 1`, with no error, warning, or confirmation output — i.e., the second call exits 0 and the "Task A" state is silently gone.
4. Invoke `stop-hook.sh` with a synthetic hook input/transcript; assert the JSON `reason` field equals "Task B (attacker prompt)", proving the swapped prompt is fed to the model.
5. Expected fixed behavior: step 2 should either exit non-zero with an error ("an active ralph loop already exists; run /cancel-ralph first") or require an explicit `--force` flag, and without that flag the file must remain unchanged (still "Task A").

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

**File:** plugins/ralph-wiggum/hooks/stop-hook.sh (L130-174)
```shellscript
# Not complete - continue loop with SAME PROMPT
NEXT_ITERATION=$((ITERATION + 1))

# Extract prompt (everything after the closing ---)
# Skip first --- line, skip until second --- line, then print everything after
# Use i>=2 instead of i==2 to handle --- in prompt content
PROMPT_TEXT=$(awk '/^---$/{i++; next} i>=2' "$RALPH_STATE_FILE")

if [[ -z "$PROMPT_TEXT" ]]; then
  echo "⚠️  Ralph loop: State file corrupted or incomplete" >&2
  echo "   File: $RALPH_STATE_FILE" >&2
  echo "   Problem: No prompt text found" >&2
  echo "" >&2
  echo "   This usually means:" >&2
  echo "     • State file was manually edited" >&2
  echo "     • File was corrupted during writing" >&2
  echo "" >&2
  echo "   Ralph loop is stopping. Run /ralph-loop again to start fresh." >&2
  rm "$RALPH_STATE_FILE"
  exit 0
fi

# Update iteration in frontmatter (portable across macOS and Linux)
# Create temp file, then atomically replace
TEMP_FILE="${RALPH_STATE_FILE}.tmp.$$"
sed "s/^iteration: .*/iteration: $NEXT_ITERATION/" "$RALPH_STATE_FILE" > "$TEMP_FILE"
mv "$TEMP_FILE" "$RALPH_STATE_FILE"

# Build system message with iteration count and completion promise info
if [[ "$COMPLETION_PROMISE" != "null" ]] && [[ -n "$COMPLETION_PROMISE" ]]; then
  SYSTEM_MSG="🔄 Ralph iteration $NEXT_ITERATION | To stop: output <promise>$COMPLETION_PROMISE</promise> (ONLY when statement is TRUE - do not lie to exit!)"
else
  SYSTEM_MSG="🔄 Ralph iteration $NEXT_ITERATION | No completion promise set - loop runs infinitely"
fi

# Output JSON to block the stop and feed prompt back
# The "reason" field contains the prompt that will be sent back to Claude
jq -n \
  --arg prompt "$PROMPT_TEXT" \
  --arg msg "$SYSTEM_MSG" \
  '{
    "decision": "block",
    "reason": $prompt,
    "systemMessage": $msg
  }'
```
