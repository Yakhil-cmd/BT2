Confirmed: `$ARGUMENTS` is expanded unquoted in `plugins/ralph-wiggum/commands/ralph-loop.md` (`"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS`), which means bash word-splits the user-supplied prompt text on whitespace before it ever reaches `setup-ralph-loop.sh`. Because of this, any literal `--max-iterations` or `--completion-promise` substring that appears as a whitespace-delimited token anywhere in what the user intended as free-text prompt content will arrive as its own separate `argv` element and be matched exactly by the `case` statement in the script.

### Title
Unquoted `$ARGUMENTS` expansion lets prompt text be reparsed as `--max-iterations`/`--completion-promise` flags - (File: plugins/ralph-wiggum/commands/ralph-loop.md)

### Summary
The `/ralph-loop` command invokes `setup-ralph-loop.sh` with `$ARGUMENTS` unquoted, so the shell performs word-splitting on the entire prompt string before argument parsing occurs. An attacker-influenced or user-supplied prompt that happens to contain the literal tokens `--max-iterations` or `--completion-promise` (e.g., pasted from an issue, PR, or repository file into the prompt) will be word-split into standalone tokens and exactly matched by the `case` statement in `setup-ralph-loop.sh`, hijacking `MAX_ITERATIONS`/`COMPLETION_PROMISE` even though the user only intended plain text.

### Finding Description
`plugins/ralph-wiggum/commands/ralph-loop.md` line 13 runs: [1](#0-0) 
Because `$ARGUMENTS` is not quoted, the shell splits it on `IFS` whitespace into separate positional parameters before `setup-ralph-loop.sh` starts its own `while [[ $# -gt 0 ]]` loop. Inside the script, the `case $1 in ... --max-iterations) ... ;; --completion-promise) ... ;; *) PROMPT_PARTS+=("$1") ;; esac` block does exact literal matching against each already-split token: [2](#0-1) 
The script itself only performs *exact* token matching (not substring/glob matching), so an attacker cannot embed the flag "mid-argument" inside a single quoted token to trigger it — but the upstream unquoted expansion of `$ARGUMENTS` means the attacker doesn't need to; the shell has already broken the prompt into individual words by the time the script sees it. Thus a prompt like:
`Please summarize repo --max-iterations 999999999 and be concise`
is intended by the user as one continuous instruction, but is delivered to the script as separate argv tokens, causing `--max-iterations 999999999` to be consumed as the flag/value pair while the surrounding words go into `PROMPT_PARTS`. The same applies to `--completion-promise`, and repeating the flag multiple times simply causes the last occurrence to win (`shift 2` each time), which is a straightforward consequence of last-flag-wins parsing combined with the unintended tokenization.

There is no validation that these flags only originate from an explicit, distinct slash-command argument; the frontmatter `argument-hint` in `plugins/ralph-wiggum/commands/ralph-loop.md` line 3 documents the flags as separate arguments, but nothing enforces that a flag string embedded in narrative prompt text is treated as literal data rather than a control token — the unquoted `$ARGUMENTS` expansion is the root cause. [3](#0-2) 

### Impact Explanation
An attacker who can influence the text a user pastes into the `/ralph-loop` prompt (e.g., copying instructions from an issue/PR/README containing the string `--max-iterations 999999999999` or repeated `--completion-promise` tokens) can set `MAX_ITERATIONS` to an attacker-chosen value or override `COMPLETION_PROMISE`, causing the Ralph stop-hook loop to run for a very long/effectively unbounded number of iterations or with a promise phrase the user never intended, consuming resources and diverging from user intent. This matches the "unauthorized modification of loop control state (unbounded iterations) from attacker-supplied text" impact described in the question.

### Likelihood Explanation
Feasibility is moderate: it requires the victim to copy/paste or otherwise include text containing the exact flag string as a standalone word (surrounded by whitespace) into the `/ralph-loop` prompt. This is a plausible scenario in repos where users copy multi-line task descriptions from issues/PRs without noticing an embedded `--max-iterations` string, especially since such strings are the documented usage syntax and prompt writers might reasonably use similar dash-flag notation for other purposes. It is deterministic and repeatable once the tokenization occurs — root cause is the unquoted `$ARGUMENTS` expansion in the command file, not any bug within `setup-ralph-loop.sh`'s own exact-match `case` parsing.

### Recommendation
Quote `$ARGUMENTS` to preserve it as intended, or better, redesign the command interface so the free-text prompt and control flags cannot be conflated:
1. Change `plugins/ralph-wiggum/commands/ralph-loop.md` line 13 to pass the prompt as a single opaque token (e.g., via an environment variable or a `--` separator convention) rather than relying on shell word-splitting of `$ARGUMENTS`.
2. In `setup-ralph-loop.sh`, require flags to appear only before a `--` separator or only as a fixed trailing/leading segment, and treat everything else literally as prompt text.
3. Alternatively, document and enforce that `--max-iterations`/`--completion-promise` must be the command's structured arguments (parsed by the slash-command framework itself, not free-text splitting) so raw prompt content is never re-tokenized as flags.

### Proof of Concept
Integration test:
```bash
# Simulate the command file's unquoted expansion behavior
ARGUMENTS="Please refactor the code --max-iterations 999999999 as needed"
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS   # unquoted, as in ralph-loop.md
grep '^max_iterations:' .claude/ralph-loop.local.md
# Expected (vulnerable) result: max_iterations: 999999999
# Expected (fixed) result: max_iterations should remain 0 (unlimited/default) and
# "--max-iterations 999999999" should appear verbatim inside the prompt body.
```
Fuzz/invariant test for `setup-ralph-loop.sh` directly (to confirm the script's own case-matching is exact, isolating the bug to the caller):
```bash
for tok in "prefix--max-iterations" "--max-iterations-suffix" "--Max-Iterations" "-- max-iterations"; do
  ./setup-ralph-loop.sh "$tok" 5 "some prompt"
  # assert MAX_ITERATIONS stays 0 for all these near-miss/adversarially-cased tokens,
  # confirming exact-match case parsing is not itself exploitable via casing/embedding.
done
```
The second test is expected to pass (no vulnerability in `setup-ralph-loop.sh`'s parser itself), while the first test demonstrates the actual exploitable path via the unquoted `$ARGUMENTS` expansion in `ralph-loop.md`.

### Citations

**File:** plugins/ralph-wiggum/commands/ralph-loop.md (L1-5)
```markdown
---
description: "Start Ralph Wiggum loop in current session"
argument-hint: "PROMPT [--max-iterations N] [--completion-promise TEXT]"
allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)"]
hide-from-slash-command-tool: "true"
```

**File:** plugins/ralph-wiggum/commands/ralph-loop.md (L12-14)
```markdown
```!
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS
```
```

**File:** plugins/ralph-wiggum/scripts/setup-ralph-loop.sh (L61-108)
```shellscript
    --max-iterations)
      if [[ -z "${2:-}" ]]; then
        echo "❌ Error: --max-iterations requires a number argument" >&2
        echo "" >&2
        echo "   Valid examples:" >&2
        echo "     --max-iterations 10" >&2
        echo "     --max-iterations 50" >&2
        echo "     --max-iterations 0  (unlimited)" >&2
        echo "" >&2
        echo "   You provided: --max-iterations (with no number)" >&2
        exit 1
      fi
      if ! [[ "$2" =~ ^[0-9]+$ ]]; then
        echo "❌ Error: --max-iterations must be a positive integer or 0, got: $2" >&2
        echo "" >&2
        echo "   Valid examples:" >&2
        echo "     --max-iterations 10" >&2
        echo "     --max-iterations 50" >&2
        echo "     --max-iterations 0  (unlimited)" >&2
        echo "" >&2
        echo "   Invalid: decimals (10.5), negative numbers (-5), text" >&2
        exit 1
      fi
      MAX_ITERATIONS="$2"
      shift 2
      ;;
    --completion-promise)
      if [[ -z "${2:-}" ]]; then
        echo "❌ Error: --completion-promise requires a text argument" >&2
        echo "" >&2
        echo "   Valid examples:" >&2
        echo "     --completion-promise 'DONE'" >&2
        echo "     --completion-promise 'TASK COMPLETE'" >&2
        echo "     --completion-promise 'All tests passing'" >&2
        echo "" >&2
        echo "   You provided: --completion-promise (with no text)" >&2
        echo "" >&2
        echo "   Note: Multi-word promises must be quoted!" >&2
        exit 1
      fi
      COMPLETION_PROMISE="$2"
      shift 2
      ;;
    *)
      # Non-option argument - collect all as prompt parts
      PROMPT_PARTS+=("$1")
      shift
      ;;
```
