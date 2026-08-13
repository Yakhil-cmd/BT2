### Title
`set -e` + bash post-increment arithmetic gotcha in `validate-agent.sh` causes premature exit that skips remaining error checks - (File: `plugins/plugin-dev/skills/agent-development/scripts/validate-agent.sh`)

### Summary
`validate-agent.sh` runs under `set -euo pipefail` and uses bare `((error_count++))` / `((warning_count++))` statements to tally issues, starting both counters at `0`. Because bash's `((expr++))` post-increment evaluates to the *pre-increment* value, the very first increment of either counter (`0 -> 1`) makes the arithmetic command return exit status `1`, and since that statement is unguarded (not part of an `if`/`&&`/`||`), `set -e` immediately terminates the script right there — long before it reaches the remaining field checks or the final tally/exit block at lines 205-217.

### Finding Description
The counters are declared once at the top of the script: [1](#0-0) 

Every subsequent issue increments one of them as a bare statement, e.g.: [2](#0-1) 

and the generic-name warning: [3](#0-2) 

`((warning_count++))` (or `((error_count++))`) when the counter's current value is `0` evaluates the post-increment expression to `0`, which `((...))` treats as command failure (exit status 1). Since the statement is not inside an `if` condition, `while`, or combined with `||`/`&&`, `set -e` fires and the whole script aborts immediately at that exact line — before running any of the later checks for `description`, `model`, `color`, or `SYSTEM_PROMPT`, and before ever reaching the intended pass/fail summary block: [4](#0-3) 

Because both counters start at `0`, this triggers on the **first** warning or error encountered in *any* run of the script — meaning the script essentially never reaches its own intended "count all issues, then decide" logic for the majority of real inputs (any file with ≥1 warning or error anywhere before the last check). The reported output is truncated to whatever was printed up to that point, and the true severity of the file (e.g. missing/invalid required fields later in the script) is never evaluated or reported.

An attacker can deliberately place a low-severity, easily satisfied warning condition early (e.g. `name: helper` which trips the generic-name warning at line 84-87) in an otherwise malicious/malformed agent file. This forces the script to die at that early low-severity warning, exit non-zero, and never execute the checks for `description`/`model`/`color`/`SYSTEM_PROMPT` that would have surfaced the actual structural problems. Anything a calling wrapper does with the exit code (e.g. `validate-agent.sh file.md || proceed_with_reduced_scrutiny`) is thus driven by an arbitrary, attacker-influenced early-exit point rather than a true tally of the file's real problems, and the emitted log looks like a single trivial warning rather than a fuller error report.

### Impact Explanation
This is a control-flow/exit-code correctness bug that decouples the script's exit status and printed diagnostics from the real validation outcome. Any automation gating on this script's exit code (pass/fail branching, "needs manual review" fallback, CI gating) is acting on incomplete/incorrect information: a file can look like it failed for a trivial cosmetic reason (single generic-name warning) when in fact deeper required-field/model/system-prompt errors were never checked because execution halted early. This matches an approval-bypass / trust-boundary-integrity issue in review tooling rather than direct RCE, since the underlying validator can be made to under-report on virtually every real invocation.

### Likelihood Explanation
Highly feasible and essentially deterministic: because both counters always start at `0`, the bug fires on the very first warning or error the script encounters in *every* run where at least one issue exists anywhere in the file (an extremely common case — e.g., missing `<example>` block, generic name, unknown model/color, etc.). No special crafting is needed beyond ordering an easy-to-trigger low-severity condition earlier than more serious ones, which is trivial for an attacker authoring the `agent.md` file.

### Recommendation
Avoid bare `((var++))` under `set -e`; use `error_count=$((error_count + 1))` / `warning_count=$((warning_count + 1))` (assignment form never returns a "false" exit status), or guard the increments with `|| true`, or use `: $((error_count++))`. Add a regression test that runs the script under `set -e` against a file with a single warning-only condition and asserts the script reaches the final summary block (exit 0) rather than aborting mid-script.

### Proof of Concept
1. Create `agent.md` with `name: helper` (triggers only the warning at lines 84-87) and otherwise fully valid `description`, `model`, `color`, and system prompt.
2. Run `bash -x validate-agent.sh agent.md; echo "exit=$?"`.
3. Expected (per script intent): all required-field checks execute, script reaches lines 208-217, and since `error_count -eq 0`, exits `0` with the "Validation passed with N warning(s)" message.
4. Actual (bug): trace shows the script aborts immediately at line 86 (`((warning_count++))`) with `exit=1`, never executing the `description`/`model`/`color`/`SYSTEM_PROMPT` checks or the summary block.
5. Assert: `exit=1` even though the file has zero real errors — demonstrating the exit code no longer reflects the intended `error_count`/`warning_count` semantics described at lines 208-217.

### Citations

**File:** plugins/plugin-dev/skills/agent-development/scripts/validate-agent.sh (L55-56)
```shellscript
error_count=0
warning_count=0
```

**File:** plugins/plugin-dev/skills/agent-development/scripts/validate-agent.sh (L61-63)
```shellscript
if [ -z "$NAME" ]; then
  echo "❌ Missing required field: name"
  ((error_count++))
```

**File:** plugins/plugin-dev/skills/agent-development/scripts/validate-agent.sh (L84-87)
```shellscript
  if [[ "$NAME" =~ ^(helper|assistant|agent|tool)$ ]]; then
    echo "⚠️  name is too generic: $NAME"
    ((warning_count++))
  fi
```

**File:** plugins/plugin-dev/skills/agent-development/scripts/validate-agent.sh (L205-217)
```shellscript
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $error_count -eq 0 ] && [ $warning_count -eq 0 ]; then
  echo "✅ All checks passed!"
  exit 0
elif [ $error_count -eq 0 ]; then
  echo "⚠️  Validation passed with $warning_count warning(s)"
  exit 0
else
  echo "❌ Validation failed with $error_count error(s) and $warning_count warning(s)"
  exit 1
fi
```
