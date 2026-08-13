### Title
Stale/attacker-movable `baseline_sha` state lets a race window smuggle unreviewed code past the Stop-hook security review - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`, `diffstate.py`)

### Summary
The `receiptToken` bug reports that a reward calculation trusts a mutable balance value that can be inflated within the same transaction via a flash loan, letting an attacker claim rewards disproportionate to real stake. The closest reachable analog in this repo is the `security-guidance` plugin's Stop-hook code-review gate, which similarly trusts a mutable, externally-movable state value — `baseline_sha` — to decide which code changes get security-reviewed. Because `baseline_sha` is captured once (at `UserPromptSubmit`) and consumed later (at `Stop`), and because the file/lock backing it can be raced or advanced by a concurrent actor in the same worktree/session, the set of "changes to review" can be shrunk out from under the check, letting newly-introduced vulnerable code slip past the automated review — the same "check reads a value that can be moved between capture and use" pattern as the flash-loan report.

### Finding Description
`handle_user_prompt_submit` captures a git snapshot SHA (`baseline_sha`) via `capture_git_baseline` and stores it in per-session state [1](#0-0) . The Stop hook later diffs against this stored `baseline_sha` to build the set of changes sent to the LLM security reviewer, and then advances the baseline so only "new" changes are reviewed next turn (per the module docstring) [2](#0-1) .

The code itself documents that this baseline is not trustworthy under concurrency: the `ENABLE_STOP_REVIEW` comment explicitly states the Stop-hook diff is "anchored on `baseline_sha…HEAD`, which a sibling agent in the same worktree can move under us" [3](#0-2) . Separately, `handle_user_prompt_submit` contains explicit TOCTOU-avoidance logic for the case where the *previous* turn's Stop hook never consumed `touched_paths` — if it did, the code intentionally preserves the old baseline; if the timing differs, the baseline is silently overwritten [4](#0-3) . This is precisely the "value read for a security decision can be raced/moved by another actor before it's consumed" failure mode described as `FAIL-OPEN STATE DRIFT` in the plugin's own review guidance [5](#0-4) .

### Impact Explanation
If the baseline value used to scope "what to review" can be advanced or lost due to timing (multiple concurrent Bash/git operations, sibling agents in a shared worktree, or a user/agent interleaving prompts and tool calls), attacker- or model-introduced vulnerable code can be committed in a window that the next Stop-hook diff never sees, because the diff is computed against a moved baseline rather than the code state that actually needs reviewing. This is functionally identical in shape to the reported bug: a security-relevant decision (how many rewards to mint / whether to flag code as reviewed) is derived from a value (`receiptToken` balance / `baseline_sha`) that is mutable in a window between being read and being acted upon, and that window is exploitable by an unprivileged party to make an unreviewed/inflated set of changes look "clean."

### Likelihood Explanation
Exploitation requires a specific timing condition — concurrent sessions/agents sharing a worktree, or a user-controllable sequence of tool calls that races `UserPromptSubmit` against `Stop` — which the plugin authors were aware enough of to add partial mitigations (`preserved` baseline logic, `ENABLE_STOP_REVIEW` kill switch, `sg-hook-once-*` sentinel de-dup). This is a defense-in-depth security *reminder* feature (not an enforcement/permission gate), so it does not itself grant privilege escalation — it only reduces the chance that Claude's own output gets flagged for a fix-up turn. Likelihood of a full bypass is moderate and requires specific multi-agent/shared-worktree conditions rather than a single-shot, always-reachable trigger.

### Recommendation
- Make the baseline capture-and-consume operation atomic with respect to the diff it authorizes: rather than trusting a possibly-stale stored SHA, recompute or re-validate that no untracked/moved commits occurred in the review window before treating a diff range as "fully reviewed."
- Where multiple agents can share a worktree, scope `baseline_sha` per-agent/tool-call (not just per-session) or fail closed (force a full review) when the stored baseline can't be proven to still represent the pre-turn state.
- Continue treating `ENABLE_STOP_REVIEW`/rate-limit gates as mitigations, but document and, where feasible, close the specific preserved-vs-overwritten baseline race in `handle_user_prompt_submit`.

### Proof of Concept
1. Start a Claude Code session in a shared git worktree with `security-guidance`'s Stop-hook review enabled.
2. Run a second, concurrent Bash/git operation in the same worktree (e.g., `git stash create` from another agent/process) so that the stored `baseline_sha` in session state is advanced past code that was already written by the first session but not yet Stop-hook-reviewed — matching the exact scenario called out in the `ENABLE_STOP_REVIEW` comment [3](#0-2) .
3. Trigger the Stop hook; the diff computed against the moved baseline no longer contains the vulnerable code introduced earlier, so the LLM security reviewer never sees it and no `exit(2)` finding is raised.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L24-35)
```python
## How the git baseline works

On each UserPromptSubmit, the plugin runs `git stash create` to get a SHA representing
the current working tree state (HEAD + any uncommitted changes). This SHA is saved to
the session state file. When the Stop hook fires, it runs `git diff <baseline_sha>` to
get only the changes made since that snapshot. After analysis, the baseline is updated
so the next Stop hook iteration only sees new changes.

This means:
- Only code Claude actually changed is reviewed (not pre-existing code)
- Mid-session commits are handled correctly (diff is against the snapshot, not HEAD)
- Each turn only reviews new changes (baseline updates after each stop hook)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L154-161)
```python
# Stop-hook git-diff review only — does NOT gate the commit/push reviews.
# Lets multi-agent / shared-worktree deployments keep the commit reviewer
# (anchored to a fixed SHA from the worker's own `git commit` stdout) while
# turning off the Stop-hook diff (anchored on baseline_sha…HEAD, which a
# sibling agent in the same worktree can move under us). The pre-existing
# ENABLE_CODE_SECURITY_REVIEW gate is shared between Stop and commit/push
# and stays for backwards compat as the all-LLM-review master switch.
ENABLE_STOP_REVIEW = os.environ.get("ENABLE_STOP_REVIEW", "1") != "0"
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L446-503)
```python
def handle_user_prompt_submit(input_data):
    """
    Handle UserPromptSubmit — capture git baseline SHA.
    Called on every user prompt. Updates the baseline so the stop hook
    only reviews changes made since the last prompt.

    Does NOT reset touched_paths/fire_count/previous_findings — those are
    consumed by Stop (consume_stop_state) and time-expired respectively.
    UPS racing the asyncRewake Stop hook caused a meaningful share of reviews
    to be lost when the wipe landed before Stop's state read.

    """
    cwd = input_data.get("cwd", "")
    if not cwd:
        debug_log("UPS: no cwd, skipping baseline capture")
        sys.exit(0)

    session_id = input_data.get("session_id", "default")
    # stash-create and ls-files both walk the worktree (~2-5s each in a very
    # large repo). Run them concurrently so UPS latency stays ≈ max(both).
    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(max_workers=2) as _ex:
        _f_sha = _ex.submit(capture_git_baseline, cwd)
        _f_ut = _ex.submit(_list_untracked, cwd)
        sha = _f_sha.result()
        # Always capture the untracked snapshot. `git stash create` returns
        # empty when there are no TRACKED changes, but pre-existing untracked
        # files still need to be excluded from the next Stop's review_set —
        # otherwise an untracked-only working tree gets every untracked file
        # reviewed on every turn until something tracked is dirtied.
        untracked_now = _f_ut.result() or {}
    head = _git_rev_parse_head(cwd)

    # If the previous turn's Stop hook never ran (user interrupt, follow-up
    # during work, tool-reject, model crash, maxTurns, PostToolUse block…),
    # touched_paths is still populated because consume_stop_state is the only
    # consumer and it runs under the state lock. Overwriting baseline_sha now
    # would re-baseline *past* those unreviewed edits, making them permanently
    # invisible to the next Stop. Preserve the old baseline so the next Stop
    # diffs the aborted turn's edits plus the new turn's edits together.
    preserved = {"value": False}

    def _save(state):
        # Only preserve if there's actually an old baseline to preserve.
        # First UPS of a session can have touched_paths if PostToolUse
        # somehow ran first (print mode, odd harnesses) — in that case
        # we still need to capture a baseline.
        if state.get("touched_paths") and state.get("baseline_sha"):
            preserved["value"] = True
            return
        if sha:
            state["baseline_sha"] = sha
            state["head_at_capture"] = head
        # untracked_at_baseline is independent of whether the stash produced
        # a SHA — write it unconditionally so compute_v2_review_set's
        # preexisting-untracked exclusion works in untracked-only trees.
        state["untracked_at_baseline"] = untracked_now
    with_locked_state(session_id, _save)
```

**File:** plugins/security-guidance/hooks/review_api.py (L97-99)
```python
  - CONTROL REGRESSION: when - lines DELETE a fail-closed validator (allowlist returning False by default, _is_safe_*, deny-by-default) and + lines replace it with a single condition, the replacement IS the finding.
  - FAIL-OPEN STATE DRIFT: when a security decision reads parsed/cached/tracked/callback state, verify error, cancellation, TOCTOU, cache-skew, and unhandled-variant paths do not yield a default that skips enforcement — broad-except→pass, unwrap_or({}), missing-finally cleanup, ignored verifier params, or stale validator maps all fail open. The finding is the path where the fallback value is the allow outcome. Also: when + lines compare against a security threshold, check whether the EXACT boundary value yields the permissive branch; when an error path triggers retry/redelivery, check whether the retry can emit a decision that overrides a stricter first decision; when sync logic reads persisted state, check whether state surviving a data wipe causes destructive sync.
  - SECURITY-REGISTRY FANOUT: when + lines add a new entity (field, enum value, credential type, alias, model variant, port, scope), Grep unchanged files for every security registry keyed on that entity class — sanitizer field-lists, redaction sets, revocation handlers, strip denylists, capability allowlists, translation maps — and flag if the new entry is missing from any. Conversely, when + lines ADD entries to such a registry, Grep for where that registry is consumed and verify each new entry's literal matches the consumer's key format (namespace prefix, case, composite key) — a mismatched entry is a silent no-op that defeats the control.
```
