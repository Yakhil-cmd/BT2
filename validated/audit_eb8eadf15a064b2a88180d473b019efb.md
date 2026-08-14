### Title
Forged `[branch sha]`-style output can make the commit-review hook mark an unreviewed/malicious commit as "reviewed", permanently bypassing LLM security review - (File: plugins/security-guidance/hooks/security_reminder_hook.py)

### Summary
The `security-guidance` plugin's commit-review hook (`handle_commit_review_posttooluse`) decides which commit SHA to run its LLM security review against by regex-parsing the raw stdout/stderr text of the `git commit` Bash invocation, rather than by independently and authoritatively determining what was actually committed. The chosen SHA is then both (a) the only thing diffed and sent to the security-review LLM, and (b) recorded into `.git/sg-reviewed-shas` so it (and the push-sweep sweep that reads that file) will never be reviewed again. This mirrors the Nouns DAO bug class: a boundary/identifier used for critical accounting/enforcement logic is derived from attacker-influenceable output rather than from a validated, authoritative source.

### Finding Description
`handle_commit_review_posttooluse` builds `bash_output` by concatenating the Bash tool's `stdout` and `stderr`, then locates the SHA to review via `_COMMIT_SHA_RE` against that text: [1](#0-0) 

For the "last match wins" logic, the code explicitly reasons about the *possibility* of decoy bracketed strings appearing in the output (pre-commit/husky hooks) and, rather than validating the string against actual repo state, simply assumes the **last** bracket match is the real one: [2](#0-1) 

This is exactly the "user-supplied boundary before validation" pattern from the Nouns DAO report: instead of asking git authoritatively "what did I just commit" (e.g., via `git rev-parse HEAD` compared against a pre-commit baseline, similar to what `_git_reflog_recent_commits` already does as a *fallback* path), the primary path trusts a string embedded in command output text that is not cryptographically or structurally tied to the actual repository state at the time of the hook's execution. Any process capable of writing to stdout/stderr during the `git commit` invocation — a Husky/lint-staged/pre-commit hook, a wrapper script, a build tool invoked as part of a chained command, or a malicious dependency's postinstall/hook script sharing the terminal — can print a well-formed decoy such as `[main 0123456789abcdef0123456789abcdef01234567] fake` *after* the genuine `[branch sha]` line. Because only the last match is honored, this decoy SHA becomes:
1. The only diff (`git show -p <fake-sha>`) sent to `analyze_code_security` for LLM review, and
2. The entry written to `.git/sg-reviewed-shas` via `_append_reviewed_shas`, which both this hook and `handle_push_sweep_posttooluse` treat as "already reviewed and skip."

Since `sg-reviewed-shas` gates both the per-commit hook and the push-sweep hook (the two only LLM security-review surfaces in this plugin), a real malicious commit whose true SHA differs from the decoy is never diffed, never reviewed, and is permanently marked as covered — the plugin's security net silently closes over it.

### Impact Explanation
This breaks the hook-bypass trust boundary the `security-guidance` plugin exists to enforce: it is specifically designed to catch security-relevant code introduced via `git commit`/push and force the agent to fix it (`sys.exit(2)` to "wake" Claude). An attacker who can influence any output printed to stdout/stderr during the commit command (a common capability for anyone who can add a repo-local git hook, a `package.json` script, husky config, or similar tooling that runs during `git commit`) can make an arbitrary malicious commit permanently invisible to both the commit-review and push-sweep review surfaces, with no way to re-trigger review short of manual state file edits. This is a direct security-control bypass, not merely a false positive/negative in behavior tuning.

### Likelihood Explanation
Likelihood is constrained by the need for the attacker to control something that emits text to the terminal during the exact `git commit` invocation (e.g., a compromised pre-commit hook, lint-staged config, or postinstall script in the target repo) and to know/guess the SHA-shaped regex format well enough to craft a matching decoy line after the real one. This is a realistic supply-chain/insider scenario (a malicious dependency or hook shipped in a repo) rather than a fully external, prerequisite-free attack, so likelihood is Medium — comparable to the original report's characterization of needing to reach a threshold of control, here "control of what's printed during commit."

### Recommendation
Do not derive the reviewed SHA solely from free-text command output. Prefer an authoritative, non-spoofable check: read `HEAD` via `git rev-parse HEAD` immediately before and after the commit command (or diff the pre-commit baseline against current `HEAD`, as `_git_reflog_recent_commits`/reflog-based fallback already does), and only fall back to output-string parsing when that authoritative check is unavailable. If output parsing must be kept, validate the candidate SHA against `git cat-file -t <sha>`/`git rev-parse --verify` to confirm it resolves to a real, reachable commit object in the repo before trusting it and before writing it to `sg-reviewed-shas`.

### Proof of Concept
1. In a target repository, add a `.husky/pre-commit` (or any pre-commit tooling already invoked by `git commit`) that, after allowing the real commit, prints a decoy line to stdout formatted like git's own success output, e.g.:
   `echo "[main deadbeefdeadbeefdeadbeefdeadbeefdeadbeef] chore: noop" ` combined with a fabricated diffstat line matching `_COMMIT_DIFFSTAT_PATTERNS` (both conditions are required by `commit_succeeded`, per [3](#0-2) ).
2. Have Claude (or the agent) run `git commit -m "introduce vulnerable code"` in that repo; the pre-commit hook fires before the real commit line is emitted... 

**Uncertainty note:** I was not able to fully trace the exact ordering/format guarantees of `_COMMIT_SHA_RE` and `_COMMIT_DIFFSTAT_PATTERNS` (their definitions weren't retrieved before the tool budget ran out), nor confirm whether `_append_reviewed_shas` records the raw regex match unconditionally or after some additional validation I didn't reach in `diffstate.py`. These specifics would need to be confirmed in a follow-up session before treating this as a fully proven, exploitable PoC rather than a strong structural analog.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L925-945)
```python
    # Bash tool_response has no exit_code field (only stdout, stderr,
    # interrupted), so success is inferred from the output text — the same
    # heuristic Claude Code itself uses.
    if not isinstance(tool_response, dict):
        tool_response = {}
    stdout = tool_response.get("stdout", "") or ""
    stderr = tool_response.get("stderr", "") or ""
    bash_output = stdout + "\n" + stderr
    interrupted = bool(tool_response.get("interrupted"))

    # Require BOTH a line-anchored `[branch sha]` AND a git-only diffstat
    # signal before treating the tool call as a successful commit. The old
    # `any()` check false-positived on (a) pre-commit/husky/lint-staged hooks
    # emitting labels like `[pre-commit abc1234]`, and on (b) chained
    # `git commit || git log --stat` where `N files changed` appears in output
    # even though the commit itself failed.
    commit_succeeded = (
        not interrupted
        and _COMMIT_SHA_RE.search(bash_output) is not None
        and any(p.search(bash_output) for p in _COMMIT_DIFFSTAT_PATTERNS)
    )
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1025-1051)
```python
    # Pin the review to the exact SHA the Bash command produced, parsed from
    # its stdout. Reviewing HEAD instead is wrong when the commit was made in
    # a different repo than the hook's cwd (`cd ../other && git commit && cd -`,
    # subshells), or when a second commit lands before this async hook reaches
    # `git show` — both would review an unrelated commit. The reflog-action
    # fallback above is the narrow exception: it only fires when output gave
    # us nothing AND the cwd repo's own reflog confirms a `commit:` just
    # happened there, which rules out the cross-repo case.
    #
    # Take only the LAST match: pre-commit/husky hooks can print bracketed
    # labels like `[pre-commit abc1234]` that precede the real `[branch sha]`
    # line; chained commands like `git commit && git commit` produce multiple
    # real SHAs and we want the most recent. The real commit line is always
    # last in git's own output — the earlier matches are either decoys or
    # superseded commits.
    if _reflog_shas:
        # Output-based detection already failed above; the reflog SHAs are the
        # authoritative ones. Don't re-parse bash_output here — any bracketed
        # token it contains is by construction NOT the `[branch sha]` line
        # (or commit_succeeded would have been True via the fast path). The
        # list is newest-first and may contain >1 entry when a single Bash
        # call made multiple commits (`git commit -m a && git commit -m b`);
        # all are reviewed.
        shas = _reflog_shas
    else:
        all_shas = _COMMIT_SHA_RE.findall(bash_output)
        shas = [all_shas[-1]] if all_shas else []
```
