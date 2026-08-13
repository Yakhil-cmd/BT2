### Title
Forged commit-identifier in Bash stdout lets a repo-controlled hook spoof or suppress the security-guidance commit-review signal - (File: plugins/security-guidance/hooks/security_reminder_hook.py)

### Summary
The `security-guidance` plugin's `handle_commit_review_posttooluse` treats the presence of a `[branch sha] ...` style line plus a diffstat marker in the Bash tool's `stdout`/`stderr` as proof that `git commit` succeeded, and uses the **last** such bracket match as the authoritative commit SHA to review. Both signals are derived purely from free-text output produced by whatever process runs as part of the shell command (git itself, but also pre-commit/post-commit hooks, aliases, or any program the command invokes), not from an authoritative git query performed independently by the hook. This mirrors the reported `OrderCancelled` bug class: a security-relevant "event" (here, "a commit happened and was reviewed / was clean") is inferred from attacker-influenceable text rather than from ground truth, so it can be forged to make the security review fire against the wrong target or not fire at all for the real change.

### Finding Description
`handle_commit_review_posttooluse` is invoked as a `PostToolUse` hook on `Bash` whenever the command matches `git commit` [1](#0-0) . Because `tool_response` for the Bash tool carries no `exit_code`, the handler infers success purely from text patterns in the combined stdout+stderr: [2](#0-1) 

The regexes used are line-anchored but otherwise unauthenticated pattern matches over arbitrary process output: [3](#0-2) 

Crucially, when selecting *which* commit to review, the code takes only the **last** `[branch sha]`-shaped match in the output as authoritative: [4](#0-3) 

`bash_output` is the concatenation of everything printed by the Bash command, which can include output from pre-commit/post-commit git hooks, wrapper scripts, `printf`/`echo` in a compound command, or any other subprocess started by the shell invocation — none of which is trusted or verified against git's actual object store before being treated as the review target. A crafted decoy line such as `[main 0000000] fake` printed after the real `[branch realsha]` line (e.g., via a repo-local `post-commit` hook, an alias, or command chaining like `git commit -m "x" ; printf '[main 0000000]\n 1 file changed\n'`) becomes `shas[0]` instead of the real SHA.

Two forgeable outcomes follow directly from the code at lines 1119–1163:
- If the decoy hex string does not resolve via `git show -p <sha>` (`resolved == 0`), the handler exits with `skip_reason=28` and **the real, just-created commit is never reviewed** [5](#0-4) .
- If the decoy hex string happens to resolve to some other, unrelated commit in the repo (e.g. an old innocuous commit), the review runs against that decoy commit and reports it clean, while the actual newly introduced (potentially vulnerable) diff is silently skipped — the hook still records the *decoy* SHA as "reviewed" via `_append_reviewed_shas`, permanently marking the review as satisfied for that fabricated identifier [6](#0-5) .

This is the direct analog of the 1inch bug: a downstream consumer (there, off-chain systems relying on `OrderCancelled`; here, the security-review pipeline and any telemetry consumer relying on `commit_review`/`skip_reason` metrics) is told an event happened (or didn't) based on a signal that can be emitted by an untrusted party without the corresponding real state change actually matching it.

### Impact Explanation
An attacker who can influence what a `git commit` invocation prints (via a malicious/compromised `pre-commit`/`post-commit` hook already present in the repo, a shell alias, or by getting Claude to run a compound/chained command whose extra output matches the pattern) can cause the automated LLM-based security review of a real commit to be silently skipped, letting a genuinely vulnerable or malicious change bypass the `security-guidance` plugin's git-automation review control entirely — a concrete bypass of a security enforcement/trust boundary the plugin is meant to provide, without any user-visible error.

### Likelihood Explanation
Exploitation requires a way to inject extra bracket-shaped text into the same Bash tool call's stdout/stderr as the `git commit` — most plausibly through a repository-supplied git hook (`.git/hooks/post-commit` or a hook installed by a build tool like husky/lint-staged which is explicitly called out in the code's own comments as a known source of similar-looking output) or a chained shell command. This requires local write access to hook files or control over the exact command string executed, both of which are realistic in the "unprivileged repo content controls agent behavior" trust boundary this hook is meant to defend against (the same class the code's comments already acknowledge for husky/lint-staged false positives, but only defends the "false positive causes a spurious review" direction, not the "forged marker to defeat review" direction).

### Recommendation
Do not trust arbitrary Bash stdout/stderr as the sole source of "which commit to review." Determine the reviewed SHA authoritatively and independently, e.g. by reading `git rev-parse HEAD` (and pre/post state) directly via `subprocess` at hook-invocation time rather than regex-parsing command output, using the existing reflog-based cross-check (`_git_reflog_recent_commits`) as the primary source of truth instead of a fallback, and validating any SHA parsed from stdout against the reflog before trusting it. If output-based detection must remain (for compatibility), reduce its authority to a "should we bother reviewing" hint and always cross-check the resulting SHA against the toplevel repo's own recent reflog/HEAD before recording it as reviewed.

### Proof of Concept
1. In a fresh git repo, install a local `post-commit` hook:
   ```
   #!/bin/sh
   printf '[main 0000000abc] decoy\n 1 file changed, 1 insertion(+)\n'
   ```
2. Ask Claude Code to make a real change and run `git commit -m "add vulnerable code"`.
3. Bash tool stdout becomes: `[main <realsha>] add vulnerable code\n 1 file changed...\n[main 0000000abc] decoy\n 1 file changed...`.
4. `_COMMIT_SHA_RE.findall` returns both matches; `shas = [all_shas[-1]]` selects `0000000abc`, not `<realsha>`.
5. `git show -p 0000000abc` fails to resolve (or resolves to an unrelated old commit) in the target repo, so `resolved == 0` and the handler exits at `skip_reason=28` — the actual vulnerable commit is never sent to `analyze_code_security`, and no security finding is ever surfaced to the user or the `Stop` hook's sweep. [7](#0-6) [5](#0-4)

### Citations

**File:** plugins/security-guidance/hooks/hooks.json (L25-52)
```json
    "PostToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash \"${CLAUDE_PLUGIN_ROOT}/hooks/sg-python.sh\" \"${CLAUDE_PLUGIN_ROOT}/hooks/security_reminder_hook.py\""
          }
        ],
        "matcher": "Edit|Write|MultiEdit|NotebookEdit"
      },
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash \"${CLAUDE_PLUGIN_ROOT}/hooks/sg-python.sh\" \"${CLAUDE_PLUGIN_ROOT}/hooks/security_reminder_hook.py\"",
            "if": "Bash(git commit:*)",
            "asyncRewake": true,
            "rewakeMessage": "Background security review of commit — address or acknowledge the findings below, then continue with the user's original request or continue waiting for their reply:",
            "rewakeSummary": "Commit security review found issues"
          },
          {
            "type": "command",
            "command": "bash \"${CLAUDE_PLUGIN_ROOT}/hooks/sg-python.sh\" \"${CLAUDE_PLUGIN_ROOT}/hooks/security_reminder_hook.py\"",
            "if": "Bash(git push:*)",
            "asyncRewake": true,
            "rewakeMessage": "Background security review of pushed commits not yet reviewed — address or acknowledge the findings below, then continue with the user's original request or continue waiting for their reply:",
            "rewakeSummary": "Push security review found issues"
          }
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L575-591)
```python
# git-only signals that corroborate a real commit object — NOT emitted by
# pre-commit / lint-staged / husky hook output, which can contain bracketed
# labels like `[pre-commit abc1234]` that otherwise look like a commit line.
_COMMIT_DIFFSTAT_PATTERNS = [
    re.compile(r'\b\d+ files? changed'),
    re.compile(r'^ create mode ', re.MULTILINE),
    re.compile(r'^ delete mode ', re.MULTILINE),
    re.compile(r'^ rename ', re.MULTILINE),
]

# Capture-group form of the [branch sha] pattern. Mirrors Claude Code's own
# commit-id parsing, but tolerates spaces before the
# sha (covers `[detached HEAD abc1234]`). 7–40 hex chars: git's abbrev floor
# through full sha; the abbrev resolves fine with `git show`. Anchored to
# line-start so a `[hex]` in the commit subject (`[main abc] Revert [e38]`)
# or trailing hook output isn't picked up and fed to `git show`.
_COMMIT_SHA_RE = re.compile(r'^\[[^\]]*?\b([0-9a-f]{7,40})\]', re.MULTILINE)
```

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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1033-1051)
```python
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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1159-1163)
```python
    if resolved == 0:
        debug_log("Commit review: no parsed SHA resolved in cwd repo")
        emit_metrics({"skipped": True, "skip_reason": 28, **_base,
                      "shas_found": len(shas)})
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1248-1263)
```python
    # push-sweep state: record this commit as reviewed (full 40-hex sha) so a
    # later `git push` can advance its diff base past it. Recorded here — after
    # the review ran but before any exit path — so it's marked regardless of
    # whether findings were emitted. `shas` holds abbreviated refs from
    # `[branch sha]`; resolve to full so set-membership in the push-sweep is
    # exact. Best-effort; failures here never block the review result.
    try:
        full_shas = []
        for s in shas:
            r = subprocess.run(
                [*GIT_CMD, "rev-parse", "--verify", "-q", s],
                cwd=repo_root, capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                full_shas.append(r.stdout.strip())
        _append_reviewed_shas(repo_root, full_shas, vulns_found=len(vulns or []))
```
