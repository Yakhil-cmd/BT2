### Title
Attacker-writable `.git/sg-reviewed-shas` cache lets a malicious/prompt-injected agent forge "already reviewed" state and permanently silence the security scanner - (File: plugins/security-guidance/hooks/diffstate.py)

### Summary
The SIZE `SizeSealed.sol` bug let an attacker set `lowestQuote` (a value meant to be written only by a trusted internal step, `finalize()`) to a sentinel that the state machine (`atState`) interpreted as "not yet finalized," bypassing the authorization checks in `cancelAuction()`/`cancelBid()`. The `security-guidance` plugin has a structurally identical pattern: whether a commit "has already been security-reviewed" is inferred purely from the *presence of its SHA* in a plain, world-writable-to-the-agent file, `.git/sg-reviewed-shas` [1](#0-0) , rather than from any cryptographically-bound or privilege-checked record. Anything (including the very Claude Code agent being monitored) that can write to `.git/` can forge this "reviewed" state and cause the tool's own gate (`_compute_push_sweep_base` / `handle_push_sweep_posttooluse`) to skip scanning malicious code before it is pushed.

### Finding Description
`_load_reviewed_shas` and `_append_reviewed_shas` maintain a append-only text file under the repo's `.git` directory that records which commit SHAs the LLM-based reviewer has already analyzed [1](#0-0) . `handle_push_sweep_posttooluse` trusts this file as the sole signal of "reviewed" state: it loads the set with `_load_reviewed_shas(repo_root)` and calls `_compute_push_sweep_base(prev_upstream, push_range, reviewed)` to decide how much of the pushed range to actually diff and send to the LLM reviewer [2](#0-1) . If every commit's SHA in the push range is already present in the file, the sweep is skipped entirely with `debug_log("Push sweep: every pushed commit already reviewed")` and the tool exits without ever invoking the analyzer [2](#0-1) . The same file also gates the reflog-fallback path in `handle_commit_review_posttooluse`, which explicitly filters out commits already "in reviewed" from the analysis set [3](#0-2) .

Critically, entries are appended to this file with no cryptographic binding to an actual completed LLM analysis — it is just a flat, unauthenticated text log (`sha\tts\tpv\tvulns_found`) written with a plain file append under an flock [4](#0-3) . Nothing prevents a process with filesystem write access to the repository (which, in the intended threat model of this plugin, explicitly includes the Claude Code agent itself — the plugin's own review prompts state "the model is the attacker, the user is the victim" for these capability-gate findings [5](#0-4) ) from directly appending an arbitrary SHA line to `.git/sg-reviewed-shas`. Once that SHA is "marked reviewed," any future commit/push carrying that SHA is treated by the state machine as already vetted and the scanner is skipped — exactly analogous to writing `type(uint128).max` into `lowestQuote` to make the contract believe `finalize()` had already run.

### Impact Explanation
The `security-guidance` plugin exists specifically to catch security-relevant code (secrets, injection, unsafe deserialization, etc.) that a compromised or prompt-injected Claude Code session might introduce, and to force the model to fix it (`exit 2` re-prompting) before code is committed/pushed [6](#0-5) . If the "already reviewed" state can be forged by the same untrusted agent the tool is meant to police, an attacker (a prompt-injected Claude session, or a malicious skill/plugin running with the agent's filesystem access) can pre-poison `.git/sg-reviewed-shas` with the SHA it intends to commit next, guaranteeing that its subsequent malicious commit and push sail through with zero LLM review and no re-prompt to "fix" the introduced vulnerability. This directly defeats the tool's core security guarantee for the unprivileged-agent trust boundary the plugin itself calls out as its highest-priority protection domain.

### Likelihood Explanation
Any code path that can run a shell command or otherwise write a file inside the repository's `.git` directory (which the agent routinely does for git operations) can perform this bypass with a single `echo "<sha>\t<ts>\t<pv>\t0" >> .git/sg-reviewed-shas` before making the targeted commit. No race condition, timing, or privileged access is required beyond what the agent already has in normal operation, making this straightforward to trigger deliberately (malicious/compromised agent) or accidentally (any tooling that manipulates `.git` internals).

### Recommendation
Do not trust an unauthenticated, agent-writable file as proof that a security review actually executed. Bind "reviewed" state to something the agent cannot forge, e.g.: store the reviewed-SHA log outside the working tree in a location not writable by the monitored agent/session (or with permissions the plugin's own hook process owns exclusively), sign/HMAC each entry with a secret unavailable to the agent, or require the recorded verdict to be attested by the actual invoked LLM call transcript/hash rather than by presence in a flat file. At minimum, treat the reviewed-shas file as a performance optimization only, and always run a lightweight structural check (e.g., verify the diff hash matches a hash captured at write time) before allowing it to suppress a review.

### Proof of Concept
1. As the Claude Code agent (or any process with the agent's shell/filesystem access) operating in a monitored repo with `security-guidance`'s push-sweep enabled.
2. Before making a malicious change, determine the next commit's SHA is not knowable in advance, so instead pre-stage the forgery immediately after committing the malicious change but before push:
   - `git add -A && git commit -m "add malicious code"` → yields SHA `X`.
   - `printf "%s\t%s\t0\t0\n" "$X" "$(date +%s)" >> .git/sg-reviewed-shas` (append `X` directly to the dedup log the same way `_append_reviewed_shas` would, per [4](#0-3) ).
3. `git push`.
4. `handle_push_sweep_posttooluse` computes `push_range` containing `X`, loads `reviewed = _load_reviewed_shas(repo_root)` which now contains `X`, and `_compute_push_sweep_base` returns `base=None` because the entire range is already in `reviewed` [7](#0-6) [2](#0-1) .
5. The push-sweep exits immediately with `skip_reason` metrics only, never running `analyze_code_security`/the agentic reviewer on the malicious diff, and no `exit 2` re-prompt is ever issued to force a fix.

Note: I was unable to directly inspect `plugins/security-guidance/hooks/hooks.json` in this pass (tool-call errors on final iteration) to confirm exactly how push/commit Bash matchers are wired, so the precise trigger conditions for when `handle_push_sweep_posttooluse` fires should be double-checked against that file in a follow-up session; the core state-confusion mechanism in `diffstate.py`/`security_reminder_hook.py` above is directly confirmed from source.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L242-264)
```python
_REVIEWED_SHAS_BASENAME = "sg-reviewed-shas"
_REVIEWED_SHAS_CAP = 500

def _reviewed_shas_path(repo_root):
    gd = _git_dir(repo_root)
    return os.path.join(gd, _REVIEWED_SHAS_BASENAME) if gd else None


def _load_reviewed_shas(repo_root):
    """Set of full 40-hex shas previously reviewed in this clone."""
    p = _reviewed_shas_path(repo_root)
    if not p or not os.path.exists(p):
        return set()
    out = set()
    try:
        with open(p, "r") as f:
            for line in f:
                sha = line.split("\t", 1)[0].strip()
                if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
                    out.add(sha)
    except OSError:
        pass
    return out
```

**File:** plugins/security-guidance/hooks/diffstate.py (L267-301)
```python
def _append_reviewed_shas(repo_root, shas, vulns_found=0):
    """Record that `shas` were reviewed. Best-effort; never raises.

    Uses fcntl.flock for the read-gc-write; appends are O_APPEND-atomic but
    GC needs the lock so concurrent CC sessions in the same clone don't race
    each other's truncation.
    """
    p = _reviewed_shas_path(repo_root)
    if not p or not shas:
        return
    import time as _time
    ts = int(_time.time())
    pv = _PV or 0
    lines = [f"{s}\t{ts}\t{pv}\t{int(vulns_found)}\n" for s in shas]
    try:
        import fcntl
        with open(p, "a+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                existing = f.read().splitlines(keepends=True)
                # Dedup by sha (first column) — keep newest, then cap.
                seen = set()
                merged = []
                for ln in (existing + lines)[::-1]:
                    sha = ln.split("\t", 1)[0].strip()
                    if sha and sha not in seen:
                        seen.add(sha)
                        merged.append(ln if ln.endswith("\n") else ln + "\n")
                merged = merged[:_REVIEWED_SHAS_CAP][::-1]
                f.seek(0)
                f.truncate()
                f.writelines(merged)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L717-729)
```python
def _compute_push_sweep_base(prev_upstream, push_range, reviewed):
    """Advance the diff base past the contiguous reviewed prefix.

    Spec: review `git diff B..HEAD` where `B` is the newest commit such that
    `prev_upstream..B` is entirely in `reviewed`. Returns (B, unreviewed_tail).
    `B == None` means the whole range is reviewed (caller should skip).
    `push_range` must be oldest→newest.

    Examples (✓=reviewed, ✗=not):
      [✓1, ✗2, ✓3]  → B=1, tail=[2,3]   (cannot trim suffix; Read is at HEAD)
      [✓1, ✓2, ✓3]  → B=None            (all reviewed → skip)
      [✗1, ✓2, ✗3]  → B=prev_upstream, tail=[1,2,3]
      []            → B=None
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L965-985)
```python
    _reflog_shas: List[str] = []
    _skip_21_sub = 0
    if not commit_succeeded and not interrupted and cwd:
        _root = _git_toplevel(cwd)
        _fresh, _stale = _git_reflog_recent_commits(_root)
        if _fresh:
            _already = _load_reviewed_shas(_root)
            _reflog_shas = [s for s in _fresh if s not in _already]
            if _reflog_shas:
                commit_succeeded = True
                debug_log(
                    f"Commit review: stdout had no `[branch sha]`; reflog "
                    f"shows {len(_reflog_shas)} fresh unreviewed commit(s) "
                    f"({_reflog_shas[0][:12]}...)"
                )
            else:
                # Fresh commit(s) in reflog but all already in
                # sg-reviewed-shas — likely a Bash retry or the commit was
                # reviewed via a prior fire. Correct to skip; sub=2 lets telemetry
                # split this from genuine fails.
                _skip_21_sub = 2
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1537-1544)
```python
    reviewed = _load_reviewed_shas(repo_root)
    base, tail = _compute_push_sweep_base(prev_upstream, push_range, reviewed)
    prefix_advanced = len(push_range) - len(tail)
    if base is None:
        debug_log("Push sweep: every pushed commit already reviewed")
        emit_metrics({**_base, "pushed": len(push_range), "unreviewed": 0,
                      "prefix_advanced": prefix_advanced})
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1945-1947)
```python
        # Exit code 2 with stderr forces Claude to continue and fix
        sys.stderr.write(PROVENANCE_BANNER + "\n\n" + concrete_guidance + CONTINUATION_SUFFIX + "\n")
        sys.exit(2)
```

**File:** plugins/security-guidance/hooks/review_api.py (L243-261)
```python
        "- NO PRIVILEGE BOUNDARY: attacker == victim. The input "
        "comes from env var / CLI arg / $HOME dotfile / HKCU / "
        "~/Library prefs / OS-user config — and the process runs at "
        "the same privilege as whoever writes that source. Also: "
        "the 'allow' decision is advisory self-gating returned to "
        "the same caller; or the prefix/suffix check is a secondary "
        "filter behind a parent-domain pin.\n"
        "  NEVER apply NO-PRIVILEGE-BOUNDARY to: SSRF/outbound-"
        "network sinks; LLM-agent capability gates (PreToolUse/"
        "PostToolUse hooks, bash allow/denylists, workspace path "
        "jails — the model is the attacker, the user is the "
        "victim); data-exposure findings (CWE-200/359/532, secrets-"
        "in-logs — the question is who READS the sink, not who "
        "controls the input); project-working-directory config "
        "(.claude/settings, .vscode/, package.json scripts — repo "
        "author ≠ repo cloner); cross-process metadata sources "
        "(psutil.Process(...), /proc/<pid>/* — different process "
        "owner is a different principal).\n"
        "- TRUSTED-HEADER NAMESPACE: the flagged header is from a "
```
