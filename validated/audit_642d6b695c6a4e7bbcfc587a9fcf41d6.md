### Title
Attacker-forgeable `.git/sg-reviewed-shas` entries let a pre-shipped clone poison push-sweep's review-state, causing a future matching commit's changes to be silently excluded from security review - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`_load_reviewed_shas` treats any well-formed 40-hex-sha line in `.git/sg-reviewed-shas` as proof that a commit was already security-reviewed, with no verification that the entry was actually produced by a prior review run in this environment. An attacker who ships repository content that becomes the victim's clone (starter template, onboarding repo, dev-container image, CI cache, etc.) can pre-populate this file with the sha of a commit object they will later fast-forward into the branch, causing `handle_push_sweep_posttooluse` to treat that commit as already reviewed and exclude its diff from the LLM security scan.

### Finding Description
`_load_reviewed_shas` (`plugins/security-guidance/hooks/diffstate.py:250-264`) reads `.git/sg-reviewed-shas` and returns the set of 40-hex-char shas found in the first tab-separated column, with no check that:
- the sha corresponds to a real, reachable commit,
- the entry was written by `_append_reviewed_shas` after an actual review, or
- the file itself hasn't been tampered with (no HMAC/signature, no binding to session or plugin state).

`handle_push_sweep_posttooluse` (`plugins/security-guidance/hooks/security_reminder_hook.py:1378-1568`) is the designated backstop for "outside-CC" commits — i.e., commits that land in the repo via any path other than a `git commit` executed through Claude Code's Bash tool (merges, fast-forwards, cherry-picks, GUI commits, etc. — see the comment at lines 1550-1558 confirming this is "the whole point of push-sweep"). It calls `_load_reviewed_shas(repo_root)` (line 1537) and passes the result into `_compute_push_sweep_base` (`security_reminder_hook.py:717-737`), which advances the diff base `B` past the contiguous *prefix* of the push range that is present in `reviewed`. The subsequent `diff_text = _git_diff_range(repo_root, base, "HEAD")` (line 1549) excludes everything at or before `base` from the LLM review.

Because a git commit object's sha is a pure deterministic hash of its tree, parent, author/committer identities and timestamps, and message, an attacker can compute the exact sha of a commit *before* it is ever applied, by fully controlling those inputs (e.g., fixed `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE`). If that same commit object is later fast-forwarded into the victim's branch unchanged (a common outcome for FF merges, direct pushes to a shared branch, or PR merges preserving the commit), its sha will exactly match the value planted in `sg-reviewed-shas`. Since this commit was never processed by `handle_commit_review_posttooluse` (it wasn't created via a Bash `git commit` in this session), push-sweep is its only review surface, and that surface trusts the forged entry unconditionally.

### Impact Explanation
This is a trust-boundary bypass of the review/export gate ("Deny means deny" for the review pipeline): a malicious commit's code changes are silently excluded from the AI-driven push-time security review, with no warning surfaced to the user (`emit_metrics` reports `skip_reason`s or a `prefix_advanced` count that looks like normal healthy dedup, not an attack indicator). This matches the "review/export logic bypass" bounty category — a scoped, complete bypass of the commit/push review gate for an attacker-chosen commit, achieved purely through repository content the attacker controls, without any elevated privilege on the victim's machine.

### Likelihood Explanation
Preconditions are realistic and require no privilege beyond the ability to (1) get the victim to use a repository/clone whose `.git` contents the attacker influenced (template repo, onboarding container image, CI/dev-container cache, etc.) and (2) later get a bit-identical commit object fast-forwarded into that branch (e.g., via a normal PR that is fast-forward-merged, or direct push to a shared branch). Both are plausible supply-chain patterns and require no exploitation of `git` itself — only exploitation of the plugin's blind trust in a plaintext, unauthenticated state file living inside `.git/`. The attack is fully repeatable and deterministic since commit hashing is deterministic given fixed inputs.

### Recommendation
Do not treat `.git/sg-reviewed-shas` as authoritative from an untrusted/attacker-influenced source:
- Bind entries to proof of an actual review performed by this plugin (e.g., an HMAC keyed by a locally-generated secret stored outside version-controlled/clone-shippable locations, or store review state outside `.git/` in a path guaranteed not to be attacker-populated via repository delivery).
- On load, discard/ignore any pre-existing entries whose commit is not verified to have gone through a review this session/plugin instance actually recorded (e.g., require entries to have been appended by the current machine's `_append_reviewed_shas`, never trust file contents present before the plugin's first run in that clone).
- Alternatively, treat `sg-reviewed-shas` purely as a performance optimization (avoid double LLM calls) but never as sufficient grounds to skip review for shas not demonstrably created via this plugin's own `_append_reviewed_shas` calls in a session — e.g., require the sha to also be present in the local reflog with a plugin-authenticated marker, not just in the flat file.

### Proof of Concept
Integration test in the style of existing push-sweep tests (`plugins/security-guidance/hooks/security_reminder_hook.py` push-sweep suite):
1. Init a bare test repo; create commit `C` with fixed `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE`, deterministic message/content; record its sha `S` via `git rev-parse HEAD`.
2. Reset the repo to before `C` (simulating "attacker ships repo without commit yet"), and manually seed `.git/sg-reviewed-shas` with `S\t<ts>\t0\t0\n` (simulating the attacker-shipped, pre-populated file) — before commit `C` has ever been created in this test repo.
3. Re-apply commit `C` (e.g., cherry-pick/fast-forward from a side ref) so `git rev-parse HEAD == S` again, confirming the sha match is exact.
4. Simulate a `git push` PostToolUse event and call `handle_push_sweep_posttooluse` with a push range that includes `S` as the sole/oldest commit.
5. Assert: `_compute_push_sweep_base` returns a `base` at or past `S` (i.e., `S` is excluded from `tail`), `_git_diff_range` is called with `base=S`, and the LLM review call (mocked) is never invoked with `C`'s actual content — i.e., the malicious diff introduced by `C` is absent from what `analyze_code_security`/the review pipeline receives, and `emit_metrics` shows no `vulns_found` for `C`'s content despite it containing a planted vulnerable pattern. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L250-264)
```python
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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L717-737)
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
    """
    i = 0
    while i < len(push_range) and push_range[i] in reviewed:
        i += 1
    if i == len(push_range):
        return None, []
    base = push_range[i - 1] if i > 0 else prev_upstream
    return base, push_range[i:]
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1537-1568)
```python
    reviewed = _load_reviewed_shas(repo_root)
    base, tail = _compute_push_sweep_base(prev_upstream, push_range, reviewed)
    prefix_advanced = len(push_range) - len(tail)
    if base is None:
        debug_log("Push sweep: every pushed commit already reviewed")
        emit_metrics({**_base, "pushed": len(push_range), "unreviewed": 0,
                      "prefix_advanced": prefix_advanced})
        sys.exit(0)

    debug_log(f"Push sweep: range={len(push_range)} prefix_advanced="
              f"{prefix_advanced} base={base[:12]} tail={len(tail)}")

    diff_text = _git_diff_range(repo_root, base, "HEAD")
    if diff_text is None:
        # Diff failed (non-zero exit / 30s timeout / git missing). Do NOT
        # mark `tail` reviewed — we did not actually review it. Marking
        # them would silently advance the prefix past unreviewed commits
        # forever (the whole point of push-sweep is to catch outside-CC
        # commits, and a 50-commit range over large files can hit the
        # 30s timeout). skip_reason=45 lets a retry / smaller subsequent
        # push still cover them, mirroring how skip_reason=31 handles
        # too-many-files without recording the tail.
        emit_metrics({**_base, "pushed": len(push_range),
                      "unreviewed": len(tail), "skip_reason": 45})
        sys.exit(0)
    diff_files = parse_diff_into_files(diff_text)
    if not diff_files:
        emit_metrics({**_base, "pushed": len(push_range),
                      "unreviewed": len(tail), "skip_reason": 30})
        # Still mark tail reviewed — there's nothing to review.
        _append_reviewed_shas(repo_root, tail, vulns_found=0)
        sys.exit(0)
```
