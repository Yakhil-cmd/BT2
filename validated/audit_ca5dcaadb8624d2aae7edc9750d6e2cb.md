### Title
`_push_section`'s last-`"To "`-header heuristic lets attacker-controlled post-push command output forge the push range, causing the push-sweep security review to be silently skipped - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`_push_section` locates the real `git push` output by taking the *last* `"\nTo "` occurrence in the combined stdout+stderr Bash buffer, on the assumption that only `git push`/`git fetch`/`git pull` ever emit `To `/`From ` header lines in that buffer. Any command chained after `git push` in the same Bash tool call (e.g. `git push && npm run build`, where the `npm` script is defined in attacker-controlled, committed `package.json`/build tooling) can print its own `"To ...\n<sha>..<sha>  branch -> branch"` text, which becomes the section `_push_section`/`_PUSH_RANGE_RE` actually parse instead of the genuine push output.

### Finding Description
`_push_section` (`security_reminder_hook.py:739-774`) is documented to strip *leading* fetch output and *trailing* fetch output around the real push's `To `/`From ` block, but its `idx = bash_output.rfind("\nTo ")` unconditionally trusts the **last** `"\nTo "` substring in the buffer as the start of the real push section: [1](#0-0) 

This is fed into `_PUSH_RANGE_RE` (`security_reminder_hook.py:637-640`) via `_detect_prev_upstream` (`security_reminder_hook.py:776-813`), whose `m.group(1)` (the "old" SHA) becomes `prev_upstream` — the diff base: [2](#0-1) [3](#0-2) 

`prev_upstream` and the derived commit list are then handed to `_compute_push_sweep_base` (`security_reminder_hook.py:717-737`), which trims the "already reviewed" prefix of the push range and returns the base commit the Stop/push-sweep diff should be taken against; if `push_range` collapses to empty, the function returns `(None, [])`, meaning "skip — nothing new to review": [4](#0-3) 

**Exploit flow:** A repository under (partial) attacker control ships a build/test script (e.g. `npm run build`, a `pre-push`/`post-push` local hook, a `Makefile` target) that is expected to run as part of a normal chained command such as `git push && npm run build`. The Bash tool result concatenates `stdout + "\n" + stderr` (this concatenation pattern is used for the analogous commit-review handler at `security_reminder_hook.py:930-932`, and the push-sweep handler builds its buffer the same way before calling `_push_section`/`_detect_prev_upstream`). The attacker's script, running with normal `git` access in the same working tree, does:

```
CUR=$(git rev-parse HEAD)
echo "To forged"
echo "$CUR..$CUR  main -> main"
```

Because this text is appended *after* the real `git push`'s own `"To <remote>\n<old>..<new>  branch -> branch"` output, `bash_output.rfind("\nTo ")` now returns the attacker's forged header instead of the real one. `_PUSH_RANGE_RE` matches the forged line and returns `old == new == HEAD`. `_detect_prev_upstream` then reports `prev_upstream == HEAD`, so the commit range between `prev_upstream` and `HEAD` computed for the sweep is empty, and `_compute_push_sweep_base` returns `(None, [])` — the push-sweep treats the entire just-pushed range as already reviewed and performs no diff/LLM security scan of it at all.

No existing check stops this: `_push_section`'s own docstring only reasons about `git fetch`/`git pull` interleavings, not arbitrary attacker-controlled command output; `_PUSH_RANGE_RE` has no provenance check tying a matched line to the actual `git push` subprocess (it is a pure text regex over combined stdout/stderr); and `_compute_push_sweep_base` blindly trusts whatever `prev_upstream`/`push_range` it is given.

### Impact Explanation
This breaks the "diff-baseline binding invariant" the plugin relies on: the automated push-time security review (`ENABLE_COMMIT_REVIEW`/push-sweep LLM scan of newly pushed commits) can be made to review the wrong (or empty) commit range, silently suppressing the vulnerability scan for commits that were actually pushed. An attacker who can get build tooling merged/committed into a repository (a normal, low-privilege contribution path) can cause any later push through that repo to bypass Claude Code's own automated security review of the pushed diff, without needing any elevated privilege, key leakage, or social engineering.

### Likelihood Explanation
- Requires only that attacker-controlled content (a script invoked via `npm run`, a Makefile, a local git hook, etc.) be present in the repository and be executed as part of a compound Bash command that also runs `git push` — a very common pattern (`git push && npm run build`, `git push && make test`, etc.).
- The attacker's script has ordinary shell/git access in the same working tree and can trivially compute `git rev-parse HEAD` to make the forged range self-consistent, requiring no privileged knowledge.
- No sandboxing, allowlist, or provenance check restricts what text a chained command may print, and `_push_section`/`_PUSH_RANGE_RE` are pure text pattern matches over concatenated stdout+stderr.
- Fully deterministic and reproducible.

### Recommendation
Do not rely on the *last* `"\nTo "` occurrence as authoritative. Bind the parsed push-range line to the actual `git push` subprocess invocation instead of scanning arbitrary combined stdout/stderr text — e.g., invoke/observe `git push` output in isolation (before any chained command runs), or require the matched `To `/range block to be the *first* one found strictly after the point in the buffer where the `git push` argv is known to have executed, and reject/ignore matches when other non-git commands have run in between. At minimum, cross-validate the parsed `old`/`new` SHAs against real git state (e.g., verify `new` corresponds to the actual pushed ref tip reported by the `Bash` tool_response for the specific `git push` invocation) rather than trusting arbitrary regex matches from mixed output.

### Proof of Concept
Unit test for `_push_section` (and downstream `_detect_prev_upstream`):

```python
def test_push_section_ignores_forged_trailing_to_header():
    real_push_output = (
        "Enumerating objects: 5, done.\n"
        "To github.com:org/repo.git\n"
        "   1111111..2222222  main -> main\n"
    )
    forged_suffix = (
        "To forged\n"
        "3333333..3333333  main -> main\n"
    )
    bash_output = real_push_output + forged_suffix

    section = _push_section(bash_output)

    # Expected: section should still contain the REAL push range line.
    assert "1111111..2222222" in section
    # Bug: current implementation returns only the forged section
    # (starts at rfind("\nTo ") -> the "To forged" header), so this
    # assertion fails and "1111111..2222222" is absent while
    # "3333333..3333333" is what gets matched instead.

    m = _PUSH_RANGE_RE.search(section)
    assert m.group(1) == "1111111" and m.group(2) == "2222222"
    # Currently m.group(1) == m.group(2) == "3333333" (forged), which
    # collapses _compute_push_sweep_base's push_range to empty and
    # causes the sweep to be skipped entirely.
```

Expected (fixed) behavior: `_push_section` extracts exactly the real push's range line even when trailing attacker-controlled output contains fake `To `/range text; `_detect_prev_upstream` returns the genuine old SHA (`1111111`), not the forged one.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L627-640)
```python
_GIT_PUSH_RE = re.compile(
    r'\bgit(?:\s+-[cC]\s+\S+|\s+--\S+=\S+)*\s+push\b'
)

# `git push` stdout: "abc1234..def5678  branch -> branch" (or `+abc..def` on
# force, `* [new branch]` on first push). The left sha is where the remote
# was BEFORE this push — exactly the base we need. Captures (old, new,
# local-ref) so the handler can verify the pushed ref == HEAD before
# diffing — `git push origin other` while on a different branch would
# otherwise diff the wrong range.
_PUSH_RANGE_RE = re.compile(
    r'^\s*\+?\s*([0-9a-f]{7,40})\.\.\.?([0-9a-f]{7,40})\s+(\S+)\s+->\s+\S+',
    re.MULTILINE,
)
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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L759-774)
```python
    if not bash_output:
        return ""
    # Match line-anchored "To " — look for "\nTo " or "To " at start-of-string.
    idx = bash_output.rfind("\nTo ")
    if idx >= 0:
        section = bash_output[idx:]
    elif bash_output.startswith("To "):
        section = bash_output
    else:
        return bash_output
    # Strip a trailing fetch/pull `From <remote>` block (push && fetch /
    # push && pull, or any wrapper that re-syncs after the push).
    end = section.find("\nFrom ")
    if end >= 0:
        section = section[:end]
    return section
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L786-790)
```python
    Returns a resolvable ref/sha or None.
    """
    m = _PUSH_RANGE_RE.search(_push_section(bash_output or ""))
    if m:
        return m.group(1)
```
