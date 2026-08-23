### Title
`ensureWorktreePathSafe` only Lstat's the final path component, allowing an attacker-planted symlink in an intermediate directory to redirect `git worktree add` writes outside the intended directory - ([File: pkg/cmd/pr/shared/worktree.go])

### Summary
`ensureWorktreePathSafe` calls `os.Lstat(path)` on the full `--worktree` path and only rejects the case where the *final* component is a symlink; it never inspects intermediate path components. If a victim clones an attacker-controlled repository that contains a symlinked directory, and the victim later passes a `--worktree` path whose parent segment resolves through that symlink, `os.Lstat` on the (non-existent) leaf returns `IsNotExist`, the check passes, and the subsequent `git worktree add -- <path> <branch>` command resolves the symlinked intermediate directory itself, writing the new worktree files outside the directory the user intended.

### Finding Description
`ensureWorktreePathSafe` is defined as: [1](#0-0) 

It performs a single `os.Lstat` on the full target path and branches only on: not-exists (allowed), stat error, symlink leaf (rejected), or non-directory leaf (rejected). Critically, `os.Lstat` does not refuse to traverse symlinks in *intermediate* path components — only the final component is left un-resolved by `Lstat` semantics. If a directory named e.g. `subdir` earlier in the path is itself a symlink (say, pointing to an arbitrary location the attacker chose when authoring their repository, which git checkout materializes as a real filesystem symlink when the victim clones it), and the final leaf (`subdir/newdir`) does not yet exist at the resolved location, `os.Lstat("subdir/newdir")` returns `ENOENT`/`IsNotExist`, and `ensureWorktreePathSafe` returns `nil`, treating the path as safe.

`ResolveWorktreeTarget` then calls `resolveWorktreeTarget`, which uses `git rev-parse` to check if the target is inside a different repo, but since the leaf path doesn't exist yet, `git rev-parse` on it fails and the function simply returns `reuse=false` with no error: [2](#0-1) 

No further check on intermediate symlinks occurs anywhere in this file.

Finally `WorktreeCheckoutCommands` builds a `git worktree add ... -- target.Path startPoint` command using the unmodified, unvalidated path: [3](#0-2) 

When this command is executed by git, git resolves the path exactly as the OS would — including following the attacker-planted symlink for the intermediate component — and creates the new worktree (a full checkout of the branch) at the symlink's target location, which can be outside the directory tree the user intended (e.g., outside the repo, or in an arbitrary location the attacker chose when crafting their repository's symlink target, subject to the victim's filesystem permissions).

Attacker path: attacker publishes a git repo (or PR branch) containing a symlink blob (mode `120000`) for a plausible-sounding directory name (e.g. `worktrees`, `build`, `.worktree-cache`) pointing to an arbitrary absolute or relative path. The victim clones this repo (`gh repo clone`) and later runs `gh pr checkout <n> --worktree worktrees/pr-123` (a natural convention, possibly even suggested in the attacker's own `CONTRIBUTING.md`). No existing check (host allowlist, safepaths, ghrepo parsing) applies here since this is purely local filesystem path handling downstream of a user-supplied CLI flag combined with attacker-controlled repository content.

### Impact Explanation
This allows an unprivileged, remote content author (via a published repository) to cause the victim's `gh` CLI to write files (a full branch checkout) to a filesystem location outside the directory the victim intended for their worktree, once the victim's `--worktree` argument happens to traverse through the planted symlink. This matches the "file write outside the intended path" impact class. The severity is bounded by the requirement that the victim's chosen `--worktree` relative-path structure must coincide with the attacker's planted symlink name/location, which is a real but non-trivial precondition rather than a fully attacker-triggered primitive.

### Likelihood Explanation
Feasibility requires: (1) victim clones/uses an attacker-authored repository containing a symlink at a plausible path, (2) victim runs `gh pr checkout --worktree <path>` (or equivalent `gh issue develop --checkout --worktree <path>`) where `<path>`'s parent segment matches the planted symlink, and (3) the leaf component does not already exist. This is realistic because attacker repos can suggest or document a specific worktree convention (e.g. in README/CONTRIBUTING) to steer victims toward exactly the vulnerable path shape, but it still depends on victim path choice, making exploitation conditional rather than automatic.

### Recommendation
Harden `ensureWorktreePathSafe` to validate every existing ancestor directory of the target path (walking up via `filepath.Dir` until an existing directory is found, using `os.Lstat` on each) and reject if any ancestor is a symlink, or alternatively resolve the longest existing ancestor with `filepath.EvalSymlinks` and confirm it stays within the expected root/repository boundary before allowing `git worktree add` to run.

### Proof of Concept
```go
func TestEnsureWorktreePathSafe_SymlinkedParentBypasses(t *testing.T) {
    base := t.TempDir()
    outside := t.TempDir() // simulates attacker-chosen target outside intended root

    // Simulate a repo checkout containing an attacker-planted symlinked directory.
    maliciousParent := filepath.Join(base, "worktrees")
    require.NoError(t, os.Symlink(outside, maliciousParent))

    // Victim passes a --worktree path whose parent traverses the symlink;
    // the leaf itself does not exist yet.
    target := filepath.Join(maliciousParent, "pr-123")

    err := ensureWorktreePathSafe(target)
    require.NoError(t, err) // BUG: should be rejected, since resolving target
                             // actually lands inside `outside`, not `base`.

    resolvedParent, _ := filepath.EvalSymlinks(maliciousParent)
    assert.Equal(t, outside, resolvedParent) // demonstrates path escapes `base`

    // Follow-up: WorktreeCheckoutCommands would emit
    // git worktree add -- target branch
    // which git resolves through the symlink, writing into `outside`
    // instead of anywhere under `base`.
}
```
Expected (fixed) behavior: `ensureWorktreePathSafe` should return an error such as `"--worktree path traverses a symlink"` for `target`, preventing the git worktree command from ever being issued against a path that resolves outside the intended directory tree.

### Citations

**File:** pkg/cmd/pr/shared/worktree.go (L38-51)
```go
func WorktreeCheckoutCommands(client *git.Client, target WorktreeTarget, branch, startPoint string) ([][]string, bool) {
	branchExists := client.HasLocalBranch(context.Background(), branch)

	if target.Reuse {
		if branchExists {
			return [][]string{{"-C", target.Path, "checkout", branch}}, true
		}
		return [][]string{{"-C", target.Path, "checkout", "-b", branch, "--track", startPoint}}, false
	}

	if branchExists {
		return [][]string{{"worktree", "add", "--", target.Path, branch}}, true
	}
	return [][]string{{"worktree", "add", "--track", "-b", branch, "--", target.Path, startPoint}}, false
```

**File:** pkg/cmd/pr/shared/worktree.go (L62-90)
```go
func resolveWorktreeTarget(client *git.Client, path string) (reuseWorktree bool, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	// git emits one line per flag, so we expect exactly two lines here.
	current, ok := revParseFacts(client, "", "--show-toplevel", "--git-common-dir")
	if !ok || len(current) != 2 {
		return false, nil
	}
	currentToplevel, currentCommonDir := current[0], current[1]

	// A non-existent or non-git target fails here: it is a fresh path for a new worktree.
	target, ok := revParseFacts(client, abs, "--show-toplevel", "--show-prefix", "--git-common-dir")
	if !ok || len(target) != 3 {
		return false, nil
	}
	targetToplevel, targetPrefix, targetCommonDir := target[0], target[1], target[2]

	switch {
	case targetCommonDir != currentCommonDir:
		return false, fmt.Errorf("--worktree path is inside a different repository")
	case targetToplevel == currentToplevel:
		return false, fmt.Errorf("--worktree path points to the repository you're already in; omit --worktree to check out here")
	case targetPrefix != "":
		return false, fmt.Errorf("--worktree path is inside an existing worktree")
	}
	return true, nil
```

**File:** pkg/cmd/pr/shared/worktree.go (L109-121)
```go
func ensureWorktreePathSafe(path string) error {
	fi, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	case fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("--worktree path must not be a symlink: %s", path)
	case !fi.IsDir():
		return fmt.Errorf("--worktree path must be a directory: %s", path)
	}
	return nil
```
