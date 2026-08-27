Based on my investigation, I found a valid analog to the reported bug class in `git-sync`.

### Title
Toggling `--submodules=off` does not retroactively remove previously-checked-out submodule content, causing stale/untrusted content to remain published - (File: `main.go`)

### Summary
The Morpho report describes a security toggle ("disallow asset as collateral") that only prevents *new* effects but does not retroactively apply to state that was established before the toggle was flipped, leaving users exposed. `git-sync` has a structurally identical flaw in `configureWorktree`: the `--submodules` flag controls whether `git submodule update --init [--recursive]` is run, but there is no corresponding action to `deinit`/remove submodule content when the flag transitions to `off` on a worktree that was previously synced with submodules enabled.

### Finding Description
`configureWorktree` only acts when submodules are enabled [1](#0-0) :
```go
if git.submodules != submodulesOff {
    ... "submodule", "update", "--init" ...
}
```
There is no `else` branch that runs `git submodule deinit` or otherwise removes already-checked-out submodule working trees when `submodules == off`.

Combined with the reuse logic in `SyncRepo`, a worktree is only recreated from scratch when the resolved commit hash changes (`changed`), or discarded when `sanityCheckWorktree` fails [2](#0-1) . `sanityCheckWorktree` only checks that the directory is non-empty, that `HEAD` matches the expected hash, and that `git fsck` passes [3](#0-2)  — it does not validate submodule state at all. Consequently, if:

1. `git-sync` first runs with `--submodules=recursive` (or `shallow`) and checks out a commit whose tree references a submodule (potentially attacker-controlled, since the submodule URL/commit comes from repo content pushed by whoever controls the tracked ref),
2. the operator later restarts `git-sync` (or the same commit remains current, so `changed` stays `false`) with `--submodules=off`, intending to disable/exclude submodule content,

the existing `.worktrees/<hash>` directory retains its already-checked-out submodule files, because `configureWorktree` performs only `reset --hard` on the superproject (which does not touch already-populated submodule working trees) and skips the submodule step entirely. The stale submodule content is never removed and continues to be served through the atomic `--link` symlink to any consumer container.

### Impact Explanation
This matches the "publishing wrong or partial content" impact category: an operator who explicitly disables submodule syncing (e.g., to exclude an untrusted or compromised submodule source) still has stale/untrusted submodule content served to downstream consumers via the published `--link`, believing it has been excluded. If the submodule previously contained executable scripts, configuration, or other consumed artifacts, downstream containers may execute or trust content that the operator believed was disabled.

### Likelihood Explanation
Likelihood is moderate: it requires an operator-initiated flag change (`--submodules` recursive/shallow → off) on a `--root` that already has synced state, which is a plausible operational pattern (e.g., reacting to a discovered malicious submodule by disabling submodules). No e2e test in `test_e2e.sh` exercises this specific transition — `e2e::submodule_sync_off` [4](#0-3)  only starts with `--submodules=off` from a fresh root, so this gap is untested and unnoticed.

### Recommendation
When `git.submodules == submodulesOff`, `configureWorktree` should explicitly run `git submodule deinit --all -f` (or otherwise remove any existing submodule working trees/gitlinks) before/instead of skipping the submodule step, ensuring the "off" setting is enforced consistently regardless of prior worktree state — mirroring the Morpho fix of ensuring a disablement setting is enforced across all paths, not just newly-created state.

### Proof of Concept
1. Create an upstream repo with a submodule pointing at attacker/untrusted content; commit it.
2. Run `git-sync --repo=... --root=$ROOT --link=link --submodules=recursive --one-time`. Confirm `$ROOT/link/<submodule>/...` is checked out.
3. Restart with the same ref/hash but `--submodules=off` (`git-sync --repo=... --root=$ROOT --link=link --submodules=off --one-time`), simulating an operator disabling submodules for the already-synced commit.
4. Observe that `$ROOT/link/<submodule>/...` files are still present and being served through the symlink, because `configureWorktree` [1](#0-0)  took no action to remove them and `sanityCheckWorktree` [3](#0-2)  does not detect the discrepancy (same `changed == false` reuse path as in `SyncRepo` [5](#0-4) ).

### Citations

**File:** main.go (L1501-1536)
```go
// sanityCheckWorktree tries to make sure that the dir is a valid git
// repository.  Note that this does not guarantee that the worktree has all the
// files checked out - git could have died halfway through and the repo will
// still pass this check.
func (git *repoSync) sanityCheckWorktree(ctx context.Context, worktree worktree) bool {
	git.log.V(3).Info("sanity-checking worktree", "repo", git.root, "worktree", worktree)

	// If it is empty, we are done.
	if empty, err := dirIsEmpty(worktree.Path()); err != nil {
		git.log.Error(err, "can't list worktree directory", "path", worktree.Path())
		return false
	} else if empty {
		git.log.V(0).Info("worktree is empty", "path", worktree.Path())
		return false
	}

	// Make sure it is synced to the right commmit.
	stdout, _, err := git.Run(ctx, worktree.Path(), "rev-parse", "HEAD")
	if err != nil {
		git.log.Error(err, "can't get worktree HEAD", "path", worktree.Path())
		return false
	}
	if stdout != worktree.Hash() {
		git.log.V(0).Info("worktree HEAD does not match worktree", "path", worktree.Path(), "head", stdout)
		return false
	}

	// Consistency-check the worktree.  Don't use --verbose because it can be
	// REALLY verbose.
	if _, _, err := git.Run(ctx, worktree.Path(), "fsck", "--no-progress", "--connectivity-only"); err != nil {
		git.log.Error(err, "worktree fsck failed", "path", worktree.Path())
		return false
	}

	return true
}
```

**File:** main.go (L1733-1747)
```go
	// Update submodules
	// NOTE: this works for repo with or without submodules.
	if git.submodules != submodulesOff {
		git.log.V(1).Info("updating submodules")
		submodulesArgs := []string{"submodule", "update", "--init"}
		if git.submodules == submodulesRecursive {
			submodulesArgs = append(submodulesArgs, "--recursive")
		}
		if git.depth != 0 {
			submodulesArgs = append(submodulesArgs, "--depth", strconv.Itoa(git.depth))
		}
		if _, _, err := git.Run(ctx, worktree.Path(), submodulesArgs...); err != nil {
			return err
		}
	}
```

**File:** main.go (L1899-1914)
```go
	if currentHash == remoteHash {
		// We seem to have the right hash already.  Let's be sure it's good.
		git.log.V(3).Info("current hash is same as remote", "hash", currentHash)
		if !git.sanityCheckWorktree(ctx, currentWorktree) {
			// Sanity check failed, nuke it and start over.
			git.log.V(0).Info("worktree failed checks or was empty", "path", currentWorktree)
			if err := git.removeWorktree(ctx, currentWorktree); err != nil {
				return false, "", err
			}
			currentHash = ""
		}
	}

	// This catches in-place upgrades from older versions where the worktree
	// path was different.
	changed := (currentHash != remoteHash) || (currentWorktree != git.worktreeFor(currentHash))
```

**File:** main.go (L1918-1945)
```go
	if changed || git.syncCount == 0 {
		git.log.V(0).Info("update required", "ref", git.ref, "local", currentHash, "remote", remoteHash, "syncCount", git.syncCount)
		metricFetchCount.Inc()

		// Reset the repo (note: not the worktree - that happens later) to the new
		// ref.  This makes subsequent fetches much less expensive.  It uses --soft
		// so no files are checked out.
		if _, _, err := git.Run(ctx, git.root, "reset", "--soft", remoteHash, "--"); err != nil {
			return false, "", err
		}

		// If we have a new hash, make a new worktree
		newWorktree := currentWorktree
		if changed {
			// Create a worktree for this hash in git.root.
			if wt, err := git.createWorktree(ctx, remoteHash); err != nil {
				return false, "", err
			} else {
				newWorktree = wt
			}
		}

		// Even if this worktree existed and passes sanity, it might not have all
		// the correct settings (e.g. sparse checkout).  The best way to get
		// it all set is just to re-run the configuration,
		if err := git.configureWorktree(ctx, newWorktree); err != nil {
			return false, "", err
		}
```

**File:** test_e2e.sh (L3171-3196)
```shellscript
function e2e::submodule_sync_off() {
    # Init submodule repo
    local submodule_repo_name="sub"
    local submodule="$WORK/$submodule_repo_name"
    mkdir "$submodule"

    git -C "$submodule" init -q -b "$MAIN_BRANCH"
    echo "submodule" > "$submodule/submodule.file"
    git -C "$submodule" add submodule.file
    git -C "$submodule" commit -aqm "init submodule file"

    # Add submodule
    git -C "$REPO" -c protocol.file.allow=always submodule add -q file://$submodule
    git -C "$REPO" commit -aqm "add submodule"

    GIT_SYNC \
        --period=100ms \
        --repo="file://$REPO" \
        --root="$ROOT" \
        --link="link" \
        --submodules=off \
        &
    wait_for_sync "${MAXWAIT}"
    assert_file_absent "$ROOT/link/$submodule_repo_name/submodule.file"
    rm -rf $submodule
}
```
