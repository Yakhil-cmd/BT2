This is the key analog. When a new hash is synced, `SyncRepo` explicitly calls `touch(currentWorktree.Path())` to "Start the stale worktree removal timer" for the *previous* worktree [1](#0-0) . `removeStaleWorktrees` later decides whether to delete a worktree purely by comparing `time.Since(fi.ModTime()) > git.staleTimeout` against the directory's mtime [2](#0-1) .

### Title
Repeated ref oscillation resets the stale-worktree removal timer, causing unbounded worktree/disk accumulation - (File: main.go)

### Summary
`SyncRepo` "restarts the clock" on a worktree's removal every time that worktree stops being current, by re-touching its mtime [1](#0-0) . `removeStaleWorktrees` uses only this mtime, not an original creation time or a fixed schedule, to decide whether a non-current worktree is eligible for deletion [2](#0-1) .

### Finding Description
This mirrors the `VaderBond.deposit()` bug class: a per-cycle "state overwrite" resets a wait/vesting timer that should represent "time since this became stale," not "time since last touched." In `git-sync`, when the synced ref changes from hash A to hash B, the previously-current worktree A gets `touch()`ed and its removal timer restarts from zero [3](#0-2) . If an attacker (or ordinary upstream activity) who controls the tracked ref/branch can cause the resolved commit to oscillate back and forth between two or more hashes (e.g., force-pushing repeatedly between commit A and commit B, or moving a branch back and forth) faster than `--stale-worktree-timeout`, every oscillation re-touches whichever worktree just became non-current. Since each of these worktrees keeps getting re-touched whenever it briefly becomes "previous," `removeStaleWorktrees`'s `time.Since(fi.ModTime()) > git.staleTimeout` check never trips for either worktree, and both worktrees are kept alive indefinitely, similar to how a bond depositor's vesting clock never completes when their deposit info keeps getting overwritten.

### Impact Explanation
Because the code creates a fresh worktree directory for the new hash but only *conditionally* removes the previous one via the stale-worktree GC path (`cleanup()` → `removeStaleWorktrees()` in the main loop) [4](#0-3) , indefinitely resetting the mtime prevents the old worktrees from ever being pruned. Because each `createWorktree` also runs `git worktree add ... --no-checkout` and a full checkout for every new hash [5](#0-4) , an oscillating ref can cause the `--root` directory to accumulate an unbounded number of live worktrees and their checked-out contents, exhausting disk space on the shared `--root`/`emptyDir` volume. This is a "persistent sync denial" style impact via disk exhaustion, not a corruption or credential-leak issue.

### Likelihood Explanation
This requires that whoever controls the upstream ref that `git-sync` tracks (i.e., an attacker with push access to the tracked branch, or a misbehaving/malicious upstream) forces the resolved commit to alternate between (at least) two values faster than `--stale-worktree-timeout` (default `0`, meaning immediate removal when defaulted, but operators commonly set larger positive windows per `docs/kubernetes.md` guidance to protect against flapping) [6](#0-5) . With the default `--stale-worktree-timeout=0`, the exposure is low because worktrees are removed on the very next cleanup pass regardless of mtime resets; the risk only becomes meaningful when operators explicitly configure a non-zero `--stale-worktree-timeout` and the tracked ref is attacker-influenced (e.g., a branch/tag the attacker can push to), which is a plausible but non-default configuration.

### Recommendation
Track and persist the worktree's true "became stale at" timestamp (e.g., record it once when a worktree stops being the current target, rather than re-touching it on every subsequent sync), so that repeated oscillation of the synced ref cannot indefinitely extend a worktree's lifetime. Alternatively, cap the total number of worktrees retained regardless of individual mtimes, independent of the stale timeout logic.

### Proof of Concept
1. Configure `git-sync` with `--stale-worktree-timeout=<N>s` where `N>0`.
2. Force-push the tracked ref to alternate between commit A and commit B at an interval shorter than `N` seconds, faster than `git-sync`'s `--period`.
3. Observe via `test_e2e.sh`-style assertions (as in `e2e::stale_worktree_timeout`, which validates staleness solely via elapsed `sleep` relative to mtime) [7](#0-6)  that both worktree directories under `$ROOT/.worktrees/` persist indefinitely because each becomes "current" again before its `staleTimeout` window (measured from its last touch) elapses, verified by the `touch(currentWorktree.Path())` call in `SyncRepo` re-arming the timer on every transition away from a given hash [1](#0-0) .

### Citations

**File:** main.go (L1420-1441)
```go
func (git *repoSync) removeStaleWorktrees() (int, error) {
	currentWorktree, err := git.currentWorktree()
	if err != nil {
		return 0, err
	}

	git.log.V(3).Info("cleaning up stale worktrees", "currentHash", currentWorktree.Hash())

	count := 0
	err = removeDirContentsIf(git.worktreeFor("").Path(), git.log, func(fi os.FileInfo) (bool, error) {
		// delete files that are over the stale time out, and make sure to never delete the current worktree
		if fi.Name() != currentWorktree.Hash() && time.Since(fi.ModTime()) > git.staleTimeout {
			count++
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
```

**File:** main.go (L1642-1663)
```go
// createWorktree creates a new worktree and checks out the given hash.  This
// returns the path to the new worktree.
func (git *repoSync) createWorktree(ctx context.Context, hash string) (worktree, error) {
	// Make a worktree for this exact git hash.
	worktree := git.worktreeFor(hash)

	// Avoid wedge cases where the worktree was created but this function
	// error'd without cleaning up.  The next time thru the sync loop fails to
	// create the worktree and bails out. This manifests as:
	//     "fatal: '/repo/root/nnnn' already exists"
	if err := git.removeWorktree(ctx, worktree); err != nil {
		return "", err
	}

	git.log.V(1).Info("adding worktree", "path", worktree.Path(), "hash", hash)
	_, _, err := git.Run(ctx, git.root, "worktree", "add", "--force", "--detach", worktree.Path().String(), hash, "--no-checkout")
	if err != nil {
		return "", err
	}

	return worktree, nil
}
```

**File:** main.go (L1752-1799)
```go
// cleanup removes old worktrees and runs git's garbage collection.  The
// specified worktree is preserved.
func (git *repoSync) cleanup(ctx context.Context) error {
	// Save errors until the end.
	var cleanupErrs multiError

	// Clean up previous worktree(s).
	if n, err := git.removeStaleWorktrees(); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	} else if n == 0 {
		// We didn't clean up any worktrees, so the rest of this is moot.
		return nil
	}

	// Let git know we don't need those old commits any more.
	git.log.V(3).Info("pruning worktrees")
	if _, _, err := git.Run(ctx, git.root, "worktree", "prune", "--verbose"); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}

	// Expire old refs.
	git.log.V(3).Info("expiring unreachable refs")
	if _, _, err := git.Run(ctx, git.root, "reflog", "expire", "--expire-unreachable=all", "--all"); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}

	// Run GC if needed.
	if git.gc != gcOff {
		args := []string{"gc"}
		switch git.gc {
		case gcAuto:
			args = append(args, "--auto")
		case gcAlways:
			// no extra flags
		case gcAggressive:
			args = append(args, "--aggressive")
		}
		git.log.V(3).Info("running git garbage collection")
		if _, _, err := git.Run(ctx, git.root, args...); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}

	if len(cleanupErrs) > 0 {
		return cleanupErrs
	}
	return nil
}
```

**File:** main.go (L1929-1970)
```go
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

		// If we have a new hash, update the symlink to point to the new worktree.
		if changed {
			// If the previous run crashed before publishing the link, then we
			// must call the pre-publish hook, and since changed is true, we will.
			// we will. If the previous run crashed after publishing the link,
			// then we do not need to call the pre-publish hook, and since
			// changed is false, we won't. The post-publish hooks are called in
			// both cases.
			err := syncHooks.beforePublish(newWorktree.Hash())
			if err != nil {
				return false, "", err
			}

			err = git.publishSymlink(newWorktree)
			if err != nil {
				return false, "", err
			}
			if currentWorktree != "" {
				// Start the stale worktree removal timer.
				err = touch(currentWorktree.Path())
				if err != nil {
					git.log.Error(err, "can't change stale worktree mtime", "path", currentWorktree.Path())
				}
			}
```

**File:** test_e2e.sh (L822-922)
```shellscript
function e2e::stale_worktree_timeout() {
    echo "${FUNCNAME[0]} 1" > "$REPO"/file
    git -C "$REPO" commit -qam "${FUNCNAME[0]}"
    local wt1
    wt1=$(git -C "$REPO" rev-list -n1 HEAD)
    GIT_SYNC \
        --period=100ms \
        --repo="file://$REPO" \
        --root="$ROOT" \
        --link="link" \
        --stale-worktree-timeout="5s" \
        &

    # wait for first sync
    wait_for_sync "${MAXWAIT}"
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_eq "$ROOT/link/file" "${FUNCNAME[0]} 1"

    # wait 2 seconds and make another commit
    sleep 2
    echo "${FUNCNAME[0]} 2" > "$REPO"/file2
    git -C "$REPO" add file2
    git -C "$REPO" commit -qam "${FUNCNAME[0]} new file"
    local wt2
    wt2=$(git -C "$REPO" rev-list -n1 HEAD)

    # wait for second sync
    wait_for_sync "${MAXWAIT}"
    # at this point both wt1 and wt2 should exist, with
    # link pointing to the new wt2
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_exists "$ROOT/link/file2"
    assert_file_exists "$ROOT/.worktrees/$wt1/file"
    assert_file_absent "$ROOT/.worktrees/$wt1/file2"

    # wait 2 seconds and make a third commit
    sleep 2
    echo "${FUNCNAME[0]} 3" > "$REPO"/file3
    git -C "$REPO" add file3
    git -C "$REPO" commit -qam "${FUNCNAME[0]} new file"
    local wt3
    wt3=$(git -C "$REPO" rev-list -n1 HEAD)

    wait_for_sync "${MAXWAIT}"

    # at this point wt1, wt2, wt3 should exist, with
    # link pointing to wt3
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_exists "$ROOT/link/file2"
    assert_file_exists "$ROOT/link/file3"
    assert_file_exists "$ROOT/.worktrees/$wt1/file"
    assert_file_absent "$ROOT/.worktrees/$wt1/file2"
    assert_file_absent "$ROOT/.worktrees/$wt1/file3"
    assert_file_exists "$ROOT/.worktrees/$wt2/file"
    assert_file_exists "$ROOT/.worktrees/$wt2/file2"
    assert_file_absent "$ROOT/.worktrees/$wt2/file3"
    assert_file_exists "$ROOT/.worktrees/$wt3/file"
    assert_file_exists "$ROOT/.worktrees/$wt3/file2"
    assert_file_exists "$ROOT/.worktrees/$wt3/file3"

    # wait for wt1 to go stale
    sleep 4

    # now wt1 should be stale and deleted,
    # wt2 and wt3 should still exist
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_exists "$ROOT/link/file2"
    assert_file_exists "$ROOT/link/file3"
    assert_file_absent "$ROOT/.worktrees/$wt1/file"
    assert_file_absent "$ROOT/.worktrees/$wt1/file2"
    assert_file_absent "$ROOT/.worktrees/$wt1/file3"
    assert_file_exists "$ROOT/.worktrees/$wt2/file"
    assert_file_exists "$ROOT/.worktrees/$wt2/file2"
    assert_file_absent "$ROOT/.worktrees/$wt2/file3"
    assert_file_exists "$ROOT/.worktrees/$wt3/file"
    assert_file_exists "$ROOT/.worktrees/$wt3/file2"
    assert_file_exists "$ROOT/.worktrees/$wt3/file3"

    # wait for wt2 to go stale
    sleep 2

    # now both wt1 and wt2 are stale, wt3 should be the only
    # worktree left
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_exists "$ROOT/link/file2"
    assert_file_exists "$ROOT/link/file3"
    assert_file_absent "$ROOT/.worktrees/$wt1/file"
    assert_file_absent "$ROOT/.worktrees/$wt1/file2"
    assert_file_absent "$ROOT/.worktrees/$wt1/file3"
    assert_file_absent "$ROOT/.worktrees/$wt2/file"
    assert_file_absent "$ROOT/.worktrees/$wt2/file2"
    assert_file_absent "$ROOT/.worktrees/$wt2/file3"
    assert_file_exists "$ROOT/.worktrees/$wt3/file"
    assert_file_exists "$ROOT/.worktrees/$wt3/file2"
    assert_file_exists "$ROOT/.worktrees/$wt3/file3"
}
```
