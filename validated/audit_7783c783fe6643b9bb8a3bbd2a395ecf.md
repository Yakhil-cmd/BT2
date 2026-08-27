Based on my analysis, I found a legitimate analog in `git-sync`.

### Title
Self-recovery logic destroys the currently-published worktree before its replacement is ready, causing the published `--link` to dangle and denying consumers access to previously-good synced content - (File: main.go)

### Summary
The external report's core theme — a system proactively cutting off access to a user's/consumer's already-valid state as part of its own defensive/recovery logic, rather than preserving access to the last-good state — has a direct analog in `git-sync`'s `SyncRepo` recovery path, where a failed worktree sanity check causes the tool to delete the currently published worktree *before* it has successfully created and published a replacement.

### Finding Description
In `SyncRepo`, when the locally recorded hash matches the remote hash, `git-sync` still re-validates the existing worktree via `sanityCheckWorktree` (which runs `git fsck --connectivity-only` and HEAD checks) [1](#0-0) . If this check fails, `git-sync` immediately calls `removeWorktree`, which does `os.RemoveAll` on the worktree directory that the published symlink (`--link`) currently points to [2](#0-1) , and only then sets `currentHash = ""` to force recreation.

The subsequent recreation path calls `createWorktree` (git worktree add), `configureWorktree`, `beforePublish` hook, and only finally `publishSymlink` — any error at any of these steps causes the function to `return false, "", err` immediately, without ever calling `publishSymlink` [3](#0-2) . Because the on-disk directory was already deleted by the earlier `removeWorktree` call, the previously-published symlink at `git.link` is now left dangling (pointing to a directory that no longer exists) [4](#0-3) .

This mirrors the report's bug class: the tool tears down a consumer's currently-accessible valid asset (the good worktree) as a side effect of "recovery," without any guarantee that the replacement will be published, leaving the consumer with nothing instead of the old-but-good state.

### Impact Explanation
Any container mounting `--root`/`--link` (the standard sidecar pattern) will suddenly find the link broken/ENOENT even though it had a previously synced, valid tree just moments before. This is a "persistent sync denial": until a sync cycle succeeds end-to-end, the application-facing symlink is unusable, even though the tool had valid data on disk right before the failed sanity check. If recreation continues to fail across iterations (e.g. sustained fetch/network/git errors, transient object corruption, or repeated `configureWorktree`/hook failures), this denial persists for as long as those errors persist, and eventually the loop can hit `--max-failures` and call `os.Exit(1)` [5](#0-4) , terminating the sidecar entirely.

### Likelihood Explanation
This path is only reachable when `sanityCheckWorktree` fails despite `currentHash == remoteHash` — e.g., interrupted `git worktree add`/checkout, disk-level corruption, external tampering with the worktree, or a corrupted object introduced by an upstream fetch. This is a maintenance/edge-case condition (similar to the "should be transient" caveat noted in the original report for the paused-strategy bug), so likelihood is comparable: medium-low, transient, but genuinely reachable without any privileged access — no malicious operator or leaked credentials required, just an unlucky/adversarial upstream state.

### Recommendation
Do not delete the currently-published worktree until a replacement worktree has been fully created, configured, and successfully published via `publishSymlink`. Reorder the logic in `SyncRepo` so that `removeWorktree(ctx, currentWorktree)` for the failed-sanity-check case is deferred until after `createWorktree`/`configureWorktree`/`publishSymlink` complete successfully for the new worktree (analogous to how "regular cleanup" of stale worktrees is already deferred to the outer loop) [6](#0-5) , ensuring the symlink always points at *something* valid throughout the recovery attempt.

### Proof of Concept
1. Start `git-sync` with `--repo`, `--root`, `--link` pointing at a healthy remote at hash `H`; wait for first successful sync — `--link` now points at `.worktrees/H`.
2. Without changing the remote ref (so `currentHash == remoteHash` on the next loop), corrupt the on-disk worktree in a way `sanityCheckWorktree`'s `fsck --connectivity-only` will catch (e.g., truncate/corrupt an object under `.git`, or simulate a partial `git worktree add` by killing the process mid checkout on a prior run) — this is the same class of scenario the existing `worktree_unexpected_removal`/`sync_recover_wrong_worktree_hash` e2e tests simulate by pausing the container and mutating `$ROOT/.worktrees/$sha` [7](#0-6) .
3. On the next sync iteration, `sanityCheckWorktree` returns `false`, so `removeWorktree` deletes `.worktrees/H` (the directory `--link` currently points to) [8](#0-7) .
4. Immediately after, inject a failure into `createWorktree`/`configureWorktree`/`beforePublish` (e.g., make the git root filesystem read-only, or supply an invalid `--sparse-checkout-file` that only fails on this recreation attempt, or fail the pre-publish exechook) so that `SyncRepo` returns an error before reaching `publishSymlink`.
5. Observe: `--link` is now a dangling symlink to a non-existent `.worktrees/H` directory; any consumer reading through `--link` gets `ENOENT`, despite `git-sync` having served valid content moments earlier — reproducing the "denial of access to previously-valid, already-held state" pattern described in the source report.

### Citations

**File:** main.go (L1056-1063)
```go
		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
```

**File:** main.go (L1592-1620)
```go
func (git *repoSync) publishSymlink(worktree worktree) error {
	targetPath := worktree.Path()
	linkDir, linkFile := git.link.Split()

	// Make sure the link directory exists.
	if err := os.MkdirAll(linkDir.String(), defaultDirMode); err != nil {
		return fmt.Errorf("error making symlink dir: %w", err)
	}

	// linkDir is absolute, so we need to change it to a relative path.  This is
	// so it can be volume-mounted at another path and the symlink still works.
	targetRelative, err := filepath.Rel(linkDir.String(), targetPath.String())
	if err != nil {
		return fmt.Errorf("error converting to relative path: %w", err)
	}

	const tmplink = "tmp-link"
	git.log.V(2).Info("creating tmp symlink", "dir", linkDir, "link", tmplink, "target", targetRelative)
	if err := os.Symlink(targetRelative, filepath.Join(linkDir.String(), tmplink)); err != nil {
		return fmt.Errorf("error creating symlink: %w", err)
	}

	git.log.V(2).Info("renaming symlink", "root", linkDir, "oldName", tmplink, "newName", linkFile)
	if err := os.Rename(filepath.Join(linkDir.String(), tmplink), git.link.String()); err != nil {
		return fmt.Errorf("error replacing symlink: %w", err)
	}

	return nil
}
```

**File:** main.go (L1622-1640)
```go
// removeWorktree is used to remove a worktree and its folder.
func (git *repoSync) removeWorktree(ctx context.Context, worktree worktree) error {
	// Clean up worktree, if needed.
	_, err := os.Stat(worktree.Path().String())
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	}
	git.log.V(1).Info("removing worktree", "path", worktree.Path())
	if err := os.RemoveAll(worktree.Path().String()); err != nil {
		return fmt.Errorf("error removing directory: %w", err)
	}
	if _, _, err := git.Run(ctx, git.root, "worktree", "prune", "--verbose"); err != nil {
		return err
	}
	return nil
}
```

**File:** main.go (L1899-1993)
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

	// We have to do at least one fetch, to ensure that parameters like depth
	// are set properly.  This is cheap when we already have the target hash.
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
		}

		err := syncHooks.afterPublish(newWorktree.Hash())
		if err != nil {
			return false, "", err
		}

		// Mark ourselves as "ready".
		setRepoReady()
		git.syncCount++
		git.log.V(0).Info("updated successfully", "ref", git.ref, "remote", remoteHash, "syncCount", git.syncCount)

		// Regular cleanup will happen in the outer loop, to catch stale
		// worktrees.

		// We can end up here with no current hash but (the expectation of) a
		// current worktree (e.g. the hash was synced but the worktree does not
		// exist).
		if currentHash != "" && currentWorktree != git.worktreeFor(currentHash) {
			// The old worktree might have come from a prior version, and so
			// not get caught by the normal cleanup.
			os.RemoveAll(currentWorktree.Path().String())
		}
```

**File:** test_e2e.sh (L735-774)
```shellscript
function e2e::worktree_unexpected_removal() {
    GIT_SYNC \
        --period=100ms \
        --repo="file://$REPO" \
        --root="$ROOT" \
        --link="link" \
        &

    # wait for first sync
    wait_for_sync "${MAXWAIT}"
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_eq "$ROOT/link/file" "${FUNCNAME[0]}"
    assert_metric_eq "${METRIC_GOOD_SYNC_COUNT}" 1
    assert_metric_eq "${METRIC_FETCH_COUNT}" 1

    # suspend time so we can fake corruption
    docker ps --filter label="git-sync-e2e=$RUNID" --format="{{.ID}}" \
        | while read -r ctr; do
            docker pause "$ctr" >/dev/null
        done

    # make a unexpected removal
    local wt
    wt=$(git -C "$REPO" rev-list -n1 HEAD)
    rm -r "$ROOT/.worktrees/$wt"

    # resume time
    docker ps --filter label="git-sync-e2e=$RUNID" --format="{{.ID}}" \
        | while read -r ctr; do
            docker unpause "$ctr" >/dev/null
        done

    wait_for_sync "${MAXWAIT}"
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_eq "$ROOT/link/file" "${FUNCNAME[0]}"
    assert_metric_eq "${METRIC_GOOD_SYNC_COUNT}" 2
    assert_metric_eq "${METRIC_FETCH_COUNT}" 2
}
```
