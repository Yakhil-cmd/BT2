### Title
`sanityCheckWorktree` can pass a partially-checked-out worktree, causing git-sync to silently (re-)publish incomplete content - (File: main.go)

### Summary
`ZcToken.withdraw` silently returns `0` tokens because it trusts a stale/uninitialized state variable (`maturityRate`) without verifying that the state truly reflects a "ready" market. The reachable analog in git-sync is `repoSync.sanityCheckWorktree`, which is used to decide whether an on-disk worktree is trustworthy enough to keep publishing via the `--link` symlink. Its own doc comment admits it does **not** guarantee the worktree is fully checked out, yet its `true` result is treated by `SyncRepo` as proof that the currently-published content is valid and no re-sync/re-publish is required. This can cause git-sync to keep serving (or newly publish) a partially checked-out repo/submodule tree without ever surfacing an error, exactly mirroring the "operation reports success but delivers incomplete/zero content" bug class from the report.

### Finding Description
`sanityCheckWorktree` at [1](#0-0)  only verifies three things: the worktree directory isn't empty, `git rev-parse HEAD` matches the worktree's hash-named directory, and `git fsck --connectivity-only` succeeds. The function's own comment states: *"Note that this does not guarantee that the worktree has all the files checked out - git could have died halfway through and the repo will still pass this check."*

This check gates a critical decision in `SyncRepo`: when the locally recorded hash already equals the remote hash, git-sync calls `sanityCheckWorktree` and, if it returns `true`, treats the existing worktree (and by extension the already-published symlink target) as good — no re-checkout, no re-publish, no error is raised: [2](#0-1) 

Because `HEAD` is set early via `git reset --hard <hash>` in `configureWorktree` before submodules are updated, a process interruption (container OOM-kill, node preemption, `SIGKILL`, disk pressure, etc.) between the `reset --hard` and the subsequent `submodule update --init` step at [3](#0-2)  leaves a worktree whose `HEAD` already matches the intended hash and whose objects are connectivity-clean (submodule gitlinks don't have to resolve for `fsck --connectivity-only` in the superproject to pass), but whose submodule directories are empty/uninitialized. On the next loop iteration, `sanityCheckWorktree` passes this half-populated worktree, `changed` evaluates to `false` (or true only for cosmetic reasons unrelated to content completeness), and git-sync happily reports a successful, "ready" sync (`setRepoReady()`) while consumers continue to read incomplete submodule content through the unchanged symlink — indefinitely, since nothing ever detects or corrects the gap.

### Impact Explanation
This matches the accepted impact class "publishing wrong or partial content": consumers of the `--link` path (e.g. sidecar application containers in Kubernetes) can be served a checkout that is missing submodule data while git-sync's own signals (readiness probe, metrics, logs) report a fully successful, healthy sync. Unlike a normal failure, this does not trigger `--max-failures` retries or alerting, so the wrong state can persist across the deployment's lifetime, similar in nature to the `withdraw` function silently returning `0` while still reporting a "successful" transaction.

### Likelihood Explanation
Requires only an ordinary interruption (crash, OOM kill, eviction) at a specific but not-unlikely window during a submodule-enabled sync — a routine occurrence for sidecar containers in Kubernetes which are subject to preemption, resource limits and restarts. No attacker privilege beyond normal operation of the sidecar/environment is needed, and the repository content itself does not need to be malicious for the race to occur, though a remote-repo operator could also intentionally structure commits/submodules to widen this window.

### Recommendation
Extend `sanityCheckWorktree` (or add a dedicated check) to verify submodule completeness (e.g. `git submodule status` shows no uninitialized "-" entries, or track a distinct "checkout complete" marker/sentinel file written only after `configureWorktree` fully finishes) before trusting an existing worktree as reflecting the remote's true, complete content. Treat lack of that marker the same as a failed sanity check, forcing `removeWorktree` + full re-checkout.

### Proof of Concept
1. Configure git-sync with `--submodules=recursive` against a repo with a submodule.
2. During the `configureWorktree` step, after `git reset --hard <hash>` succeeds but before `git submodule update --init --recursive` completes, kill the git-sync process/container (simulating OOM/eviction).
3. Restart git-sync. In `SyncRepo`, `currentHash == remoteHash` and `sanityCheckWorktree` (main.go:1505-1536) returns `true` because `rev-parse HEAD` and `fsck --connectivity-only` both succeed despite the submodule directory being empty.
4. git-sync logs "update not required", calls `setRepoReady()`, and the symlink keeps pointing at the partially-populated worktree — the consumer sees a repo missing submodule files while git-sync reports full success (analogous to the existing e2e test scaffolding around worktree corruption at [4](#0-3) , which currently only exercises unexpected worktree removal, not partial-submodule-checkout detection).

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

**File:** main.go (L1727-1747)
```go
	// Reset the worktree's working copy to the specific ref.
	git.log.V(1).Info("setting worktree HEAD", "hash", hash)
	if _, _, err := git.Run(ctx, worktree.Path(), "reset", "--hard", hash, "--"); err != nil {
		return err
	}

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

**File:** main.go (L1899-1910)
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
```

**File:** test_e2e.sh (L732-774)
```shellscript
##############################################
# Test worktree unexpected removal
##############################################
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
