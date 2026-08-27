### Title
Attacker-controlled ref oscillation defeats stale-worktree cleanup, causing unbounded disk growth - (File: main.go)

### Summary
`git-sync`'s stale-worktree cleanup uses a purely time-based (mtime) heuristic, refreshed on every publish, analogous to the PoolTogether bug where a period-boundary check ("same period ⇒ no new observation / reset the record") let an attacker keep resetting state before a boundary was crossed. Here, an attacker who controls commits on the synced `--ref` (untrusted upstream repo content, not a git-sync operator or leaked credential) can keep pushing/reverting between two or more commits faster than `--stale-worktree-timeout`, perpetually resetting each worktree's mtime and preventing `removeStaleWorktrees` from ever collecting them — causing unbounded worktree accumulation under `--root` and eventual disk exhaustion / sync denial.

### Finding Description
`SyncRepo` computes `changed` purely by comparing the currently-published hash to the newly fetched hash [1](#0-0) . Whenever `changed` is true, it creates (or re-creates) a worktree for the new hash and republishes the symlink; critically, it also calls `touch(currentWorktree.Path())` on the *previous* worktree solely to "start the stale worktree removal timer" [2](#0-1) .

The actual cleanup decision is made later by `removeStaleWorktrees`, which deletes any worktree directory whose name is not the current hash and whose `ModTime()` is older than `git.staleTimeout` — nothing else gates deletion [3](#0-2) . `createWorktree` unconditionally removes and recreates the on-disk directory for a hash whenever it becomes the active target again [4](#0-3) , which also resets that directory's mtime.

Because the "freshness" of a worktree is reset by two independent, remotely-triggerable events (becoming the *current* worktree via `createWorktree`, or becoming the *immediately-previous* worktree via the `touch()` call), an attacker who can push new commits to the tracked ref faster than the configured `--stale-worktree-timeout` (default relates to `--period`, which itself defaults to 10s per README) can indefinitely keep any set of worktrees "fresh": e.g. cycling through N distinct commit hashes with a period shorter than the stale timeout ensures every one of the N worktree directories gets its mtime refreshed before it can ever be judged stale. This is directly analogous to the PoolTogether bug: a time/period-boundary check (`currentPeriod == newestObservationPeriod` there; `time.Since(fi.ModTime()) > staleTimeout` here) that can be perpetually reset by attacker-controlled activity occurring within the window, defeating the intended finalization/cleanup semantics.

### Impact Explanation
Each new distinct commit hash produces a new `.worktrees/<hash>` directory containing a full checkout (and, if submodules are used, submodule checkouts as well, per `e2e::submodule_sync_default`) [5](#0-4) . If an attacker with push access to the tracked branch (or an attacker who can influence the upstream, e.g. via a compromised CI job, a malicious PR merge automation, or a webhook-driven mirror) cycles through many distinct commits faster than `--stale-worktree-timeout`, `git-sync` will accumulate a growing number of full worktree checkouts under `--root` that are never reclaimed. This can exhaust the volume backing `--root` (frequently a Kubernetes `emptyDir` or PVC sized for one or two checkouts), leading to persistent sync denial: once the volume is full, `git worktree add`/`git fetch` calls begin failing, which matches the "persistent sync denial" impact category.

### Likelihood Explanation
This requires only:
- The ability to push arbitrary commits to the ref that `git-sync` tracks (a realistic "untrusted repo content" scenario — e.g., a branch that isn't fully access-controlled, or a repo where a compromised bot/PR pipeline can land commits), and
- A sync `--period` and `--stale-worktree-timeout` combination where the attacker can produce more distinct commits than the timeout window allows to expire (well within reach for automated pushers; default `--period` is 10s and `--stale-worktree-timeout` is likewise on the order of seconds/minutes per the flag docs) [6](#0-5) .

No credentials, no operator misbehavior, and no exploitation of git-sync internals beyond its documented sync loop are needed — it is a straightforward abuse of the time-window based cleanup logic. Likelihood is Medium: it depends on the deployment allowing untrusted/high-frequency pushes to the synced ref, but where that holds, exploitation is trivial and reliable.

### Recommendation
Bound worktree retention by more than elapsed time since last touch:
- Cap the total number of retained worktrees (e.g., `--max-worktrees`) regardless of mtime, evicting the oldest by *creation* order rather than by "last became current/previous" mtime.
- Track staleness using an immutable creation timestamp (or monotonic sync-count/generation number) recorded once when the worktree is created, instead of an mtime that can be refreshed by unrelated later events (`touch()` on demotion, recreation via `createWorktree`).
- Enforce a hard disk-usage ceiling under `--root` and refuse/alert when exceeded, independent of the stale-timeout heuristic.

### Proof of Concept
1. Deploy `git-sync` with `--repo=<attacker-influenceable repo>` `--ref=<branch>` `--period=1s` `--stale-worktree-timeout=5s` `--root=/root`.
2. As the attacker (someone with push rights to `<branch>`, e.g. via a compromised automation), script a loop that pushes alternating/rotating distinct commits (A, B, C, A, B, C, …) to `<branch>` every ~1s, i.e., faster than the 5s stale timeout.
3. Observe: every 1s, `SyncRepo` finds `changed == true` (per `main.go:1899-1918`), creates a fresh worktree for the new hash via `createWorktree` (`main.go:1644-1663`, resetting mtime), and calls `touch()` on the demoted worktree (`main.go:1960-1970`), resetting its mtime as well.
4. Because `removeStaleWorktrees` only deletes directories whose mtime is older than `staleTimeout` and isn't the current hash (`main.go:1420-1441`), none of A/B/C's worktree directories ever age past 5s, so all three (and any further distinct commits introduced this way) persist indefinitely under `/root/.worktrees/`.
5. Extend the rotation set (more distinct commits) to grow disk usage arbitrarily until the volume backing `--root` is exhausted, at which point subsequent `git worktree add`/fetch operations fail and syncing halts (persistent sync denial).

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

**File:** main.go (L1644-1663)
```go
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

**File:** main.go (L1899-1918)
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
```

**File:** main.go (L1960-1970)
```go
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

**File:** test_e2e.sh (L3007-3018)
```shellscript
    GIT_SYNC \
        --period=100ms \
        --repo="file://$REPO" \
        --root="$ROOT" \
        --link="link" \
        &
    wait_for_sync "${MAXWAIT}"
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_exists "$ROOT/link/$submodule_repo_name/submodule.file"
    assert_file_eq "$ROOT/link/$submodule_repo_name/submodule.file" "submodule"
    assert_metric_eq "${METRIC_GOOD_SYNC_COUNT}" 1
```

**File:** README.md (L463-467)
```markdown
    --period <duration>, $GITSYNC_PERIOD
            How long to wait between sync attempts.  This must be at least
            10ms.  This flag obsoletes --wait, but if --wait is specified, it
            will take precedence.  If not specified, this defaults to 10
            seconds ("10s").
```
