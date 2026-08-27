Based on the investigation, there is a valid analog in `git-sync`: a single attacker-controlled commit can be "accepted" during the early stages of the sync loop (fetch + `git reset --soft`) but is guaranteed to fail during the later checkout/submodule stage, and — because the default `--max-failures` is `0` — that single failure terminates the whole process, creating a crash-loop / persistent sync denial that is fully attacker-triggerable through ordinary repository content.

### Title
Attacker-controlled commit content causes deterministic post-fetch checkout failure and default-config process termination (persistent sync denial) - (File: main.go)

### Summary
`repoSync.SyncRepo` advances the local repo's committed state (`git reset --soft <remoteHash>`) as soon as a new commit is fetched, before actually attempting to materialize that commit into a worktree (`createWorktree`/`configureWorktree`, including `git reset --hard` and `git submodule update --init`). Any commit whose tree cannot be fully checked out or whose submodules cannot be initialized (e.g. a `.gitmodules` entry pointing at an unreachable/invalid URL) will always pass the "acceptance" step but always fail the later "materialization" step — exactly mirroring the reported pattern where a user-controlled parameter passes an early state transition but is guaranteed to fail a later check. Because `--max-failures` defaults to `0` ("any sync failure will terminate git-sync"), this single bad commit causes git-sync to exit immediately, and since the underlying repo state (fetch ref / branch HEAD) is unchanged, the very next restart hits the identical failure again.

### Finding Description
The sync pipeline in `repoSync.SyncRepo` is:
1. `git.fetch(ctx, git.ref)` — fetches the new commit [1](#0-0) 
2. `git reset --soft <remoteHash>` — advances the repo's local state to the new commit unconditionally once a change is detected [2](#0-1) 
3. `createWorktree` — `git worktree add --no-checkout` (does not validate the tree can actually be checked out) [3](#0-2) 
4. `configureWorktree` — only here does git actually attempt `git reset --hard <hash>` and, since `--submodules` defaults to `recursive`, `git submodule update --init [--recursive]` [4](#0-3) [5](#0-4) 

Step 2 unconditionally commits to the new remote hash as the repo's tracked state before step 4 performs the checks that can actually fail. An attacker who can push (or get merged) a single commit that adds/modifies `.gitmodules` with an unreachable or invalid submodule URL will pass fetch/reset cleanly, but `git submodule update --init` in `configureWorktree` will always fail for that commit. `SyncRepo` returns that error every time this commit is the fetch target.

Back in the main loop, any error increments `failCount`, and if `getMaxFailures()` (which defaults to `*flMaxFailures == 0`) is reached, git-sync calls `os.Exit(1)` immediately: [6](#0-5) [7](#0-6) [8](#0-7) 

Because the container/pod supervisor will typically restart git-sync after it exits, and the tracked ref (e.g. a branch HEAD) still points at the same bad commit, the process will fetch the same commit, fail the same submodule step, and exit again — a persistent crash loop that denies service until an operator notices and force-pushes/reverts the offending commit or changes `--ref`.

### Impact Explanation
This causes complete, repeated denial of the sync sidecar with default configuration (`--max-failures` unset ⇒ `0`, `--submodules` unset ⇒ `recursive`). Any application relying on git-sync as a sidecar to serve files loses the ability to receive updates and the sidecar container itself crash-loops, which in Kubernetes can also trip pod restart back-off and liveness/readiness probes, escalating to broader service disruption. No credentials or privileged access are needed by the attacker — only the ability to get one commit onto the tracked ref (a common capability in GitOps/CI workflows where PRs from lower-trust contributors are merged or where a branch is directly writable).

### Likelihood Explanation
Highly likely to be exploitable in realistic deployments: `--submodules` is `recursive` by default so no special opt-in is required, `--max-failures` is `0` by default so a single bad commit is sufficient, and adding a broken `.gitmodules` entry is trivial for anyone with commit access to the tracked ref. No race conditions or timing requirements are involved — the failure is deterministic on every sync attempt against that commit.

### Proof of Concept
1. Deploy git-sync with default flags: `--repo=<repo>`, `--ref=main`, `--root=/tmp/root`, `--link=link` (no `--max-failures`, default `--submodules=recursive`).
2. In the tracked repo, on `main`, add a `.gitmodules` file referencing a submodule with an unreachable/invalid URL, e.g.:
   ```
   [submodule "bad"]
       path = bad
       url = https://example.invalid/does-not-exist.git
   ```
   and commit/push it (this can be done by any contributor able to push/merge to `main`).
3. Observe git-sync's next sync cycle: `fetch` succeeds, `reset --soft` succeeds, `worktree add --no-checkout` succeeds, but `git submodule update --init --recursive` in `configureWorktree` fails because the submodule URL is unreachable.
4. `SyncRepo` returns an error; the main loop increments `failCount` to `1`, `getMaxFailures()` returns `0`, so `failCount >= maxFails` is true and git-sync calls `os.Exit(1)` immediately. [9](#0-8) 
5. Restart git-sync (as a Kubernetes pod restart would): it fetches the same `main` HEAD (the bad commit), fails the same submodule step, and exits again — reproducing indefinitely until the offending commit is reverted or `--ref` is changed.

### Citations

**File:** main.go (L182-184)
```go
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
```

**File:** main.go (L213-215)
```go
	flMaxFailures := pflag.Int("max-failures",
		envInt(0, "GITSYNC_MAX_FAILURES", "GIT_SYNC_MAX_FAILURES"),
		"the number of consecutive failures allowed before aborting (-1 will retry forever")
```

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

**File:** main.go (L1885-1887)
```go
	if err := git.fetch(ctx, git.ref); err != nil {
		return false, "", err
	}
```

**File:** main.go (L1918-1927)
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
```

**File:** README.md (L442-446)
```markdown
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```
