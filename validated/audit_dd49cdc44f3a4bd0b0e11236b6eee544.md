Confirmed: `publishSymlink` in `main.go:1592-1620` never removes a pre-existing `tmp-link` before creating it, and there's no retry/cleanup path in `SyncRepo` for this specific failure mode — matching the "no handling for a partially-completed step, leaving the process permanently stuck" bug class from the report.

### Title
Persistent Sync Denial via Un-Cleaned `tmp-link` After Interrupted `publishSymlink` - (File: main.go)

### Summary
`repoSync.publishSymlink` creates a temporary symlink named `tmp-link` inside the `--link` directory and then renames it onto the final `--link` path to achieve an atomic publish [1](#0-0) . If the process is interrupted, killed, or the `os.Rename` call fails for any reason (e.g. `ENOSPC`, permission denied, unexpected external tampering with the `--link` directory) after `tmp-link` is created but before the rename completes, the leftover `tmp-link` file is never cleaned up on the next attempt.

### Finding Description
`publishSymlink` unconditionally calls `os.Symlink(targetRelative, filepath.Join(linkDir.String(), tmplink))` without first removing any pre-existing `tmp-link`, and returns an error immediately if that call fails [2](#0-1) . On the very next sync attempt, `SyncRepo` recomputes state, potentially recreates the worktree, and calls `publishSymlink` again [3](#0-2) . Because `tmp-link` still exists from the earlier aborted attempt, `os.Symlink` will fail every time with "file exists", and `publishSymlink` will keep returning `"error creating symlink: %w"` indefinitely.

This mirrors the SteadeFi bug class exactly: a multi-step "publish" operation (create liquidity / create tmp-link → add liquidity / rename to final link) that has no recovery/cleanup logic for the case where the first step succeeded but the second step didn't complete, and the process is retried repeatedly without ever clearing the stale intermediate state.

The failure then propagates up: `SyncRepo` returns an error, `main`'s loop increments `failCount` and retries at `--period` forever (or up to `--max-failures`, which defaults to abort-after-first-failure, but any positive/negative configuration continues attempting the exact same doomed operation) [4](#0-3) . Unlike `createWorktree`, which explicitly guards against exactly this class of "wedge" state by removing any stale leftover worktree before creating a new one ("Avoid wedge cases where the worktree was created but this function error'd without cleaning up") [5](#0-4) , no equivalent guard exists for `tmp-link` in `publishSymlink`.

### Impact Explanation
Once `tmp-link` is left behind, git-sync can never publish a new revision again without external/manual intervention (deleting the stray file) — this is a persistent sync denial. The application/pod consuming the `--link` symlink is stuck serving a stale (or, on very first sync, no) revision indefinitely, and with `--one-time` unset, the process loops forever emitting the same "error creating symlink: file exists" error, burning CPU cycles and never recovering, closely paralleling the report's "loop of borrow more => add liquidity => get canceled ... until keeper runs out of gas" scenario.

### Likelihood Explanation
This requires an interruption between the two filesystem operations in `publishSymlink` (e.g., container OOM-kill, `SIGKILL`, node crash, disk-full during rename, or a race where an external actor/process touches the link directory). Kubernetes sidecars are routinely killed abruptly (pod eviction, node preemption, OOM), so hitting this timing window during a live rollout is a realistic operational occurrence rather than a purely theoretical race.

### Recommendation
In `publishSymlink`, remove any pre-existing `tmp-link` before attempting to create it (e.g. `os.Remove(filepath.Join(linkDir.String(), tmplink))`, ignoring `os.ErrNotExist`), mirroring the defensive cleanup already implemented in `createWorktree` for stale worktree directories [5](#0-4) . This ensures each publish attempt starts from a clean state regardless of how the previous attempt terminated.

### Proof of Concept
1. Run git-sync with `--repo`, `--root`, `--link=link`, `--period=1s`.
2. Let it complete an initial successful sync (or intercept before the first one).
3. Simulate an interrupted publish: manually create `<root>/tmp-link` pointing anywhere (`ln -s x <root>/tmp-link`) to emulate a crash between `os.Symlink` and `os.Rename` in `publishSymlink` [1](#0-0) .
4. Trigger a new commit on the remote so `changed` becomes true on the next loop iteration.
5. Observe that every subsequent `SyncRepo` call fails with `"error creating symlink: symlink tmp-link: file exists"`, `failCount` increments every cycle, and the symlink at `--link` never advances — the process never recovers on its own; the `tmp-link` file must be removed out-of-band to unblock it.

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

**File:** main.go (L1608-1617)
```go
	const tmplink = "tmp-link"
	git.log.V(2).Info("creating tmp symlink", "dir", linkDir, "link", tmplink, "target", targetRelative)
	if err := os.Symlink(targetRelative, filepath.Join(linkDir.String(), tmplink)); err != nil {
		return fmt.Errorf("error creating symlink: %w", err)
	}

	git.log.V(2).Info("renaming symlink", "root", linkDir, "oldName", tmplink, "newName", linkFile)
	if err := os.Rename(filepath.Join(linkDir.String(), tmplink), git.link.String()); err != nil {
		return fmt.Errorf("error replacing symlink: %w", err)
	}
```

**File:** main.go (L1648-1654)
```go
	// Avoid wedge cases where the worktree was created but this function
	// error'd without cleaning up.  The next time thru the sync loop fails to
	// create the worktree and bails out. This manifests as:
	//     "fatal: '/repo/root/nnnn' already exists"
	if err := git.removeWorktree(ctx, worktree); err != nil {
		return "", err
	}
```

**File:** main.go (L1955-1963)
```go
			err := syncHooks.beforePublish(newWorktree.Hash())
			if err != nil {
				return false, "", err
			}

			err = git.publishSymlink(newWorktree)
			if err != nil {
				return false, "", err
			}
```
