### Title
Persistent sync denial after successful publish — `afterPublish` hook failure causes `SyncRepo` to report error and block readiness even though content is already published - ([File: main.go])

### Summary
In the Y2K Finance report, `getLatestPrice()` is called purely for **informational/logging purposes** (populating an event) at the tail end of `triggerEndEpoch()`, yet a revert from that call blocks the entire function, even though the state-changing/critical work (marking risk-holders as winners) has effectively already been decided. The analogous flaw in `git-sync` is in `repoSync.SyncRepo()`: the **post-publish notification hook** (`syncHooks.afterPublish`) — whose only job is to notify consumers via exec/webhook that a new hash is available — is invoked *after* the atomic symlink publish has already succeeded, but its failure is still treated as a fatal error for the whole sync operation, which can escalate into a hard process termination (`os.Exit(1)`) via the `--max-failures` counter, even though the critical action (publishing new content behind `--link`) already completed correctly.

### Finding Description
`SyncRepo` performs the critical, atomic operation first, then treats an auxiliary/informational hook the same as a hard sync failure: [1](#0-0) 

Specifically:
1. When `changed` is true, `git.publishSymlink(newWorktree)` runs and — on success — the new content is **already live** at `--link` (this is the "critical action," analogous to the vault epoch having ended and winners being determined).
2. Immediately after, `syncHooks.afterPublish(newWorktree.Hash())` is called purely to fire exec/webhooks notifying the consumer. This is documented as best-effort/idempotent/retryable machinery, not a requirement for the symlink to be correct: [2](#0-1) 
3. However, if `afterPublish` returns an error, `SyncRepo` returns an error for the *entire sync*, **before** `setRepoReady()` is called and **before** `git.syncCount++`: [3](#0-2) 
4. Back in the main loop, this is treated identically to a real sync failure: `failCount` is incremented, and once `failCount >= maxFails`, the whole process exits: [4](#0-3) 
5. Because `git.syncCount` was never incremented, the next loop iteration re-enters the "update required" branch unconditionally (`changed || git.syncCount == 0`), re-running only the tail (`afterPublish`) without re-doing anything wrong — but if the hook keeps failing (e.g. webhook endpoint down, analogous to the Arbitrum sequencer being down), the failure count keeps climbing on every cycle: [5](#0-4) 

This exactly mirrors the reported bug class: an **informational/notification-only external call** (webhook/exechook, analogous to `getLatestPrice()`'s log-only usage) is allowed to gate completion of, and eventually terminate, an operation whose critical, user-visible effect (publishing new content / entitling withdrawal) has already happened.

### Impact Explanation
If `--webhook-url` or `--exechook-command` is configured and that external endpoint/script is transiently unavailable or slow to return success (a very plausible operational condition — process restarts, throttling, sidecar not yet ready, etc.), then:
- `setRepoReady()` is never called for that cycle, so the `--http-bind` readiness endpoint keeps returning failure even though the symlink content is already correct and up to date, which can cause Kubernetes to treat the pod as NotReady/unhealthy indefinitely.
- `failCount` accumulates purely due to the notification hook, and once it reaches `--max-failures`/`--init-max-failures`, `git-sync` calls `os.Exit(1)`, killing the sidecar entirely — a **persistent sync denial** for the whole pod, not just a missed notification, even though the actual Git content was already correctly and atomically published.

This satisfies the "Accept" criteria of persistent sync denial and denial of an already-completed publish being surfaced/relied upon (readiness) — it is not merely dependency flakiness with no impact, because it escalates to full process death via the standard failure-counting path.

### Likelihood Explanation
This requires the operator to have configured `--webhook-url` or `--exechook-command` (a normal, documented, and common feature) and for that endpoint/command to be flaky or down for longer than `--webhook-backoff`/`--exechook-backoff` times `--max-failures` retries — a realistic operational scenario (e.g., a slow-starting sidecar consuming the webhook, or a rate-limited external notification endpoint), directly analogous to the "Arbitrum sequencer down / in grace period" precondition in the original report. No attacker-controlled repo content is strictly required; this is triggerable purely by external dependency unavailability, matching the same bug class as the source report.

### Recommendation
Decouple the "publish success" signal from "notification hook success":
- Call `setRepoReady()` and increment `git.syncCount` (and clear `failCount`) as soon as `publishSymlink` succeeds, regardless of `afterPublish` hook outcome.
- Run `afterPublish` asynchronously/best-effort (it is already retried internally by `HookRunner`), and do not let its error propagate as a `SyncRepo` failure that feeds into `failCount`/`--max-failures`/`os.Exit(1)`.
- If hook failures need to be surfaced, use a separate metric/log channel rather than the sync failure counter that can terminate the process.

### Proof of Concept
1. Start `git-sync` with `--webhook-url=http://<endpoint-that-will-fail>` and a low `--max-failures` (e.g. 3) and short `--webhook-backoff`.
2. Let the first sync succeed: `publishSymlink` runs, `--link` now points at the correct new worktree hash (content is live and correct).
3. Have the webhook endpoint return a non-success status (or be down) for longer than `--webhook-backoff * --max-failures`.
4. Observe: `afterPublish` keeps failing → `SyncRepo` keeps returning an error → `failCount` climbs each `--period` cycle (main.go:1056‑1063) → once `failCount >= maxFails`, `git-sync` calls `os.Exit(1)` main.go:1059-1061, terminating the sidecar — even though `--link` already contains fully correct, up-to-date content and no further Git work was needed.

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

**File:** main.go (L1912-1919)
```go
	// This catches in-place upgrades from older versions where the worktree
	// path was different.
	changed := (currentHash != remoteHash) || (currentWorktree != git.worktreeFor(currentHash))

	// We have to do at least one fetch, to ensure that parameters like depth
	// are set properly.  This is cheap when we already have the target hash.
	if changed || git.syncCount == 0 {
		git.log.V(0).Info("update required", "ref", git.ref, "local", currentHash, "remote", remoteHash, "syncCount", git.syncCount)
```

**File:** main.go (L1947-1981)
```go
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
```

**File:** README.md (L654-666)
```markdown
HOOKS

    Webhooks and exechooks are executed asynchronously from the main git-sync
    process.  If a --webhook-url or --exechook-command is configured, they will
    be invoked whenever a new hash is synced, including when git-sync starts up
    and find that the --root directory already has the correct hash.  For
    exechook, that means the command is exec()'ed, and for webhooks that means
    an HTTP request is sent using the method defined in --webhook-method.
    Git-sync will retry both forms of hooks until they succeed (exit code 0 for
    exechooks, or --webhook-success-status for webhooks).  If unsuccessful,
    git-sync will wait --exechook-backoff or --webhook-backoff (as appropriate)
    before re-trying the hook.  Git-sync does not ensure that hooks are invoked
    exactly once, so hooks must be idempotent.
```
