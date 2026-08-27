### Title
Liveness/readiness probe reports permanent "healthy" after first sync, masking indefinite staleness during sync failures - (File: main.go, README.md)

### Summary
The externally reported issue centers on a fundamental oracle design flaw: once a data source is accepted as valid, the system does not verify continuing freshness, allowing an attacker to cheaply keep the data stale while downstream consumers still treat it as trustworthy/live. The same class of bug exists in `git-sync`'s `--http-bind` health endpoint: it is a one-shot gate ("5xx until first sync, `200` thereafter") rather than a continuous freshness signal, so once a pod passes its first sync it is permanently reported healthy even if every subsequent sync attempt fails and the published content grows arbitrarily stale.

### Finding Description
`git-sync`'s HTTP endpoint contract is explicitly documented as returning "a 5xx error until the first sync is complete, and a `200` status thereafter" [1](#0-0) . In the main sync loop, `setRepoReady()` is invoked only on the success branch after the first successful `git.SyncRepo` call, and there is no corresponding call that reverts readiness to "not ready" when subsequent sync attempts fail [2](#0-1) .

On failure, the loop only increments `failCount` and aborts the whole process once `failCount >= maxFails` [3](#0-2) . Both `--max-failures` and `--init-max-failures` can be configured with a negative value to "retry forever" [4](#0-3) , meaning the process will never exit even if it can never successfully sync again — while the `/` health endpoint continues to report `200` from the moment of the first success onward, and the previously published symlink target (last known-good worktree) keeps being served as current data.

This mirrors the Tellor analog precisely: a "freshness" signal (Tellor's dispute window / reporter cadence; git-sync's liveness probe) is treated as durable proof of correctness/currency, when in fact it only certifies a point-in-time event and gives no guarantee about the present state. An attacker who controls or disrupts the upstream `--repo` (e.g., by force-pushing history that breaks subsequent fetches, corrupting refs, or otherwise causing durable fetch/checkout failures after a benign first sync) can induce indefinite staleness that is invisible to Kubernetes probes and to any external monitoring keyed off the HTTP endpoint.

### Impact Explanation
This qualifies under "persistent sync denial" and "publishing wrong or partial (stale) content" as defined in the acceptance criteria. Downstream applications and orchestrators (Kubernetes liveness/readiness probes) will continue treating the sidecar as healthy and the mounted `--link` path as current, even though the content may be arbitrarily old and diverged from the actual remote state. This is analogous to the oracle staleness scenario where consumers act on old data believing it fresh, enabling stale-data-dependent attacks or simply silent service degradation that operators cannot detect through the intended health-check mechanism.

### Likelihood Explanation
Any condition that causes durable (not merely transient) sync failures after the initial successful sync — remote-side history corruption, ref manipulation, or network/auth failures that the operator configured to "retry forever" via a negative `--max-failures` — will trigger this behavior. This does not require a malicious operator or leaked credentials; it only requires that the upstream repository (the untrusted, attacker-influenced input) becomes unfetchable/unsyncable after git-sync has already succeeded once, which is a realistic and easily reachable condition.

### Recommendation
Make the health endpoint reflect current sync freshness rather than a one-time latch: track the timestamp/age of the last successful sync and the current `failCount`, and have the HTTP handler return an unhealthy status (5xx) once `failCount` exceeds a threshold or once the time since last success exceeds a configurable staleness bound (e.g., a `--max-staleness` flag compared against `--period`). This gives Kubernetes probes and external monitors a true, continuous freshness signal instead of a permanent post-first-success `200`.

### Proof of Concept
1. Start `git-sync` with `--http-bind`, `--period=10s`, and `--max-failures=-1` (retry forever) against a legitimate repo; wait for the first successful sync — the endpoint now returns `200` [1](#0-0) .
2. Have the upstream repository (attacker-controlled or compromised) become permanently unfetchable after this point (e.g., force-push a history rewrite that git-sync cannot resolve, or corrupt the ref being tracked).
3. Every subsequent iteration of the loop hits the error branch, incrementing `failCount` but never calling anything that flips readiness back to false, and since `--max-failures=-1` the process never exits [3](#0-2) .
4. The `/` endpoint continues returning `200` indefinitely while the symlink at `--link` still points to the last successfully synced (now stale/possibly outdated or divergent) worktree, with no observable signal to the operator or orchestrator that sync has stopped making progress.

### Citations

**File:** README.md (L397-402)
```markdown
    --http-bind <string>, $GITSYNC_HTTP_BIND
            The bind address (including port) for git-sync's HTTP endpoint.
            The '/' URL of this endpoint is suitable for Kubernetes startup and
            liveness probes, returning a 5xx error until the first sync is
            complete, and a 200 status thereafter. If not specified, the HTTP
            endpoint is not enabled.
```

**File:** README.md (L442-446)
```markdown
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```

**File:** main.go (L1056-1073)
```go
		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
		} else {
			if !initialSyncDone {
				initialSyncDone = true
				waitTime = *flPeriod
				if *flInitPeriod != *flPeriod {
					log.V(0).Info("initial sync complete, switching to normal period", "initPeriod", flInitPeriod.String(), "period", flPeriod.String())
				}
			}
			// this might have been called before, but also might not have
			setRepoReady()
```
