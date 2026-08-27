### Title
Liveness/readiness endpoint never reverts once "ready", masking indefinite sync failures ("wall stays active even though the heartbeat stopped") - (File: main.go)

### Summary
`git-sync` exposes an HTTP endpoint intended for Kubernetes startup/liveness probes that returns `200` once the repo has synced and `5xx` before that [1](#0-0) . The readiness state is tracked by a one-way, mutex-guarded boolean latch, `repoReady`, set exclusively via `setRepoReady()` and never reset back to `false` [2](#0-1) .

### Finding Description
In the main sync loop, on a successful sync `setRepoReady()` is called, but on a failed sync (`git.SyncRepo` returning an error) the loop only increments `failCount` and logs — it never clears the readiness flag [3](#0-2) . If `--max-failures` is configured with a negative value ("retry forever", per the documented, explicitly supported behavior [4](#0-3) ) or a value that simply hasn't been reached yet, `git-sync` will keep retrying indefinitely on persistent errors (unreachable remote, expired/rotated credentials, broken askpass URL, GitHub App token failure, etc. — all paths that funnel through `refreshCreds`/`SyncRepo` and increment `failCount` on error [5](#0-4) ) while the HTTP endpoint continues to report `200 OK` forever, because `repoReady` was already latched `true` from an earlier successful sync [6](#0-5) .

This is directly analogous to the referenced Olympus finding: the "wall" (here, the readiness/liveness signal and the published symlink content) keeps being treated as valid/active by consumers even though the underlying "heartbeat" (a successful, up-to-date sync) has stopped. There is no `SYNC_THRESHOLD`-style freshness check comparing "now" against "time of last successful sync" gating the health signal — exactly the missing check called out in the report's recommended mitigation.

### Impact Explanation
Kubernetes liveness/readiness probes hitting this endpoint will keep the Pod marked `Ready`/alive indefinitely, so orchestration will not restart or fail over the sidecar even though the mounted volume is silently stale (persistent sync denial without detection). Consumers of the `--link` symlink volume (application containers) have no reliable signal that the data they are reading has stopped updating, which can lead application logic that trusts "container is Ready therefore data is current" to operate on stale/wrong content indefinitely — matching the "publishing wrong or partial content" / "persistent sync denial" impact classes.

### Likelihood Explanation
This requires no privileged access or malicious operator: any of the normal untrusted/uncontrolled failure modes already reachable in production (remote repo becomes unreachable, network partition, credential/token rotation issues via `--askpass-url` or GitHub App auth, or an attacker-controlled remote that starts stalling/erroring fetches) will trigger this. Because `--max-failures=-1` ("retry forever") is a documented, first-class configuration, and even with a positive `--max-failures` there is a window (up to `maxFailures-1` consecutive failures) during which the stale "ready" signal persists, likelihood of occurrence in real deployments is moderate-to-high.

### Recommendation
Track the timestamp of the last *successful* sync and gate the HTTP health response on both `repoReady == true` AND `time.Since(lastSuccessfulSync) <= freshnessThreshold` (configurable, analogous to the `SYNC_THRESHOLD * frequency()` check recommended in the referenced report). On sync failure, either reset `repoReady` after a bounded number of consecutive failures, or make the health check freshness-aware so probes can detect and react to a stalled sync loop instead of relying on a one-way latch.

### Proof of Concept
1. Start `git-sync` with `--http-bind`, `--max-failures=-1` (or a value not yet reached), pointing at a reachable repo.
2. Wait for the first successful sync; the HTTP endpoint returns `200 OK`, and Kubernetes marks the pod ready [7](#0-6) .
3. Make the remote repo unreachable (network block, revoke credentials, or corrupt `--askpass-url` response) so every subsequent `git.SyncRepo` call errors.
4. Observe: `failCount` increments each cycle but `repoReady` is never reset [5](#0-4) [8](#0-7) .
5. Continue polling the HTTP endpoint — it keeps returning `200 OK` indefinitely (as also verified by the existing e2e test that only checks the transition from `503`→`200`, never a reversal, at `test_e2e.sh:2915-2924`) [9](#0-8) , even though the synced content behind `--link` has stopped updating.

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

**File:** main.go (L1052-1073)
```go
	for {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)

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

**File:** main.go (L1273-1287)
```go
// repoReady indicates that the repo has been synced.
var readyLock sync.Mutex
var repoReady = false

func getRepoReady() bool {
	readyLock.Lock()
	defer readyLock.Unlock()
	return repoReady
}

func setRepoReady() {
	readyLock.Lock()
	defer readyLock.Unlock()
	repoReady = true
}
```

**File:** test_e2e.sh (L2915-2924)
```shellscript
    # check that health endpoint fails
    if [[ $(curl --write-out '%{http_code}' --silent --output /dev/null http://localhost:$HTTP_PORT) -ne 503 ]] ; then
        fail "health endpoint should have failed: $(curl --write-out '%{http_code}' --silent --output /dev/null http://localhost:$HTTP_PORT)"
    fi
    wait_for_sync "${MAXWAIT}"

    # check that health endpoint is alive
    if [[ $(curl --write-out '%{http_code}' --silent --output /dev/null http://localhost:$HTTP_PORT) -ne 200 ]] ; then
        fail "health endpoint failed"
    fi
```
