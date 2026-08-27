## Finding

### Title
Liveness endpoint never reflects sync staleness after first successful sync - ([File: main.go])

### Summary
The `consult_price` bug pattern (returning a value derived from state that is never checked for freshness) has a direct analog in `git-sync`'s HTTP liveness/readiness endpoint. The endpoint is documented as returning "a 5xx error until the first sync is complete, and a 200 status thereafter" [1](#0-0)  — but "thereafter" is literal: once the first sync succeeds, the health status is latched permanently regardless of subsequent sync failures.

### Finding Description
The `/` handler only consults a single, one-way boolean, `repoReady`, via `getRepoReady()`: [2](#0-1) 

`repoReady` is set by `setRepoReady()` but there is no corresponding "unset"/reset function anywhere in the codebase — a full-repo grep for `repoReady|setRepoReady|getRepoReady` shows only the getter, setter, and its call sites, none of which ever flip the flag back to `false`. Once `setRepoReady()` is invoked after the first successful sync, `getRepoReady()` returns `true` for the remainder of the process lifetime [3](#0-2) .

Meanwhile, the steady-state sync loop can continue to fail indefinitely (subject only to `--max-failures`, which can be set negative to retry forever) without ever resetting readiness: [4](#0-3) [5](#0-4) 

The `--http-bind` "/" endpoint is explicitly documented as suitable for "Kubernetes startup and liveness probes" [1](#0-0) , so operators are expected to treat a 200 response as a signal that the sidecar (and by extension, the synced data behind `--link`) is healthy/current. But exactly like the oracle's `consult_price`, which returns `price_average` without checking `price_last`'s age, this endpoint returns "OK" without checking whether a sync has actually succeeded recently — it only checks whether one *ever* succeeded.

### Impact Explanation
Any condition that makes ongoing syncs fail after the first one succeeds — e.g. remote branch protection changes, upstream repo becoming unreachable, credential/token expiry (`--password-file` rotation providing a bad token), askpass URL becoming unavailable, or a hostile/compromised upstream that starts erroring — causes the `--link` target to freeze at a stale commit indefinitely, while the liveness probe keeps returning 200. Kubernetes will not restart or fail the pod, and downstream consumers of the sidecar-shared volume have no signal that the data they are reading is stale. This is a persistent sync denial that is invisible to the standard health-check contract, directly mirroring the oracle bug's "stale value returned without a freshness check" root cause.

### Likelihood Explanation
This requires no attacker access to the git-sync process or Kubernetes config beyond normal operating conditions: any upstream outage, revoked credential, or network partition that occurs after the first successful sync will trigger this behavior. With `--max-failures` set negative (an explicitly supported "retry forever" mode) or set to a value high enough to outlast typical probe failure thresholds, the stale state can persist arbitrarily long while appearing healthy.

### Recommendation
Track the age or success state of the *most recent* sync attempt (not just "ever succeeded") and expose it through the liveness/readiness endpoint — e.g., reset `repoReady` to `false` (or expose a separate "degraded" status) once `failCount` exceeds a threshold, or surface `time.Since(lastSuccessfulSync)` and fail the probe once it exceeds some multiple of `--period`.

### Proof of Concept
1. Start `git-sync --http-bind=:8080 --repo=<repo> --root=/tmp/git --link=link --period=5s --max-failures=-1`.
2. Wait for the first successful sync; `curl localhost:8080/` returns 200, as shown by the e2e test asserting 200 after `wait_for_sync` [6](#0-5) .
3. Revoke access to the remote (e.g., break credentials or make the repo URL unreachable) so all subsequent sync attempts fail; with `--max-failures=-1` the process never exits [7](#0-6) .
4. `curl localhost:8080/` continues to return 200 indefinitely, and `$ROOT/link` continues to serve the old, now-arbitrarily-stale commit, with no observable failure signal to Kubernetes or consumers.

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

**File:** main.go (L442-446)
```go
	// Init logging very early, so most errors can be written to a file.
	if *flDeprecatedV >= 0 {
		// Back-compat
		*flVerbose = *flDeprecatedV
	}
```

**File:** main.go (L865-872)
```go
		// This is a dumb liveliness check endpoint. Currently this checks
		// nothing and will always return 200 if the process is live.
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if !getRepoReady() {
				http.Error(w, "repo is not ready", http.StatusServiceUnavailable)
			}
			// Otherwise success
		})
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

**File:** test_e2e.sh (L2919-2924)
```shellscript
    wait_for_sync "${MAXWAIT}"

    # check that health endpoint is alive
    if [[ $(curl --write-out '%{http_code}' --silent --output /dev/null http://localhost:$HTTP_PORT) -ne 200 ]] ; then
        fail "health endpoint failed"
    fi
```
