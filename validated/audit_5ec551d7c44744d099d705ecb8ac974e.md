### Title
Off-by-one in `--max-failures`/`--init-max-failures` check causes premature sync-loop termination - (File: `main.go`)

### Summary
The sync-loop failure guard in `main()` uses `failCount >= maxFails` to decide when to abort, which aborts one failure earlier than the documented "N failures allowed before aborting" contract, mirroring the reported `<=`/`<` boundary-check bug class (inclusive comparison used where an exclusive one — or vice versa — was intended).

### Finding Description
The sync loop tracks consecutive failures and compares them against the configured limit: [1](#0-0) 

```go
if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
    failCount++
    updateSyncMetrics(metricKeyError, start)
    if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
        log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
        os.Exit(1)
    }
    log.Error(err, "error syncing repo, will retry", "failCount", failCount)
}
```

The flags are documented as an *allowance* of N consecutive failures before aborting: [2](#0-1) [3](#0-2) 

With `--max-failures=N` (N>0), a user reading "the number of consecutive failures allowed before aborting" expects N failures to be tolerated and the process to abort only once that allowance is exceeded (i.e., on the (N+1)th failure). Instead, because the comparison is `failCount >= maxFails`, the process aborts as soon as `failCount` reaches `N` — i.e., after only N failures, having tolerated just N-1. This is the same class of boundary defect as the reported Lido issue (`<=` used where `<` was correct, here `>=` used where `>` matches the documented semantics), causing the guard to fire one iteration earlier than intended.

Note: for `N=0` the documented behavior ("any sync failure will terminate git-sync") is still satisfied by both `>=` and `>` variants only if `failCount` starts at 1 after the first failure — with `>=0` any failure triggers immediately, which is correct for the N=0 case, but for N≥1 the same operator produces the one-failure-early abort described above.

### Impact Explanation
This causes premature/persistent sync denial: git-sync will exit(1) and stop syncing one retry earlier than the operator configured via `--max-failures`/`--init-max-failures`, reducing the intended tolerance for transient failures (e.g., transient network blips, transient remote unavailability). In a Kubernetes sidecar deployment this can cause the pod/container to be considered failed and restarted sooner than the operator intended, which is a low-severity but reachable correctness/availability issue purely from configuration and normal (even attacker-influenced, e.g., transient remote failures) operation — no privileged access is required to trigger it, only normal sync failures.

### Likelihood Explanation
High likelihood: any deployment that sets `--max-failures` or `--init-max-failures` to a value greater than 0 and experiences failures (network blips, transient auth failures, remote outages) will hit this boundary every time it approaches the configured limit, since the loop logic is deterministic and always compares with `>=`.

### Recommendation
Change the abort condition to be strictly greater than the configured allowance, matching the documented "N failures allowed before aborting" semantics:

```go
if maxFails := getMaxFailures(); maxFails >= 0 && failCount > maxFails {
    log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
    os.Exit(1)
}
```

This ensures exactly `maxFails` consecutive failures are tolerated before aborting on the `(maxFails+1)`th failure, consistent with the README's documented contract. Existing e2e coverage should be extended to assert the exact failure count at which abort occurs (currently `e2e::init_max_failures_exceeded` only asserts eventual failure, not the boundary count): [4](#0-3) 

### Proof of Concept
1. Run git-sync with `--max-failures=2 --period=100ms --repo=file:///does/not/exist --root=$ROOT --link=link`.
2. Observe logs: after only 2 consecutive failed sync attempts (`failCount` reaching 2), git-sync logs `"too many failures, aborting"` and calls `os.Exit(1)`.
3. Per the documented semantics ("2 consecutive failures allowed before aborting"), it should tolerate 2 failures and only abort on the 3rd; instead it aborts on the 2nd, one retry earlier than configured — directly analogous to the reported inclusive/exclusive boundary defect.

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

**File:** README.md (L416-422)
```markdown
    --init-max-failures <int>, $GITSYNC_INIT_MAX_FAILURES
            The number of consecutive failures allowed before aborting during
            the initial sync phase (before the first successful sync).  Once
            the initial sync succeeds, --max-failures applies instead.
            Setting this to a negative value will retry forever during the
            initial sync.  If this flag is not set, --max-failures applies
            to the initial sync phase as well.
```

**File:** README.md (L442-446)
```markdown
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```

**File:** test_e2e.sh (L3953-3964)
```shellscript
##############################################
function e2e::init_max_failures_exceeded() {
    assert_fail \
        GIT_SYNC \
            --period=100ms \
            --init-max-failures=3 \
            --max-failures=-1 \
            --repo="file:///does/not/exist" \
            --root="$ROOT" \
            --link="link"
    assert_file_absent "$ROOT/link/file"
}
```
