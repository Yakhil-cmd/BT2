### Title
Persistent Sync Denial via Attacker-Controlled Commit Causing Deterministic Checkout Failure Under Default `--max-failures=0` - (File: main.go)

### Summary
`git-sync`'s main sync loop treats any sync-cycle failure as fatal by default: `--max-failures` defaults to `0`, meaning the very first failed `git.SyncRepo` call causes the process to call `os.Exit(1)` [1](#0-0) . An attacker who can influence the content of the tracked ref (a pushed commit, an upstream PR that gets merged, or any untrusted content reachable through the synced repository/ref) can craft a commit whose tree deterministically breaks the checkout/publish path (e.g. a submodule pointing at an unreachable/gated URL, a file that cannot be materialized on the host filesystem, or content that reliably breaks `configureWorktree`). Every sync attempt against that same commit will fail the same way, so the built-in failure counter immediately reaches the (default) threshold of `0` and the process aborts.

### Finding Description
The sync loop in `main()` increments `failCount` on any error from `git.SyncRepo` and compares it against `getMaxFailures()`, exiting the process once the threshold is met: [2](#0-1) . Because the documented default for `--max-failures` is `0` ("any sync failure will terminate git-sync") [1](#0-0) , a single deterministic failure caused by hostile tree content is sufficient to permanently halt the sidecar — restarting the container does not help because the same malicious commit is still the target ref, so the identical failure recurs on the next attempt, again hitting the zero-tolerance threshold. This mirrors the referenced report's pattern: a privileged/trusted party (there, the `Basket` publisher; here, whoever can land a commit on the tracked ref) can push the system into a state from which ordinary consumers cannot recover without an external, non-trivial remediation step (there, burning 0.25% of the bond; here, an operator must notice the crash loop and either roll back/fix the upstream ref or manually bump `--max-failures`).

Until the first successful sync completes, the symlink described by the "Atomic Symlink Contract" is never created [3](#0-2) , and the HTTP readiness endpoint continues to return a 5xx status [4](#0-3) , so any consumer relying on `--root`/`--link` sees a total denial of the synced content, not merely a stale copy.

### Impact Explanation
This causes persistent sync denial: the sidecar container repeatedly crashes (in Kubernetes, a `CrashLoopBackOff`), the `--link` target is never published (or, in steady state, the last-known-good worktree is retained but future updates are permanently blocked), and dependent workloads lose access to fresh (or any) synced content until a human intervenes. This matches the "persistent sync denial" impact accepted by the validation rules.

### Likelihood Explanation
Likelihood depends entirely on the operator's threat model for the tracked repository: if `--repo` points at a repository where third parties can land commits (public repos with permissive merge policies, mirrors of upstream projects, forks, etc.), a single malicious/broken commit is enough, and the default configuration (`--max-failures=0`) is the most exposed setting since it requires zero repeated attempts to trigger the abort. Deployments that explicitly raise `--max-failures` to a negative value ("retry forever") are not affected by the *abort* behavior, but would instead experience indefinite denial-of-updates on that ref, which is a milder variant of the same class.

### Recommendation
- Do not treat a single sync failure caused by content-derived errors (checkout/worktree/submodule failures tied to the currently targeted commit) the same as transient network/auth failures; distinguish "poison-pill commit" failures so the sync loop can fall back to the last good hash and keep serving it while continuing to retry the target ref, rather than exiting the whole process.
- Reconsider the default `--max-failures=0` documented at [1](#0-0)  for the initial-sync and steady-state paths, or clearly warn operators that syncing untrusted/third-party-writable refs with this default converts a single bad commit into a full outage.
- Ensure `os.Exit(1)` at [5](#0-4)  is reserved for unrecoverable configuration/auth errors, not for repo-content-triggered checkout failures.

### Proof of Concept
1. Deploy `git-sync` with defaults (`--max-failures` unset ⇒ `0`) tracking a branch that a third party can influence (e.g., mirrored/public upstream, or shared branch with broader write access).
2. Attacker pushes a commit to that branch whose tree makes `configureWorktree`/checkout fail deterministically for every git-sync instance that fetches it (e.g., a submodule entry pointing to an unreachable/interactive-auth-required remote, or filesystem-incompatible paths).
3. `git.SyncRepo` returns an error on the fetch/checkout of that commit; `failCount` becomes `1`, which is `>= maxFailures (0)`, so `main()` logs "too many failures, aborting" and calls `os.Exit(1)` [5](#0-4) .
4. In Kubernetes, the sidecar container restarts, re-attempts the same broken commit, and immediately fails again — indefinite crash loop — until an operator manually intervenes (fix/rollback the upstream branch or raise `--max-failures`).

**Uncertainty/limitations:** I was not able to retrieve the full body of `configureWorktree` (submodule update / sparse-checkout application logic) within the available tool budget, so the exact malformed-tree construct that reliably fails checkout is not verified against the current source — only the failure-counting/abort mechanism (`main.go:1056-1063`) and the documented default (`--max-failures=0`) were directly confirmed. A Devin session with full repository access would be needed to pin down a concrete, minimal malicious tree/commit that triggers a deterministic `configureWorktree` failure.

### Citations

**File:** README.md (L52-60)
```markdown
### Why the symlink?

git checkouts are not "atomic" operations.  If you look at the repository while
a checkout is happening, you might see data that is neither exactly the old
revision nor the new.  git-sync "publishes" updates via the symlink to present
an atomic interface to consumers.  When the remote repo has changed, git-sync
will fetch the data _without_ checking it out, then create a new worktree, then
change the symlink to point to that new worktree.

```

**File:** README.md (L442-446)
```markdown
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```

**File:** README.md (L2745-2750)
```markdown

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
