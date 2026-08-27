### Title
Unbounded submodule expansion in `configureWorktree` allows attacker-controlled commits to cause persistent sync denial - (File: main.go)

### Summary
git-sync's `configureWorktree` runs `git submodule update --init --recursive` on whatever `.gitmodules` content is present in the fetched commit, with no limit on the number, depth, or size of submodules. An attacker who can get a malicious commit synced (e.g. a merged PR, a compromised/attacker-writable branch, or any ref that git-sync is configured to track) can add a large number of submodules or deeply/circularly nested recursive submodules, causing each sync attempt to consume excessive time/bandwidth/disk and repeatedly exceed `--sync-timeout`, eventually driving git-sync to abort via `--max-failures` — producing persistent sync denial. This is the closest git-sync analog of the AuctionHouse `_settleAuction` report: an operation that fans out into many attacker-controlled, resource-costly external operations (creators/`receive()` calls in the Solidity case; submodule clones/checkouts here) with no cap on count/cost.

### Finding Description
`configureWorktree` unconditionally executes `git submodule update --init --recursive` (with `--depth` when shallow) whenever `git.submodules != submodulesOff`, once per successful worktree creation: [1](#0-0) 

This call operates on the `.gitmodules` file and submodule references that come entirely from the synced remote's commit content — i.e., attacker-controlled data if the tracked branch/ref can be influenced by an untrusted contributor. There is no flag or code path that limits:
- the number of submodule entries,
- the recursion depth (`--recursive` is applied unconditionally when `submodules=recursive`, the default),
- the size/bandwidth of each submodule fetch.

The whole `SyncRepo` (including `initRepo`, fetch, worktree creation, and `configureWorktree`) runs under a single `context.WithTimeout(context.Background(), *flSyncTimeout)` (default 120s): [2](#0-1) 

If `configureWorktree`'s submodule step alone exceeds `--sync-timeout` (achievable with many submodules or large/slow ones), the whole sync attempt fails, is counted against `--max-failures` (default 0 — meaning *any* failure aborts the process): [3](#0-2) 

Because the malicious commit is present at the tip of the tracked ref, every subsequent retry (or container restart, which is the standard Kubernetes remediation for a crashed sidecar) re-fetches the same commit and re-attempts the same expensive/failing submodule expansion, reproducing the failure indefinitely. This satisfies the "persistent sync denial" impact category, mirroring the AuctionHouse pattern where a single attacker-controlled record (`creators[]` / `.gitmodules`) fans out into many expensive per-item external operations with no bound, and where a single expensive item can push the whole operation over a hard resource/time limit.

### Impact Explanation
- The synced `--link` is never updated (or is stuck on the last-known-good hash, which may itself already reflect a compromised state depending on when the attack lands), starving consumer pods of fresh content.
- With `--max-failures=0` (default) or any bounded value, git-sync exits non-zero, which under Kubernetes typically triggers container restarts; each restart repeats the same expensive/failing submodule work against the same malicious commit, yielding a crash loop / persistent denial of the sync sidecar.
- No credentials, code execution, or data exfiltration occurs — the impact is limited to availability (sync denial), consistent with the DoS class of the referenced report, not a "no-impact" analog.

### Likelihood Explanation
- Requires the attacker to get a commit merged/pushed onto the ref that git-sync tracks (an "attacker-pushed commit" scenario per the validation rules) — a standard assumption for CI/CD or sidecar sync of a shared/collaborative repository.
- `submodules=recursive` is the **default** behavior, so no special flags are required by the operator to be exposed to this; only `--depth`/`--sync-timeout` values affect how easy it is to exceed the timeout.
- The attack is straightforward to construct (add many `.gitmodules` entries pointing to large/slow/deeply-nested repos) and does not require any privileged git-sync configuration.

### Recommendation
- Bound submodule processing: enforce a configurable maximum submodule count/depth before invoking `git submodule update --init --recursive`, or reject/`--submodules=off` fallback with a clear error when `.gitmodules` exceeds a sane threshold.
- Apply a dedicated, independently-configurable timeout to the submodule step (distinct from overall `--sync-timeout`) so a single bad commit cannot consume the whole sync budget, and surface a clear "submodule sync exceeded limits" error rather than a generic timeout/failure.
- Consider capping `--jobs`/parallelism and total fetched bytes for submodules, and/or requiring explicit opt-in for `--submodules=recursive` on untrusted repos.
- Document that consumers of git-sync should not point `--repo`/`--ref` at branches writable by untrusted parties without additional review gates, since `.gitmodules` content is fully attacker-influenced content.

### Proof of Concept
1. In the upstream repository that git-sync tracks (e.g. via `--repo=<url> --ref=<branch>`), an attacker with write/PR-merge access adds a `.gitmodules` file referencing hundreds of submodules (or a small number of submodules with deep, cyclic-looking recursive submodule chains), each pointing at reachable-but-slow or large git remotes.
2. Run git-sync against this ref with default settings (`--submodules=recursive`, default `--sync-timeout=120s`, default `--max-failures=0`):
   ```
   git-sync --repo=<attacker-influenced-repo> --root=/tmp/root --link=link --period=10s
   ```
3. Observe that `configureWorktree`'s `git submodule update --init --recursive` step (main.go:1733-1747) takes longer than `--sync-timeout`, causing `SyncRepo` to return an error; because `--max-failures` defaults to 0, git-sync calls `os.Exit(1)` on the very next failure (main.go:1056-1063).
4. Under a Kubernetes Deployment/sidecar restart policy, the container restarts and re-attempts the same sync against the same malicious commit, reproducing the failure indefinitely — a persistent sync denial without any change to the malicious commit. [1](#0-0) [4](#0-3)

### Citations

**File:** main.go (L1052-1063)
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
```

**File:** main.go (L1733-1747)
```go
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
