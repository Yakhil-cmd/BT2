### Title
Persistent sync denial via attacker-controlled `.gitmodules` causing unconditional, unguarded `git submodule update` failures - (File: main.go)

### Summary
`ExtraRewardStashV2.stashRewards()`'s root cause was that an externally-controlled input (an arbitrary reward token from `IGauge(gauge).reward_tokens`) is fed unconditionally into an operation (`safeTransfer`) that can revert, with no upstream guard, causing the whole function — and therefore all future calls to it — to become permanently blocked. The closest reachable analog in `git-sync` is `configureWorktree()`'s submodule step: whenever `--submodules` is not `off`, every sync unconditionally executes `git submodule update --init [--recursive] [--depth N]` against whatever `.gitmodules` content the currently-fetched, attacker-influenced commit contains, with no validation of, or fallback for, that externally supplied configuration.

### Finding Description
`configureWorktree()` runs the submodule update unconditionally based on repo content that is entirely outside git-sync's control: [1](#0-0) 

This is invoked from `SyncRepo()` on every sync pass after a new commit is fetched and a worktree is created/reset to it: [2](#0-1) 

If the `git submodule update` command fails for any reason tied to the fetched commit's `.gitmodules` (e.g., an entry whose URL is unreachable, malformed, deliberately pointing at a bogus/blocked target, or otherwise causes `git` to error), `configureWorktree` returns that error directly, and `SyncRepo` propagates it unmodified: [3](#0-2) 

The outer sync loop in `main()` treats this as a generic failure, increments `failCount`, and retries on the normal `--period`/`--init-period` cadence — it never skips or disables the submodule step, never falls back, and never marks the offending commit as "known-bad": [4](#0-3) 

Because the `.gitmodules` file (and the tree object referenced by the synced commit) is entirely attacker-controlled repo content — the same trust boundary the external report exploited via `IGauge(gauge).reward_tokens` — this is a reachable, code-supported analog: an untrusted/attacker-influenced commit can encode a submodule configuration that reliably makes the mandatory post-checkout step fail on every single sync attempt, exactly as the unchecked `safeTransfer(arb, amount)` reliably reverted on every call to `stashRewards()` once a zero-transfer-reverting token entered the external `reward_tokens` list.

### Impact Explanation
Once such a commit becomes the target `--ref` (e.g. it lands on the tracked branch/tag), `git-sync` can no longer complete a sync: `configureWorktree` fails every time, so `SyncRepo` never reaches `publishSymlink`, and the published `--link` is frozen at the last-good commit. This is a **persistent sync denial**: the base function of the sidecar (keeping the published tree up to date) is unavailable for as long as the bad commit is the resolved ref, and there is no automatic remediation path — it can only be fixed by an operator force-pushing a corrected commit or reconfiguring `--submodules=off`. If `--max-failures` is non-negative, the process eventually calls `os.Exit(1)`, terminating the sidecar entirely: [5](#0-4) 

This mirrors the Medium-severity characterization of the original finding: no funds/keys are at risk, but a base, security-relevant availability guarantee (atomic, continuously updated publication) is broken by content the operator does not directly control (the same reasoning the report used: "pool reward token list is external and not directly controllable").

### Likelihood Explanation
Likelihood depends entirely on the trust model of the tracked repository. If `git-sync` is pointed at a repo where arbitrary/lower-trust contributors can land commits (e.g. via merged PRs, a mirrored public upstream, or a compromised remote/branch), a single crafted `.gitmodules` entry is sufficient to trigger the condition on the very next sync — there is no rate-limit or validation gate in git-sync's own code before the submodule step runs. This is lower likelihood than a fully "unprivileged, no-permission-needed" bug because it requires the ability to introduce a commit into the synced ref, but it does not require any git-sync operator misconfiguration beyond the (very common) default of `--submodules=recursive`.

### Recommendation
- Treat submodule update failures distinctly from other sync errors: log and skip/quarantine the specific commit (or fall back to `--submodules=off` behavior for that pass) rather than blocking the entire sync loop indefinitely.
- Consider adding a bounded retry/backoff specifically for the submodule step separate from the main fetch/checkout failure count, and surface a clear, actionable error (e.g. "submodule update failed for commit `<hash>`; publication frozen at `<last-good-hash>`") so operators can act quickly.
- Document explicitly that `.gitmodules` content is untrusted input when `--submodules` is not `off`, and recommend `--submodules=off` for repositories where the tracked ref can be influenced by lower-trust contributors.

### Proof of Concept
1. Configure `git-sync` with default/`recursive` submodules against a repo that accepts commits/PRs from a lower-trust contributor (or simulate by pushing directly):
   ```
   git-sync --repo=<repo> --root=<root> --link=link --period=10s
   ```
2. On the tracked ref, add a `.gitmodules` entry whose submodule URL is guaranteed to fail during `git submodule update --init` (e.g. an unreachable host, a URL disallowed by the local `protocol.*.allow` git config, or a path referencing a nonexistent commit that cannot be fetched), then commit and push.
3. On the next sync pass, `git-sync` fetches the new commit successfully (`git.fetch`/`rev-parse FETCH_HEAD^{}` succeed) and creates the worktree, but `configureWorktree()`'s `git submodule update --init ...` fails at [6](#0-5) , causing `SyncRepo` to return an error.
4. Observe that the `--link` symlink remains pinned to the previous commit indefinitely, `failCount` increments on the standard `--period`, and (depending on `--max-failures`) the process eventually exits — reproducing the "operation fails every time due to unguarded external content" pattern from the source report.

Note: I could not fully verify whether any additional guard exists elsewhere in the codebase (outside the indexed excerpts) that specifically special-cases submodule failures, since the code index may not include every helper file; a live Devin session with full repository access would be needed to confirm there is no such mitigation already present.

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

**File:** main.go (L1929-1946)
```go
		// If we have a new hash, make a new worktree
		newWorktree := currentWorktree
		if changed {
			// Create a worktree for this hash in git.root.
			if wt, err := git.createWorktree(ctx, remoteHash); err != nil {
				return false, "", err
			} else {
				newWorktree = wt
			}
		}

		// Even if this worktree existed and passes sanity, it might not have all
		// the correct settings (e.g. sparse checkout).  The best way to get
		// it all set is just to re-run the configuration,
		if err := git.configureWorktree(ctx, newWorktree); err != nil {
			return false, "", err
		}

```
