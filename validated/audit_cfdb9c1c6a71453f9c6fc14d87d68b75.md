### Title
Persistent sync denial from a single malfunctioning/malicious submodule with no per-submodule disable mechanism - (File: main.go)

### Summary
`git-sync`'s `--submodules` flag only supports three global states (`recursive`, `shallow`, `off`) with no way to exclude or disable one specific submodule while still syncing the rest of the repository and its other submodules. If an attacker with push access to the synced repository (or a compromised upstream submodule dependency) introduces a single broken/malicious submodule entry, the entire sync loop is permanently blocked, even though the rest of the repository content is fine — directly analogous to the H-03 report's "no way to remove a malfunctioning derivative" issue.

### Finding Description
`configureWorktree` runs a single `git submodule update --init [--recursive] [--depth N]` command that updates *all* submodules of the checked-out commit in one shot: [1](#0-0) 

The `--submodules` flag exposed to operators is coarse-grained — it can only be set to `recursive`, `shallow`, or `off` for the entire repository, with no mechanism to allow-list/deny-list a specific submodule path or URL: [2](#0-1) 

If any single submodule in the tree fails to update (unreachable host, protocol rejected by git's `protocol.*.allow` defaults, authentication failure, or a submodule the operator no longer trusts), `git submodule update` returns a non-zero exit code, `configureWorktree` returns an error, and this propagates up through `createWorktree`/`SyncRepo` to the main loop: [3](#0-2) 

Because there is no derivative-style "adjustWeight"/removal equivalent (i.e., no way to exclude just the one bad submodule while keeping submodule syncing enabled for the rest), the operator's only remedy is `--submodules=off`, which disables *all* submodules globally — a destructive, all-or-nothing workaround, not a targeted fix. Until that flag is changed and the sidecar is redeployed, every sync attempt at every subsequent commit (even ones that would otherwise be clean) fails identically, since the broken submodule reference is baked into the checked-out tree.

### Impact Explanation
This results in persistent sync denial: the published `--link` symlink stops advancing at the last good commit, `--max-failures` (if configured) will eventually cause `os.Exit(1)` at main.go:1059-1061 [4](#0-3) , crash-looping the sidecar, or (if unset/negative) the process retries forever without making progress, denying legitimate consumers of the synced content any updates — the same class of "users can fail to unstake"-style DOS as the source report, translated to "consumers never get updated content."

### Likelihood Explanation
Requires an attacker (or compromised collaborator) with push access to the synced repository, or control over a referenced submodule URL, to introduce one broken/hostile submodule entry — this is squarely within the "attacker-pushed commit/ref" threat model called out in scope. No special git-sync flags beyond the default `--submodules=recursive` are needed; it is the default behavior.

### Recommendation
Add a mechanism to skip/exclude individual submodules by path or name (e.g., a `--submodule-exclude` flag translated into `git -c submodule.<name>.update=none submodule update ...`, or `git config submodule.<name>.active false` before running `submodule update`), so a single malfunctioning or untrusted submodule can be disabled without turning off submodule support entirely, and so pre-existing good submodules keep syncing even if one is faulty.

### Proof of Concept
1. Attacker with push access adds a submodule entry in `.gitmodules` pointing to a URL that will reliably fail (e.g., an unreachable host, or a protocol blocked by git's default `protocol.*.allow` settings) and commits it to the tracked ref.
2. `git-sync` fetches the new commit and calls `configureWorktree`, which runs `git submodule update --init --recursive` at main.go:1737-1746 [5](#0-4) ; this command fails because of the one broken submodule.
3. `SyncRepo` returns an error every cycle; the `--link` symlink never advances past the last good commit, and (if `--max-failures` is set) the process eventually exits at main.go:1059-1061, or otherwise loops indefinitely without making progress — a persistent denial of sync for all future commits until an operator manually intervenes by disabling all submodules via `--submodules=off`.

### Citations

**File:** main.go (L182-184)
```go
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
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
