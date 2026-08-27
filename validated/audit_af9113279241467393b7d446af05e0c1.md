### Title
Untrusted repo content can force unbounded, automatic submodule fetch/clone on every sync cycle - (File: main.go)

### Summary
`git-sync` defaults to `--submodules=recursive` and, on every successful sync, automatically runs `git submodule update --init --recursive` against whatever `.gitmodules` content exists at the currently-synced ref, with no size, count, or cost limits and no user confirmation step.

### Finding Description
In `configureWorktree`, after checking out the target hash, `git-sync` unconditionally updates submodules whenever `git.submodules != submodulesOff` (the default is `recursive`): [1](#0-0) 

The list of submodules, their URLs, and their nesting depth are all defined by `.gitmodules` in the synced repository content itself — i.e., by whoever can push/merge into the tracked `--ref`. This is directly analogous to the Timeswap finding: an operation with potentially very high resource cost (network/disk/CPU) is triggered automatically as a side effect of a routine, low-privilege action (a `mint`/here, a normal commit/merge to the tracked ref) rather than being an explicit, opt-in, cost-aware choice by the operator of the sidecar.

Mitigating factor: when `--depth` is set (the CLI default is `1`), the same depth is passed to the submodule update command: [2](#0-1) [3](#0-2) 
This bounds each individual submodule's history, but places no limit on the **number** of submodules, the **size of each submodule's tree/blobs at that single commit**, or **nesting depth** (recursive submodules-of-submodules), all of which are attacker-controlled via repo content.

### Impact Explanation
Whoever controls content merged into the synced ref (e.g., a low-privilege contributor whose PRs get merged, or an upstream/fork used as `--repo`) can add many submodules or submodules pointing to very large upstream repositories (potentially chained several levels deep via `--recursive`). Because this update runs automatically on **every sync period** (default 10s) without any operator opt-in or size/cost check, it can:
- Cause large, uncontrolled egress network traffic and disk usage on the git-sync sidecar/host.
- Cause the sync to exceed `--sync-timeout` (default 120s) repeatedly, driving `--max-failures` and resulting in persistent sync denial (the "funds not lost, but design-level cost/DoS problem" analog to the original finding, where 0xean downgraded to a design issue rather than direct fund loss).

This matches the accepted impact category of "persistent sync denial" from unbounded, non-consensual expensive work triggered by untrusted content.

### Likelihood Explanation
Likelihood is moderate and configuration-dependent: it only manifests when `--submodules` is left at its default `recursive` (or set to `shallow`) value and the tracked repository/ref allows content from parties who are not the operator (common in CI/CD "GitOps" style deployments where PRs from less-trusted contributors are auto-merged into the synced branch). No malicious operator, leaked key, or node compromise is required — only the ability to add commits/`.gitmodules` entries to the ref git-sync already syncs, i.e., ordinary "attacker-pushed commit/ref" content as scoped by this analysis.

### Recommendation
- Document prominently (as Timeswap did) that `--submodules=recursive/shallow` will automatically execute unbounded `git submodule update --init --recursive` driven entirely by the content of the synced ref, and that operators syncing less-trusted refs should use `--submodules=off` or restrict who can modify `.gitmodules`.
- Consider adding explicit limits: a maximum submodule count/size, a `--submodules-max-depth`, or a flag requiring the operator to pre-approve/allow-list submodule URLs before they are fetched, similar to the recommendation in the referenced report to make the expensive path opt-in rather than automatic.
- Ensure `--sync-timeout` failures from oversized submodule updates surface clearly in metrics/logs so persistent denial is observable rather than silently retried forever.

### Proof of Concept
1. Operator runs `git-sync --repo=<REPO> --root=<ROOT> --link=link` (defaults: `--submodules=recursive`, `--depth=1`, `--period=10s`, `--sync-timeout=120s`).
2. An untrusted contributor merges a commit into the tracked ref that adds a `.gitmodules` referencing dozens of large public repositories (or a chain of nested submodules-of-submodules).
3. On the next sync (`configureWorktree` at [1](#0-0) ), git-sync automatically runs `git submodule update --init --recursive [--depth N]` for every submodule found, downloading their content without any operator confirmation or per-submodule size cap.
4. If the aggregate submodule content exceeds what can be fetched within `--sync-timeout`, every sync attempt fails, `failCount` increments toward `--max-failures`, resulting in persistent sync denial; if it succeeds, it still incurs unbounded bandwidth/disk cost on every period.

### Citations

**File:** main.go (L176-178)
```go
	flDepth := pflag.Int("depth",
		envInt(1, "GITSYNC_DEPTH", "GIT_SYNC_DEPTH"),
		"create a shallow clone with history truncated to the specified number of commits")
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
