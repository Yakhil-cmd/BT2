### Title
Unbounded submodule fetch size forces disk/network cost on git-sync host despite `--depth`/`--filter` caps - ([File: main.go])

### Summary
`git-sync`'s `fetch()` function applies the operator-configured `--depth` and `--filter` caps only to the top-level repository fetch, but `configureWorktree()` performs a separate, unconstrained `git submodule update --init [--recursive]` that never propagates `--filter` and only conditionally propagates `--depth`. An attacker who controls content of the synced upstream repository (the only "input" git-sync trusts) can add or modify `.gitmodules` entries to point at arbitrarily large or numerous repositories, forcing the git-sync sidecar to download and store far more data than the operator intended or capped, exactly mirroring the "min amount is treated as unbounded max, victim pays disproportionate cost" bug class from the original report.

### Finding Description
The top-level fetch enforces the operator's size/history bounds: [1](#0-0) 

But submodule expansion, which is enabled by default (`--submodules` defaults to `"recursive"`), is handled separately and does not inherit the `--filter` bound at all, and only inherits `--depth` when the top-level `--depth` happens to be non-zero: [2](#0-1) 

Flag documentation confirms `--filter` is described purely as a top-level clone optimization and `--submodules` defaults to full recursive expansion with no independent size/depth/count cap of its own: [3](#0-2) [4](#0-3) 

Because there is no cap analogous to a "max loan amount," an attacker who can push commits to (or control) the upstream repo git-sync is pointed at can:
- Add/modify `.gitmodules` to reference one or many large external repositories, or deeply nested chains of submodules.
- Since `submodulesArgs` never includes `--filter`, even a `blob:none`/`tree:0` partial-clone configuration on the parent repo is bypassed for every submodule, forcing full blob downloads.
- Since `--depth` is only forwarded to submodules when the top-level `--depth != 0`, any configuration syncing full history (`--depth=0`, as documented at `README.md:271-274`) also fetches full submodule history with no size ceiling.

This is directly analogous to the reported issue: a value the operator believes is bounded (loan amount / here, sync payload size) is in practice unbounded because expansion logic (lender buyout / here, submodule recursion) inherits none of the intended caps, forcing the victim (borrower / here, the git-sync pod and its `--root` volume) to "pay" far more than intended.

### Impact Explanation
Uncontrolled submodule expansion can exhaust the `--root` volume's disk space or the pod's network egress budget, since each sync attempt re-runs `submodule update --init --recursive` inside `configureWorktree`. Once disk fills, subsequent syncs fail (worktree creation, `.git` writes, or clone operations all fail with ENOSPC), which meets the "persistent sync denial" impact bar: the sidecar can no longer publish new commits via the atomic symlink flip, effectively freezing or breaking the mounted content for the application container it serves.

### Likelihood Explanation
This is reachable purely from attacker-controlled upstream repository content — no privileged operator action or leaked credentials are needed beyond git-sync being configured (in its default, unmodified `--submodules=recursive` mode) to sync a repository the attacker can push to or that they otherwise control (a common scenario for CI-mirrored or user-supplied config repos). The default configuration (`--submodules` defaulting to `"recursive"`, `--depth` defaulting to `1` but easily set to `0` for full history per the documented default-history tradeoff) makes this trivially triggerable without any special flags beyond normal usage.

### Recommendation
- Propagate `--filter` to `git submodule update` (git supports `--filter` on `submodule update` in modern versions) so partial-clone bounds apply uniformly to submodules.
- Always pass an explicit `--depth` to submodule updates (defaulting to the same value used for the top-level fetch, including when it's the default shallow value) rather than only when the top-level `--depth != 0`.
- Add an explicit operator-configurable cap (e.g., `--max-submodule-depth`/`--max-repo-size`) so a single malicious upstream commit cannot force unbounded disk consumption regardless of top-level settings.

### Proof of Concept
1. Operator runs git-sync with defaults (`--submodules=recursive`, `--filter=blob:none`, `--depth=1`) against an upstream repo the attacker can commit to.
2. Attacker adds a `.gitmodules` entry pointing to a very large (or many) external repositories, or a chain of nested submodules each referencing large blobs.
3. On next sync, `fetch()` correctly applies `--filter=blob:none --depth=1` to the top-level fetch, but `configureWorktree()`'s `submodule update --init --recursive` (main.go:1737-1746) has no `--filter` argument, so it performs full, unfiltered clones of every (nested) submodule.
4. Disk usage under `--root` grows far beyond what the operator's `--filter`/`--depth` settings were meant to bound, eventually filling the volume and causing all subsequent sync attempts to fail — a persistent sync denial triggered entirely by attacker-controlled repo content.

### Citations

**File:** main.go (L176-187)
```go
	flDepth := pflag.Int("depth",
		envInt(1, "GITSYNC_DEPTH", "GIT_SYNC_DEPTH"),
		"create a shallow clone with history truncated to the specified number of commits")
	flFilter := pflag.String("filter",
		envString("", "GITSYNC_FILTER"),
		"use partial clone with the specified filter (e.g. 'blob:none', 'tree:0')")
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
	flSparseCheckoutFile := pflag.String("sparse-checkout-file",
		envString("", "GITSYNC_SPARSE_CHECKOUT_FILE", "GIT_SYNC_SPARSE_CHECKOUT_FILE"),
		"the path to a sparse-checkout file")
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

**File:** main.go (L2002-2029)
```go
func (git *repoSync) fetch(ctx context.Context, ref string) error {
	git.log.V(2).Info("fetching", "ref", ref, "repo", redactURL(git.repo))

	// Fetch the ref and do some cleanup, setting or un-setting the repo's
	// shallow flag as appropriate.
	args := []string{"fetch", git.repo, ref, "--verbose", "--no-progress", "--prune", "--no-auto-gc"}
	if git.depth > 0 {
		args = append(args, "--depth", strconv.Itoa(git.depth))
	} else {
		// If the local repo is shallow and we're not using depth any more, we
		// need a special case.
		shallow, err := git.isShallow(ctx)
		if err != nil {
			return err
		}
		if shallow {
			args = append(args, "--unshallow")
		}
	}
	if git.filter != "" {
		args = append(args, "--filter", git.filter)
	}
	if _, _, err := git.Run(ctx, git.root, args...); err != nil {
		return err
	}

	return nil
}
```

**File:** README.md (L300-306)
```markdown
    --filter <string>, $GITSYNC_FILTER
            Use partial clone with the specified filter.  This can reduce
            the amount of data transferred when cloning large repositories.
            Common values are 'blob:none' (omit all blobs, fetch on demand)
            and 'tree:0' (omit all trees and blobs).  This is most effective
            when combined with --depth and --sparse-checkout-file.  See
            https://git-scm.com/docs/partial-clone for more information.
```
