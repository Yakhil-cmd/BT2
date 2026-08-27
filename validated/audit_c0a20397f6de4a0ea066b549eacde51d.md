### Title
Attacker-controlled repository content (object graph size / submodule graph) can make per-sync `git fsck` and recursive `git submodule update` exceed `--sync-timeout`, causing persistent sync denial - (File: `main.go`)

### Summary
The external report describes a gas-exhaustion class bug: work performed by a function scales with attacker/protocol-influenced input size (validator counts, operator lists) rather than with anything the caller can bound, so the function can become uncallable and the intended state transition (releasing liquidity / depositing) is perpetually blocked. The reachable analog in `git-sync` is that two of the mandatory steps of every sync cycle - repository consistency checking (`git fsck --connectivity-only`) and submodule materialization (`git submodule update --init --recursive`) - perform work whose cost is fully determined by the content of the tracked upstream repository (object count, ref count, number and nesting of submodules), which is content pushed by whoever has commit access to that repository, not by the git-sync operator. Both operations run inside the same per-sync budget (`--sync-timeout`, default 120s), so a sufficiently large/complex repository state can make every single sync attempt exceed the timeout, which is functionally the same "unboundedly expensive per-call work causes the operation to be non-executable" pattern flagged in the source report.

### Finding Description
Every sync pass validates the repo/worktree before trusting it: [1](#0-0) 
and the equivalent worktree check: [2](#0-1) 
Both call `git fsck --no-progress --connectivity-only`, whose cost scales with the number of objects/refs reachable in the repository - a quantity controlled entirely by the content that was pushed upstream, not by any git-sync flag.

Separately, `configureWorktree` unconditionally performs submodule materialization (default behavior is `submodulesRecursive`): [3](#0-2) 
`git submodule update --init --recursive` walks the full submodule graph declared in `.gitmodules` at the synced commit. The number of submodules, and the depth of nested submodules-of-submodules, is fully attacker-controlled content of the tracked commit; there is no cap on submodule count or recursion depth exposed by git-sync, only `--depth` (shallow clone depth) and `--submodules={recursive,shallow,off}`, none of which bound the number of independent submodule remotes that must be cloned/updated.

Per the documented model, all of a sync's work (fetch, reset, fsck, worktree creation, submodule update, publish) must complete within `--sync-timeout` (default 120s): [4](#0-3) 
Because `fsck` and the recursive submodule walk are proportional to attacker-influenced repository state and are not independently boundable by the operator, a maliciously (or just very largely) structured commit can make the mandatory pre-publish validation and submodule step alone exceed `--sync-timeout` on every attempt.

### Impact Explanation
If every sync attempt exceeds `--sync-timeout`, `SyncRepo` never completes successfully for that commit. Depending on `--max-failures`/`--init-max-failures`, this results in either indefinite retries that never publish the new content (persistent sync denial - the "link" directory is frozen on stale content or never initialized) or process termination after the configured failure threshold, which in a Kubernetes sidecar deployment means the shared volume is never refreshed and the container/pod effectively stops serving fresh config/code. This matches the "persistent sync denial" impact class explicitly accepted by the validation criteria, and is the direct functional analog of the original report's "function may not release enough liquidity... resulting in partial fulfillment" / "depositToConsensusLayer is no longer callable" outcomes - an operation whose cost is driven by external, attacker-shaped data becomes impossible to complete within its operational constraints.

### Likelihood Explanation
Likelihood is moderate: it requires the party controlling the synced repository content (anyone with commit/push rights to the upstream `--repo`, or anyone able to influence the fetched ref/commit if the deployment tracks a mutable branch from a less-trusted source) to craft a commit with a very large object graph or a very large/deeply nested submodule graph. This is a lower-privilege actor than "the git-sync operator" (who only configures `--repo`/`--ref`/timeouts), consistent with the "unprivileged analog reachable from untrusted repo content" scope, but it is not reachable from a fully anonymous network attacker without some ability to affect the tracked repository's content.

### Recommendation
- Make `git fsck` optional or bound its cost (e.g., skip on subsequent syncs of a repo that was already sanity-checked once and hasn't shown corruption, or allow disabling `--connectivity-only` checks via a flag).
- Add an explicit, independently configurable timeout/limit for submodule materialization (e.g., a `--submodules-timeout` distinct from `--sync-timeout`, and/or a maximum submodule count/depth guard) so a pathological submodule graph cannot consume the entire sync budget and starve the publish step.
- Surface metrics/log signals distinguishing "fsck timeout" / "submodule timeout" from generic fetch failures so operators can detect this failure mode instead of experiencing silent persistent staleness.

### Proof of Concept
1. Deploy `git-sync` with `--repo` pointing at a repository the PoC author controls and can push to, with default `--sync-timeout=120s` and default `--submodules=recursive`.
2. Push a commit whose tree declares a very large number of submodule entries in `.gitmodules` (or a deep chain of submodules-of-submodules), each pointing at a small but independently-cloneable remote.
3. Trigger a sync; `configureWorktree`'s `git submodule update --init --recursive` call [5](#0-4)  must sequentially initialize/clone every submodule in the graph, and `sanityCheckWorktree`'s `git fsck --connectivity-only` [6](#0-5)  must walk the resulting enlarged object graph on every subsequent sync.
4. Observe that with a sufficiently large graph, wall-clock time for these steps exceeds `--sync-timeout`, causing `SyncRepo` to repeatedly fail and the `--link` target to never advance to the new commit (or the process to exit after `--max-failures`), demonstrating persistent sync denial driven purely by attacker-controlled repository content.

### Citations

**File:** main.go (L1457-1499)
```go
// sanityCheckRepo tries to make sure that the repo dir is a valid git repository.
func (git *repoSync) sanityCheckRepo(ctx context.Context) bool {
	git.log.V(3).Info("sanity-checking git repo", "repo", git.root)
	// If it is empty, we are done.
	if empty, err := dirIsEmpty(git.root); err != nil {
		git.log.Error(err, "can't list repo directory", "path", git.root)
		return false
	} else if empty {
		git.log.V(3).Info("repo directory is empty", "path", git.root)
		return false
	}

	// Check that this is actually the root of the repo.
	if root, _, err := git.Run(ctx, git.root, "rev-parse", "--show-toplevel"); err != nil {
		git.log.Error(err, "can't get repo toplevel", "path", git.root)
		return false
	} else {
		root = strings.TrimSpace(root)
		if root != git.root.String() {
			git.log.Error(nil, "repo directory is under another repo", "path", git.root, "parent", root)
			return false
		}
	}

	// Consistency-check the repo.  Don't use --verbose because it can be
	// REALLY verbose.
	if _, _, err := git.Run(ctx, git.root, "fsck", "--no-progress", "--connectivity-only"); err != nil {
		git.log.Error(err, "repo fsck failed", "path", git.root)
		return false
	}

	// Check if the repository contains an unreleased lock file. This can happen if
	// a previous git invocation crashed.
	if lockFile, err := hasGitLockFile(git.root); err != nil {
		git.log.Error(err, "error calling stat on file", "path", lockFile)
		return false
	} else if len(lockFile) > 0 {
		git.log.Error(nil, "repo contains lock file", "path", lockFile)
		return false
	}

	return true
}
```

**File:** main.go (L1505-1536)
```go
func (git *repoSync) sanityCheckWorktree(ctx context.Context, worktree worktree) bool {
	git.log.V(3).Info("sanity-checking worktree", "repo", git.root, "worktree", worktree)

	// If it is empty, we are done.
	if empty, err := dirIsEmpty(worktree.Path()); err != nil {
		git.log.Error(err, "can't list worktree directory", "path", worktree.Path())
		return false
	} else if empty {
		git.log.V(0).Info("worktree is empty", "path", worktree.Path())
		return false
	}

	// Make sure it is synced to the right commmit.
	stdout, _, err := git.Run(ctx, worktree.Path(), "rev-parse", "HEAD")
	if err != nil {
		git.log.Error(err, "can't get worktree HEAD", "path", worktree.Path())
		return false
	}
	if stdout != worktree.Hash() {
		git.log.V(0).Info("worktree HEAD does not match worktree", "path", worktree.Path(), "head", stdout)
		return false
	}

	// Consistency-check the worktree.  Don't use --verbose because it can be
	// REALLY verbose.
	if _, _, err := git.Run(ctx, worktree.Path(), "fsck", "--no-progress", "--connectivity-only"); err != nil {
		git.log.Error(err, "worktree fsck failed", "path", worktree.Path())
		return false
	}

	return true
}
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

**File:** README.md (L538-541)
```markdown
    --sync-timeout <duration>, $GITSYNC_SYNC_TIMEOUT
            The total time allowed for one complete sync.  This must be at least
            10ms.  This flag obsoletes --timeout, but if --timeout is specified,
            it will take precedence.  If not specified, this defaults to 120
```
