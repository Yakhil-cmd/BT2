### Title
Hardcoded `--depth` flag applied to all submodules causes persistent sync denial when a submodule host rejects shallow fetches - (File: main.go)

### Summary
`git-sync`'s `configureWorktree` unconditionally appends `--depth <N>` to the `git submodule update --init` invocation whenever the operator has set `--depth`, with no ability to override or disable it per-submodule. This mirrors the Yearn report's root cause: a fixed parameter (there, `maxLoss=1bps`; here, a global `--depth`) applied indiscriminately in a git argv construction that offers no fallback path, so once the parameter is incompatible with a specific remote's capabilities, the operation always fails.

### Finding Description
In the submodule-update path of `configureWorktree`, the depth argument is derived only from the top-level `--depth` flag and applied globally to every submodule, with no per-submodule override, no fallback to unshallow, and no way for `git-sync` itself to detect or work around a submodule remote that doesn't support shallow fetch: [1](#0-0) 

Compare this to the top-level repo fetch, which *does* have escape-hatch logic: if the current state is shallow and depth is no longer requested, it explicitly issues `--unshallow`: [2](#0-1) 

No equivalent flexibility exists for submodules. `git submodule update --init --depth N` will fail with something like `fatal: attempt to fetch/clone from a shallow repository` or a server-side rejection ("shallow fetch not allowed") if the target submodule server disallows shallow clones (e.g., some self-hosted Git servers, or servers configured with `uploadpack.allowFilter`/`allowReachableSHA1InWant` restrictions but not shallow). Because `.gitmodules` and submodule commit pins are ordinary repository content, an attacker who can push to the branch `git-sync` tracks controls which submodule URL is fetched. If they add or repoint a submodule to a host that rejects shallow clones, every subsequent `SyncRepo` call will hit this hardcoded `--depth` argument and fail identically — the operator has no flag to selectively disable depth for that one submodule, only for all submodules (via `--depth 0`), which then defeats the operator's original shallow-clone intent for the primary purpose of running `--depth`.

This is the direct structural analog to the Yearn report: a hardcoded parameter baked into a call/selector, applied without regard to the specific target's constraints, causing unconditional failure once those constraints are violated — with the only "fix" being to disable the feature entirely rather than parameterize it per-target.

### Impact Explanation
Once triggered, `SyncRepo` returns an error every sync loop iteration `git.fetch` → `git.configureWorktree` → submodule update fails, so `changed` is never reached and the symlink is never republished; this is a **persistent sync denial** for the whole repo (not just the submodule), since `configureWorktree` returning an error aborts the entire sync of the parent worktree. This matches the accepted "persistent sync denial" impact category.

### Likelihood Explanation
Requires the operator to have set `--depth` (non-zero) and to have submodule syncing enabled (`--submodules` not `off`) — both of which are documented, common configurations for shallow, bandwidth-conscious syncs. Given those flags, the trigger is fully within the untrusted repo content: any contributor/attacker with push access to the tracked ref can add/modify `.gitmodules` to point at a host that rejects shallow fetches (or simply pin a commit unreachable via shallow fetch on an existing submodule remote). This requires no privileged access to git-sync's config, only push access to the synced repository — a realistic "attacker-pushed commit" scenario.

### Recommendation
Do not propagate the top-level `--depth` unconditionally to `git submodule update`. Instead:
- Detect shallow-fetch failures on submodule update and retry once with `--depth` omitted (i.e., an "unshallow" fallback for submodules, mirroring the logic already present for the main repo fetch).
- Alternatively, expose a separate `--submodules-depth` (or `--no-submodules-depth`) flag so operators can decouple submodule shallow-fetch behavior from the top-level repo's depth, rather than an all-or-nothing choice.

### Proof of Concept
1. Run `git-sync` with `--repo=<attacker-writable-repo> --depth=1 --submodules=recursive --root=/tmp/root --link=repo`.
2. Attacker pushes a commit to the tracked ref adding a `.gitmodules` entry pointing to a Git host/server configured to reject shallow fetch requests (e.g., a server enforcing `uploadpack.allowReachableSHA1InWant=false` and no shallow support), or pins a submodule commit not reachable within a shallow window.
3. On the next sync, `git.fetch` for the parent succeeds, but `configureWorktree` → `git submodule update --init --depth 1` fails at [3](#0-2) .
4. `SyncRepo` returns an error every iteration thereafter; the symlink is never updated and no new content is ever published, producing indefinite sync denial until the operator manually intervenes (e.g., unsets `--depth`).

### Citations

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

**File:** main.go (L2001-2029)
```go
// fetch retrieves the specified ref from the upstream repo.
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
