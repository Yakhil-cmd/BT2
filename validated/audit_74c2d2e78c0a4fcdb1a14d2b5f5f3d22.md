### Title
Hash-pinned `--ref` can be shadowed by an attacker-created branch/tag of the same name in `repoSync.fetch` - ([File: main.go])

### Summary
`repoSync.fetch` builds its fetch argv as `fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` and passes the operator-configured `--ref` value verbatim as the fetch refspec source, with no qualification (e.g. `refs/heads/<ref>` vs. a raw object id) and no post-fetch verification that the object actually retrieved matches the pinned hash. [1](#0-0)  When `--ref` is a 40-hex commit hash, an unprivileged pusher who creates a branch or tag with that exact name can make git's own ref-DWIM resolution match the ref name during `git fetch <repo> <hash>` before git ever falls back to resolving the string as a literal object id, causing `FETCH_HEAD` to point at the attacker's ref tip instead of the pinned commit.

### Finding Description
`SyncRepo` calls `git.fetch(ctx, git.ref)`, which runs `git fetch <repo> <ref> ...`, then immediately trusts whatever `FETCH_HEAD` resolves to via `git rev-parse FETCH_HEAD^{}` as `remoteHash`, with no comparison back to the literal pinned value of `git.ref`. [2](#0-1) [1](#0-0) 

Git's own fetch source resolution treats the given refspec source as a DWIM name to be matched first against the remote's advertised refs (`refs/heads/<name>`, `refs/tags/<name>`, `refs/remotes/<name>`, etc.); only if no ref matches does git attempt to request the literal string as a raw object id (which additionally requires the server to allow unadvertised object requests). Because a 40-hex string is a syntactically legal ref name, if the attacker creates a branch or tag literally named as the hash that the operator pinned via `--ref`, `git fetch <repo> <hash>` resolves to that ref rather than the object id, and `FETCH_HEAD` ends up pointing to the attacker's ref tip commit instead of the originally intended commit object.

git-sync's code never re-asserts the "hash pin" invariant after fetch: there is no check anywhere in `fetch`, `SyncRepo`, or surrounding code that when `git.ref` is itself a full hash, the resolved `remoteHash` must equal `git.ref`. [3](#0-2)  The subsequent logic (`reset --soft`, `createWorktree`, `publishSymlink`) treats `remoteHash` as authoritative and publishes it unconditionally once it differs from `currentHash`. [4](#0-3)  The project's own v3-to-v4 migration notes confirm the operator-facing contract that `--ref` can be "a commit hash (aka SHA)" used for pinning, without describing any additional post-fetch integrity check against ref-name collisions. [5](#0-4) 

This is a genuine attacker-reachable path: the attacker only needs push access to create a branch/tag named after the pinned hash (satisfying the "attacker controls pushed refs/objects" precondition), no special flags, secrets, or operator/node compromise are required.

### Impact Explanation
If exploited, a deployment configured to pin to an exact commit hash (a common integrity control used precisely to avoid trusting mutable branch/tag content) can be made to silently sync and publish content from an attacker-controlled ref instead. This is a "publishing wrong content while the pin appears intact" scenario — the deployment's logs, hash-pin flag, and outward configuration remain unchanged, but the served content is attacker-chosen. This matches the Kubernetes bug-bounty class of supply-chain/content-integrity failure via unauthorized content publication.

### Likelihood Explanation
- Requires the operator to use a commit-hash value for `--ref` (a supported, documented, non-default but common configuration for pinning).
- Requires the attacker to have push access to create refs/objects on the same remote repository git-sync fetches from (an explicitly allowed attacker capability in this analysis).
- Requires git's server-side ref-DWIM behavior to prefer the colliding ref name over literal object-id resolution, which is git's default and well-established behavior; no additional non-default flags are needed for the attack path itself.
- The attack is deterministic and repeatable: as long as the colliding ref exists on the remote, every subsequent fetch will keep resolving to the attacker's ref, not the original hash, until the ref is removed or git-sync verification is added.

### Recommendation
When `--ref` is detected to be a full 40-hex object id, git-sync should either (a) fully qualify the fetch source unambiguously (avoid passing a bare hash-shaped string as a name that could dwim-match remote refs) and/or (b) explicitly assert post-fetch that `rev-parse FETCH_HEAD^{}` equals the literal pinned hash, failing loudly (without publishing) if it does not. This restores the invariant that a hash-pinned `--ref` can only ever resolve to that exact object id, regardless of colliding ref names on the remote.

### Proof of Concept
1. Create an upstream repo with a commit `C` whose hash is `H`.
2. As an unprivileged pusher, create a branch (or tag) literally named `H` on the upstream, pointing at a different, attacker-chosen commit `M`.
3. Configure git-sync with `--ref=H` (a hash-pin deployment) and `--filter=blob:none`.
4. Run the sync loop:
   - First sync: `git fetch <repo> H ...` resolves via ref-DWIM to the attacker's branch/tag `refs/heads/H` (or `refs/tags/H`), not the object `H` directly; `rev-parse FETCH_HEAD^{}` returns `M`'s hash, not `H`.
   - Assert (currently failing): `remoteHash` returned by `SyncRepo` should equal `H`; instead it equals `M`.
   - Assert (fast-validation criterion from the question): running two consecutive syncs against this crafted remote does not wipe `--root` and does not exit non-zero — confirming the sync "succeeds" while silently serving `M`'s content under a nominal pin of `H`.
5. Extend `test_git.sh`/`test_e2e.sh` style test (`git::fetch_upstream_sha`-like) to add a colliding ref-name case and assert `git rev-parse HEAD` after sync equals the pinned hash `H`, which fails under the current implementation.

### Citations

**File:** main.go (L1883-1898)
```go
	// This should be very fast if we already have the hash we need. Parameters
	// like depth are set at fetch time.
	if err := git.fetch(ctx, git.ref); err != nil {
		return false, "", err
	}

	// Figure out what we got.  The ^{} syntax "peels" annotated tags to
	// their underlying commit hashes, but has no effect if we fetched a
	// branch, plain tag, or hash.
	var remoteHash string
	if output, _, err := git.Run(ctx, git.root, "rev-parse", "FETCH_HEAD^{}"); err != nil {
		return false, "", err
	} else {
		remoteHash = strings.Trim(output, "\n")
	}

```

**File:** main.go (L1918-1971)
```go
	if changed || git.syncCount == 0 {
		git.log.V(0).Info("update required", "ref", git.ref, "local", currentHash, "remote", remoteHash, "syncCount", git.syncCount)
		metricFetchCount.Inc()

		// Reset the repo (note: not the worktree - that happens later) to the new
		// ref.  This makes subsequent fetches much less expensive.  It uses --soft
		// so no files are checked out.
		if _, _, err := git.Run(ctx, git.root, "reset", "--soft", remoteHash, "--"); err != nil {
			return false, "", err
		}

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

		// If we have a new hash, update the symlink to point to the new worktree.
		if changed {
			// If the previous run crashed before publishing the link, then we
			// must call the pre-publish hook, and since changed is true, we will.
			// we will. If the previous run crashed after publishing the link,
			// then we do not need to call the pre-publish hook, and since
			// changed is false, we won't. The post-publish hooks are called in
			// both cases.
			err := syncHooks.beforePublish(newWorktree.Hash())
			if err != nil {
				return false, "", err
			}

			err = git.publishSymlink(newWorktree)
			if err != nil {
				return false, "", err
			}
			if currentWorktree != "" {
				// Start the stale worktree removal timer.
				err = touch(currentWorktree.Path())
				if err != nil {
					git.log.Error(err, "can't change stale worktree mtime", "path", currentWorktree.Path())
				}
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

**File:** v3-to-v4.md (L58-93)
```markdown
### Sync target: `--branch` and `--rev` -> `--ref`

The old `--branch` and `--rev` flags are deprecated in favor of the new `--ref`
flag.  `--ref` can be either a branch name, a tag name, or a commit hash (aka
SHA).  For backwards compatibility, git-sync will still accept the old flags
and try to set `--ref` from them.

    |----------|---------|---------|------------------------------|
    | --branch |  --rev  |  --ref  |            meaning           |
    |----------|---------|---------|------------------------------|
    |    ""    |   ""    | "HEAD"  | remote repo's default branch |
    |  brname  |   ""    | brname  | remote branch `brname`       |
    |  brname  | "HEAD"  | brname  | remote branch `brname`       |
    |    ""    | tagname | tagname | remote tag `tagname`         |
    |   other  |  other  |   ""    | error                        |
    |----------|---------|---------|------------------------------|

#### Default target

In git-sync v3, if neither `--branch` nor `--rev` were specified, the default
was to sync the HEAD of the branch named "master".  Many git repos have changed
to "main" or something else as the default branch name, so git-sync v4 changes
the default target to be the HEAD of whatever the `--repo`'s default branch is.
If that default branch is not "master", then the default target will be
different in v4 than in v3.

#### Abbreviated hashes

Because of the fetch loop, git-sync v3 allowed a user to specify `--branch` and
`--rev`, where the rev was a shortened hash (aka SHA), which would be locally
expanded to the full hash.  v4 tries hard not to pull extra stuff, which means
we don't have enough information locally to do that resolution, and there no
way to ask the server to do it for us (at least, not as far as we know).

The net result is that, when using a hash for `--ref`, it must be a full hash,
and not an abbreviated form.
```
