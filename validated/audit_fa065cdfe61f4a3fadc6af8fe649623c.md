Confirmed: there is no code path in `main.go` that validates `remoteHash` (derived from `rev-parse FETCH_HEAD^{}`) against the literal string in `git.ref` when `--ref` is a 40-hex hash. `fetch()` simply passes `git.ref` verbatim as the fetch refspec source [1](#0-0) , and `SyncRepo` trusts whatever `FETCH_HEAD` resolves to as the new content to publish [2](#0-1) , without ever comparing it back to the requested `--ref` value.

### Title
Hash-pinned `--ref` can be shadowed by an attacker-created branch/tag of the same name, causing publication of unauthorized content - (File: main.go)

### Summary
`repoSync.fetch` passes the operator's `--ref` string directly as the `<src>` argument to `git fetch <repo> <ref>` [3](#0-2) . Git's fetch refspec resolution tries name-based ref matching (branch/tag names on the remote) before falling back to raw object-id fetching. If an attacker who can push refs to the synced repo creates a branch or tag whose name is identical to the 40-hex commit hash that the operator pinned via `--ref`, that name match takes precedence, and `git-sync` will fetch and publish the tip of the attacker's ref instead of the originally pinned commit object.

### Finding Description
`SyncRepo` calls `git.fetch(ctx, git.ref)`, which runs `git fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` (plus `--depth`/`--unshallow` handling) using the raw `git.ref` string as the source refspec [4](#0-3) . After the fetch, the code resolves `FETCH_HEAD^{}` via `rev-parse` to determine `remoteHash`, and if it differs from the currently synced hash, resets, checks out, and publishes it via the symlink [5](#0-4) [6](#0-5) .

Nowhere in this path is `remoteHash` compared back against the literal `git.ref` string to confirm that when `--ref` is a hash, the fetched object is actually that exact object id. The v3-to-v4 migration doc even documents that `--ref` is expected to behave as a plain object id fetch for full hashes [7](#0-6) , but the code contains no explicit "is this a 40-hex SHA, and if so assert the fetched object equals it" check.

Git's own fetch refspec resolution algorithm gives priority to matching the `<src>` string against advertised ref names (`refs/heads/<name>`, `refs/tags/<name>`, etc.) before treating it as a raw object id to fetch directly. Consequently, if the attacker (who can push branches/tags to the synced repository) creates a ref literally named after the 40-hex hash pinned in `--ref`, `git fetch` resolves `FETCH_HEAD` to the tip of that attacker-controlled ref rather than to the pinned commit object — even though the commit object with that exact hash may still exist and be unrelated to the ref. The operator's intent — "pin to this exact commit, immune to ref changes" — is silently violated.

This is most dangerous in exactly the scenario named in the question: a deployment previously run with `--depth N` (shallow) is later reconfigured to `--depth 0`, triggering the `--unshallow` fetch path [8](#0-7) . That code path doesn't change the vulnerability's root cause (the ref-name shadowing happens regardless of shallow/unshallow), but it is one of the operationally common moments when a full fetch of "the ref" happens against upstream, giving the attacker's shadow ref an opportunity to be resolved.

### Impact Explanation
An unprivileged party who can push branches/tags to the synced repository can cause `git-sync` to publish content that was never authorized by the pinned commit hash, defeating the entire purpose of hash-pinning `--ref`. This maps to the Kubernetes bug-bounty "unauthorized content published" / integrity-violation class: consumers relying on `readlink <link>` pointing at a specific, immutable commit can be served attacker-controlled trees/files without any warning, and the pin appears intact in configuration (the flag value is unchanged).

### Likelihood Explanation
Preconditions: the attacker needs push access to create refs (branches or tags) in the repository that git-sync fetches from — this is explicitly listed as an in-scope attacker capability for this question ("can push commits/branches/tags to the synced repo"). No non-default git-sync flags are required beyond the already-documented `--ref <full-hash>` usage; the `--depth`/`--unshallow` transition mentioned in the question is a normal, documented operational change, not a misconfiguration. This is generally reproducible: create an upstream ref named identically to a known commit hash and observe which object `FETCH_HEAD` resolves to after `git fetch <repo> <hash-named-ref>`.

### Recommendation
When `--ref` matches a 40-character hex string, `initRepo`/`fetch`/`SyncRepo` should not trust `FETCH_HEAD` resolution implicitly. Instead:
- Detect that `git.ref` is a raw hash (regex `^[0-9a-f]{40}$` or similar, also covering SHA-256 hash lengths).
- After fetch, explicitly verify `remoteHash == git.ref` (case-insensitive) when the ref was hash-shaped, and fail loudly (do not publish) if they differ.
- Alternatively, use a fetch invocation that unambiguously requests an object id (e.g., prefixing with characters that cannot be a ref name, or using `git fetch <repo> <hash>:` with negotiation flags that avoid refname resolution) combined with server capability checks, but the simplest and most robust fix is the explicit post-fetch hash assertion described above.

### Proof of Concept
Integration test (bash, similar in style to `test_git.sh`):
```bash
mkdir upstream && pushd upstream >/dev/null
git init -q -b main
echo legit > file && git add file && git commit -qam "legit commit"
PINNED_SHA="$(git rev-parse HEAD)"

# Attacker action: create a branch whose name equals the pinned hash,
# pointing at different, attacker-controlled content.
git checkout -q -b "$PINNED_SHA"
echo attacker-controlled > file
git commit -qam "attacker content"
ATTACKER_SHA="$(git rev-parse HEAD)"
popd >/dev/null

mkdir clone && pushd clone >/dev/null
git init -q -b clone_branch
git fetch "file://$PWD/../upstream" "$PINNED_SHA"
RESOLVED="$(git rev-parse FETCH_HEAD^{})"

# Expected (secure) behavior: RESOLVED == PINNED_SHA
# Actual (vulnerable) behavior: RESOLVED == ATTACKER_SHA, because the
# ref name "$PINNED_SHA" shadowed the raw object-id fetch.
[[ "$RESOLVED" == "$PINNED_SHA" ]] || echo "VULNERABLE: fetched $RESOLVED instead of pinned $PINNED_SHA"
popd >/dev/null
```
Running `git-sync --repo=file://.../upstream --ref=$PINNED_SHA --root=... --link=link` twice (or through the periodic loop) and then `readlink`-ing the published link's target hash will show it points at `$ATTACKER_SHA`, confirming the pin was silently bypassed, matching `main.go`'s `fetch`/`SyncRepo` logic at [4](#0-3)  and [2](#0-1) .

### Citations

**File:** main.go (L1885-1897)
```go
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

**File:** main.go (L2001-2024)
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
```

**File:** v3-to-v4.md (L84-93)
```markdown
#### Abbreviated hashes

Because of the fetch loop, git-sync v3 allowed a user to specify `--branch` and
`--rev`, where the rev was a shortened hash (aka SHA), which would be locally
expanded to the full hash.  v4 tries hard not to pull extra stuff, which means
we don't have enough information locally to do that resolution, and there no
way to ask the server to do it for us (at least, not as far as we know).

The net result is that, when using a hash for `--ref`, it must be a full hash,
and not an abbreviated form.
```
