### Title
Unqualified ref in `git fetch <repo> <ref>` lets an attacker-created same-named tag shadow the target branch - (File: main.go, `repoSync.fetch`)

### Summary
`repoSync.fetch` builds the fetch argv as `fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc [--depth N|--unshallow] [--filter F]`, passing the operator-supplied `--ref` value to `git fetch` unqualified (not prefixed with `refs/heads/`). [1](#0-0)  Git's ref-name disambiguation on the source side of a plain (non-`refs/`-prefixed) fetch argument checks `refs/tags/<name>` before `refs/heads/<name>`, so if an attacker who can push to the source repository creates a tag with the same short name as the configured branch (e.g. tag `main` next to branch `main`), the fetch resolves to the tag's object instead of the branch tip.

### Finding Description
`SyncRepo` calls `git.fetch(ctx, git.ref)` every sync cycle [2](#0-1) , and `fetch` passes `ref` straight through as the unqualified source refspec to `git fetch <repo> <ref> ...` [3](#0-2) . After the fetch, `SyncRepo` resolves `FETCH_HEAD^{}` and publishes that hash via the symlink, trusting whatever ref git actually fetched [4](#0-3) .

Because `ref` is not qualified as `refs/heads/<ref>`, git's remote-side ref matching uses the standard disambiguation precedence (matching gitrevisions' rules for unqualified names): an exact `refs/<name>` path, then `refs/tags/<name>`, then `refs/heads/<name>`, etc. This means a same-named tag takes priority over a same-named branch. An attacker who has push access to the source repo (the documented threat model: "attacker controls pushes to the synced repo") can create a tag identical to the branch name the operator configured via `--ref`, pointing at attacker-controlled content, and the next fetch cycle will resolve `FETCH_HEAD` to the tag's commit rather than the branch's current tip — with no error, warning, or check that the fetched object matches the expected ref *type*.

This is independent of `--depth`; the depth flags only affect how much history is retrieved once the (wrong) ref has already been selected, they do not participate in ref resolution. The `--depth=1` framing in the question is not required to trigger the bug, though it is consistent with the documented default deployment recommendation and does not mitigate it.

No code in `fetch`, `SyncRepo`, or elsewhere validates that the resolved `FETCH_HEAD` actually corresponds to `refs/heads/<ref>` as opposed to `refs/tags/<ref>` or any other ref namespace; there's no explicit `refs/heads/` qualification, no `--refmap`, and no post-fetch check comparing against `git ls-remote --heads`.

### Impact Explanation
This allows an unprivileged repo-content attacker to substitute the published workload content with attacker-chosen commits, without ever needing operator, node, or credential compromise — matching the "unauthorized content published to consumers / supply-chain code substitution into the workload" impact class. Every consumer of the synced volume/symlink receives the attacker's tag content believing it to be the operator-approved branch tip.

### Likelihood Explanation
Preconditions: (1) attacker has push access sufficient to create refs (tags) in the source repository being synced — this matches the stated threat model ("Pushes a tag... Unprivileged: can push commits/branches/tags to the synced repo"); (2) the operator configures `--ref` to a branch name (the common/documented usage) rather than a fully qualified `refs/heads/<name>` or a specific commit SHA. No non-default git-sync flags are required beyond the already-documented `--ref` and (optionally) `--depth`. This is fully repeatable on every sync cycle as long as the conflicting tag exists, and requires no race condition or timing dependency.

### Recommendation
Qualify the fetch refspec explicitly instead of passing a bare name, e.g. fetch `refs/heads/<ref>:...` (or `+refs/heads/<ref>` / `refs/tags/<ref>` depending on intended ref type) when `--ref` is known/expected to be a branch, or explicitly detect/reject ambiguity by checking `git ls-remote` for both `refs/heads/<ref>` and `refs/tags/<ref>` and failing loudly (or preferring the documented ref type) rather than relying on git's implicit DWIM precedence order.

### Proof of Concept
```bash
# Server-side repo:
mkdir upstream && cd upstream
git init -b main
echo v1 > file && git add file && git commit -qam "legit branch commit"
BRANCH_SHA=$(git rev-parse HEAD)

# Attacker (has push access) creates a tag with the SAME NAME as the branch,
# pointing to different, attacker-controlled content.
echo malicious > evil && git add evil && git commit -qam "attacker commit"
git tag main            # tag "main" now shadows branch "main"
git reset --hard "$BRANCH_SHA"   # restore branch tip so branch still looks legit
TAG_SHA=$(git rev-parse refs/tags/main)

cd .. && mkdir clone && cd clone && git init -b clone_branch

# Simulate git-sync's fetch call exactly as in repoSync.fetch:
git fetch "file://$(pwd)/../upstream" main --verbose --no-progress --prune --no-auto-gc
git rev-parse FETCH_HEAD^{}
# EXPECTED (if invariant holds): equals $BRANCH_SHA
# ACTUAL: equals $TAG_SHA -- the attacker's tag is fetched instead of the branch
```
Assertion for a unit/integration test: `git rev-parse FETCH_HEAD^{}` after `repoSync.fetch(ctx, "main")` should equal `git rev-parse refs/heads/main` on the server, but instead equals `git rev-parse refs/tags/main`, demonstrating the branch/tag ambiguity is not resolved correctly by git-sync's unqualified fetch invocation.

### Citations

**File:** main.go (L1885-1887)
```go
	if err := git.fetch(ctx, git.ref); err != nil {
		return false, "", err
	}
```

**File:** main.go (L1892-1897)
```go
	var remoteHash string
	if output, _, err := git.Run(ctx, git.root, "rev-parse", "FETCH_HEAD^{}"); err != nil {
		return false, "", err
	} else {
		remoteHash = strings.Trim(output, "\n")
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
