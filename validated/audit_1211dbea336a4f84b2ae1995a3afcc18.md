### Title
Attacker-controlled repo content can permanently deny sync by forcing the pre-publish hook to fail before the symlink is ever updated - (File: main.go)

### Summary
`SyncRepo` treats the `--pre-publish-exechook-command` result as a hard gate on publishing: if `syncHooks.beforePublish()` returns an error, the function bails out *before* `publishSymlink` runs, so the new (and any subsequent identical) hash is never published, exactly mirroring the reported pattern where an optional side-payment/side-hook's failure blocks the primary state transition for everyone downstream.

### Finding Description
In `SyncRepo`, once a new hash is fetched and a worktree is created, `beforePublish` is invoked prior to `publishSymlink`, and any error it returns causes the whole sync attempt to fail without updating the link: [1](#0-0) 

The pre-publish exechook is documented to run "with the synced repo as its working directory," meaning its exit status can be influenced by the *content of the just-fetched, attacker-controlled commit* when the operator's hook command inspects or executes anything from the checked-out tree (a documented, expected usage pattern): [2](#0-1) 

Because the worktree for a given hash is deterministically named and already exists on retry (`createWorktree`/`removeWorktree`/`worktreeFor`), an attacker who can push a commit whose tree content reliably makes the pre-publish command fail (e.g., a broken build script, syntax error, or an intentionally hanging/erroring artifact) causes the loop to keep detecting the same `remoteHash` as "changed" and keep failing at the same `beforePublish` gate on every retry, since the symlink and thus `currentWorktree` never advances: [3](#0-2) 

This failure is fed back into the main retry loop, which increments `failCount` and — critically — the default value of `--max-failures` is `0`, meaning "any sync failure will terminate git-sync": [4](#0-3) [5](#0-4) 

The result: a single attacker-controlled commit can either wedge the symlink forever at the last-known-good hash (if `--max-failures` is set to tolerate retries) or crash the git-sync process entirely (with default settings), denying all consumers of `--link` any further updates — the same "one hostile actor blocks the shared, otherwise-successful operation for everyone" pattern as the original `claimFees` finding, where the factory owner's revert blocked fee distribution to legitimate parties.

### Impact Explanation
This is a persistent sync/publish denial for every consumer of the sidecar's `--link` output. Depending on `--max-failures`, it either freezes the published content at a stale hash indefinitely or terminates the git-sync process outright (default `--max-failures=0`), which in a Kubernetes sidecar deployment can cascade into pod restarts/CrashLoopBackOff, taking down application availability that depends on fresh repo content.

### Likelihood Explanation
Requires: (1) the operator to have configured `--pre-publish-exechook-command` to do anything that reads/executes/depends on the freshly checked-out repo content (a normal, documented use case — e.g., validation, build, lint), and (2) an attacker with push access to the synced ref (or a MITM/compromised upstream) to craft a commit whose content deterministically fails that command. Likelihood is therefore contingent on hook configuration, similar in spirit to the original finding's dependency on a compromised/malicious privileged party, but here the "privileged party" is replaced by attacker-supplied repo content evaluated by the operator's own hook.

### Recommendation
- Do not let a failing pre-publish (or post-publish) hook be treated identically to a git-command failure with respect to `--max-failures`/process termination; separate "hook failed" from "sync failed" in the failure-count/backoff/exit logic.
- Consider making pre-publish hook failures non-fatal to publishing (log-and-continue, with clear opt-in for strict "block publish" behavior), or provide a bounded/independent retry/backoff for the hook distinct from the main fetch/publish retry counter so a poisoned commit cannot exhaust `--max-failures` and kill the whole sidecar.
- Document explicitly that any hook which executes/inspects untrusted repo content is a DOS vector and should be sandboxed/timeboxed (there is already `--pre-publish-exechook-timeout`, but timeout expiry still counts as a hard sync failure, which does not solve the root issue).

### Proof of Concept
1. Deploy git-sync with `--repo=<attacker-writable-or-mirrored-repo> --root=... --link=link --pre-publish-exechook-command=./validate.sh` where `validate.sh` is a normal operator script that runs something derived from repo content (e.g., `npm ci && npm test`, or a schema/lint check).
2. Attacker pushes a commit that is syntactically/structurally guaranteed to fail `validate.sh` (e.g., corrupt `package.json`, or a script that always exits non-zero).
3. git-sync fetches the new hash, creates the worktree, and calls `beforePublish` per `main.go:1955-1958`; the hook fails, `SyncRepo` returns an error without calling `publishSymlink`.
4. On each retry, the same worktree/hash is detected and the same hook failure recurs, incrementing `failCount` in the loop at `main.go:1056-1063`.
5. With default `--max-failures=0`, git-sync calls `os.Exit(1)` on the very next failure, terminating the sidecar and halting all future syncs for every consumer of `--link` — or, if `--max-failures` is raised/negative, the link is permanently stuck on the last good hash while the attacker's commit is the intended target ref, denying legitimate updates indefinitely.

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

**File:** main.go (L1899-1919)
```go
	if currentHash == remoteHash {
		// We seem to have the right hash already.  Let's be sure it's good.
		git.log.V(3).Info("current hash is same as remote", "hash", currentHash)
		if !git.sanityCheckWorktree(ctx, currentWorktree) {
			// Sanity check failed, nuke it and start over.
			git.log.V(0).Info("worktree failed checks or was empty", "path", currentWorktree)
			if err := git.removeWorktree(ctx, currentWorktree); err != nil {
				return false, "", err
			}
			currentHash = ""
		}
	}

	// This catches in-place upgrades from older versions where the worktree
	// path was different.
	changed := (currentHash != remoteHash) || (currentWorktree != git.worktreeFor(currentHash))

	// We have to do at least one fetch, to ensure that parameters like depth
	// are set properly.  This is cheap when we already have the target hash.
	if changed || git.syncCount == 0 {
		git.log.V(0).Info("update required", "ref", git.ref, "local", currentHash, "remote", remoteHash, "syncCount", git.syncCount)
```

**File:** main.go (L1947-1963)
```go
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
```

**File:** README.md (L442-446)
```markdown
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```

**File:** README.md (L474-480)
```markdown
    --pre-publish-exechook-command <string>, $GITSYNC_PRE_PUBLISH_EXECHOOK_COMMAND
            An optional command to be executed after syncing a new hash of the
            remote repository but before publishing the symlink (see --link).
            This command does not take any arguments and executes with the
            synced repo as its working directory. The $GITSYNC_HASH environment
            variable will be set to the previous git hash that was synced. This
            hook will always be invoked as it runs before any sync attempt.
```
