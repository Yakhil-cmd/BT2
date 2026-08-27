Based on my investigation, I found a genuine "effects-before-interaction-completes" analog to the reentrancy bug class in the `--pre-publish-exechook-command` feature.

### Title
Pre-publish exec-hook contract is not honored — symlink is published before the hook completes ([File: main.go](main.go), [pkg/hook/hook.go](pkg/hook/hook.go))

### Summary
`git-sync` documents `--pre-publish-exechook-command` as a hook that runs "after syncing a new hash... but before publishing the symlink" [1](#0-0) . In reality, `SyncRepo` treats queuing the hook as equivalent to running it: `beforePublish` only enqueues the hash into a non-blocking channel and immediately returns success, after which the symlink is published unconditionally, without ever waiting for the hook process to actually finish.

### Finding Description
`syncHooks.beforePublish` is defined as: [2](#0-1) 

`HookRunner.Send` performs a "fire-and-forget" enqueue rather than a synchronous invocation: [3](#0-2) [4](#0-3) 

The actual hook execution (`r.hook.Do(ctx, hash)`) happens later, asynchronously, in the separately-started `HookRunner.Run` goroutine [5](#0-4) .

In `SyncRepo`, the code calls `beforePublish` and, since it always returns `nil` immediately, proceeds straight to `publishSymlink` — the "effect" (making the new worktree visible to consumers via the atomic symlink flip) happens with no guarantee that the "interaction" (the pre-publish hook) has completed, succeeded, or even started running: [6](#0-5) 

The only place `WaitForCompletion` is invoked is in `--one-time` mode, and even then it is called *after* `git.cleanup(ctx)` has already run and long after `publishSymlink` executed inside the already-returned `SyncRepo` call: [7](#0-6) 

In the default (recurring, non-`--one-time`) mode — which is the normal sidecar deployment pattern shown in the docs and demo manifest — there is no wait at all; the loop simply proceeds to sleep for `--period` and re-poll.

### Impact Explanation
The documented purpose of `--pre-publish-exechook-command` is to let operators gate publication on a check of the freshly-fetched content (e.g. scanning/validating the new commit) before it becomes visible through the `--link` symlink contract that downstream sidecar consumers rely on [1](#0-0) . Because the symlink flip is decoupled from the hook's actual completion/success, an attacker who can push a malicious commit to the synced upstream repository gets that content published to the shared volume regardless of whether the pre-publish hook would have rejected it — i.e. "publishing wrong or partial content" before the intended gate fires. This is the checks-effects-interactions analog of the Vyper `refund()` bug: the state-changing effect (symlink publish) is not ordered after the interaction (hook execution) it's documented to depend on.

### Likelihood Explanation
No special flags beyond the already-documented `--pre-publish-exechook-command` are required to hit this in the way an operator would naturally deploy it (steady-state polling, not `--one-time`). Any operator who follows the documented contract and assumes pre-publish validation blocks publication is silently exposed, and any attacker who can influence the synced repo's content (the standard git-sync threat: untrusted upstream content) can win the race trivially since the hook runs in a separate, unsynchronized goroutine.

### Recommendation
Make `beforePublish` block on hook completion (e.g. use `HookRunner.WaitForCompletion`-style synchronous execution, or run the pre-publish hook inline in `SyncRepo` via `hook.Do` directly) so `publishSymlink` is only reached after the pre-publish hook has verifiably succeeded, matching the documented contract. Update/extend `e2e::pre_publish_exechook_success` to assert publish does not occur until the hook completes (including a failing-hook variant proving the symlink is *not* updated).

### Proof of Concept
1. Configure git-sync with `--pre-publish-exechook-command=/scan.sh` where `/scan.sh` is a slow or intentionally-failing validation script.
2. Push a malicious commit to the synced upstream repo.
3. Observe that `SyncRepo` calls `beforePublish` (which just does a non-blocking channel send) and then immediately calls `publishSymlink`, flipping `--link` to the new (unvalidated) worktree, before `/scan.sh` has run or returned — see `main.go:1955-1963` and `pkg/hook/hook.go:79-89`. Consumers reading through `--link` see the malicious content whether or not `/scan.sh` would have failed.

### Citations

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

**File:** main.go (L1021-1028)
```go
	syncHooks := syncHooks{
		refreshCreds: refreshCreds,
		beforePublish: func(hash string) error {
			if prePubExechookRunner != nil {
				prePubExechookRunner.Send(hash)
			}
			return nil
		},
```

**File:** main.go (L1089-1105)
```go
			// Clean up old worktree(s) and run GC.
			if err := git.cleanup(ctx); err != nil {
				log.Error(err, "git cleanup failed")
			}

			// Determine if git-sync should terminate for one of several reasons
			if *flOneTime {
				// Wait for hooks to complete at least once, if not nil, before
				// checking whether to stop program.
				// Assumes that if hook channels are not nil, they will have at
				// least one value before getting closed
				exitCode := 0 // is 0 if all hooks succeed, else is 1
				if prePubExechookRunner != nil && changed {
					if err := prePubExechookRunner.WaitForCompletion(); err != nil {
						exitCode = 1
					}
				}
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

**File:** pkg/hook/hook.go (L79-89)
```go
func (d *hookData) send(newHash string) {
	d.set(newHash)

	// Non-blocking write.  If the channel is full, the consumer will see the
	// newest value.  If the channel was not full, the consumer will get another
	// event.
	select {
	case d.ch <- struct{}{}:
	default:
	}
}
```

**File:** pkg/hook/hook.go (L122-125)
```go
// Send sends hash to hookdata.
func (r *HookRunner) Send(hash string) {
	r.data.send(hash)
}
```

**File:** pkg/hook/hook.go (L128-156)
```go
func (r *HookRunner) Run(ctx context.Context) {
	var lastHash string

	// Wait for trigger from hookData.Send
	for range r.data.events() {
		// Retry in case of error
		for {
			// Always get the latest value, in case we fail-and-retry and the
			// value changed in the meantime.  This means that we might not send
			// every single hash.
			hash := r.data.get()
			if hash == lastHash {
				break
			}

			if err := r.hook.Do(ctx, hash); err != nil {
				r.log.Error(err, "hook failed", "hash", hash, "retry", r.backoff)
				updateHookRunCountMetric(r.hook.Name(), "error")
				// don't want to sleep unnecessarily terminating anyways
				r.sendOneTimeResultAndTerminate(false)
				time.Sleep(r.backoff)
			} else {
				updateHookRunCountMetric(r.hook.Name(), "success")
				lastHash = hash
				r.sendOneTimeResultAndTerminate(true)
				break
			}
		}
	}
```
