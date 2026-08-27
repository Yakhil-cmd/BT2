## Title
Pre-publish hook does not gate the symlink publish, allowing unverified attacker-controlled content to be published — (File: `main.go`, `pkg/hook/hook.go`)

### Summary
`git-sync`'s `--pre-publish-exechook-command` is documented and coded as a gate that should run and complete *before* the new worktree is exposed via the published symlink. In practice, `beforePublish` only enqueues the hash into the `HookRunner`'s async queue (`Send`) and returns immediately with `nil`, without waiting for the hook to actually execute or succeed. `git.publishSymlink(newWorktree)` is called right after, regardless of whether the pre-publish hook has run, is still running, or has failed. This is the same root-cause shape as the oracle report: an "accept" action proceeds without confirming that the thing being accepted (here, the fetched/attacker-influenced commit) actually cleared the check that was supposed to gate it.

### Finding Description
In the sync loop wiring: [1](#0-0) 

`beforePublish` calls `prePubExechookRunner.Send(hash)` and returns `nil` immediately — it never calls `WaitForCompletion()` or otherwise blocks for the hook's result.

`HookRunner.Send` -> `hookData.send` is explicitly documented as non-blocking / coalescing: [2](#0-1) 

The consumer goroutine (`HookRunner.Run`) executes asynchronously in its own loop, retrying on failure and always picking up "the latest value" — meaning intermediate hashes can be skipped and there is no synchronous coupling between "hook enqueued" and "hook completed successfully": [3](#0-2) 

Meanwhile, `SyncRepo` calls `beforePublish` and then, without waiting for its real completion, immediately calls `publishSymlink` to flip the atomic contract to the new (attacker-influenced, since `--repo` content is untrusted/remote) worktree: [4](#0-3) 

The in-code comment even states the intended invariant — "we must call the pre-publish hook... since changed is true, we will" — but "calling" here only means enqueuing an async job, not confirming its outcome before publish: [5](#0-4) 

This mirrors the oracle bug class: a validating/gating step (`acceptPendingOracle` verifying the pending value / here, the pre-publish hook validating new content) can be bypassed by a race — the "accept" (symlink publish) proceeds using the state at hand without confirming the check that consumers rely on for safety actually completed against that exact state.

### Impact Explanation
If an operator relies on `--pre-publish-exechook-command` to validate, scan, or transform new commits from the (partially or fully attacker-influenced) `--repo` before exposing them to consumers via the `--link` symlink — which is the stated purpose of a "pre-publish" hook — this control is not actually enforced. The symlink can be (and per the async/non-blocking design, will race to be) published before the hook finishes, or even after the hook fails, since `beforePublish` swallows any relationship between hook outcome and the publish decision. This can result in publishing unvalidated/wrong content to consumers, defeating the pre-publish safety gate — falling under "publishing wrong or partial content."

### Likelihood Explanation
This triggers on every sync when `--pre-publish-exechook-command` is configured and the remote ref changes (an event fully controllable by whoever can push to the tracked `--repo`/`--ref`, i.e., untrusted repo content per the threat model). No special timing exploitation is required beyond normal operation, since `Send()` is unconditionally non-blocking in the current implementation — every use of this flag is affected, not just a narrow race window.

### Recommendation
Make `beforePublish` synchronous with respect to the pre-publish hook's outcome: call `WaitForCompletion()` (as already implemented for one-time mode) on the pre-publish `HookRunner`, or otherwise block until the hook has executed and succeeded for the specific `hash` being published, and propagate failure by aborting the publish (do not call `publishSymlink`) instead of allowing `SyncRepo` to proceed unconditionally.

### Proof of Concept
1. Run `git-sync` with `--pre-publish-exechook-command=/slow-or-failing-check.sh` pointed at a repo the attacker can push to.
2. Attacker pushes a new commit to the tracked ref.
3. `SyncRepo` detects `changed == true`, calls `syncHooks.beforePublish(hash)`, which only calls `prePubExechookRunner.Send(hash)` (non-blocking) and returns `nil` immediately — confirmed at [6](#0-5) .
4. `git.publishSymlink(newWorktree)` executes immediately afterward at [7](#0-6) , before the pre-publish hook goroutine (which runs concurrently per [8](#0-7) ) has necessarily finished the check on that hash — or even if it will subsequently report failure.
5. Consumers reading through `--link` observe the new, attacker-influenced content despite the configured "pre-publish" gate not having confirmed it.

Note: I was not able to inspect the full README section describing the exact documented semantics of `--pre-publish-exechook-command` (only grep match counts were available, not the text), so I cannot cite the documented guarantee verbatim — this should be verified against README.md's description of that flag in a full session if precise wording is needed.

### Citations

**File:** main.go (L1021-1038)
```go
	syncHooks := syncHooks{
		refreshCreds: refreshCreds,
		beforePublish: func(hash string) error {
			if prePubExechookRunner != nil {
				prePubExechookRunner.Send(hash)
			}
			return nil
		},
		afterPublish: func(hash string) error {
			if exechookRunner != nil {
				exechookRunner.Send(hash)
			}
			if webhookRunner != nil {
				webhookRunner.Send(hash)
			}
			return nil
		},
	}
```

**File:** main.go (L1947-1971)
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
			if currentWorktree != "" {
				// Start the stale worktree removal timer.
				err = touch(currentWorktree.Path())
				if err != nil {
					git.log.Error(err, "can't change stale worktree mtime", "path", currentWorktree.Path())
				}
			}
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

**File:** pkg/hook/hook.go (L127-157)
```go
// Run waits for trigger events from the channel, and run hook when triggered.
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
}
```
