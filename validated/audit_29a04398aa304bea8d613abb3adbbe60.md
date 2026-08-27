### Title
Pre-publish exec-hook does not gate symlink publication, violating documented ordering guarantee - (File: main.go, pkg/hook/hook.go)

### Summary
The bug report describes a re-entrancy class issue: an external callback (`_assessFees`) is invoked before the caller's own state is finalized, allowing the callee to observe/act on inconsistent state. The closest reachable analog in `git-sync` is the `--pre-publish-exechook-command` mechanism: `git-sync` documents that this hook runs "before publishing the symlink" (i.e., it is meant to gate the atomic publish), but the implementation fires the hook asynchronously and unconditionally proceeds to publish regardless of whether the hook has run or succeeded, so the "external call" and the "state finalization" (symlink flip) are not properly ordered/serialized.

### Finding Description
In `main()`, the `beforePublish` callback is defined to simply enqueue the hash to the pre-publish `HookRunner` and return `nil` immediately, without waiting for the hook to execute or checking its result: [1](#0-0) 

`HookRunner.Send` performs a non-blocking write to a buffered channel and returns instantly; the actual hook execution happens in a separate goroutine started via `go prePubExechookRunner.Run(context.Background())`: [2](#0-1) [3](#0-2) 

In `SyncRepo`, the call sequence is `syncHooks.beforePublish(...)` (which always returns `nil` immediately because it hard-codes `return nil`) followed unconditionally by `git.publishSymlink(newWorktree)`: [4](#0-3) 

This contradicts the documented contract for `--pre-publish-exechook-command`, which states it runs "after syncing a new hash of the remote repository but before publishing the symlink": [5](#0-4) 

Because the hook execution is dispatched to an independent goroutine and the main sync loop does not wait on it (no `WaitForCompletion` call outside of `--one-time` mode, and even then the wait only happens after publish/cleanup in the outer loop, not before `publishSymlink`), the symlink can be atomically flipped to expose the new worktree to consumers before the pre-publish hook has actually executed or validated anything, and even if the hook subsequently fails.

### Impact Explanation
This is analogous to the reported re-entrancy pattern in spirit: a callback intended to run and complete before the system's state is finalized is instead invoked out-of-band with no synchronization, so the "finalize" step (`publishSymlink`) proceeds independent of the callback's outcome. Operators who rely on `--pre-publish-exechook-command` to validate, sign, or sanitize newly-synced (attacker-influenced, since `--repo`/`--ref` content is externally controlled) content before it becomes visible via `--link` will have that guarantee silently violated, allowing **publishing of wrong or partial/unvalidated content** to consumers of the shared volume.

### Likelihood Explanation
This is deterministically reachable any time `--pre-publish-exechook-command` is configured and a new hash is synced (i.e., any attacker who can push a new commit/ref that git-sync fetches). No malicious operator, leaked keys, or mocked components are required — it is a straightforward logic/ordering flaw in the mainline sync loop.

### Recommendation
Make the pre-publish hook synchronous with respect to `publishSymlink`: either block on `WaitForCompletion` (or an equivalent per-hash completion channel) before calling `git.publishSymlink`, and propagate the hook's real success/failure into the `beforePublish` return value instead of hard-coding `nil`, so a failing or slow pre-publish hook actually prevents symlink publication as documented.

### Proof of Concept
1. Configure `git-sync` with `--pre-publish-exechook-command=/slow_or_failing_validator.sh` and a normal `--period`.
2. Push a new commit to the synced repo/ref.
3. Observe via `test_e2e.sh`-style instrumentation (e.g. `e2e::pre_publish_exechook_fail_retry`, `pkg/hook/hook_test.go` patterns) that `beforePublish` returns before the validator script has completed, since `Send` only enqueues to a channel: [6](#0-5) 
4. Confirm `$ROOT/link` is updated to the new hash immediately, independent of the validator's exit status, contradicting the documented "before publishing the symlink" ordering: [4](#0-3)

### Citations

**File:** main.go (L960-967)
```go
		prePubExechookRunner = hook.NewHookRunner(
			exechook,
			*flPrePubExechookBackoff,
			hook.NewHookData(),
			log,
			*flOneTime,
		)
		go prePubExechookRunner.Run(context.Background())
```

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

**File:** main.go (L1955-1963)
```go
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

**File:** pkg/hook/hook.go (L122-157)
```go
// Send sends hash to hookdata.
func (r *HookRunner) Send(hash string) {
	r.data.send(hash)
}

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
