### Title
Pre-publish hook does not gate `publishSymlink` — unverified content published despite hook failure - ([File: main.go, pkg/hook/hook.go])

### Summary
`syncHooks.beforePublish` only *enqueues* the new hash to the async `HookRunner` via `Send()`/`hookData.send()` and returns immediately; `SyncRepo` then calls `publishSymlink` unconditionally, without waiting for the pre-publish hook to actually run or succeed. This breaks the documented contract that the pre-publish hook runs "before publishing the symlink" and gates the publish, allowing an attacker with repo-push access to get unverified/failing content published.

### Finding Description
In `main.go`, the `syncHooks` used by `SyncRepo` are wired as: [1](#0-0) 

`beforePublish` calls `prePubExechookRunner.Send(hash)` and returns `nil` immediately — it does not block on hook completion. `HookRunner.Send` just forwards to `hookData.send`: [2](#0-1) [3](#0-2) 

The actual hook execution happens asynchronously in `HookRunner.Run`, running in its own goroutine (`go prePubExechookRunner.Run(...)`): [4](#0-3) [5](#0-4) 

Back in `SyncRepo`, the publish happens immediately after `beforePublish` returns, with no wait for the hook's result: [6](#0-5) 

Because `hookData` is a single-slot, non-blocking channel (`d.ch <- struct{}{}` with `default:` fallback) and `d.set(newHash)` always overwrites the stored hash, if a second hash arrives while the runner is still retrying/backing off on a previous one, the previous hash is silently dropped from being (re-)checked — yet its content may already have been published by the time the overwrite occurs, since publish in the main loop is synchronous and sequential per iteration and does not wait on the hook at all.

This is confirmed by the existing e2e test `e2e::pre_publish_exechook_fail_once`, which runs git-sync with a failing `--pre-publish-exechook-command` and explicitly asserts the symlink and its content are published anyway, even though the process ultimately exits with failure: [7](#0-6) 

The failure is only surfaced via `WaitForCompletion`, which is checked solely in `--one-time` mode and only *after* `publishSymlink` has already executed inside `SyncRepo`: [8](#0-7) 

In continuous (non `--one-time`) mode there is no completion check at all — hook failures are logged and retried forever in the background while the symlink has already been flipped to the new (unverified) content.

### Impact Explanation
This is a publish-integrity failure: content that the pre-publish hook is meant to validate (e.g. signature/policy checks) is published to the `--link` symlink regardless of whether that validation succeeds. An attacker who can push arbitrary commits/tags to the synced repo (explicitly in the stated unprivileged threat model) can get malicious or unvalidated content published to consumers even when an operator has configured a gating pre-publish hook, defeating the purpose of that control. This matches "unverified content published despite a gating hook."

### Likelihood Explanation
No non-default or unsupported flags are required beyond the documented `--pre-publish-exechook-command` (and optionally `--pre-publish-exechook-backoff`), both supported settings. The behavior is deterministic and reproducible on every push in the default (continuous) mode, and is explicitly demonstrated by the repository's own e2e test for the `--one-time` case, confirming it is not a timing fluke but the designed control flow: `Send()`/`beforePublish` never blocks on hook success before `publishSymlink` runs.

### Recommendation
Make the pre-publish hook synchronous and blocking with respect to `publishSymlink`: `SyncRepo` should wait for the pre-publish hook to run to completion (success) for the exact hash about to be published before calling `publishSymlink`, and abort/retry the sync (without publishing) if the hook fails, in both one-time and continuous modes. This likely requires refactoring `HookRunner`/`hookData` to support a synchronous "run-and-wait" call path for the pre-publish case (distinct from the fire-and-forget model appropriate for post-publish `exechook`/`webhook`), and ensuring the single-slot channel cannot silently drop a hash that is about to be (or already was) published without its gating check running.

### Proof of Concept
Reuse the existing e2e test as the reproducible PoC (already in-tree): [7](#0-6) 

This test configures `--pre-publish-exechook-command="/$EXECHOOK_COMMAND_FAIL_SLEEPY"` with `--one-time`, asserts the overall process exits with failure (`assert_fail`), yet still asserts:
```
assert_link_exists "$ROOT/link"
assert_file_exists "$ROOT/link/file"
assert_file_eq "$ROOT/link/file" "${FUNCNAME[0]}"
```
i.e., the new content was published to `$ROOT/link` despite the pre-publish hook failing — directly demonstrating that hook success does not gate the publish, satisfying the "unverified content published despite a gating hook" outcome.

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

**File:** main.go (L1094-1119)
```go
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
				if exechookRunner != nil {
					if err := exechookRunner.WaitForCompletion(); err != nil {
						exitCode = 1
					}
				}
				if webhookRunner != nil {
					if err := webhookRunner.WaitForCompletion(); err != nil {
						exitCode = 1
					}
				}
				log.DeleteErrorFile()
				log.V(0).Info("exiting after one sync", "status", exitCode)
				os.Exit(exitCode)
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

**File:** pkg/hook/hook.go (L127-156)
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
```

**File:** test_e2e.sh (L2646-2662)
```shellscript
function e2e::pre_publish_exechook_fail_once() {
    cat /dev/null > "$RUNLOG"

	assert_fail \
        GIT_SYNC \
            --one-time \
            --repo="file://$REPO" \
            --root="$ROOT" \
            --link="link" \
            --pre-publish-exechook-command="/$EXECHOOK_COMMAND_FAIL_SLEEPY" \
            --pre-publish-exechook-backoff=1s

    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_eq "$ROOT/link/file" "${FUNCNAME[0]}"
    assert_file_lines_eq "$RUNLOG" 1
}
```
