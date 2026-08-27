### Title
Pre-publish hook fires asynchronously and does not block symlink publication - violates checks-before-effects ordering (File: main.go)

### Summary
The report's bug class — an internal effect (accounting update / fund transfer) being committed before the external interaction it depends on has actually completed — has an analog in `git-sync`'s publish path. `git.publishSymlink()`, the atomic "effect" that exposes new content to consumers, is executed immediately after firing the pre-publish hook, without waiting for that hook to actually run or succeed, contradicting the tool's own documented contract.

### Finding Description
`SyncRepo` calls `syncHooks.beforePublish(hash)` and then immediately calls `git.publishSymlink(newWorktree)`: [1](#0-0) 

The `beforePublish` closure only performs a non-blocking `Send()` to a hook-runner channel and returns `nil` unconditionally, without waiting for the hook's `Do()` to run or succeed: [2](#0-1) 

`HookRunner.Send` -> `hookData.send` is explicitly a non-blocking channel write, and the actual execution of the hook command happens later in a separate goroutine started at startup (`go prePubExechookRunner.Run(...)`), decoupled from the calling `SyncRepo` flow entirely: [3](#0-2) [4](#0-3) [5](#0-4) 

The manual explicitly documents `--pre-publish-exechook-command` as "an optional command to be executed after syncing a new hash of the remote repository but **but before publishing the symlink**": [6](#0-5) 

But the actual "effect" (`publishSymlink`, which flips the atomic contract consumers rely on) is not gated on completion of that hook — it is only gated by `WaitForCompletion()`, which is exclusively invoked in `--one-time` mode: [7](#0-6) 
In continuous (non-one-time) mode — the primary Kubernetes sidecar use case — there is no synchronization at all between the pre-publish hook's actual execution/completion and the symlink flip.

### Impact Explanation
This is analogous to the checks-effects-interactions violation in the report: the tool's "effect" (publishing new content via the atomic symlink — the entire trust contract stated in the README: "Consumers of the synced files should always use this link ... it is updated atomically and should always be valid") is committed before the "interaction" it logically depends on (the pre-publish hook, intended to validate or prepare the worktree) has completed. In continuous mode, consumers can observe the new hash via the symlink before the pre-publish hook has even started, finished, or reported failure, meaning:
- Consumers may read content that the operator intended to be gated on a pre-publish validation/transformation step, i.e. "publishing wrong or partial content" relative to the documented guarantee.
- If the pre-publish hook is meant to reject bad content (fail closed), a slow or failing hook does not prevent publication in steady-state mode, silently defeating the intended safety gate.

This is unprivileged in the sense that it is triggered on every normal sync cycle by design (an attacker who controls the upstream repo content that the hook is meant to vet gains no benefit from the intended check, since the check is race-prone against publication).

### Likelihood Explanation
This occurs on every sync cycle where `--pre-publish-exechook-command` is configured and `--one-time` is not set (the common sidecar deployment), because the asynchronous, non-blocking `Send`/goroutine design is unconditional, not a corner case requiring a malicious token/timing trick.

### Recommendation
Make `beforePublish` synchronous: have `SyncRepo` block on the pre-publish hook's actual execution and result (similar to how `WaitForCompletion` is currently only wired for `--one-time`) before calling `publishSymlink`, and abort/retry publication if the hook fails, restoring the checks-before-effects ordering that the documented contract promises.

### Proof of Concept
1. Configure git-sync with `--pre-publish-exechook-command=/slow_or_failing_check.sh` in continuous mode (no `--one-time`).
2. Trigger a new commit on the synced ref.
3. Observe (via logging/instrumentation of the hook script and the `--link` symlink target) that `publishSymlink` flips the symlink to the new worktree hash immediately, while the pre-publish hook goroutine is still executing (or has failed) in the background — confirmable by the code paths at [8](#0-7)  and [9](#0-8) , which show no blocking/handshake between the two.

### Citations

**File:** main.go (L474-480)
```go
	if *flDepth < 0 { // 0 means "no limit"
		fatalConfigErrorf(log, true, "invalid flag: --depth must be greater than or equal to 0")
	}

	switch submodulesMode(*flSubmodules) {
	case submodulesRecursive, submodulesShallow, submodulesOff:
	default:
```

**File:** main.go (L944-968)
```go
	// Startup pre-publish-exechooks goroutine
	var prePubExechookRunner *hook.HookRunner
	if *flPrePubExechookCommand != "" {
		logname := "pre-publish-exechook"
		log := log.WithName(logname)
		exechook := hook.NewExechook(
			logname,
			cmd.NewRunner(log),
			*flPrePubExechookCommand,
			func(hash string) string {
				return git.worktreeFor(hash).Path().String()
			},
			[]string{},
			*flPrePubExechookTimeout,
			log,
		)
		prePubExechookRunner = hook.NewHookRunner(
			exechook,
			*flPrePubExechookBackoff,
			hook.NewHookData(),
			log,
			*flOneTime,
		)
		go prePubExechookRunner.Run(context.Background())
	}
```

**File:** main.go (L1021-1037)
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
