### Title
Pre-publish exechook does not gate publish: `beforePublish` is fire-and-forget, so the symlink is published before (or without ever waiting for) the hook to observe/approve the worktree - ([File: main.go, pkg/hook/hook.go, pkg/hook/exechook.go])

### Summary
In steady-state sync, `SyncRepo`'s `beforePublish` callback only enqueues the hash to `HookRunner` via a non-blocking `Send` and unconditionally returns `nil`, so `git.publishSymlink(newWorktree)` executes immediately regardless of whether the pre-publish exechook has run or succeeded for that hash. Combined with `HookRunner.Run`'s coalescing behavior (it only ever processes the *latest* hash in the channel, potentially skipping intermediate hashes), an attacker who controls the pace of pushes to the synced repo can force publish to run for hashes whose pre-publish hook never ran (or ran too late to matter), defeating the invariant "the pre-publish hook observes exactly the tree that will be published."

### Finding Description
The relevant call path is: [1](#0-0) 

```go
beforePublish: func(hash string) error {
    if prePubExechookRunner != nil {
        prePubExechookRunner.Send(hash)
    }
    return nil
},
```

This is invoked from `SyncRepo`: [2](#0-1) 

`syncHooks.beforePublish(newWorktree.Hash())` returns `nil` unconditionally (as long as `prePubExechookRunner != nil`), because `HookRunner.Send` is fire-and-forget: [3](#0-2) [4](#0-3) 

The actual hook execution happens asynchronously in `HookRunner.Run`, in a separate goroutine, consuming from a size-1 non-blocking channel: [5](#0-4) 

Because the channel is size-1 and writes are non-blocking (`default:` branch drops the wake-up signal if the channel is full), and the loop always re-fetches "the latest value" via `r.data.get()`, if two or more syncs happen before the hook goroutine catches up, **intermediate hashes are silently skipped** — the code comment even states "we might not send every single hash." Meanwhile `SyncRepo` has already called `publishSymlink` for each of those hashes because `beforePublish` never blocks on hook completion or success in the non-`--one-time` path.

Thus, for the normal sidecar/steady-state mode (no `--one-time`), the pre-publish hook is not actually gating: publish proceeds independent of whether the hook for that specific hash ran, is still running, or has failed. `Exechook.Do` itself (`pkg/hook/exechook.go:65-80`) correctly computes `worktreePath` from the hash it receives and runs against that specific worktree, but by the time (or regardless of whether) it runs, the symlink may already point to a newer or different hash, or the hook for the currently-published hash may simply never execute due to coalescing.

An attacker who can push commits/branches to the synced repo controls how many distinct hashes arrive within a `--period` window (this is explicitly named as an in-scope capability). By pushing rapidly, they can force multiple `SyncRepo` iterations to occur before the async `HookRunner` goroutine drains its queue, guaranteeing that pre-publish validation is skipped for some published revisions, or that the publish for hash N proceeds without waiting for a hook verdict on N at all.

### Impact Explanation
This breaks the documented "gate" semantics of `--pre-publish-exechook-command` ("An optional command to be executed ... but before publishing the symlink"). A consumer relying on the pre-publish hook to validate/scan content before symlink flip can end up with **unverified or unvalidated content published** — matching the "publishing wrong or partial content" / "symlink/publish integrity failure" impact class named in the rules.

### Likelihood Explanation
- Requires only the documented, default-supported `--pre-publish-exechook-command` flag (a normal, intended feature) — no non-default/unsafe flag combination needed.
- Requires no operator misconfiguration beyond using the hook feature as documented.
- Fully reproducible: an attacker with ordinary push access to the synced repo (explicitly an allowed capability in this audit) can trigger this by pushing several distinct commits back-to-back, faster than the hook's runtime, well within a short `--period`.
- The race is deterministic given the non-blocking `Send`/coalescing design, not a narrow timing coincidence, and is easily reached automated via unit tests against `HookRunner` and `SyncRepo`.

### Recommendation
Make `beforePublish` synchronous and gating: block until the pre-publish hook actually completes for the specific hash being published, and propagate hook failure/error as a real error from `beforePublish` so `SyncRepo` aborts the publish (do not call `publishSymlink`) when the hook has not succeeded for that exact hash. If asynchronous behavior must be retained for other reasons, ensure `HookRunner` guarantees processing of every hash sequentially (no coalescing) and that `SyncRepo` waits on a per-hash completion signal (similar to `WaitForCompletion`, but generalized beyond `--one-time` mode) before calling `publishSymlink`.

### Proof of Concept
Unit test outline (Go, using `pkg/hook`):
```go
func TestPrePublishHookSkippedUnderRapidPublish(t *testing.T) {
    data := hook.NewHookData()
    var executedHashes []string
    var mu sync.Mutex
    fakeHook := &fakeExechook{
        do: func(ctx context.Context, hash string) error {
            mu.Lock(); executedHashes = append(executedHashes, hash); mu.Unlock()
            time.Sleep(50 * time.Millisecond) // simulate slow hook
            return nil
        },
    }
    runner := hook.NewHookRunner(fakeHook, 0, data, testLogger, false)
    go runner.Run(context.Background())

    // Simulate SyncRepo publishing 5 rapid hashes without waiting for hook.
    for i := 0; i < 5; i++ {
        hash := fmt.Sprintf("hash-%d", i)
        runner.Send(hash)          // fire-and-forget, as beforePublish does
        publishSymlink(hash)       // publish proceeds immediately regardless
        time.Sleep(5 * time.Millisecond)
    }
    time.Sleep(500 * time.Millisecond)

    // Assertion: the hook should have observed every published hash, but
    // due to coalescing + non-blocking publish, executedHashes will be a
    // strict subset of the 5 published hashes.
    assert.Equal(t, 5, len(executedHashes), "pre-publish hook must observe every published revision")
}
```
Expected current (buggy) result: `len(executedHashes) < 5`, demonstrating that publish outpaces/bypasses the gating hook, i.e., the invariant "the pre-publish hook observes exactly the tree that will be published" fails.

### Citations

**File:** main.go (L1023-1028)
```go
		beforePublish: func(hash string) error {
			if prePubExechookRunner != nil {
				prePubExechookRunner.Send(hash)
			}
			return nil
		},
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
