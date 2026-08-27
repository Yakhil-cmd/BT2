### Title
Pre-publish exec-hook is fire-and-forget: symlink is published before (and regardless of) hook completion/success - (File: main.go, pkg/hook/hook.go)

### Summary
The reported Solidity bug is a Checks-Effects-Interactions violation: a callback to an untrusted party is invoked before critical state updates complete, enabling those updates to be observed/exploited in an inconsistent state. The closest reachable analog in `git-sync` is in `SyncRepo`, where the `--pre-publish-exechook-command` (documented as a gate that must run "before publishing the symlink") is actually dispatched asynchronously and non-blockingly, so the atomic symlink publish (the consumer-visible "effect") proceeds without waiting for the hook to actually finish or succeed.

### Finding Description
`SyncRepo` calls `syncHooks.beforePublish(newWorktree.Hash())` immediately before `git.publishSymlink(newWorktree)`: [1](#0-0) 

`beforePublish` is wired to `prePubExechookRunner.Send(hash)`, which returns `nil` unconditionally: [2](#0-1) 

`HookRunner.Send` only writes the hash into a channel-backed queue; it does not run the hook or wait for it: [3](#0-2) 

The underlying `hookData.send` is an explicitly **non-blocking** channel write: [4](#0-3) 

The actual hook execution (`hook.Do(ctx, hash)`, e.g. running the `--pre-publish-exechook-command`) happens in a separate goroutine (`HookRunner.Run`, started via `go prePubExechookRunner.Run(...)`), fully decoupled from the call in `SyncRepo`: [5](#0-4) [6](#0-5) 

As a result, `SyncRepo` calls `publishSymlink` right after "sending" the pre-publish hook, without any guarantee that the hook has run, let alone succeeded — exactly the CEI-violation pattern from the report: an external call/callback (the exec hook, effectively a caller-supplied program) is interleaved with a state change (the atomic symlink flip) instead of gating it. Even in `--one-time` mode, the only place the pre-publish hook's success is checked is later in the outer loop via `WaitForCompletion()`, which happens **after** `SyncRepo` (and thus `publishSymlink`) has already returned: [7](#0-6) 

By that point the symlink has already been atomically repointed to the new worktree, so a failing/incomplete pre-publish hook can only cause the process to exit with a non-zero code — it cannot prevent the publish from having already happened. This is consistent with the e2e test `e2e::pre_publish_exechook_fail_once`, which expects `GIT_SYNC` to `assert_fail` (nonzero exit) even though the link/content assertions pass, confirming the symlink flip is not actually gated by hook success: [8](#0-7) 

### Impact Explanation
The documented contract for `--pre-publish-exechook-command` is that it runs "after syncing a new hash ... but before publishing the symlink," implying it can be used to validate, transform, or gate content (e.g., decrypt, scan, or verify a commit) before it becomes visible to consumers via the `--link` symlink: [9](#0-8) 

Because the hook dispatch is asynchronous/non-blocking and its result is checked too late (or, outside `--one-time` mode, never joined to the publish decision at all), an attacker who can influence the synced content (e.g., an attacker-pushed commit on the tracked ref) can cause the symlink to be published to consumers before the intended pre-publish validation completes or even when that validation fails. This matches the accepted impact category of "publishing wrong or partial content" to consumers of the atomic symlink contract.

### Likelihood Explanation
This triggers on every sync where `--pre-publish-exechook-command` is configured and there is new content to publish (`changed == true`), which is the normal, unprivileged code path reachable purely by pushing a new commit to the tracked ref — no malicious operator, leaked keys, or special flags beyond the already-documented `--pre-publish-exechook-command` are required.

### Recommendation
Make the pre-publish hook synchronous and blocking with respect to `publishSymlink`: `SyncRepo` should invoke the pre-publish hook's `Do()` directly (or wait on a per-call completion channel) and only proceed to `git.publishSymlink()` if the hook returns success, mirroring the Checks-Effects-Interactions fix recommended in the source report (perform the "callback"/external action and confirm its outcome before performing the state-changing effect).

### Proof of Concept
1. Configure `git-sync` with `--pre-publish-exechook-command` pointing to a slow/failing validator script (as in `EXECHOOK_COMMAND_FAIL_SLEEPY` used by `e2e::pre_publish_exechook_fail_once`).
2. Push a new commit to the tracked ref.
3. Observe that `SyncRepo` calls `syncHooks.beforePublish` (which merely enqueues the hash, see `main.go:1955` and `pkg/hook/hook.go:123-125`) and immediately proceeds to `git.publishSymlink(newWorktree)` at `main.go:1960`, updating the consumer-visible symlink.
4. Only afterward (outside `SyncRepo`, in the main loop) is the hook's completion checked via `WaitForCompletion()` (`main.go:1101-1105`), and only in `--one-time` mode — by then the symlink already points at the new, unvalidated worktree, as reflected in the `e2e::pre_publish_exechook_fail_once` test expectations (`test_e2e.sh:2646-2662`).

### Citations

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

**File:** main.go (L1095-1105)
```go
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
