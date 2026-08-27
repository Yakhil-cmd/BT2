### Title
Pre-publish exec-hook does not block symlink publication, defeating the "gate before publish" contract - (File: main.go, pkg/hook/hook.go)

### Summary
`git-sync`'s `--pre-publish-exechook-command` is documented as a gate that must finish running *before* the new content is made visible via the `--link` symlink. In practice, `SyncRepo` only enqueues the hook asynchronously and immediately proceeds to publish the symlink without waiting for the hook to actually execute or complete, so untrusted repository content can become visible to consumers before (or even without) the pre-publish validation actually running for that hash — the same class of bug as the Sandclock finding, where an operation finalized state based on the assumption that a dependent call had already completed.

### Finding Description
`syncHooks.beforePublish` is defined to call `prePubExechookRunner.Send(hash)` and return `nil` immediately: [1](#0-0) 

`HookRunner.Send` merely forwards to `hookData.send`, which performs a **non-blocking** channel write and returns without waiting for the hook's `Do()` to run or finish: [2](#0-1) 

`SyncRepo` treats `beforePublish` returning `nil` as the pre-publish step being "done", and immediately calls `git.publishSymlink(newWorktree)` right after: [3](#0-2) 

The actual hook execution happens in a separate long-running goroutine (`prePubExechookRunner.Run`) that consumes from the channel and calls `h.cmdrunner.Run(...)` at its own pace: [4](#0-3) [5](#0-4) 

The README explicitly documents an ordering guarantee that the implementation does not enforce: the command should run "after syncing a new hash ... but before publishing the symlink": [6](#0-5) 

Because `Send` is fire-and-forget, there is no synchronization point that forces `publishSymlink` to wait for the hook goroutine to actually pick up the hash and finish `Do()`. The main sync loop can race ahead and publish the symlink essentially concurrently with (or even before) the hook's `os/exec` call actually starts, and if a subsequent commit triggers another sync cycle quickly, the hook's channel/hash state (`hookData.hash`) can be overwritten before the previous hash's hook run occurs at all, per the documented (but security-relevant) admission: "Hooks are not guaranteed to succeed on every single hash change." This is analogous to the Sandclock Vault bug, where `claimers.onWithdraw` mutated share state before the underlying value transfer completed, letting a reentrant call observe/exploit the gap between "logically done" and "actually done."

### Impact Explanation
An attacker who controls the synced repository content (the untrusted, attacker-pushed-commit trust boundary explicitly in scope) can push a rapid sequence of commits. Because the pre-publish gate is not actually blocking, `git-sync` can publish a new worktree via the `--link` symlink to the consuming application container before the pre-publish-exechook-command (which operators rely on for validation/build/gating steps) has completed for that hash, or the hook can be skipped for a given hash entirely due to the hash being overwritten in `hookData` before `Do()` runs. This results in publishing wrong/partial or ungated content to consumers, undermining the operator's intended safety gate on the delivered artifact.

### Likelihood Explanation
Likelihood is moderate to high in any deployment that relies on `--pre-publish-exechook-command` as a gate: the race is triggered simply by normal repository activity (fast successive pushes) or by a hook whose execution takes any non-trivial amount of time relative to `publishSymlink`'s speed, no privileged access to the git-sync process itself is required, only the ability to push commits to the tracked ref, which matches the "attacker-pushed commit" threat model in scope.

### Recommendation
Make `beforePublish` synchronous with respect to the actual pre-publish hook execution: block on the hook's completion (or a completion signal) for the specific `newWorktree.Hash()` before calling `publishSymlink`, rather than treating the mere enqueue (`Send`) as sufficient. This mirrors the recommended fix pattern of ensuring dependent state/effects are fully settled before external-visible finalization occurs.

### Proof of Concept
1. Configure git-sync with `--pre-publish-exechook-command` pointing to a script that sleeps for several seconds (simulating validation/build work) before exiting 0.
2. Push a commit to the tracked repo/ref.
3. Observe via logs/timing that `SyncRepo` calls `git.publishSymlink` (main.go:1960) essentially immediately after `beforePublish` returns (main.go:1955-1958), while the exechook's `os/exec` invocation (pkg/hook/exechook.go:75) is still sleeping in the separate `prePubExechookRunner.Run` goroutine.
4. The `--link` symlink already points at the new worktree hash while the "gate" command has not finished, demonstrating that the documented "before publishing the symlink" ordering is not enforced. [7](#0-6)

### Citations

**File:** main.go (L944-967)
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
```

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

**File:** pkg/hook/exechook.go (L65-80)
```go
func (h *Exechook) Do(ctx context.Context, hash string) error {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	worktreePath := h.getWorktree(hash)

	env := os.Environ()
	env = append(env, envKV("GITSYNC_HASH", hash))

	h.log.V(0).Info("running exechook", "hash", hash, "command", h.command, "timeout", h.timeout)
	stdout, stderr, err := h.cmdrunner.Run(ctx, worktreePath, env, h.command, h.args...)
	if err == nil {
		h.log.V(1).Info("exechook succeeded", "hash", hash, "stdout", stdout, "stderr", stderr)
	}
	return err
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
