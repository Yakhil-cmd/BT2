Found a real analog. The `HookRunner.Run` mechanism in `pkg/hook/hook.go` uses a "latest value wins" coalescing pattern that is structurally the same TOCTOU class as the Governor quorum bug: a value (`hash`) is captured once for a check/decision, but by the time the corresponding action actually executes, the underlying state has already moved on to a newer value — and the action silently uses whatever is "current" at execution time rather than the value that was current when the decision was triggered.

### Title
Exechook/Webhook hash-vs-worktree TOCTOU: hook body runs against a worktree that no longer matches the `GITSYNC_HASH` it was invoked for - (File: `pkg/hook/hook.go`, `pkg/hook/exechook.go`)

### Summary
`HookRunner.Run` intentionally coalesces rapid successive sync events and always re-reads "the latest value" (`r.data.get()`) rather than the value that triggered the event [1](#0-0) . This mirrors the Governor bug pattern: a quantity is snapshotted at decision time (`proposal.quorumVotes` / here, the triggering sync's hash) but the actual state used when the action executes (`token.getPastVotes` / here, the worktree directory on disk) can have already changed by the time execution happens.

### Finding Description
`repoSync.SyncRepo` calls `syncHooks.beforePublish` and `afterPublish`, which feed hashes into a `hookData` object via `Send` [2](#0-1) . `hookData.send` stores the hash and signals via a non-blocking, size-1 channel: "If the channel is full, the consumer will see the newest value" [3](#0-2) . The consumer loop in `HookRunner.Run` explicitly always fetches "the latest value" before invoking the hook, and documents that "we might not send every single hash" [4](#0-3) .

`Exechook.Do` then resolves the worktree path purely from the `hash` it was handed: `worktreePath := h.getWorktree(hash)` and runs the command there with `GITSYNC_HASH` set to that same hash [5](#0-4) . If two sync events fire in quick succession (e.g., an attacker who controls the upstream remote pushes two commits within one `--period` window, or during the initial fast-retry `--init-period` phase), the second `SyncRepo` run's `beforePublish`/`afterPublish` call to `Send` overwrites `hookData.hash` before the hook goroutine has processed the first event. Because `HookRunner.Run` reads `r.data.get()` at execution time rather than capturing the hash at signal time, the hook command can be invoked once, but with the value already advanced to the *second* commit's hash, while `worktreePath` for the *stale* trigger no longer corresponds to what the operator expects the hook to have observed atomically. More importantly, the "lastHash" dedup logic means an intermediate hash's `beforePublish`/`afterPublish` firing can be **skipped entirely** — the hook never runs for that hash at all, only for the final one, silently dropping a sync generation's hook invocation. This is the direct structural analog of "tokens minted between quorum computation and vote": a per-generation decision is computed and dispatched at time T1, but the actor that consumes it acts on the value it reads at T2, which may already be a different generation's value.

### Impact Explanation
For consumers relying on `--exechook-command`/`--webhook-url` to run per-commit side effects (e.g., cache invalidation, config reload, signing verification of a specific commit) keyed by `GITSYNC_HASH`, this coalescing behavior means a hook invocation is not guaranteed once-per-published-hash. This can cause a downstream consumer to skip processing a specific revision (persistent sync/notification denial for that revision) or to run against a worktree/hash combination whose freshness the operator did not intend, similar to how the quorum bug caused an unintended-but-not-obviously-wrong value to be used for a security decision. It does not, by itself, grant remote code execution or credential disclosure beyond what the operator's own hook command already does.

### Likelihood Explanation
This requires an attacker who controls the pushes to the tracked ref (already an assumed threat actor for git-sync's supply-chain surface) to push at least two commits within a window smaller than the hook's completion time or the sync period, which is realistic for fast `--period`/`--init-period` settings or for a hook whose command execution is slow (bounded by `--exechook-timeout`). No special git-sync flags beyond enabling `--exechook-command` (or webhook) are required.

### Recommendation
Capture the hash argument at the moment the event is dequeued and pass a copy through the channel itself (e.g., a buffered channel of hash strings, or record the pending hash alongside the "in-flight" hash) instead of separately storing "latest" state that is read independently of the triggering event; alternatively, document explicitly that hook invocations are best-effort/coalesced and not guaranteed once-per-hash, so operators do not build correctness-critical logic (e.g., audit or security notifications) on top of it.

### Proof of Concept
1. Configure `git-sync --exechook-command=/slow_hook.sh --exechook-timeout=5s --period=100ms --repo=<attacker-controlled-remote>`.
2. Attacker pushes commit A, then within <5s pushes commit B, then commit C.
3. `SyncRepo` runs for A, calls `syncHooks.afterPublish("A")` → `hookData.send("A")`.
4. Before the hook goroutine picks it up (it's still sleeping/running from a prior invocation or hasn't started), `SyncRepo` runs for B, then C, each calling `send`, each time overwriting `d.hash` and refreshing the non-blocking channel slot per `hookData.send` [3](#0-2) .
5. `HookRunner.Run`'s loop, per iteration of `for range r.data.events()`, calls `r.data.get()` and finds `hash == "C"` twice in a row (once for the event meant for A, once for the event meant for B), so it `break`s without invoking `h.hook.Do` for A or B at all [6](#0-5) .
6. Result: hook never runs with `GITSYNC_HASH=A` or `GITSYNC_HASH=B`, even though `main.go`'s `SyncRepo` published symlinks and reported `good_sync_count` for both — a silent, persistent skip of per-revision hook processing that an operator relying on it for security-relevant per-commit actions would not detect without additional out-of-band monitoring.

### Citations

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

**File:** pkg/hook/hook.go (L132-155)
```go
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
```

**File:** main.go (L1947-1976)
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

		err := syncHooks.afterPublish(newWorktree.Hash())
		if err != nil {
			return false, "", err
		}
```

**File:** pkg/hook/exechook.go (L65-76)
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
```
