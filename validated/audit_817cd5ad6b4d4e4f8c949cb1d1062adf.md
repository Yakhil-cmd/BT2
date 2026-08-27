### Title
Post-publish exec-hook can run against a worktree that has already been deleted by immediate stale-worktree cleanup, permanently losing the hook's ability to act on that revision - ([File: main.go](main.go))

### Summary
The reported Alchemix bug is a "burn-before-claim" race: a resource (the veALCX token) is irreversibly destroyed (`_burn`) before a dependent claim (`Voter::claimBribes`) that references it by identity can be executed, permanently losing the reward. The closest reachable analog in `git-sync` is the interaction between the post-publish `exechook` (which is handed a `hash` and independently resolves its own worktree path via `getWorktree(hash)`), the asynchronous, coalescing `HookRunner`, and the worktree cleanup logic that can delete a worktree "immediately" once it becomes stale.

### Finding Description
When a sync completes, `SyncRepo` calls `syncHooks.afterPublish(newWorktree.Hash())`, which asynchronously signals the `exechookRunner`/`webhookRunner` via `HookRunner.Send(hash)` [1](#0-0) . The hook runner does not execute synchronously; it stores the hash in a size-1, non-blocking channel and a background goroutine (`HookRunner.Run`) later calls `hook.Do(ctx, hash)` [2](#0-1) .

Immediately after firing the hooks, the *same* sync loop iteration invokes `git.cleanup(ctx)`, which calls `removeStaleWorktrees()` [3](#0-2) . `--stale-worktree-timeout` defaults to `0`, meaning a worktree becomes eligible for removal "immediately" on the very next cleanup pass [4](#0-3) . `removeStaleWorktrees` deletes any worktree directory (other than the current one) whose mtime exceeds the timeout via `removeDirContentsIf` calling `os.RemoveAll` internally in `removeWorktree` [5](#0-4) [6](#0-5) .

The `Exechook.Do` implementation resolves the worktree path for the hash it is given at execution time (not at signal time) via `h.getWorktree(hash)` and then runs the external command with that directory as its working directory [7](#0-6) . Because the hook runner is asynchronous and can be delayed (e.g., a slow/backing-off previous hook run, command scheduling, or a fast `--period`), by the time `hook.Do` actually executes, `git.cleanup` may already have removed the target worktree for that hash — the directory the exechook needs no longer exists. Additionally, `hookData.send` explicitly documents that under rapid successive syncs "the consumer will see the newest value ... the consumer will [not] get another event" for skipped intermediate hashes [8](#0-7)  — so an exechook tied to an older, now-stale hash can be silently coalesced away entirely, and that worktree is deleted before any hook ever fires for it.

This mirrors the reported bug's structure: an entity (worktree / veALCX token) that a downstream consumer (exechook / `claimBribes`) depends on by identity is destroyed by an unrelated maintenance path (`cleanup` / `withdraw`→`_burn`) before the consumer's claim (`hook.Do` / `claimBribes`) can execute, and there is no ordering guarantee or "claim before destroy" barrier between the two paths.

### Impact Explanation
If an operator configures `--exec-hook-command` (or webhook logic that shells out and reads generated artifacts from the worktree) to process each synced revision — e.g., signing, scanning, or copying files from the worktree for a specific hash — a sufficiently fast attacker-controlled push cadence (attacker with write access to the tracked ref/branch) or default `--stale-worktree-timeout=0` can cause the target worktree to be deleted before (or exactly as) the exec hook attempts to read it, causing the hook to fail (`no such file or directory`) or operate on wrong/partial data for that hash. This falls under "publishing wrong or partial content" / "persistent sync denial" of the hook path, since the hook can never successfully act on that specific commit once its worktree is reclaimed — an unrecoverable, permanent loss of hook execution for that revision, analogous to the permanently lost bribes in the report.

### Likelihood Explanation
Requires either the default `--stale-worktree-timeout=0` combined with a short `--period` and an attacker able to push commits rapidly to the synced ref, or a hook command whose execution/backoff is slower than the sync period. This is a real but narrow timing window, not a guaranteed exploit path in all configurations; verifying the exact race window (whether `os.Stat`/`Run` in the exec path already fails cleanly vs. silently succeeding on wrong data) would require running the e2e harness (`test_e2e.sh`), which was not executed in this analysis.

### Recommendation
- Have `SyncRepo` (or the hook dispatch path) pin/reference-count the worktree for a hash while a hook is pending/running, and have `removeStaleWorktrees` skip any worktree that still has hooks queued or in-flight for its hash.
- Alternatively, resolve and pass an absolute, hook-specific snapshot path at `Send`-time rather than re-resolving `getWorktree(hash)` lazily at `Do`-time, and treat a resolution failure as a fatal, non-silent error surfaced to sync failure metrics rather than a generic command failure.
- Document and/or enforce a minimum `--stale-worktree-timeout` greater than the maximum expected hook execution/backoff time when exec/webhooks are configured.

### Proof of Concept
Conceptual reproduction (not run):
1. Start `git-sync` with `--period=200ms`, default `--stale-worktree-timeout=0`, and `--exec-hook-command=/bin/sleep-and-read.sh` where the script sleeps briefly before reading a file from its CWD (the worktree).
2. Push two commits to the tracked branch in quick succession (within less than the exec hook's execution+backoff time).
3. Observe: `SyncRepo` publishes hash A, fires `afterPublish` for A, then quickly publishes hash B and fires `afterPublish` for B before the `HookRunner` goroutine has invoked `Do` for A; per `hookData.send`'s documented coalescing behavior, the runner may skip straight to B, and `git.cleanup` removes A's worktree on the next pass because it is no longer "current" and the stale timeout is 0 [9](#0-8) [8](#0-7) .
4. Result: the exechook never runs for hash A, and A's worktree directory is permanently gone — no way to retroactively invoke the hook against that revision's checked-out content, paralleling the permanently unclaimable bribes in the original report.

### Citations

**File:** main.go (L1089-1092)
```go
			// Clean up old worktree(s) and run GC.
			if err := git.cleanup(ctx); err != nil {
				log.Error(err, "git cleanup failed")
			}
```

**File:** main.go (L1420-1441)
```go
func (git *repoSync) removeStaleWorktrees() (int, error) {
	currentWorktree, err := git.currentWorktree()
	if err != nil {
		return 0, err
	}

	git.log.V(3).Info("cleaning up stale worktrees", "currentHash", currentWorktree.Hash())

	count := 0
	err = removeDirContentsIf(git.worktreeFor("").Path(), git.log, func(fi os.FileInfo) (bool, error) {
		// delete files that are over the stale time out, and make sure to never delete the current worktree
		if fi.Name() != currentWorktree.Hash() && time.Since(fi.ModTime()) > git.staleTimeout {
			count++
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
```

**File:** main.go (L1622-1640)
```go
// removeWorktree is used to remove a worktree and its folder.
func (git *repoSync) removeWorktree(ctx context.Context, worktree worktree) error {
	// Clean up worktree, if needed.
	_, err := os.Stat(worktree.Path().String())
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	}
	git.log.V(1).Info("removing worktree", "path", worktree.Path())
	if err := os.RemoveAll(worktree.Path().String()); err != nil {
		return fmt.Errorf("error removing directory: %w", err)
	}
	if _, _, err := git.Run(ctx, git.root, "worktree", "prune", "--verbose"); err != nil {
		return err
	}
	return nil
}
```

**File:** main.go (L1973-1976)
```go
		err := syncHooks.afterPublish(newWorktree.Hash())
		if err != nil {
			return false, "", err
		}
```

**File:** main.go (L2868-2873)
```go
    --stale-worktree-timeout <duration>, $GITSYNC_STALE_WORKTREE_TIMEOUT
            The length of time to retain stale (not the current link target)
            worktrees before being removed. Once this duration has elapsed,
            a stale worktree will be removed during the next sync attempt
            (as determined by --sync-timeout). If not specified, this defaults
            to 0, meaning that stale worktrees will be removed immediately.
```

**File:** pkg/hook/hook.go (L79-156)
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

// NewHookRunner returns a new HookRunner.
func NewHookRunner(hook Hook, backoff time.Duration, data *hookData, log logintf, oneTime bool) *HookRunner {
	hr := &HookRunner{hook: hook, backoff: backoff, data: data, log: log}
	if oneTime {
		hr.oneTimeResult = make(chan bool, 1)
	}
	return hr
}

// HookRunner struct.
type HookRunner struct {
	// Hook to run and check
	hook Hook
	// Backoff for failed hooks
	backoff time.Duration
	// Holds the data as it crosses from producer to consumer.
	data *hookData
	// Logger
	log logintf
	// Used to send a status result when running in one-time mode.
	// Should be initialised to a buffered channel of size 1.
	oneTimeResult chan bool
}

// Just the logr methods we need in this package.
type logintf interface {
	Info(msg string, keysAndValues ...any)
	Error(err error, msg string, keysAndValues ...any)
	V(level int) logr.Logger
}

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
```

**File:** pkg/hook/exechook.go (L65-79)
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
```
