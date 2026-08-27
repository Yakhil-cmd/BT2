### Title
Exechook/Runner subprocesses are not killed as a process group, allowing orphaned grandchildren to survive context cancellation - ([File: pkg/hook/exechook.go])

### Summary
`Exechook.Do` runs the operator-configured hook command via `cmd.Runner.Run`, which internally uses `exec.CommandContext` with no `SysProcAttr`/`Setpgid` configuration. [1](#0-0) [2](#0-1)  When the context deadline (`--sync-timeout`/hook timeout) fires, Go's `exec.CommandContext` only sends `SIGKILL` to the direct child PID, not to any process group; any grandchildren spawned by the hook command (or by git itself, e.g. build/install scripts triggered from synced repo content) are never signaled and can persist indefinitely, holding CPU and open file descriptors on the `--root` worktree.

### Finding Description
`Exechook.Do` builds `env` from `os.Environ()` plus `GITSYNC_HASH` and calls `h.cmdrunner.Run(ctx, worktreePath, env, h.command, h.args...)`. [1](#0-0)  That delegates to `runWithStdin` in `pkg/cmd/cmd.go`, which builds the process with plain `exec.CommandContext(ctx, command, args...)` and never sets `cmd.SysProcAttr` to create a new process group, nor does it kill `-pid` (the negative PID / process group) on context cancellation. [2](#0-1)  A repo-wide search confirms no `Setpgid`/`SysProcAttr`/process-group handling exists anywhere in the application code (only in vendored `x/sys` packages, which are unrelated).

Go's standard library documents that `exec.CommandContext`'s automatic termination calls `cmd.Process.Kill()`, which affects only the single tracked process, not any descendants it spawns. If the operator-configured `--pre-publish-exechook-command` (or `--exechook-command`) script forks a detached child (e.g. `some-build-tool &`, a package-manager post-install hook triggered from attacker-supplied repo content, or a script that double-forks/`setsid`s to escape the parent's session), that grandchild is not part of the tracked `os/exec` process and will not receive `SIGKILL` when the hook context times out. It survives with an open working directory inside the synced worktree, consuming CPU and blocking removal/relocking of that worktree path by the next sync cycle (`git-sync` uses atomic worktree swap via symlink, so a still-open/still-running process pinning an old worktree directory can accumulate over repeated pushes).

The attacker's leverage here is indirect: they cannot set flags or write the hook script itself, but they fully control the git content (tags/branches/commits) that is checked out into `worktreePath` and referenced by `GITSYNC_HASH`. In any deployment where the operator's hook script processes that content in a way that invokes subprocesses (a common, documented use case for `--exechook-command`/`--pre-publish-exechook-command`, e.g. build/install/test hooks), a malicious commit can cause those subprocesses to spawn additional orphaned children that outlive the hook's context — and `cmd.Runner`/`Exechook` provide no mechanism to prevent or clean this up.

### Impact Explanation
Repeated pushes each trigger a new hook invocation; if each invocation leaks one or more orphaned children that ignore the parent's termination, CPU and worktree-held file descriptors accumulate over time. This matches the Kubernetes bug-bounty "resource exhaustion" / persistent-stall impact class: unbounded orphan processes tie up node CPU and can pin old worktree directories open, interfering with git-sync's worktree cleanup/pruning and effectively locking stale repository state on disk.

### Likelihood Explanation
Exploitability is conditional and moderate, not universal:
- Requires the operator to configure `--exechook-command`/`--pre-publish-exechook-command` with a script that itself invokes subprocesses influenced by repo content (a normal but non-default configuration choice — the attacker cannot set this flag themselves).
- Requires the invoked subprocess to detach/escape the parent process's lifecycle (background it, double-fork, or `setsid`) so it is not itself killed when the direct child dies; a subprocess that terminates when its parent's stdout/stdin pipes close, or is killed as a normal child-of-child by init/reaper, would not exhibit the leak.
- The attacker fully controls the repo content that flows into `worktreePath`/`GITSYNC_HASH`, so triggering the hook logic is trivial (just push), but making the operator's hook actually spawn a persistent orphan depends on how that hook script is written.
- The underlying `exec.CommandContext`-only-kills-direct-child behavior is a genuine, unconditional Go-level property confirmed by the lack of any `SysProcAttr`/process-group handling in `pkg/cmd/cmd.go`, so once the precondition (a hook that forks orphans) is met, the leak is fully repeatable on every publish.

### Recommendation
In `pkg/cmd/cmd.go`'s `runWithStdin`, put the child in its own process group (`cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}` on Unix) and, on context cancellation, kill the negative PID (the whole process group) instead of relying on `exec.CommandContext`'s default single-process kill — e.g., start the command, then run a goroutine that on `ctx.Done()` calls `syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)`. Apply this to all callers of `Runner.Run`/`RunWithStdin`, including `Exechook.Do`, so that git subprocess trees and hook subprocess trees are fully reaped on timeout.

### Proof of Concept
Unit test sketch for `pkg/hook/exechook_test.go` (or a new test) using a shell hook script that forks a detached grandchild and sleeps past the hook timeout:
```sh
#!/bin/sh
# _test_tools/exechook_orphan.sh
( setsid sleep 60 >/tmp/orphan.marker 2>&1 & )
exit 0
```
Test:
1. Configure `Exechook` with `timeout` = 1s and `command` = `_test_tools/exechook_orphan.sh`.
2. Call `Do(ctx, hash)`; expect it to return after ~1s (context deadline error).
3. After `Do` returns, inspect `/proc` (or use `ps -o pid,ppid,pgid` filtering by session) for a `sleep 60` process still running with PPID=1 (reparented) — assert it is *not* present if the fix (process-group kill) is applied, and demonstrate it *is* still running (orphaned) against the current unfixed code, confirming the invariant "no subprocess outlives its context" is violated.

### Citations

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

**File:** pkg/cmd/cmd.go (L63-94)
```go
func runWithStdin(ctx context.Context, log logintf, cwd string, env []string, stdin, command string, args ...string) (string, string, error) {
	cmdStr := cmdForLog(command, args...)
	log.V(5).Info("running command", "cwd", cwd, "cmd", cmdStr)

	cmd := exec.CommandContext(ctx, command, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	if len(env) != 0 {
		cmd.Env = env
	}
	outbuf := bytes.NewBuffer(nil)
	errbuf := bytes.NewBuffer(nil)
	cmd.Stdout = outbuf
	cmd.Stderr = errbuf
	cmd.Stdin = bytes.NewBufferString(stdin)

	start := time.Now()
	err := cmd.Run()
	wallTime := time.Since(start)
	stdout := strings.TrimSpace(outbuf.String())
	stderr := strings.TrimSpace(errbuf.String())
	if ctx.Err() == context.DeadlineExceeded {
		return stdout, stderr, fmt.Errorf("Run(%s): %w: { stdout: %q, stderr: %q }", cmdStr, ctx.Err(), stdout, stderr)
	}
	if err != nil {
		return stdout, stderr, fmt.Errorf("Run(%s): %w: { stdout: %q, stderr: %q }", cmdStr, err, stdout, stderr)
	}
	log.V(6).Info("command result", "stdout", stdout, "stderr", stderr, "time", wallTime)

	return stdout, stderr, nil
}
```
