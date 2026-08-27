### Title
`exec.CommandContext` cancellation only kills the direct git process, not child processes spawned during submodule fetches, allowing orphaned subprocesses to survive `--sync-timeout` - ([File: pkg/cmd/cmd.go])

### Summary
`runWithStdin` in `pkg/cmd/cmd.go` creates the git process via `exec.CommandContext(ctx, command, args...)` without setting a process group (`SysProcAttr`) and without any explicit process-tree cleanup on cancellation. `exec.CommandContext`'s built-in cancellation only sends the kill signal to the directly spawned process (the top-level `git` invocation), not to any children that `git` itself forks (e.g. per-submodule `git fetch`/`git clone` subprocesses during `git submodule update --recursive`). If an attacker-controlled repository defines submodules pointing at slow/hanging remotes, the top-level `git` process can be killed at `--sync-timeout` expiry while its child fetch processes remain running and continue consuming CPU, memory, and disk.

### Finding Description
`runWithStdin` at [1](#0-0)  builds the command with `cmd := exec.CommandContext(ctx, command, args...)` and calls `cmd.Run()`. Go's standard library documents that `CommandContext`'s automatic cancellation behavior (killing the process when the context is done) only affects the process created by `exec.Cmd` itself — it does **not** propagate to any subprocesses that process spawns, unless the caller places the child in its own process group (via `SysProcAttr.Setpgid`) and explicitly signals the whole group (e.g. with `syscall.Kill(-pid, ...)`) on cancellation. No such `SysProcAttr` configuration or explicit process-group kill logic exists in `pkg/cmd/cmd.go` [2](#0-1) .

When git-sync runs `git submodule update --init --recursive` (or similar, driven by attacker-controlled `.gitmodules` content/refs in the synced repository) via this `Run`/`RunWithStdin` API, git itself forks additional `git fetch`/`git clone`/`git-remote-*` child processes to fetch each submodule. If the outer `--sync-timeout` expires while a submodule fetch is in progress, `ctx` becomes `Done()`, `exec.CommandContext` kills the top-level `git submodule update` process, and `runWithStdin` returns a `context.DeadlineExceeded` error at [3](#0-2) . However, the grandchild fetch process for the slow submodule was not part of that direct kill target and, having been reparented, keeps running independently, continuing to use CPU/network/disk after git-sync has already logged the operation as timed out and moved on to its next sync cycle.

### Impact Explanation
Each timed-out sync cycle involving a slow/hostile submodule can leave one or more orphaned `git fetch`/`git clone` processes running in the container. Because git-sync repeats its sync loop, repeated timeouts compound the number of live orphaned processes, leading to unbounded accumulation of CPU usage, open file descriptors, network connections, and disk I/O/space (e.g., partial `.git/modules/*` objects being written) — a resource-exhaustion / denial-of-service condition against the container/pod, matching the Kubernetes bounty "resource exhaustion / DoS" impact class. Because git-sync's own health/liveness signaling is based on completing a sync within `--sync-timeout`, the tool reports the operation as failed/timed-out while the underlying work silently continues, violating the LIVENESS_AND_HONESTY invariant (the reported timeout state no longer reflects actual system state).

### Likelihood Explanation
This requires an attacker to control repository content that references submodules with slow-responding or intentionally stalling remotes (well within the stated attacker capability of controlling "repo content and refs that git-sync fetches"). It further requires git-sync to be configured to sync submodules (a supported, documented feature, e.g. `--submodules=recursive`, which is on by default in this codebase unless explicitly disabled) and a finite `--sync-timeout` (also a normal, documented, commonly-used flag). No non-default or unsupported flags beyond ordinary submodule syncing are needed. The behavior is reliably reproducible: `exec.CommandContext`'s children-are-not-killed limitation is a well-known, deterministic property of Go's `os/exec` package, not a probabilistic race.

### Recommendation
Configure the spawned `git` command to run in its own process group (`cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}` on Unix), and on context cancellation explicitly kill the entire process group (e.g., `syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)`) instead of relying solely on `exec.CommandContext`'s default single-process kill. Alternatively/additionally, use `cmd.Cancel` (Go 1.20+) to install a custom cancel function that kills the process group, and verify via `context.Err()` combined with process-tree reaping that no descendant git processes remain after a timeout.

### Proof of Concept
Integration test outline:
1. Set up a local git repository with a `.gitmodules` entry pointing to a submodule remote served by a test HTTP/git server that intentionally stalls (e.g., slow-loris style response) after the child git fetch process starts.
2. Run git-sync (or directly call `pkg/cmd.Runner.Run`) with `--submodules=recursive` and a short `--sync-timeout` (e.g., 2s) against this repo.
3. After `Run` returns with a `context.DeadlineExceeded` error, inspect the process tree (`pgrep -P <git-sync-pid>` or reading `/proc/<pid>/task/*/children` recursively) for lingering `git-remote-*`/`git fetch` processes tied to the submodule fetch.
4. Assert that no such git-related child processes remain running; the test should currently fail (demonstrating the orphaned child process persisting past the reported timeout) prior to the fix, and pass after implementing process-group kill on cancellation.

### Citations

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
