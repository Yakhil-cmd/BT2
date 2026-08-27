### Title
`runWithStdin` only kills the direct git child on timeout, leaving grandchild processes (e.g. `ext::` submodule helpers) running and able to hold git locks - ([File: pkg/cmd/cmd.go])

### Summary
`runWithStdin` builds the git command with `exec.CommandContext(ctx, ...)` and never sets `cmd.SysProcAttr` (no `Setpgid`), a custom `cmd.Cancel`, or `cmd.WaitDelay`. When the context deadline is exceeded, Go's default `CommandContext` behavior sends `SIGKILL` only to the direct child process (the `git` binary), not to its process group, so any grandchild processes spawned by git (e.g. a shell/loop launched through an `ext::` submodule URL or a smudge/clean filter) are reparented and continue running after `runWithStdin` returns an error to the caller.

### Finding Description
`pkg/cmd/cmd.go` `runWithStdin` (lines 63-94) does: [1](#0-0) 
`cmd := exec.CommandContext(ctx, command, args...)` followed by `cmd.Run()`, with no `SysProcAttr{Setpgid: true}`, no custom `cmd.Cancel`, and no `cmd.WaitDelay`. Go's stdlib `exec.CommandContext` only calls `Process.Kill()` on the immediate child when the context is canceled/expires; it does not create or kill a process group. If the attacker-controlled repository content causes git to fork a subprocess that itself forks further children (a classic case is a `.gitmodules` entry using the `ext::` transport helper, or a smudge/clean filter defined in a tracked `.gitattributes`/config that git would consult), killing the top-level `git` process does not terminate those descendants. They become orphans owned by init/PID 1 and can keep running indefinitely (e.g., a shell loop), potentially holding a lock such as `index.lock` inside the repository's `.git` directory that git-sync operates on, or simply consuming CPU/memory.

This is a real and repo-scoped code-review finding: there is no `SysProcAttr`, `Cancel`, or `WaitDelay` set anywhere in the file, confirmed by direct inspection.

### Impact Explanation
If a grandchild process retains a hold on the working tree/index lock file under `--root`, subsequent `Run` calls invoked by git-sync's sync loop (which reuses the same repo checkout) will fail with "Unable to create '.../index.lock': File exists" indefinitely, matching the "permanent sync wedging" impact class. Orphaned long-running children also constitute a resource-exhaustion vector (CPU/memory/file descriptors) inside the container, consistent with the described bounty impact category.

### Likelihood Explanation
Exploitability depends on git-sync actually exercising a code path where git spawns subprocess trees that can outlive the parent — e.g., if the deployment enables submodule recursion and an attacker can control `.gitmodules` content (a supported, documented feature referenced throughout `main.go`), or if a repo can define smudge/clean filters that get executed by underlying git invocations. I was not able to fully confirm within available context whether git-sync's default git invocations for the core clone/fetch path (as opposed to submodule-recursion codepaths) actually trigger untrusted filter/helper execution, or whether such helpers are gated by git's own protections (`protocol.ext.allow` defaults to "never" for such transports in modern git, and submodule recursion is typically opt-in). This uncertainty affects whether the attacker-controlled precondition (arbitrary `ext::` helper via `.gitmodules`) is reachable without additional non-default configuration. The underlying code weakness in `runWithStdin` (missing process-group kill on timeout) is verified directly from the source, but reachability from unprivileged repo content alone could not be fully confirmed with the tools available in this session.

### Recommendation
Set `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}` when constructing the command, and kill the entire process group (`syscall.Kill(-pgid, syscall.SIGKILL)`) either via a custom `cmd.Cancel` function or immediately after detecting `ctx.Err() == context.DeadlineExceeded`. Additionally consider setting `cmd.WaitDelay` (Go 1.20+) to bound how long `Wait` will block for I/O after the kill signal is sent.

### Proof of Concept
```go
// pkg/cmd/cmd_test.go
func TestRunWithStdinKillsProcessGroup(t *testing.T) {
    // fake "git" binary: a shell script that forks a child that sleeps forever,
    // then the parent itself sleeps forever too, e.g.:
    //   #!/bin/sh
    //   (sleep 1000 &)   # orphaned grandchild
    //   sleep 1000       # parent, will be SIGKILLed by CommandContext
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()
    _, _, err := runWithStdin(ctx, logger, "", nil, "", fakeGitPath)
    if !errors.Is(err, context.DeadlineExceeded) {
        t.Fatalf("expected DeadlineExceeded, got %v", err)
    }
    time.Sleep(200 * time.Millisecond)
    // assert no leftover "sleep 1000" process remains (e.g. via pgrep),
    // and assert no stale .git/index.lock blocks a subsequent Run() call.
}
```
Currently this test would show the grandchild `sleep` process still alive after `runWithStdin` returns, demonstrating the orphaned-process leak.

### Citations

**File:** pkg/cmd/cmd.go (L67-86)
```go
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
```
