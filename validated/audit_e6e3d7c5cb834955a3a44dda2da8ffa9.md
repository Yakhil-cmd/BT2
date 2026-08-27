### Title
`exec.CommandContext` in `runWithStdin` only kills the direct `git` process on `--sync-timeout`, letting git-spawned transport helpers (e.g. submodule fetch children) survive and continue consuming resources - ([File: pkg/cmd/cmd.go])

### Summary
`runWithStdin` builds every git invocation with `exec.CommandContext(ctx, ...)` and never sets a `SysProcAttr`/process-group, a custom `cmd.Cancel`, or `cmd.WaitDelay`. When the sync-timeout context is canceled, Go's stdlib only sends `SIGKILL` to the immediate `git` child; it does not touch any grandchildren git itself forked (transport helpers such as `git-remote-https`/`ssh`, or per-submodule fetch subprocesses started by `git submodule update --init [--recursive]`). An attacker who controls repo content (e.g. a submodule URL pointing at attacker-controlled infrastructure) can make that inner transfer hang forever, so after `--sync-timeout` fires the orphaned helper keeps running and consuming CPU/memory/sockets, and this repeats every sync cycle.

### Finding Description
`runWithStdin` (`pkg/cmd/cmd.go:63-93`) is the single execution primitive used by all `repoSync.Run`/`RunWithStdin` calls (`main.go:1343-1350`), including `fetch` (`main.go:2002-2029`) and `configureWorktree`'s submodule update (`main.go:1733-1747`, invoking `git submodule update --init [--recursive]`). It constructs the command as: [1](#0-0) 

No `cmd.SysProcAttr{Setpgid: true}`, no `cmd.Cancel` override, and no `cmd.WaitDelay` are set. With Go's default `exec.CommandContext` semantics, when `ctx` becomes `Done()` the runtime calls `cmd.Process.Kill()`, which sends `SIGKILL` only to the PID of the `git` process itself — not to a process group and not recursively to any processes `git` has forked.

Git routinely forks child processes to perform network I/O: remote helpers (`git-remote-https`, `git-remote-http`), `ssh` for SSH transports, and for `git submodule update --init --recursive` a separate `git fetch`/`git clone` child per submodule. If the attacker (who controls the repo content, including `.gitmodules` submodule URLs, per the threat model) points a submodule at an endpoint that accepts the connection but never completes the transfer (e.g., sends partial pack data and stalls), the outer `git submodule update` process blocks in `cmd.Wait()` while its already-spawned transport child keeps the socket open and buffers data. When `--sync-timeout` elapses, `ctx.Err() == context.DeadlineExceeded` is detected at `pkg/cmd/cmd.go:85`, but by then only the parent `git` process has been (or will be) `SIGKILL`ed — the still-running transport subprocess is reparented (to PID 1 of the container, or to git-sync's own `pkg/pid1.ReRun` init loop if `--use-pid1` style re-exec is active) and continues running independent of git-sync's belief that the operation "timed out."

Because `main.go`'s sync loop re-derives a fresh timeout context on every cycle (via `*flSyncTimeout`), each stalled submodule fetch can leave behind another orphaned helper process, so the leak compounds across cycles rather than being bounded to one occurrence.

None of the existing protections stop this: `absPath` validation, `fsck`, and `safe.directory` only guard against path/config integrity issues, not process lifecycle; the only two related knobs (`ctx.Err()` check and `wallTime` logging) merely report the timeout after the fact and do not attempt to kill or reap descendants.

### Impact Explanation
Scoped impact: orphaned, resource-consuming subprocesses (open sockets, allocated memory, CPU spent on a partial/slow transfer) survive the perceived `--sync-timeout` expiry and accumulate across sync cycles, since a new stalled child can be produced on every retry while old ones may still be alive. This is a resource-exhaustion / denial-of-service class issue (CPU, memory, file-descriptor, and socket exhaustion within the container over time), driven purely by attacker-controlled repo/submodule content and reachable without any non-default flags — `--sync-timeout` is the normal, documented timeout flag.

### Likelihood Explanation
Preconditions are minimal and all within the stated attacker capability: control of repo content (a `.gitmodules` entry or arbitrary ref that git-sync fetches) and the ability to run a server that accepts a connection but stalls the transfer. No special flags beyond the default `--sync-timeout` are required, `--submodules` defaults to recursive syncing already, and the behavior is fully repeatable each sync cycle. The only variable is git version/transport specifics (SSH vs HTTPS helper process behavior differs slightly), but the core defect — `exec.CommandContext` not killing descendants — is a well-documented Go/os-exec limitation, not something git or safe.directory mitigates.

### Recommendation
Run every git invocation in its own process group (`cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}`) and replace reliance on the default kill behavior with a `cmd.Cancel` function that sends `SIGKILL` to the negated PGID (`syscall.Kill(-pgid, syscall.SIGKILL)`), plus set `cmd.WaitDelay` to bound how long `Wait` blocks for I/O draining after cancellation. This ensures that when `--sync-timeout` fires, git and all of its transport-helper descendants are terminated together.

### Proof of Concept
Integration test sketch for `pkg/cmd/cmd_test.go`:
```go
func TestTimeoutKillsGrandchildren(t *testing.T) {
    // Script that forks a background sleep and then hangs itself,
    // simulating git spawning a transport helper.
    script := `#!/bin/sh
    sleep 30 &
    echo $! > /tmp/grandchild.pid
    sleep 30`
    // write script to tmp, chmod +x
    ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
    defer cancel()
    r := NewRunner(testLogger)
    _, _, _ = r.Run(ctx, "", nil, scriptPath)
    time.Sleep(1 * time.Second)
    pidBytes, _ := os.ReadFile("/tmp/grandchild.pid")
    pid, _ := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
    // Expected (failing) assertion: grandchild should be dead.
    if err := syscall.Kill(pid, 0); err == nil {
        t.Fatalf("grandchild process %d is still alive after context timeout", pid)
    }
}
```
Expected result on the current code: the assertion fails — the grandchild `sleep 30` process (standing in for a git transport helper/submodule fetch child) is still running after the parent script was killed on context cancellation, demonstrating the orphaned-process leak.

### Citations

**File:** pkg/cmd/cmd.go (L63-81)
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
```
