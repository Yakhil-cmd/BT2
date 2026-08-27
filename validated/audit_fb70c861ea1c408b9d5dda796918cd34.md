### Title
Unbounded in-memory buffering of subprocess stdout/stderr in `runWithStdin` enables attacker-driven OOM - (File: pkg/cmd/cmd.go)

### Finding Description
`runWithStdin` captures all stdout and stderr of every git subprocess into two `bytes.Buffer` instances with no size cap: `outbuf := bytes.NewBuffer(nil)` / `errbuf := bytes.NewBuffer(nil)` are wired directly as `cmd.Stdout`/`cmd.Stderr` [1](#0-0) . The buffers are fully materialized in memory (`outbuf.String()`, `errbuf.String()`) before any trimming or truncation occurs [2](#0-1) . There is no `io.LimitReader`, no max-output flag, and no early termination of the subprocess based on output volume.

`Runner.Run`/`Runner.RunWithStdin` are the generic execution path used for every git invocation issued by `main.go` (clone, fetch, checkout, worktree, etc.) [3](#0-2) . Because the attacker fully controls the remote repository content and refs that git-sync fetches (per the threat model), they can create an arbitrarily large number of refs, tags, or objects, or trigger verbose/failure output paths in git that are proportional to repository size (e.g., ref advertisement during fetch, error messages listing conflicting refs). Every byte of that output is buffered in-process before the function returns.

`cmdForLog` only affects how the invoked command line is rendered in logs and is not part of the output-capture path; it does not perform allocation proportional to command output and does not mitigate or worsen this issue [4](#0-3) .

Nothing in the reachable code path bounds buffer growth: `exec.CommandContext` provides a deadline/cancellation for run time, but `ctx` cancellation only stops the process — it does not cap bytes already buffered, and cancellation itself only occurs after a configured sync timeout, by which point gigabytes could already have been written to the buffer.

### Impact Explanation
An attacker with only push/ref-control access to the source repository can force git-sync's git subprocesses (e.g., `fetch`) to emit very large stdout/stderr streams (via huge ref counts, oversized commit messages in `log`-style calls, or verbose error output), which `runWithStdin` accumulates without bound in the sidecar's memory. Sustained or repeated triggering can exhaust the container's memory limit and cause the kubelet to OOM-kill the git-sync sidecar, matching the "OOM kill: denial of updates" impact class — sync stalls until the pod is restarted and the attacker can repeat the pattern to keep it wedged.

### Likelihood Explanation
No non-default flags are required; every git command run through `Runner.Run`/`RunWithStdin` goes through this identical unbounded-buffer path [5](#0-4) . The attacker only needs push access to the synced repository (explicitly listed as an available capability) and can repeat the attack by pushing new refs/branches at will, making this a low-effort, repeatable resource-exhaustion vector against any deployment, not specifically tied to `--webhook-url`.

### Recommendation
Bound subprocess output capture, e.g., wrap `cmd.Stdout`/`cmd.Stderr` with an `io.LimitedReader`/limited writer (or a ring buffer capturing only the last N KB), and treat exceeding the limit as a command failure that kills the subprocess (`cmd.Process.Kill()`) rather than allowing unbounded growth. Apply the same cap uniformly across all git invocations that go through `runWithStdin`.

### Proof of Concept
Integration test sketch:
1. Stand up a local git remote with a script/hook that, on `git-upload-pack`/fetch negotiation, streams several GB of ref advertisement data (e.g., generate 5,000,000 lightweight tags, or use a fake `git` shim invoked via `PATH` override that just writes `dd if=/dev/zero bs=1M count=4096` to stdout to simulate the "huge fetch verbosity" scenario).
2. Call `cmd.NewRunner(...).Run(ctx, cwd, env, "git", "fetch", ...)` against that remote.
3. Monitor process RSS during the call; assert that memory grows proportionally to attacker-controlled output size with no cap, and that for a sufficiently large output the process either OOMs or the test times out due to unbounded buffering, demonstrating the missing bound in `runWithStdin`.

### Citations

**File:** pkg/cmd/cmd.go (L50-61)
```go
// Run runs the given command, returning the stdout, stderr, and any error.
func (r Runner) Run(ctx context.Context, cwd string, env []string, command string, args ...string) (string, string, error) {
	// call depth = 2 to erase the runWithStdin frame and this one
	return runWithStdin(ctx, r.log.WithCallDepth(2), cwd, env, "", command, args...)
}

// RunWithStdin runs the given command with standard input, returning the stdout,
// stderr, and any error.
func (r Runner) RunWithStdin(ctx context.Context, cwd string, env []string, stdin, command string, args ...string) (string, string, error) {
	// call depth = 2 to erase the runWithStdin frame and this one
	return runWithStdin(ctx, r.log.WithCallDepth(2), cwd, env, stdin, command, args...)
}
```

**File:** pkg/cmd/cmd.go (L63-78)
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
```

**File:** pkg/cmd/cmd.go (L83-84)
```go
	stdout := strings.TrimSpace(outbuf.String())
	stderr := strings.TrimSpace(errbuf.String())
```

**File:** pkg/cmd/cmd.go (L96-108)
```go
func cmdForLog(command string, args ...string) string {
	if strings.ContainsAny(command, " \t\n") {
		command = fmt.Sprintf("%q", command)
	}
	argsCopy := make([]string, len(args))
	copy(argsCopy, args)
	for i := range args {
		if strings.ContainsAny(args[i], " \t\n") {
			argsCopy[i] = fmt.Sprintf("%q", args[i])
		}
	}
	return command + " " + strings.Join(argsCopy, " ")
}
```
