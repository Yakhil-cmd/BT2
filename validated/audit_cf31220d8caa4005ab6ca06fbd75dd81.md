### Title
Unbounded stdout/stderr buffering in `runWithStdin` allows attacker-controlled git output to exhaust sidecar memory - ([File: pkg/cmd/cmd.go])

### Finding Description
`runWithStdin` captures the full stdout and stderr of every git subprocess into in-memory `bytes.Buffer` instances with no size cap: [1](#0-0) 
The buffers are filled by `cmd.Run()` and only trimmed/quoted for logging after the process exits [2](#0-1) , so nothing is streamed, truncated, or rate-limited while the command is running. `cmdForLog` only affects how the invoked command line is rendered for logs and does not bound output size [3](#0-2) .

Every git invocation issued through `Runner.Run`/`Runner.RunWithStdin` goes through this same unbounded path [4](#0-3) . An attacker who can push refs/objects to the upstream repository that git-sync fetches controls parts of what git will print — e.g., very large numbers of branches/tags inflating `ls-remote`/`fetch` ref-advertisement output, or verbose fetch/error text — and none of that is capped before being buffered fully in memory.

### Impact Explanation
If an attacker can drive a single git invocation's stdout+stderr to gigabytes (e.g., through an extreme number of refs or degenerate repository structure), the sidecar process's memory usage grows unbounded until the OS OOM-kills it, interrupting git-sync's ability to publish updates. This matches the Kubernetes-style "denial of service via resource exhaustion" impact class (OOM kill / denial of updates), scoped to availability, not to code execution or secret leakage.

### Likelihood Explanation
The precondition is only that the attacker has push/ref-control over the repository git-sync syncs (an explicitly in-scope unprivileged capability), with no non-default flags required — `--error-file` and `--root` do not materially affect this path since the vulnerability is in generic output capture used for every git command. However, actually reaching "gigabytes" of single-command output requires the attacker to construct a repository with an extreme number of refs/objects or otherwise coerce very high-verbosity output, which is resource-intensive for the attacker to produce and may be constrained by upstream git server limits, git-sync's own context timeouts (`--sync-timeout`), and typical repository hosting quotas. I could not fully verify from the available code exploration which specific git subcommands and flags git-sync issues in `main.go` (e.g., whether verbose flags are used, whether `ls-remote`/`fetch` output size scales with attacker-controlled ref count) due to iteration limits, so the precise achievable output volume per attacker-controlled repository is not confirmed.

### Recommendation
Bound the captured output in `runWithStdin`, e.g., wrap `outbuf`/`errbuf` with an `io.LimitedWriter`/truncating writer that stops copying and marks output as truncated once a configurable cap (e.g., a few MB) is reached, and surface truncation in the returned error/log rather than buffering indefinitely.

### Proof of Concept
Not independently reproduced — an integration test would need to: (1) point git-sync at a git remote serving an artificially large number of refs or a script (`_test_tools/git_slow_fetch.sh`-style) that emits many megabytes to stdout/stderr, (2) invoke `Runner.Run` with a corresponding git subcommand, and (3) assert process RSS grows unbounded / exceeds a configured cgroup memory limit, causing an OOM kill, versus the fixed behavior where output is truncated and memory stays bounded.

### Citations

**File:** pkg/cmd/cmd.go (L51-61)
```go
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

**File:** pkg/cmd/cmd.go (L74-78)
```go
	outbuf := bytes.NewBuffer(nil)
	errbuf := bytes.NewBuffer(nil)
	cmd.Stdout = outbuf
	cmd.Stderr = errbuf
	cmd.Stdin = bytes.NewBufferString(stdin)
```

**File:** pkg/cmd/cmd.go (L80-91)
```go
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
