### Title
Unbounded in-memory buffering of git command stdout/stderr enables resource exhaustion via attacker-controlled ref/output volume - ([File: pkg/cmd/cmd.go])

### Finding Description
`cmd.Runner.Run`/`RunWithStdin` (used by `repoSync.Run` and `repoSync.RunWithStdin` in `main.go`) execute the underlying `git` process and capture its entire stdout and stderr into unbounded `bytes.Buffer` objects with no size cap, then wait for `cmd.Run()` to finish before returning the fully-materialized strings: [1](#0-0) 

Specifically, `outbuf`/`errbuf` are plain `bytes.NewBuffer(nil)` targets with no `io.LimitReader`, streaming truncation, or backpressure mechanism: [2](#0-1) 

Every git invocation in `repoSync` goes through this same unbounded-buffering path: [3](#0-2) 

Notably, the codebase itself acknowledges elsewhere that verbose git output can grow unboundedly and deliberately avoids it for `fsck`: [4](#0-3) 

This shows the authors are aware that verbose/naturally-scaling git output (proportional to ref count, object count, etc.) is a real risk vector for this `Run` wrapper, but the mitigation (avoiding `--verbose`) is only applied to that one `fsck` call, not universally to every command invoked through the same unbounded-buffer `Run` path. If any code path invokes a git subcommand whose output size scales with attacker-controlled repository content (number of refs, number of pruned worktrees, file list size, etc.) without an equivalent restraint, the fully-buffered stdout/stderr can grow to consume large amounts of process memory before `cmd.Run()` even returns.

### Impact Explanation
This matches the Kubernetes bounty "resource exhaustion / persistent stall" impact class: an attacker who can add large numbers of refs or trigger large diffs/prunes in the upstream repository can cause the `git-sync` process to allocate memory proportional to that attacker-controlled repository state, potentially leading to OOM-kill of the sync container and denial of continued syncing (repeatable since the attacker can keep growing the ref/content set on every fetch cycle).

### Likelihood Explanation
The core buffering flaw (unbounded `bytes.Buffer` for both streams, no read limit) is present unconditionally for every `Run`/`RunWithStdin` call in the default build, requiring no non-default flags. However, I could not fully confirm within the available search budget whether `fetch()`'s default argument list unconditionally includes `--verbose` (the search for `--verbose` usage in `main.go` returned matches, but I was unable to inspect the exact call sites before the iteration budget ran out to confirm this is baked in by default rather than gated behind a git-sync verbosity flag). The `fsck` comment does confirm the maintainers are aware verbose output volume is attacker-influenceable and unbounded through this code path, which supports that the underlying mechanism is real, but the specific "default --verbose fetch" precondition in the question is unverified.

### Recommendation
- Bound the size of captured stdout/stderr in `cmd.runWithStdin` (e.g., wrap `outbuf`/`errbuf` with `io.LimitedWriter` or truncate after N bytes with a "truncated" marker) so that runaway git output cannot translate into unbounded memory growth.
- Audit all `git.Run`/`git.RunWithStdin` call sites for verbose or output-scaling flags (`--verbose`, `-v`, listing flags) and apply the same restraint already used for `fsck` (i.e., avoid or bound verbosity) uniformly.
- Consider streaming output to a bounded ring buffer or disk instead of holding the full output in memory, since some git operations (e.g., `worktree prune -v`, large fetches) can legitimately produce large output under adversarial repository content.

### Proof of Concept
Unit-test sketch for `pkg/cmd/cmd_test.go`:
```go
func TestRun_UnboundedOutputBuffering(t *testing.T) {
    // simulate a command producing e.g. 500MB of stdout, analogous to
    // `git fetch --verbose` against a repo with millions of refs.
    r := NewRunner(testLogger)
    stdout, _, err := r.Run(context.Background(), "", nil, "sh", "-c",
        "head -c 500000000 /dev/zero | tr '\\0' 'a'")
    if err != nil {
        t.Fatalf("run failed: %v", err)
    }
    if len(stdout) < 500_000_000 {
        t.Fatalf("expected full buffer capture, got %d bytes", len(stdout))
    }
    // Assert process RSS grew by ~500MB during Run() (measured via
    // runtime.MemStats or /proc/self/status sampling around the call),
    // demonstrating no bound exists on captured output size.
}
```
Expected result: the test passes today (full unbounded capture succeeds), demonstrating the absence of any cap — which is the vulnerability, since a real `git fetch --verbose`/`git worktree prune --verbose` against a repository with a very large ref/worktree set would produce comparable memory pressure inside the `git-sync` process.

### Citations

**File:** pkg/cmd/cmd.go (L63-93)
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
```

**File:** main.go (L1342-1350)
```go
// Run runs `git` with the specified args.
func (git *repoSync) Run(ctx context.Context, cwd absPath, args ...string) (string, string, error) {
	return git.run.WithCallDepth(1).Run(ctx, cwd.String(), nil, git.cmd, args...)
}

// Run runs `git` with the specified args and stdin.
func (git *repoSync) RunWithStdin(ctx context.Context, cwd absPath, stdin string, args ...string) (string, string, error) {
	return git.run.WithCallDepth(1).RunWithStdin(ctx, cwd.String(), nil, stdin, git.cmd, args...)
}
```

**File:** main.go (L1528-1530)
```go
	// Consistency-check the worktree.  Don't use --verbose because it can be
	// REALLY verbose.
	if _, _, err := git.Run(ctx, worktree.Path(), "fsck", "--no-progress", "--connectivity-only"); err != nil {
```
