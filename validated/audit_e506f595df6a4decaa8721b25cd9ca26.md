### Title
Unbounded in-memory buffering of git stdout/stderr enables memory-exhaustion DoS from attacker-controlled repo content - ([File: pkg/cmd/cmd.go])

### Summary
`runWithStdin` in `pkg/cmd/cmd.go` captures the entirety of a git subprocess's stdout and stderr into unbounded `bytes.Buffer` objects before ever inspecting the exit code or error. Because every git invocation in `main.go` (fetch, checkout, submodule update, etc.) goes through this helper, an attacker who controls the synced repository's content (e.g. a crafted `.gitattributes` or submodule configuration that causes git to emit a very large amount of warning/diagnostic output on every operation) can force git-sync to buffer arbitrarily large output into memory on each sync cycle.

### Finding Description
`runWithStdin` wires `cmd.Stdout` and `cmd.Stderr` directly to two `bytes.NewBuffer(nil)` instances with no size cap or streaming: [1](#0-0) . The function only inspects `err`/`ctx.Err()` after `cmd.Run()` returns, meaning all output must be fully read into memory (and the buffers fully grown) before any success/failure determination happens: [2](#0-1) . This helper (`Runner.Run` / `Runner.RunWithStdin`) is the single code path `main.go` uses to invoke `git fetch`, `git checkout`, `git submodule update`, etc., so any git subcommand that can be coaxed into producing massive output (large numbers of `.gitattributes`-driven per-file warnings, deeply nested or numerous submodules with warnings, etc.) will have that output fully buffered by git-sync before the exit code is checked. There is no cap on buffer size and no streaming/discarding of output, so output volume is bounded only by available process memory and repo content the attacker controls (a repro precondition explicitly allowed by the threat model — attacker controls repo content/refs).

### Impact Explanation
This matches a resource-exhaustion / liveness impact class: a sync cycle can consume unbounded memory while processing attacker-crafted content, potentially causing the process to be OOM-killed mid-cycle. If the OOM occurs after a previous successful publish, the last-known-good "ready" state/symlink is not updated to reflect failure, so the readiness signal remains stale rather than reflecting the current sync problem, and the container may crash-loop repeatedly on the same poisoned commit/ref.

### Likelihood Explanation
No non-default flags are required; the vulnerable code path is used unconditionally for all git invocations in `pkg/cmd/cmd.go`. Feasibility depends on how much stderr output can practically be generated per git operation from repo content alone (e.g., via `.gitattributes` warnings or submodule warnings) — achieving true OOM likely requires a git version/configuration that emits large per-file diagnostics, which is plausible but requires a specific crafted repo and is not guaranteed on all git versions. Repeatability is high once such a repo is fetched, since git-sync will re-run the same problematic command on every poll/sync cycle.

### Recommendation
Bound the amount of stdout/stderr captured (e.g., cap buffer size with `io.LimitReader`/`io.CopyN`-style wrapping, or use `bytes.Buffer` with a max-size guard that truncates and marks output as truncated), and/or stream output while checking for size limits, so a misbehaving or malicious git invocation cannot cause unbounded memory growth. Surface a clear "output truncated" failure rather than allowing indefinite buffering.

### Proof of Concept
Integration test: create a local bare git repo containing a `.gitattributes` (or submodule config) engineered to make `git checkout`/`git submodule update` emit an extremely large volume of warnings (e.g., thousands of lines per file across many files). Point `git-sync` at this repo with a constrained memory limit (e.g., run the test binary under a cgroup/`ulimit -v`), call the sync path that invokes `pkg/cmd.Runner.Run` for the checkout, and assert that: (1) memory usage during the call stays bounded (e.g., via `runtime.MemStats` or external memory limit not exceeded), and (2) on exceeding the bound, `Run` returns a bounded/truncated-output error rather than causing the test process to be OOM-killed.

### Citations

**File:** pkg/cmd/cmd.go (L74-81)
```go
	outbuf := bytes.NewBuffer(nil)
	errbuf := bytes.NewBuffer(nil)
	cmd.Stdout = outbuf
	cmd.Stderr = errbuf
	cmd.Stdin = bytes.NewBufferString(stdin)

	start := time.Now()
	err := cmd.Run()
```

**File:** pkg/cmd/cmd.go (L85-93)
```go
	if ctx.Err() == context.DeadlineExceeded {
		return stdout, stderr, fmt.Errorf("Run(%s): %w: { stdout: %q, stderr: %q }", cmdStr, ctx.Err(), stdout, stderr)
	}
	if err != nil {
		return stdout, stderr, fmt.Errorf("Run(%s): %w: { stdout: %q, stderr: %q }", cmdStr, err, stdout, stderr)
	}
	log.V(6).Info("command result", "stdout", stdout, "stderr", stderr, "time", wallTime)

	return stdout, stderr, nil
```
