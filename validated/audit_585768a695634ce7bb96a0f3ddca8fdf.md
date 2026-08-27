### Title
Unbounded in-memory buffering of git command stdout/stderr enables memory-exhaustion DoS - ([File: pkg/cmd/cmd.go])

### Summary
`runWithStdin` in `pkg/cmd/cmd.go`, which backs every git invocation made by `repoSync` in `main.go` (fetch, checkout, submodule update, etc.), captures the child process's stdout and stderr into unbounded `bytes.Buffer` objects and only inspects the exit code after `cmd.Run()` returns. A malicious repo that causes git to emit an extremely large volume of stdout/stderr (e.g., via crafted `.gitattributes` filters/warnings or submodule configuration) can force git-sync to buffer arbitrarily large output in memory during a single sync cycle before any error or exit-code check occurs.

### Finding Description
`Runner.Run`/`Runner.RunWithStdin` call `runWithStdin`, which sets: [1](#0-0) 
`cmd.Stdout` and `cmd.Stderr` to plain `bytes.NewBuffer(nil)` instances with no size cap, and `cmd.Run()` blocks until the process exits — there is no streaming read, no `io.LimitReader`, and no incremental inspection of output size. Only after `cmd.Run()` returns does the code trim and check the buffered strings and the error: [2](#0-1) 

This helper is the sole mechanism `repoSync` uses to invoke git subcommands (fetch, checkout, submodule update, ls-remote, rev-parse, etc.) throughout `main.go`. An attacker who controls the repo content that git-sync fetches (fully within the described threat model — they control refs/content, not flags or the pod) can commit a `.gitattributes` file or submodule configuration engineered to make git print an extremely large amount of warning/diagnostic text per file on every `fetch`/`checkout`/`submodule update` (e.g., via filter/clean-warnings, huge numbers of tracked paths triggering per-path lines, or crafted attributes that produce repeated stderr noise). Because output is buffered fully in memory rather than streamed or bounded, each sync cycle re-triggers unbounded memory growth proportional to attacker-chosen output size, independent of the actual git exit code.

There is no size limit enforced by `absPath` handling, `safe.directory`, or `protocol.allow`-type protections here — those guard path/URL/protocol issues, not command output volume. A context deadline (`--sync-timeout`) can eventually cancel a long-running command, but that only bounds wall-clock time, not the amount of data buffered before cancellation — a sufficiently fast/large output stream (e.g., millions of short warning lines) can exhaust memory well within a permitted timeout window, and the buffering itself is what causes memory pressure regardless of the eventual outcome.

### Impact Explanation
This matches the "permanent sync wedging or resource exhaustion" impact class: an attacker-controlled repo can cause git-sync's underlying process to consume excessive memory on every sync attempt, potentially causing the container to be OOM-killed or to stall due to memory pressure, mid-cycle, before the exit code is ever evaluated and before `repoSync` can mark the sync as failed. Since the last successful publish's readiness state is untouched until a new sync completes, repeated OOM/stalls on this path could leave the readiness/liveness signal reflecting stale success while the process is actually failing to make progress — a liveness/honesty violation for consumers relying on git-sync's `--root`/readiness output.

### Likelihood Explanation
No non-default flags are required — this is the code path used for every git command git-sync issues, using default full-buffer capture. It only requires the attacker to control the repository content/refs that are fetched (explicitly in-scope per the threat model). The attack is fully repeatable on every sync cycle as long as the malicious ref/content remains reachable, since the vulnerable buffering behavior is unconditional and not something an operator can disable via existing flags.

### Recommendation
Replace unbounded `bytes.Buffer` capture in `runWithStdin` (`pkg/cmd/cmd.go`) with a bounded capture mechanism, e.g., wrap the buffers with a size-limiting writer that stops accumulating (or truncates with a marker) after a fixed cap (e.g., a few MB), and/or stream stdout/stderr line-by-line with a maximum retained size, ensuring the command's exit code and error are still surfaced correctly and a truncation warning is logged/returned instead of buffering indefinitely.

### Proof of Concept
Add an integration test that runs `pkg/cmd.Runner.Run` (or the whole `SyncRepo` flow) against a local git server whose checkout hook/`.gitattributes` triggers a script that writes several hundred MB to stdout/stderr before exiting non-zero. Run the test under a `ulimit`/cgroup memory limit (or `GOMEMLIMIT`) and assert that the process is killed/OOMs rather than the runner returning a bounded error, demonstrating the missing cap. A fix should make the same test pass by returning a truncated-output error without exceeding the memory bound.

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

**File:** pkg/cmd/cmd.go (L82-93)
```go
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
