### Title
Unbounded in-memory buffering of subprocess stdout/stderr in `runWithStdin` enables memory-exhaustion DoS - (File: pkg/cmd/cmd.go)

### Finding Description
`runWithStdin` captures all standard output and standard error of every git subprocess it runs into two `bytes.Buffer` instances with no size limit, timeout-based truncation, or streaming/discard mechanism: [1](#0-0) 

Every git operation issued by git-sync (fetch, ls-remote, log, checkout, etc., via `Runner.Run`/`Runner.RunWithStdin`) funnels through this function, and the full contents of stdout/stderr are read into memory before being trimmed and returned: [2](#0-1) 

An unprivileged attacker who can push refs/commits to the synced repository controls the volume of data that some of these internal git invocations must process and report — e.g., creating a very large number of branches/tags increases the size of ref-listing output, and large trees/history can inflate verbose fetch/log output. Because the buffers have no cap, that attacker-influenced output size directly and proportionally increases sidecar memory consumption for the duration of the command, with no backpressure or bound.

The hook-related pieces cited in the question (`GITSYNC_HASH` validation, exechook backoff) are not part of this path: `Exechook.Do` invokes an operator-configured `h.command`/`h.args`, not attacker-controlled input [3](#0-2) , so the attacker cannot inject arbitrary command output size through the hook mechanism itself — the exploitable surface is git-sync's own internal git subprocess calls that use the same `runWithStdin`, not the hook's exec.

### Impact Explanation
If an attacker-controlled repository state causes a single internal git command (e.g., a ref listing or fetch) to produce gigabytes of stdout/stderr, that entire output is retained in memory as two growing `bytes.Buffer`s until the process exits. Repeated pushes that keep inflating ref/branch/tag counts or history size can push sidecar memory usage high enough to trigger an OOM kill by the container runtime, which matches the Kubernetes bug-bounty "OOM kill: denial of updates" impact class — the sync loop is disrupted and legitimate updates stop being published until the pod restarts and re-syncs.

### Likelihood Explanation
No non-default flags are required; this is a property of every `Runner.Run`/`RunWithStdin` call, all of which go through `runWithStdin`. The attacker only needs the documented, in-scope capability of pushing to the synced repository (creating enough refs, or otherwise large enough git output) to inflate the size of an internal git command's captured output. This is repeatable — each push/sync cycle that grows repo metadata further increases memory pressure — though it is bounded by how much attacker-controlled data actually translates into subprocess output size for the specific git subcommands git-sync invokes, and by container memory limits. The magnitude required for an actual OOM depends on operator-configured pod memory limits, which are outside attacker control.

### Recommendation
Bound the captured output in `runWithStdin`, e.g., wrap `outbuf`/`errbuf` with an `io.LimitedWriter`/custom capped writer that truncates after a fixed size (with an indicator that truncation occurred), or stream large outputs to a temp file with a size cap instead of an in-memory `bytes.Buffer`. Consider also disabling/limiting git verbosity flags used internally and paginating or capping ref-listing style commands.

### Proof of Concept
Unit test sketch for `pkg/cmd/cmd_test.go`:
```go
func TestRunWithStdin_UnboundedOutput(t *testing.T) {
    // Use a helper "producer" command (e.g. `yes` piped through `head -c`)
    // that emits N gigabytes to stdout, run via Runner.Run, and observe
    // process RSS growth is unbounded / proportional to N with no cap,
    // demonstrating absence of any output size limit in runWithStdin.
}
```
Integration repro: point git-sync at a repository with an attacker-pushed large number of refs (e.g., thousands of branches) or a history producing large `git log`/`fetch` verbose output, run git-sync's normal fetch/sync loop, and monitor sidecar RSS to confirm it scales with attacker-controlled ref/output volume with no upper bound enforced by `runWithStdin`.

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

**File:** pkg/cmd/cmd.go (L74-84)
```go
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
```

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
