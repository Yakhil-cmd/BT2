### Title
Unbounded in-memory buffering of git command output enables attacker-controlled memory exhaustion / DoS - (File: `pkg/cmd/cmd.go`)

### Summary
The Sherlock report describes a malicious PoolTogether prize winner returning a huge blob of `returndata` from an external call inside `claimPrizes`, which forces the caller's transaction to burn gas copying that data, exhausting the available gas and reverting the whole batch (leaving only 1/64 gas for the remainder). The reachable analog in `git-sync` is the command runner in `pkg/cmd/cmd.go`, which captures the entire stdout/stderr of every `git` invocation into unbounded `bytes.Buffer`s, with no cap on output size. Because `git-sync` runs many git subcommands (log, show, fetch --verbose, etc.) against content that ultimately originates from a remote/attacker-controlled repository, a malicious remote can craft refs/commits whose git output (e.g., large commit messages, verbose fetch/clone progress, or diff/log content) is enormous, forcing `git-sync` to allocate that data fully in memory before it can even inspect it.

### Finding Description
`runWithStdin` in [1](#0-0)  creates `outbuf := bytes.NewBuffer(nil)` and `errbuf := bytes.NewBuffer(nil)` and attaches them directly as `cmd.Stdout`/`cmd.Stderr` with no maximum size, no streaming/truncation, and no discard-after-threshold logic [2](#0-1) . Every call site that shells out to `git` in `main.go` goes through this `Runner.Run`/`RunWithStdin` API, so any git subcommand whose output size is influenced by remote repository content (commit messages, tags, verbose transfer statistics, etc., pulled from an attacker-controlled `--repo` remote) is buffered in full into process memory before `cmd.Run()` returns.

This is the closest unprivileged analog to the Sherlock "gas bomb" pattern: in the original bug, an external contract's return value size directly drives the caller's resource consumption (gas) with no cap, letting the callee weaponize the caller's own resource-accounting logic. Here, the analogous resource is process memory (not gas), and the "external call" is `exec.CommandContext` invoking `git` against attacker-influenced repository state; there is no upper bound on `outbuf`/`errbuf` growth analogous to a gas-limit check.

The mitigating factor is that `exec.CommandContext` is wrapped with a `context.Context` deadline (e.g. `--exechook-timeout`, `--sync-timeout`-style contexts used elsewhere in `main.go`), so the subprocess is eventually killed on timeout [3](#0-2) . However, the timeout bounds wall-clock time, not memory: a git command can generate gigabytes of output on stdout within a short window (e.g., a crafted object with pathological content, or `-v`/`--stat`-heavy output across many refs) before the deadline fires, so the buffer can still grow very large during that window, and repeated sync attempts (`--period`) let an attacker retrigger the allocation indefinitely.

### Impact Explanation
If a remote repository crafted by an attacker (one `git-sync` is configured to sync from, or one reachable via an unauthenticated/less-trusted mirror/proxy) produces outsized git command output, the `git-sync` process can be driven to allocate large amounts of memory repeatedly on every sync cycle. In a Kubernetes sidecar deployment (`git-sync`'s primary use case) this can lead to the pod being OOM-killed, causing persistent sync denial for the legitimate workload sharing that pod — analogous to the "loss of gas fees / denial of legitimate claims" impact in the original report. This does not achieve code execution, arbitrary file write, or credential disclosure, so it is bounded to a denial-of-service class impact.

### Likelihood Explanation
Exploitability requires the attacker to control (or compromise) the content of the git remote that `git-sync` is configured to sync — i.e., an "attacker-pushed commit/ref" scenario as scoped. This is a realistic unprivileged threat model for `git-sync`, since its entire purpose is to sync from a remote repository that may not be fully trusted (e.g., GitOps flows pulling from a shared or less-tightly-controlled repo). No credentials, misconfiguration, or malicious-operator assumptions are needed beyond normal push access to the tracked repository/ref.

### Recommendation
Bound the size of captured command output in `runWithStdin` (`pkg/cmd/cmd.go`), e.g. by wrapping `outbuf`/`errbuf` with an `io.LimitedWriter`-style guard or streaming output while enforcing a maximum byte cap, and treat truncation as a recoverable error rather than allowing unbounded buffer growth. Consider also using flags that reduce verbosity for internal git invocations (avoiding `-v`/full log bodies where not needed) and re-validate that `context.Context` timeouts are tight enough to limit worst-case memory growth per invocation.

### Proof of Concept
Not independently verified against a live binary/runtime in this review (no sandbox/filesystem access available in this mode); conceptually: configure `git-sync --repo=<attacker-controlled-remote>`; have the attacker commit an object with an extremely large embedded message/content (e.g., multi-hundred-MB commit message or file causing verbose `git` command output when `git-sync` runs internal commands such as log/show/fetch with verbose flags); observe the `git-sync` process's resident memory grow unbounded during `runWithStdin`'s buffering in [4](#0-3)  on each periodic sync, potentially triggering an OOM kill of the sidecar container.

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
