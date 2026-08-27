### Title
Malicious repo content with many/nested submodules or refs causes unbounded resource consumption and persistent sync denial in `configureWorktree` - (File: main.go)

### Summary
The Lighthouse report describes a DoS where an unprivileged network peer, by creating a large number of discv5 sessions, exhausted resources and crashed the discovery service. The closest reachable analog in `git-sync` is an unprivileged actor who can push content to the synced repository (an "attacker-pushed commit/ref", explicitly in scope per the rules) crafting a `.gitmodules` file with a large number of submodules (or deeply nested/recursive submodule chains) to force `git-sync`'s per-cycle `git submodule update --init --recursive` invocation to consume unbounded time/resources, causing the sync loop to stall or exceed `--sync-timeout` repeatedly, which is treated as a sync failure and can lead to persistent sync denial (`--max-failures` exhaustion → `os.Exit(1)`).

### Finding Description
`configureWorktree` runs `git submodule update --init [--recursive]` on every sync cycle whenever `--submodules` is not `off` [1](#0-0) . Because the submodule graph (`.gitmodules`) is fully controlled by whoever can push to the tracked repo, an unprivileged content contributor can add an arbitrarily large number of submodules or deeply nested recursive submodule references. This git operation is wrapped in a `context.WithTimeout(context.Background(), *flSyncTimeout)` for the whole `SyncRepo` call [2](#0-1) , and the underlying command execution uses `exec.CommandContext(ctx, ...)` [3](#0-2) , so an oversized submodule tree will simply cause repeated timeout failures rather than an immediate crash. Each failure increments `failCount`, and once `failCount` reaches `--max-failures` (or `--init-max-failures` during the initial phase), `git-sync` calls `os.Exit(1)` [4](#0-3) , terminating the sidecar entirely. Since `--max-failures` defaults to `0` (meaning "any failure aborts") [5](#0-4) , a default-configured deployment would abort on the very first timed-out sync of a maliciously bloated submodule tree.

This mirrors the report's bug class — an unprivileged, remote actor whose crafted input (many discv5 sessions / many submodules) causes the target service (discovery service / git-sync sync loop) to become unavailable.

### Impact Explanation
If `git-sync` aborts due to exhausted `--max-failures`, the Kubernetes sidecar dies and the shared volume is never refreshed, causing "persistent sync denial" for the consuming application container — matching one of the explicitly accepted impacts in this analog assessment. Even with `--max-failures=-1` (retry forever), the sync loop would be perpetually consumed retrying the same oversized submodule checkout, starving CPU/network/disk and never publishing a fresh symlink, which is functionally the same denial-of-service outcome.

### Likelihood Explanation
This requires only push/merge access to content that ends up in the tracked ref (a `.gitmodules` file and enough submodule remotes), which is the same "attacker-pushed commit/ref" threat model explicitly permitted by the validation rules. No special git-sync privilege, credentials, or flags beyond the (recursive-by-default) `--submodules=recursive` setting are needed — recursive submodules is the *default* behavior [6](#0-5) . The main uncertainty is the magnitude of resource exhaustion achievable purely through submodule count/nesting versus a hard crash — this is a resource-exhaustion/service-denial analog, not a memory-safety crash, so likelihood of "denial" is high but likelihood of "the process itself crashing" (as opposed to graceful timeout+`os.Exit(1)`) is lower and I could not verify an actual unbounded-memory or panic condition in the available code.

### Recommendation
- Add a submodule-specific timeout/limit (e.g., cap on submodule count or recursion depth) independent of the overall `--sync-timeout`, so a single oversized `.gitmodules` cannot force full deployment failure.
- Consider making repeated timeout-classified failures not count toward `--max-failures` abort by default, or expose a flag to keep the last-known-good publish alive while retrying, avoiding total service denial.
- Document guidance for operators to set `--submodules=off` or `--depth`/`--filter` restrictions when syncing repos with less-trusted contributors.

### Proof of Concept
1. Configure `git-sync` with default flags against a repository where an unprivileged contributor can push commits (default `--submodules=recursive`, default `--max-failures=0`).
2. Attacker pushes a commit adding a `.gitmodules` file referencing a very large number of submodules (or a submodule chain that recursively references itself/many nested submodules), all resolvable but expensive to clone/update.
3. On the next sync cycle, `configureWorktree`'s `git submodule update --init --recursive` call [7](#0-6)  exceeds `--sync-timeout`, `SyncRepo` returns an error, `failCount` reaches the default `max-failures` of `0`, and `git-sync` calls `os.Exit(1)` [4](#0-3) , terminating the sidecar and halting all further publishing to `--link`.

*Note: I was unable to fully verify whether this produces an actual process crash/OOM versus only a controlled timeout+exit, since I do not have execution access to reproduce resource consumption at scale; the analysis above is based on static code review of the sync loop, timeout wiring, and submodule handling.*

### Citations

**File:** main.go (L182-184)
```go
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
```

**File:** main.go (L1052-1063)
```go
	for {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)

		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
```

**File:** main.go (L1733-1747)
```go
	// Update submodules
	// NOTE: this works for repo with or without submodules.
	if git.submodules != submodulesOff {
		git.log.V(1).Info("updating submodules")
		submodulesArgs := []string{"submodule", "update", "--init"}
		if git.submodules == submodulesRecursive {
			submodulesArgs = append(submodulesArgs, "--recursive")
		}
		if git.depth != 0 {
			submodulesArgs = append(submodulesArgs, "--depth", strconv.Itoa(git.depth))
		}
		if _, _, err := git.Run(ctx, worktree.Path(), submodulesArgs...); err != nil {
			return err
		}
	}
```

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

**File:** README.md (L442-446)
```markdown
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```
