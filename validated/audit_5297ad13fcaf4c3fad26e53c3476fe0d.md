### Title
Unbounded, attacker-controlled recursive submodule expansion causes resource-exhaustion DoS on every sync attempt - (File: main.go, pkg/cmd/cmd.go)

### Summary
Similar to the dForce `calcAccountEquity` issue — where the size of an attacker-influenced collection (collateral/borrow positions) is looped over without any cap, letting the attacker push the per-call cost past a hard resource limit — `git-sync`'s `configureWorktree` unconditionally runs `git submodule update --init --recursive` over whatever submodule graph exists in the **attacker-pushed commit**, with no limit on the number or depth of submodules. Combined with the fact that `--sync-timeout` cancellation only kills the direct child process (not any grandchildren `git` processes spawned for nested submodules), a malicious remote repo can force every sync attempt to leak long-running/orphaned subprocesses, producing unbounded resource consumption and persistent sync denial.

### Finding Description
`configureWorktree` runs submodule initialization based purely on the content of the fetched commit, with `--submodules` defaulting to `recursive`: [1](#0-0) 

The number of submodules, the depth of nested submodules, and the remotes they point to are entirely determined by the tree of the commit that was fetched — i.e., by whatever an attacker with push access (or a malicious upstream) puts in the repository. There is no cap on submodule count/recursion depth analogous to the missing cap on collateral/borrow positions in the original report.

Each `git.Run` invocation (including the submodule update call) is executed via `pkg/cmd.Runner`, which relies on `exec.CommandContext`: [2](#0-1) 

`exec.CommandContext` only arranges for the immediate child process to be killed when the context is canceled; it does not set up a process group, so any grandchild `git` (or transport) processes started while recursively cloning nested submodules are not guaranteed to be reaped when the parent `git submodule update --init --recursive` is killed at `--sync-timeout` expiration. The whole `SyncRepo` call runs under a single context created with `flSyncTimeout`: [3](#0-2) 

If the timeout is hit, the outer loop simply records a failure and retries after `waitTime`/`--period`, indefinitely unless `--max-failures` is exceeded: [4](#0-3) 

Because each failed attempt can leave behind orphaned subprocess trees (cloning arbitrarily large/slow/nested submodule graphs the attacker controls), every sync period compounds the number of leaked processes and their network/CPU/disk usage.

### Impact Explanation
An attacker who can push to the synced repository (or control/compromise the upstream remote) can craft a commit with many submodules or deeply nested submodule chains (potentially pointing at large or intentionally slow-to-clone repositories). This:
- Causes each sync attempt to run far longer than expected, hitting `--sync-timeout` repeatedly.
- Leaves orphaned git subprocesses that are not killed by the context cancellation, accumulating CPU, memory, disk, and network usage on the host/pod over time.
- Eventually exhausts node resources or repeatedly exceeds `--max-failures`, causing `git-sync` to `os.Exit(1)` — a persistent denial of synchronization for the sidecar and, in shared-node scenarios, potential resource starvation of co-located workloads.

This matches the "persistent sync denial" impact category, driven by an unbounded, attacker-influenced iteration (submodule graph) with no configurable cap, directly analogous to the unbounded `calcAccountEquity` loop in the original report.

### Likelihood Explanation
`--submodules` defaults to `recursive`, so this is exploitable under the default configuration without any special flags. Any party with write access to the synced repository (or the ability to redirect the `--repo` URL, e.g., via a compromised upstream) can trigger it — no leaked credentials, malicious operator, or malicious node assumption is required. The likelihood is moderate-to-high in any deployment that syncs a repository from a source not fully trusted to never add malicious submodules (e.g., syncing third-party or user-contributed repos).

### Recommendation
- Set a process group (e.g., `Setpgid`/`Pgid` and kill the whole group via `syscall.Kill(-pgid, ...)`) when spawning git commands, so `--sync-timeout` reliably terminates all descendant processes, including those spawned during recursive submodule clones.
- Add explicit, configurable limits on submodule count and recursion depth (or require `--submodules=off`/`shallow` by default) for repositories from untrusted sources.
- Consider applying a stricter, independent timeout to the submodule update step distinct from the overall sync timeout, and track/kill any leftover child processes proactively after cancellation.

### Proof of Concept
1. Deploy `git-sync` with default settings (`--submodules` defaults to `recursive`, some finite `--sync-timeout`, default `--max-failures`).
2. As a user with push access to the synced repo (or as the operator of the upstream remote), add a commit that includes many submodules and/or a chain of deeply nested submodules, at least one of which points to a slow-to-clone or very large repository.
3. Trigger a sync; observe that `configureWorktree`'s `git submodule update --init --recursive` call runs past `--sync-timeout` and is canceled, but nested `git` subprocesses cloning individual submodules continue running (verifiable via `ps`/`pstree` on the container/host) because `exec.CommandContext` only kills the direct child.
4. Repeat over subsequent `--period` sync attempts; observe accumulating orphaned processes and resource usage, and repeated sync failures counted toward `--max-failures`, eventually causing `git-sync` to exit (persistent denial of sync) or the node to become resource-starved.

### Citations

**File:** main.go (L1052-1054)
```go
	for {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)
```

**File:** main.go (L1056-1063)
```go
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
