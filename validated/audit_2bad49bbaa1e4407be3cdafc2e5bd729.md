### Title
Uncontrolled Resource Consumption via Unbounded Submodule Recursion in Synced Repo Content - (File: `main.go`)

### Summary
`git-sync`'s default `--submodules=recursive` behavior runs `git submodule update --init --recursive` on every worktree checkout with no limit on the number or nesting depth of submodules defined by the synced repository's `.gitmodules` content. A repository that git-sync is pointed at (or a submodule dependency reachable from it) can define an arbitrarily large number of submodules or deeply nested submodule chains, forcing the git-sync process to spend excessive CPU, memory, disk, and network resources on every sync cycle, closely analogous to the unbounded resource consumption caused by a crafted GraphQL query in the referenced advisory.

### Finding Description
When a worktree is checked out, `configureWorktree` unconditionally builds and runs a submodule update command whenever `git.submodules != submodulesOff` (the default is `recursive`): [1](#0-0) 

The `--recursive` flag causes git to walk the entire submodule tree with no cap on submodule count or recursion depth; only `--depth` (default `1`) bounds each individual submodule clone's history, not the number of submodules or the fan-out/nesting of the submodule graph. This mirrors the go-ethereum GraphQL issue, where the query language allowed unbounded nesting/complexity with no server-side limits.

Because `--submodules` defaults to `"recursive"`: [2](#0-1) 

any consumer of git-sync who points it at a repository they don't fully control (e.g. syncing a third-party or user-supplied repo/branch, or a repo where an attacker can add a submodule via a merged/forked branch) is exposed by default. Since the sync loop calls `configureWorktree` on every changed sync, this resource-consuming operation is retried each time a new commit/hash is fetched: [3](#0-2) 

While the command is executed under `exec.CommandContext(ctx, ...)` (so it will eventually be killed when `--sync-timeout` elapses): [4](#0-3) 

this only bounds wall-clock time per attempt; it does not bound the number of concurrent/serial `git clone` sub-operations git spawns internally to satisfy a huge or deeply-nested `.gitmodules`, nor the memory/disk consumed before the timeout fires. On failure (or repeated timeout), `main`'s failure-counting logic (`--max-failures`, default `0`) can cause git-sync to `os.Exit(1)` and be restarted by its supervisor (e.g., Kubernetes), producing a persistent sync-denial / crash loop rather than a one-off failure.

### Impact Explanation
An attacker who can influence the content of the synced repository (or any of its submodules, recursively) can force git-sync to spend excessive memory, disk space, and CPU on every sync attempt, and can force repeated sync failures/timeouts. This matches "persistent sync denial" from the validation criteria: legitimate consumers of the `--link` output stop receiving updates because every sync attempt is consumed by unbounded submodule processing, and the container can enter a crash-restart loop.

### Likelihood Explanation
`--submodules=recursive` is the default configuration, so no special flags are required for exposure beyond git-sync being configured to sync a repository that is not fully trusted (a common pattern, e.g., CI/CD pipelines syncing PR branches, GitOps controllers syncing user-managed repos). Constructing a `.gitmodules` file with hundreds/thousands of submodule entries, or a submodule chain that recursively references itself/others many levels deep, is straightforward for anyone with push/PR access to the synced repo or its submodules.

### Recommendation
- Do not default `--submodules` to `recursive`; require operators to opt in.
- Add configurable limits on submodule count and recursion depth (e.g., a `--max-submodules` / `--submodules-depth` flag) and reject/skip checkouts that exceed them before invoking `git submodule update --init --recursive`.
- Consider running submodule updates with stricter resource limits (ulimits, cgroups) independent of `--sync-timeout`, and fail fast with a clear error rather than silently consuming resources until timeout.
- Document the resource-exhaustion risk of `--submodules=recursive` prominently, similar to go-ethereum's stance on the GraphQL endpoint not being hardened against hostile input.

### Proof of Concept
1. Create a git repository `A` and configure `git-sync --repo=A --submodules=recursive` (default).
2. In repository `A`, add a large number of submodule entries in `.gitmodules` (e.g., thousands of trivial repos), or create a chain of submodules `A -> B -> C -> ... -> N` each referencing the next, several hundred levels deep.
3. Push/commit this state to `A` and let git-sync pick it up.
4. Observe that `configureWorktree` (`main.go:1733-1747`) invokes `git submodule update --init --recursive`, consuming disproportionate CPU/memory/disk/network resources or hitting `--sync-timeout` on every sync cycle, repeating on every subsequent `--period` tick and blocking legitimate publication of new content via the `--link` symlink.

### Citations

**File:** main.go (L182-184)
```go
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
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

**File:** main.go (L1929-1945)
```go
		// If we have a new hash, make a new worktree
		newWorktree := currentWorktree
		if changed {
			// Create a worktree for this hash in git.root.
			if wt, err := git.createWorktree(ctx, remoteHash); err != nil {
				return false, "", err
			} else {
				newWorktree = wt
			}
		}

		// Even if this worktree existed and passes sanity, it might not have all
		// the correct settings (e.g. sparse checkout).  The best way to get
		// it all set is just to re-run the configuration,
		if err := git.configureWorktree(ctx, newWorktree); err != nil {
			return false, "", err
		}
```

**File:** pkg/cmd/cmd.go (L63-90)
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
```
