### Title
Unbounded in-memory buffering of `git` subprocess stdout/stderr enables memory DoS from attacker-controlled ref/branch counts - (File: `pkg/cmd/cmd.go`)

### Summary
Every invocation of `git` by `git-sync` captures the full stdout and stderr of the subprocess into unbounded, unlimited `bytes.Buffer` objects. The `fetch` command is always run with `--verbose` and `--prune`, whose output size scales with the number of refs/branches on the remote. An attacker who can push refs to the synced repository (or control/MITM the git server for `--repo`) can inflate this output arbitrarily, forcing `git-sync` to allocate memory proportional to attacker-controlled content, with no bound. This mirrors the Bitcoin Core CVE-2024-52915 pattern of allocating memory sized by attacker-controlled protocol content with no per-message/response cap.

### Finding Description
`pkg/cmd/cmd.go`'s `runWithStdin` wires the command's `Stdout`/`Stderr` to plain `bytes.Buffer` values with no `io.LimitReader`/size cap: [1](#0-0) 

This function backs every `git.Run`/`git.RunWithStdin` call in `main.go`, including the repository `fetch` step, which is executed on every sync cycle using `--verbose --no-progress --prune`: [2](#0-1) 

`git fetch --verbose --prune` prints one line per updated, new, or pruned ref. The number and length of these lines is entirely determined by the state of the remote repository — i.e., by whatever an attacker with push access (or control of a malicious/MITM git server matching `--repo`) has put there (thousands of branches/tags, extremely long ref names, etc.). Because the capturing buffer has no size ceiling, `git-sync` will allocate memory proportional to that attacker-influenced output on every fetch, indefinitely, since fetch happens on every sync period.

This is directly analogous to the underlying root cause of the Bitcoin CVE: a size value/repeat-count that is controlled by an untrusted remote peer is used, unchecked, to drive an in-memory allocation with no upper bound, unlike Bitcoin Core's later fix which caps memory used per peer message.

### Impact Explanation
Repeated large `--verbose`/`--prune` fetch output causes uncontrolled memory growth in the `git-sync` process on every sync cycle (default every 10s), leading to persistent sync denial via OOM-kill of the sidecar container, and by extension denial of the atomic-publish contract that `git-sync` provides to the application pod. This falls into the "persistent sync denial" impact category permitted by scope.

### Likelihood Explanation
Requires only that the attacker have push access to (or the ability to add refs/branches on) the repository configured via `--repo`, or that `--repo` point at a git server the attacker controls (a normal supported configuration, not a "malicious operator" of git-sync itself). No special flags beyond default fetch behavior (`--verbose`, `--prune`, always set) are needed. This is a realistic scenario for shared/public repos or CI-triggered mirrors where write access is broader than the git-sync operator's trust boundary.

### Recommendation
Wrap `cmd.Stdout`/`cmd.Stderr` with `io.LimitWriter`/`io.LimitReader`-backed buffers (or `bytes.Buffer` variants capped at a fixed size, e.g. a few MB) in `runWithStdin` (`pkg/cmd/cmd.go`), truncating captured output with a clear indicator when the limit is exceeded, so that command-output capture memory usage is bounded regardless of remote repository content.

### Proof of Concept
1. Configure `git-sync --repo=<attacker-writable-repo> --root=/git --link=link`.
2. As the attacker, push a very large number of branches/tags (or extremely long ref names) to that repo.
3. On each sync cycle, `git-sync` executes `git fetch <repo> <ref> --verbose --no-progress --prune ...` via `runWithStdin` (`pkg/cmd/cmd.go:63-94`), which buffers all verbose ref-update/prune lines into an unbounded `bytes.Buffer`.
4. Repeated syncs against a large/growing ref set cause the `git-sync` process's memory usage to grow unbounded, eventually triggering OOM and sync denial. [1](#0-0) [2](#0-1)

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

**File:** main.go (L2001-2029)
```go
// fetch retrieves the specified ref from the upstream repo.
func (git *repoSync) fetch(ctx context.Context, ref string) error {
	git.log.V(2).Info("fetching", "ref", ref, "repo", redactURL(git.repo))

	// Fetch the ref and do some cleanup, setting or un-setting the repo's
	// shallow flag as appropriate.
	args := []string{"fetch", git.repo, ref, "--verbose", "--no-progress", "--prune", "--no-auto-gc"}
	if git.depth > 0 {
		args = append(args, "--depth", strconv.Itoa(git.depth))
	} else {
		// If the local repo is shallow and we're not using depth any more, we
		// need a special case.
		shallow, err := git.isShallow(ctx)
		if err != nil {
			return err
		}
		if shallow {
			args = append(args, "--unshallow")
		}
	}
	if git.filter != "" {
		args = append(args, "--filter", git.filter)
	}
	if _, _, err := git.Run(ctx, git.root, args...); err != nil {
		return err
	}

	return nil
}
```
