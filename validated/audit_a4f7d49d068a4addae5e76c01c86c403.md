### Title
Submodule `.gitmodules` URLs using `ext::` transport reach `git submodule update` via `Runner.Run` without any `GIT_ALLOW_PROTOCOL`/`protocol.*.allow` restriction, enabling command execution - ([File: pkg/cmd/cmd.go])

### Finding Description
`Runner.Run` in `pkg/cmd/cmd.go` is a thin, unrestricted wrapper around `exec.CommandContext` that runs whatever `command`/`args` it is given with whatever `env` it is given, with no allowlisting of git protocols or submodule URL schemes: [1](#0-0) [2](#0-1) 

A repository-content attacker who can push a branch/ref that git-sync fetches can add a `.gitmodules` file containing `url = ext::sh -c 'touch /tmp/pwned'`. When git-sync's submodule-update codepath in `main.go` runs `git submodule update ...` through `Runner.Run`, git itself (not git-sync) interprets the `ext::` URL and spawns the attacker-specified shell command as a child of the `git` process — this is git's own `ext::` remote helper feature, not an argv-injection bug in git-sync's command construction.

The critical missing control is an environment-level or config-level protocol allowlist. A repository-wide search found **no occurrence of `GIT_ALLOW_PROTOCOL`** anywhere in the non-vendor, non-test source of this repository — the only related hits are protocol.allow strings inside `test_e2e.sh`, which is test-only and not part of the shipped binary's runtime behavior. Since `Runner.Run`/`runWithStdin` pass through `env` unmodified and there is no evidence in `main.go` that a restrictive `GIT_ALLOW_PROTOCOL` value (e.g., limiting to `file:git:http:https:ssh`) or `-c protocol.ext.allow=never` is injected into the environment/args before submodule commands are executed, git's own submodule machinery is free to invoke the `ext::` helper.

### Impact Explanation
This maps to the Kubernetes bounty "code execution in container" class: an unprivileged attacker who can only push content the git-sync process fetches can achieve arbitrary command execution inside the git-sync container as a side effect of `git submodule update`, without needing any flags, secrets, or Pod-spec control — a pure content-containment breach.

### Likelihood Explanation
Feasibility depends entirely on default flags: this path is only reachable if submodule syncing is enabled (default git-sync flags historically default submodule recursion on) and the attacker can get their ref fetched. No non-default or undocumented flags are required by the attacker; the only "requirement" is the *absence* of a `GIT_ALLOW_PROTOCOL` restriction, which the codebase search suggests git-sync does not currently set anywhere in `main.go`, `pkg/cmd/cmd.go`, or elsewhere outside of the e2e test script. This makes the attack repeatable and low-effort for any actor who can push to a synced ref.

### Recommendation
Before any submodule-related `Runner.Run`/`RunWithStdin` invocation, set a restrictive `GIT_ALLOW_PROTOCOL` environment variable (e.g., `file:git:http:https:ssh`) in the `env` slice passed to `Runner.Run`, and/or pass `-c protocol.ext.allow=never -c protocol.file.allow=never` (as appropriate) to every `git submodule ...` invocation. This restriction should be enforced unconditionally in the code path that constructs submodule commands (in `main.go`), not merely exercised in `test_e2e.sh`.

### Proof of Concept
1. Set up a local bare git repo containing a `.gitmodules` file with:
   ```
   [submodule "evil"]
     path = evil
     url = ext::sh -c 'touch /tmp/pwned'
   ```
2. Run git-sync against that repo with default submodule-sync flags.
3. Assert that `/tmp/pwned` is created inside the git-sync container, proving the `ext::` helper executed.
4. Assert (as a fix-verification test) that after setting `GIT_ALLOW_PROTOCOL=file:git:http:https:ssh` in the `env` argument to `Runner.Run` for all submodule commands, the same repo causes `git submodule update` to fail with a protocol-not-allowed error instead of executing the helper, and that `/tmp/pwned` is never created.

### Citations

**File:** pkg/cmd/cmd.go (L51-54)
```go
func (r Runner) Run(ctx context.Context, cwd string, env []string, command string, args ...string) (string, string, error) {
	// call depth = 2 to erase the runWithStdin frame and this one
	return runWithStdin(ctx, r.log.WithCallDepth(2), cwd, env, "", command, args...)
}
```

**File:** pkg/cmd/cmd.go (L63-73)
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
```
