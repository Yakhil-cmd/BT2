### Title
Global SSH identity files are offered to any host referenced by attacker-influenced submodule URLs, enabling private-key fingerprint/credential-exposure analogous to unrestricted approval grants - ([File: main.go])

### Summary
The AnyswapFacet bug is a case of a privileged capability (ERC20 approval) being granted to an address that is effectively derived from untrusted input, with no allow-listing or scope restriction, allowing that address to later exercise the capability against unrelated funds. The closest reachable analog in `git-sync` is in `SetupGitSSH`, which builds a single, global `GIT_SSH_COMMAND` string that offers **all** configured SSH identity files to **whatever host** git ends up connecting to, including hosts that are only reached because they are referenced inside `.gitmodules` of the fetched (and therefore only as trustworthy as the remote content) repository.

### Finding Description
`SetupGitSSH` constructs one `GIT_SSH_COMMAND` value for the whole process: [1](#0-0) 

Every path in `pathsToSSHSecrets` (`--ssh-key-file`, which may be specified multiple times, e.g. for accessing several different remotes/submodules) is appended as a `-i` flag with no per-`Host` scoping: [2](#0-1) 

This single `ssh` invocation is used for every git network operation for the lifetime of the process — for the primary `--repo` fetch and for every submodule `git submodule update --init [--recursive]`: [3](#0-2) 

Submodule URLs are read from `.gitmodules`, which is part of the content fetched from the remote repository, i.e. from data that (per the threat model in scope here) is only as trusted as "content in the synced repo," not as trusted as the operator-supplied `--repo`/`--ssh-key-file` flags. Because `ssh` (via `GIT_SSH_COMMAND`) is configured with `-i` for *every* configured key and no `Host`-based restriction (and, when `--ssh-known-hosts=false`, also `StrictHostKeyChecking=no`), any submodule (or nested submodule) URL that points at an attacker-controlled SSH endpoint will cause the ssh client to attempt public-key authentication using all configured identities — offering every private key configured for git-sync (which may back multiple, unrelated repositories/tenants) to a host chosen by repository content rather than by the operator.

This mirrors the root cause of the reported bug: a security-relevant credential/capability (there: infinite ERC20 approval; here: SSH key offering) is extended to a destination (`_anyswapData.router` there; the submodule host here) that is derived from data the operator did not explicitly authorize, with no allow-listing of destinations and no scoping of the granted capability to the specific relationship it was meant for.

### Impact Explanation
- Public key fingerprints for all configured `--ssh-key-file` identities are disclosed to an attacker-controlled SSH endpoint reached via a malicious/compromised submodule URL, even if that identity was intended only for a different, unrelated remote.
- Combined with `--ssh-known-hosts=false` (a documented, supported configuration) there is no host verification, so an attacker who can influence `.gitmodules` content of the synced repo (e.g., through a merged PR, a compromised upstream mirror, or a MITM'd unauthenticated transport) fully controls the SSH server that will receive these key offers.
- Impact is bounded by SSH pubkey-auth semantics (the private key material itself is not transmitted), so this does not by itself achieve full credential disclosure or code execution; it is a confidentiality/scoping weakness (which key exists / is in use) rather than a direct funds-drain equivalent. I could not find a stronger, more directly exploitable git-sync analog (e.g., no evidence of unscoped infinite "approval" of HTTP credentials — HTTP credentials stored via `git credential approve`/`--credential` are matched by git's own protocol+host credential-helper logic) within the code I was able to review.

### Likelihood Explanation
Requires: (1) `--ssh-key-file` configured with one or more keys, (2) the synced repository (or one of its submodules, recursively) to contain or later obtain a `.gitmodules` entry pointing at an SSH URL under attacker control, and (3) typically `--ssh-known-hosts=false` (or an accepted/poisoned known_hosts entry) to avoid host-key verification friction. This requires some measure of write influence over the synced repository content (or its submodule tree), which is a plausible position for the "untrusted repo content" threat class in scope, but is not a fully unauthenticated remote attacker path against a hardened, read-only mirror configuration.

### Recommendation
- Scope SSH identities per remote host using `ssh_config` `Host`/`IdentityFile`/`IdentitiesOnly yes` blocks generated from the specific hosts the operator expects (`--repo` host and any explicitly whitelisted submodule hosts), instead of a single flat `-i` list applied globally.
- Do not allow `.gitmodules`-derived hosts to silently inherit all configured identities; prefer failing closed (require the operator to explicitly map host → key, similar to how `--credential` already scopes HTTP creds by URL) when submodule host is not on that map.
- Continue to strongly encourage/enforce `--ssh-known-hosts=true` for any configuration that syncs submodules from URLs originating in the synced content.

### Proof of Concept
1. Operator runs `git-sync --repo=ssh://good-host/repo --ssh-key-file=/etc/git-secret/ssh --ssh-known-hosts=false --submodules=recursive`.
2. An attacker who can influence the content of `repo` (e.g. via a merged commit or a submodule pointer update) adds/modifies `.gitmodules` to include `url = ssh://attacker-host/evil`.
3. On the next sync, `configureWorktree` runs `git submodule update --init --recursive` [4](#0-3) , which invokes `ssh` via the process-wide `GIT_SSH_COMMAND` built in `SetupGitSSH` [2](#0-1) , offering all configured identity files to `attacker-host`.
4. The attacker's SSH server logs/observes the offered public keys for authentication attempts, disclosing which identities are in use/available to git-sync, without the operator having authorized that host to see them.

### Citations

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

**File:** main.go (L2069-2102)
```go
func (git *repoSync) SetupGitSSH(setupKnownHosts bool, pathsToSSHSecrets []string, pathToSSHKnownHosts string) error {
	git.log.V(1).Info("setting up git SSH credentials")

	// If the user sets GIT_SSH_COMMAND we try to respect it.
	sshCmd := os.Getenv("GIT_SSH_COMMAND")
	if sshCmd == "" {
		sshCmd = "ssh"
	}

	// We can't pre-verify that key-files exist because we call this path
	// without knowing whether we actually need SSH or not, in which case the
	// files may not exist and that is OK.  But we can make SSH report more.
	switch {
	case git.log.V(9).Enabled():
		sshCmd += " -vvv"
	case git.log.V(7).Enabled():
		sshCmd += " -vv"
	case git.log.V(5).Enabled():
		sshCmd += " -v"
	}

	for _, p := range pathsToSSHSecrets {
		sshCmd += fmt.Sprintf(" -i %s", p)
	}

	if setupKnownHosts {
		sshCmd += fmt.Sprintf(" -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s", pathToSSHKnownHosts)
	} else {
		sshCmd += " -o StrictHostKeyChecking=no"
	}

	git.log.V(9).Info("setting $GIT_SSH_COMMAND", "value", sshCmd)
	if err := os.Setenv("GIT_SSH_COMMAND", sshCmd); err != nil {
		return fmt.Errorf("can't set $GIT_SSH_COMMAND: %w", err)
```
