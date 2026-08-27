### Title
Unrestricted submodule URL/protocol handling during `git submodule update --init` allows attacker-pushed `.gitmodules` content to drive arbitrary clone transports - (File: main.go, `configureWorktree`)

### Summary
The state-transition bug in the external report is a class of "untrusted/attacker-influenced content is consumed without verifying it against a trusted, independent source before acting on it." In `git-sync`, the closest reachable analog is `repoSync.configureWorktree`, which runs `git submodule update --init` (optionally `--recursive`) directly against whatever `.gitmodules` content was fetched from the (potentially attacker-controlled) upstream `--repo`/`--ref`, without any allow-listing or restriction of submodule URLs/transports imposed by git-sync itself.

### Finding Description
After fetching and checking out the target hash, `configureWorktree` unconditionally updates submodules when `--submodules` is not `off`: [1](#0-0) 

The submodule URLs and paths are defined entirely by the `.gitmodules` file, which is part of the synced repository's tree — i.e., content that an attacker with write/PR access to the tracked branch/tag/ref can control. `git-sync` passes this straight to `git submodule update --init [--recursive] [--depth N]` with no additional restriction such as `-c protocol.ext.allow=never`, `-c protocol.file.allow=never`, or a URL allow-list. This mirrors the beacon-kit flaw: the "deposit" (here, submodule content) is trusted and acted upon without independent verification against a known-good source or scope restriction (e.g., limiting submodule origins to the same host or a fixed allow-list).

### Impact Explanation
Depending on the git version bundled in the git-sync image and its compiled-in defaults for `protocol.*.allow`, a malicious `.gitmodules` entry could:
- Point to internal/unexpected hosts (SSRF-like fetches from the sync pod's network position), or
- Use dangerous transports (e.g., `ext::`) if the underlying git version/config does not disable them, resulting in command execution as the git-sync process.

This directly maps to the "code execution" and "persistent sync denial" impact categories called out in the validation rubric.

### Likelihood Explanation
Requires: (1) `--submodules` not set to `off` (it defaults to non-off in some configurations per README), and (2) an attacker able to introduce a malicious `.gitmodules` into the tracked ref (a plausible untrusted-repo-content scenario, e.g., syncing a public/community repo or one where PRs can land on the tracked branch). Actual exploitability of the transport (e.g., `ext::`) further depends on the git binary's compiled default for `protocol.allow`, which recent upstream git versions restrict by default — this is a required caveat, since modern git already disables `ext::`/`file` transports for submodules unless explicitly re-enabled via `GIT_ALLOW_PROTOCOL`/`protocol.*.allow`. git-sync itself does not add any independent restriction, so the safety is incidentally inherited from the vendored git binary's defaults rather than from a verification step in `git-sync`.

### Recommendation
- Explicitly set restrictive protocol allow-lists before running submodule commands, e.g. `git -c protocol.file.allow=never -c protocol.ext.allow=never submodule update --init ...`, rather than relying on the ambient git binary's defaults.
- Optionally validate `.gitmodules` submodule URLs against an operator-configured allow-list (e.g., restrict to the same host/org as `--repo`) before invoking `submodule update`.

### Proof of Concept
1. Attacker with push/PR access to the tracked branch adds a `.gitmodules` entry with an untrusted/dangerous URL scheme.
2. git-sync syncs the new commit (`SyncRepo` → `createWorktree` → `configureWorktree`).
3. `configureWorktree` runs `git submodule update --init --recursive` (main.go:1737) against the attacker-controlled `.gitmodules`, with no protocol restriction applied by git-sync, relying solely on the vendored git binary's own defaults for safety.

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
