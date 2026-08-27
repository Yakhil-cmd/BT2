### Title
SSRF / Arbitrary Outbound Request via Attacker-Controlled `.gitmodules` Submodule URLs During Automatic `git submodule update` - ([File: main.go])

### Summary
`git-sync` automatically runs `git submodule update --init [--recursive]` on every synced commit whenever the `--submodules` mode is not `off` [1](#0-0) . The submodule URLs used for this operation come entirely from the `.gitmodules` file, which is repository content controlled by whoever can push a commit or ref to the tracked repository — i.e., untrusted, attacker-influenced input, analogous to a smart contract supplying `OffchainLookup` URLs in the reported web3.py CCIP Read SSRF. `git-sync` performs no validation, allowlisting, or protocol restriction on these URLs before invoking `git submodule update`, which will fetch from whatever destination (`http://`, `https://`, `git://`, `ssh://`, or `file://`) is specified.

### Finding Description
The relevant code path is `configureWorktree`, invoked on every new commit checkout:
```go
if git.submodules != submodulesOff {
    submodulesArgs := []string{"submodule", "update", "--init"}
    if git.submodules == submodulesRecursive {
        submodulesArgs = append(submodulesArgs, "--recursive")
    }
    ...
    git.Run(ctx, worktree.Path(), submodulesArgs...)
}
``` [1](#0-0) 

This runs unconditionally for every synced ref unless the operator explicitly sets `--submodules=off`, mirroring the report's "default-on exposure" pattern where CCIP Read fires automatically without opt-in. The `.gitmodules` file and its `url = ...` entries are ordinary repository content; an attacker who can push a branch/PR/commit that git-sync eventually syncs (e.g., a tracked branch open to external contributions, a mirrored fork, or any workflow where git-sync polls a ref that isn't fully trust-gated) fully controls the destination git-sync will contact. There is no code in `main.go` that restricts allowed submodule protocols (no `protocol.allow`/`GIT_ALLOW_PROTOCOL` configuration was found in the codebase), no hostname/IP allowlist, and no blocking of private/reserved ranges before the `git submodule update` call executes.

This is a structurally identical bug class to the web3.py CCIP Read report: (1) a feature is enabled by default, (2) it consumes a destination (URL/host) that originates from third-party-controlled data embedded in synced content, and (3) the library/tool issues an outbound network request to that destination with no destination-policy hook.

### Impact Explanation
A malicious or compromised contributor to a tracked repository can force the git-sync process to issue outbound network requests to arbitrary destinations reachable from the pod/host, including internal services and cloud metadata endpoints (e.g., `169.254.169.254`), by adding/modifying `.gitmodules` entries. Depending on the git version and its default protocol policy, this could also reach `file://` submodule URLs, which is a known primitive for reading local files or (on older/misconfigured gits) SSRF/local access outside `--root`. This satisfies the "publishing wrong or partial content," "credential/token disclosure" (via SSRF to metadata services or internal creds endpoints), and potentially "code execution" impact classes depending on transport availability.

### Likelihood Explanation
`--submodules` defaults to enabling submodule processing in typical git-sync deployments (only `--submodules=off` disables it), so most deployments are exposed by default without any explicit opt-in, exactly like `global_ccip_read_enabled = True` in the web3.py report [2](#0-1) . Any deployment that syncs a branch/PR ref where an untrusted party can land a commit (common in CI/staging setups, forked-PR previews, or multi-tenant repos) is directly reachable. I was not able to fully confirm the exact default value string for `--submodules` or whether any implicit `protocol.allow` restriction is set elsewhere in the vendored git binary/config due to running out of tool iterations — this should be verified against the actual default flag value and git version's built-in protocol policy before treating this as fully confirmed exploitable for `file://`/`ext::` transports specifically.

### Recommendation
- Default `--submodules` to `off` or require explicit operator opt-in for recursive submodule fetching, consistent with the EIP-3668 guidance the report cites (safe-by-default, explicit override hook).
- When submodules are enabled, restrict allowed transport protocols via `-c protocol.allow=...` / `GIT_ALLOW_PROTOCOL` (e.g., only `https`), and disallow `file://`/`ext::` for submodule fetches unless explicitly allowlisted by the operator.
- Provide an explicit allowlist/blocklist mechanism for submodule remote hosts, similar to what EIP-3668 recommends for CCIP Read clients.

### Proof of Concept
1. Attacker pushes a commit to a branch/ref that git-sync is configured to track, adding a `.gitmodules` entry:
   ```
   [submodule "x"]
       path = x
       url = http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```
2. git-sync syncs the new commit and, per `configureWorktree`, runs `git submodule update --init --recursive` in the new worktree [3](#0-2) , causing the git-sync host to make an outbound request to the attacker-chosen URL with no validation.
3. Depending on the environment, this can leak cloud credentials, probe internal network services, or otherwise be used as an SSRF primitive — with no allowlist/blocklist or protocol restriction implemented in `git-sync` to prevent it.

### Citations

**File:** main.go (L478-482)
```go
	switch submodulesMode(*flSubmodules) {
	case submodulesRecursive, submodulesShallow, submodulesOff:
	default:
		fatalConfigErrorf(log, true, "invalid flag: --submodules must be one of %q, %q, or %q", submodulesRecursive, submodulesShallow, submodulesOff)
	}
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
