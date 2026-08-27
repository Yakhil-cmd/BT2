### Title
SSRF via attacker-controlled submodule URLs during `git submodule update` - (File: main.go)

### Summary
The reported GitLab issue is a webhook SSRF where a user-supplied URL causes the server to make outbound requests to arbitrary/internal hosts, leaking port-open/closed state. In git-sync, the `--webhook-url` and `--askpass-url` flags are operator-supplied at deploy time [1](#0-0) , so they are not a valid analog (not attacker-reachable from repo content). However, git-sync's submodule handling provides a genuinely attacker-reachable analog: submodule URLs come from `.gitmodules`, which is untrusted content controlled by whoever can push to the synced repository.

### Finding Description
When submodules are enabled (`--submodules` not set to `off`), `configureWorktree` runs `git submodule update --init [--recursive] [--depth N]` against the checked-out worktree [2](#0-1) . The submodule URLs used by this command are read directly from `.gitmodules`, a file that is part of the synced repository content and therefore fully attacker-controlled by anyone who can push a commit (or control the upstream repo git-sync points to). By committing a `.gitmodules` entry with `url = http://169.254.169.254/latest/meta-data/iam/security-credentials/` or `url = http://127.0.0.1:<port>/...`, an attacker can cause the git-sync process to make outbound HTTP(S)/git requests to internal hosts, cloud metadata endpoints, or scan for open ports on the pod's network — exactly the SSRF pattern described in the report (differentiating open vs. closed ports via error/success behavior), because `git.Run` surfaces stdout/stderr from the submodule fetch, which is logged at higher verbosity levels (`-v 5`/`-v 6` log all executed commands and command output per the README) [3](#0-2) .

Unlike the malicious-operator/leaked-key patterns explicitly excluded by the rules, this path requires no special privilege beyond the ability to have git-sync configured to sync a repository the attacker (partially) controls — a normal, supported git-sync use case (e.g., syncing a third-party or contributor-writable repo).

### Impact Explanation
This allows internal network reconnaissance/SSRF from the git-sync sidecar's network position: probing internal services (e.g., Kubernetes internal APIs, cloud metadata services) and inferring reachability/state via git's fetch error messages (analogous to "Connection refused" vs. HTTP 404 behavior in the original report). If credentials are configured via `--credential` for URL-specific auth (used for submodules per the README's authentication section) [4](#0-3) , there is additional risk that credentials intended for one submodule host could be sent to an attacker-specified URL if the attacker crafts a `.gitmodules` URL matching a credential pattern, though this would require additional conditions to verify with certainty.

### Likelihood Explanation
High for any deployment where git-sync syncs a repository whose content (including `.gitmodules`) is not fully trusted (e.g., syncing a repo where external contributors can open merge requests that get merged, or where the "repo" itself is attacker-influenced). Submodules default to being processed whenever `--submodules` isn't explicitly set to `off` [5](#0-4) .

### Recommendation
- Document clearly that `.gitmodules` URLs are untrusted input and can result in git-sync issuing requests to arbitrary hosts, including internal/metadata endpoints, when submodules are enabled.
- Consider supporting/recommending `git config protocol.allow` restrictions (e.g., restrict to `https`, disallow `file`) applied specifically to the submodule-update invocation, or an explicit allowlist flag for permitted submodule URL hosts/prefixes.
- Avoid logging raw stdout/stderr of submodule fetch commands at default-adjacent verbosity levels, since this can leak internal service fingerprinting info (open/closed port behavior) to log consumers, mirroring the original report's oracle.

### Proof of Concept
1. Configure git-sync to sync a repository with `--submodules=recursive` (or leave the default) where an attacker (e.g., a merged external contribution) can modify `.gitmodules`.
2. Attacker adds a submodule entry:
   ```
   [submodule "x"]
       path = x
       url = http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```
3. On next sync, `configureWorktree` executes `git submodule update --init --recursive` against this URL [6](#0-5) , causing the git-sync process to issue an outbound request to the internal metadata service from within the cluster network, with success/failure surfaced through git-sync's error handling and verbose logs.

### Citations

**File:** main.go (L251-257)
```go
	flWebhookURL := pflag.String("webhook-url",
		envString("", "GITSYNC_WEBHOOK_URL", "GIT_SYNC_WEBHOOK_URL"),
		"a URL for optional webhook notifications when syncs complete (must be idempotent)")
	flWebhookMethod := pflag.String("webhook-method",
		envString("POST", "GITSYNC_WEBHOOK_METHOD", "GIT_SYNC_WEBHOOK_METHOD"),
		"the HTTP method for the webhook")
	flWebhookStatusSuccess := pflag.Int("webhook-success-status",
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

**File:** README.md (L554-565)
```markdown
    -v, --verbose <int>, $GITSYNC_VERBOSE
            Set the log verbosity level.  Logs at this level and lower will be
            printed.  Logs follow these guidelines:

            - 0: Minimal, just log updates
            - 1: More details about updates
            - 2: Log the sync loop
            - 3: More details about the sync loop
            - 4: More details
            - 5: Log all executed commands
            - 6: Log stdout/stderr of all executed commands
            - 9: Tracing and debug messages
```

**File:** README.md (L620-624)
```markdown
            When using submodules it may be necessary to specify more than one
            username and password, which can be done with --credential
            ($GITSYNC_CREDENTIAL).  All of the username+password pairs, from
            both --username/$GITSYNC_PASSWORD and --credential are fed into
            'git credential approve'.
```
