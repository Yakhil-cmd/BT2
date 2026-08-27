### Title
Host-scoped (not path-scoped) credential caching allows attacker-controlled submodules to exfiltrate git-sync's stored credentials - (File: main.go)

### Summary
`git-sync` configures a global, host-level git credential cache and then runs `git submodule update --init --recursive` against submodule URLs that are entirely controlled by the content of the tracked (and potentially attacker-influenced) repository. Because git's credential matching defaults to `protocol://host` and `credential.useHttpPath` is never enabled, any credential git-sync has previously stored for the main repo's host (via `--username`/`--password-file`, `--credential`, or `--askpass-url`) will be transparently replayed to *any* submodule URL on that same host, including a different, attacker-owned path/repo. A single push adding or modifying `.gitmodules` is enough to trigger exfiltration on the very next unmodified sync cycle, with no verification step, allow-list, or per-path credential scoping to stop it — directly analogous to the reported EigenLayer issue where a single externally-influenced state change was immediately trusted and empowered with no cooldown for defenders to react.

### Finding Description
`SetupDefaultGitConfigs` sets the global credential helper to a plain time-based cache with no path scoping: [1](#0-0) 

Credentials supplied via `--username`/`--password-file`, `--credential`, or `--askpass-url` are stored via `git credential approve` keyed by whatever URL string is supplied (usually just the main repo's URL/host): [2](#0-1) [3](#0-2) 

Every sync cycle, `configureWorktree` unconditionally runs `git submodule update --init [--recursive]` against the checked-out tree, i.e. against whatever `.gitmodules` content is present in the currently synced commit: [4](#0-3) 

Git's credential subsystem, absent `credential.useHttpPath=true` (never set by git-sync), matches stored credentials by `protocol` + `host` only — not by full path. Consequently, if the tracked repository's remote is `https://host/org/repo` and an attacker who can influence the tracked repo's content (e.g., a compromised/malicious upstream branch, a malicious PR merged by a maintainer, or a compromised mirror) adds a submodule pointing to `https://host/attacker/evil-repo`, the credential helper will happily hand git-sync's cached username/password to that attacker-controlled path on the very next `--period` sync — with zero cooldown, confirmation, or scoping check in between.

### Impact Explanation
This results in credential/token disclosure to an attacker-controlled endpoint, matching the accepted impact class ("credential or token disclosure"). Depending on the credential's scope (a PAT, GitHub App-derived token, or shared service credential used for the whole host), this can cascade into unauthorized repository access, further supply-chain compromise, or lateral access to any other repos reachable with that credential — mirroring how the original report's uncontained state change (LST share inflation) cascaded into full AVS compromise.

### Likelihood Explanation
Likelihood is medium: it requires an attacker to be able to introduce a commit into the tracked repository (or its default branch/ref) that git-sync will fetch — the same "external compromise" premise used in the original report (a compromised/malicious upstream update). No git-sync operator privilege, mocked-only path, or leaked key is required; the tracked repo content itself is the untrusted-input vector, which is squarely within git-sync's threat model (git-sync exists specifically to pull content it does not otherwise trust). The one-cycle propagation (`--period`, `--sync-on-signal`) gives operators effectively no window to detect and pause before the credential is sent.

### Recommendation
- Set `credential.useHttpPath=true` (or otherwise scope stored credentials to the exact `scheme://host/path` they were issued for) in `SetupDefaultGitConfigs` so credentials are never replayed across differing repository paths on the same host.
- When `--credential` is used for submodules, ensure git-sync validates that submodule URLs discovered at sync time match an explicit allow-list of expected hosts/paths before invoking `git submodule update`, rather than trusting whatever `.gitmodules` currently contains.
- Consider isolating submodule credential material from the main repo's credential material by default, requiring explicit opt-in (as `--credential` already partially supports) rather than falling back to broad host-scoped credentials.

### Proof of Concept
1. Configure git-sync against `https://git.example.com/org/main-repo` using `--username`/`--password-file` (or `--askpass-url`), which is stored via `StoreCredentials` under `https://git.example.com/...` [2](#0-1) , cached globally without path scoping [5](#0-4) .
2. An attacker who can land a commit in `main-repo` (compromised branch/PR/mirror) adds `.gitmodules` with a submodule URL `https://git.example.com/attacker/evil-repo`.
3. On the next sync cycle, `configureWorktree` runs `git submodule update --init --recursive` [4](#0-3) ; git's credential helper matches by host only and sends the cached username/password to `attacker/evil-repo`, which the attacker's git server logs, achieving credential exfiltration with no cooldown or verification step in between.

### Citations

**File:** main.go (L1733-1746)
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

**File:** main.go (L2133-2185)
```go
func (git *repoSync) CallAskPassURL(ctx context.Context) error {
	git.log.V(3).Info("calling auth URL to get credentials")

	var netClient = &http.Client{
		Timeout: time.Second * 1,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, git.authURL, nil)
	if err != nil {
		return fmt.Errorf("can't create auth request: %w", err)
	}
	resp, err := netClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("can't access auth URL: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		errMessage, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("auth URL returned status %d, failed to read body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("auth URL returned status %d, body: %q", resp.StatusCode, string(errMessage))
	}
	authData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("can't read auth response: %w", err)
	}

	username := ""
	password := ""
	for line := range strings.SplitSeq(string(authData), "\n") {
		keyValues := strings.SplitN(line, "=", 2)
		if len(keyValues) != 2 {
			continue
		}
		switch keyValues[0] {
		case "username":
			username = keyValues[1]
		case "password":
			password = keyValues[1]
		}
	}

	if err := git.StoreCredentials(ctx, git.repo, username, password); err != nil {
		return err
	}

	return nil
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
