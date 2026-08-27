### Title
Confused-deputy credential disclosure via attacker-controlled submodule URL sharing the credential cache's host-only match scope - (File: main.go)

### Summary
`git-sync` stores all authentication material (username/password, `--askpass-url` responses, GitHub App tokens, `--credential` entries) in a single, process-global git credential cache that is not scoped to the specific repository or path being fetched. Because `git submodule update --init` (run for every synced commit when submodules are enabled) shares this same global git config/credential store as the top-level `--repo` fetch, an attacker who can influence the synced repository's tree (e.g. a merged/pushed commit adding or modifying `.gitmodules`) can point a submodule at a different repository on the *same host* as an already-credentialed URL and have git-sync's cached credentials silently replayed against it, similar in spirit to the Mover `topupproxy`/`exchangeproxy` bug where a shared whitelist plus an over-broad (unlimited-scope) grant let attacker-supplied call data redirect privileged access to an unintended target.

### Finding Description
- `SetupDefaultGitConfigs` globally configures `credential.helper` as `cache --timeout 3600` and `core.askPass=true` (never prompt): [1](#0-0) 
- Credentials obtained from `--username`/`--password`, `--askpass-url`, GitHub App tokens, and `--credential` entries are all funneled into the same `git credential approve` call, which stores them in that global cache: [2](#0-1) [3](#0-2) [4](#0-3) 
- After checking out a commit, `configureWorktree` unconditionally runs `git submodule update --init [--recursive]` using the exact same global git configuration/credential cache as the top-level repo fetch: [5](#0-4) 
- Git's default credential-cache matching key is `protocol://host` (path-independent, since `credential.useHttpPath` defaults to false and is never set by git-sync). Consequently, any credential approved for one URL on a host will be offered for *any other path/repo* on that same host during the submodule fetch — this is analogous to the report's "shared whitelist" (`exchangeproxy`/`topupproxy` sharing one `trustedregistry`) and to the "unlimited allowance...rather than only the amount of the current topup" (the credential grant is not scoped to the intended repo/path).
- The `--credential` flag documentation itself acknowledges that submodules may need distinct credentials, but all of them still land in the one shared, host-scoped cache: [6](#0-5) 

### Impact Explanation
If an attacker can get content merged/pushed into the synced ref (a realistic, already-in-scope threat: "attacker-pushed commit... reachable from untrusted repo content, submodules"), they can add a `.gitmodules` entry whose URL is `same-scheme://same-host/<attacker-chosen-path>`. When git-sync next syncs, `configureWorktree`'s `submodule update --init` will automatically authenticate to that path using the operator's real, privileged git credentials (PAT, GitHub App installation token, etc.) because the credential cache matches by host only. This:
- discloses/uses the privileged credential against a target the operator never intended it for (credential/token disclosure & confused-deputy use), and
- can cause git-sync to fetch and then publish (via the atomic symlink) private repository content the attacker was not authorized to read on that host, i.e. "publishing wrong content" to whatever consumes the synced volume.

This satisfies the "Accept" criteria of credential/token disclosure and publishing wrong/partial content, driven purely from attacker-controlled repo content (a `.gitmodules` change), with no privileged operator or leaked key required — only the standard `--submodules` (recursive/on) flag, which is off by default (`submodules=off`) but commonly enabled in production per the e2e suite's default coverage of submodule syncing.

### Likelihood Explanation
Requires: (1) `--submodules` set to something other than `off` (a common, documented, supported configuration, not the compile-time default but widely used for repos with vendored content), and (2) the attacker having write/merge access to at least one file (`.gitmodules`) in the synced ref. Given git-sync's stated purpose of syncing potentially collaborative/CI-driven repositories, and that submodule URLs are fully attacker-influenceable file content, likelihood is moderate: it depends on submodules being enabled and on host-shared credentials existing (askpass-url, GitHub App, or multiple `--credential` entries for the same host), which is explicitly the scenario the README calls out ("When using submodules it may be necessary to specify more than one username and password").

### Recommendation
1. Scope stored credentials to the exact URL/path they were issued for by setting `credential.useHttpPath=true` (or equivalent per-URL isolation) so cached credentials are not replayed against arbitrary paths on the same host.
2. Do not rely on a single shared, process-global credential cache for both the top-level `--repo` and submodule fetches; consider isolating submodule credential resolution to explicitly-provided `--credential` entries only, and refuse to store or reuse the main `--askpass-url`/GitHub App token for submodule URLs unless explicitly whitelisted.
3. Add an option to disable automatic submodule credential propagation, or to restrict submodule URLs to an explicit host allowlist independent of the main repo's credentialed host.

### Proof of Concept
1. Operator runs `git-sync --repo=https://git.example.com/org/app.git --askpass-url=http://metadata/git-creds --submodules=recursive --root=/data --link=current`. The askpass URL returns a token with broad read access across `git.example.com`.
2. Attacker (who has push/merge rights to `org/app`, e.g. via an accepted PR) adds `.gitmodules`:
   ```
   [submodule "steal"]
       path = steal
       url = https://git.example.com/org/private-secret-repo.git
   ```
   and commits it to the synced branch.
3. On the next sync cycle, `configureWorktree` runs `git submodule update --init --recursive` (`main.go:1733-1747`), and because the credential cache in `SetupDefaultGitConfigs`/`StoreCredentials` matches by `https://git.example.com` only (`main.go:2276-2303`, `main.go:2055-2067`), git transparently authenticates to `org/private-secret-repo.git` using the operator's cached askpass token.
4. `private-secret-repo`'s contents are checked out into the worktree and published via the atomic symlink flip, becoming readable to anyone/anything consuming the git-sync volume — including the attacker if they also have read access to the published output (e.g. a shared CI artifact, sidecar-mounted volume, or downstream service), despite never having had direct git access to `private-secret-repo`.

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

**File:** main.go (L2255-2274)
```go
	tokenResponse := struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return err
	}

	git.appTokenExpiry = tokenResponse.ExpiresAt

	// username must be non-empty
	username := "-"
	password := tokenResponse.Token

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

**File:** README.md (L249-268)
```markdown
    --credential <string>, $GITSYNC_CREDENTIAL
            Make one or more credentials available for authentication (see git
            help credential).  This is similar to --username and
            $GITSYNC_PASSWORD or --password-file, but for specific URLs, for
            example when using submodules.  The value for this flag is either a
            JSON-encoded object (see the schema below) or a JSON-encoded list
            of that same object type.  This flag may be specified more than
            once.

            Object schema:
              - url:            string, required
              - username:       string, required
              - password:       string, optional
              - password-file:  string, optional

            One of password or password-file must be specified.  Users should
            prefer password-file for better security.

            Example:
              --credential='{"url":"https://github.com", "username":"myname", "password-file":"/creds/mypass"}'
```
