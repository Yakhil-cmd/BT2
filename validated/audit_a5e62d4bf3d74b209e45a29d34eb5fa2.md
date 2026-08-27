### Title
Credential Leakage to Attacker-Controlled Submodule URLs via Missing `credential.useHttpPath` - ([File: main.go])

### Summary
`git-sync` stores git credentials (username/password, GitHub App tokens, askpass-supplied secrets) using `git credential approve` against a `credential.helper` of `cache --timeout 3600`, without ever setting `credential.useHttpPath`. Git's credential cache, by default, keys stored credentials by `protocol://host` only, not by the full path. Because git-sync auto-updates submodules found in the untrusted, attacker-influenced repo content it syncs (`--submodules`), an attacker who can add/modify a `.gitmodules` entry pointing to a different repository path on the *same host* as `--repo` can cause git to present the cached credentials to that attacker-controlled path without any additional approval step — analogous to the reported bug where a "gateway" address could move any user's tokens without an explicit per-holder approval, because the authorization check ("is this the same trusted counterpart?") was too coarse.

### Finding Description
- `SetupDefaultGitConfigs` sets `credential.helper` to `cache --timeout 3600` and never sets `credential.useHttpPath = true`: [1](#0-0) 
- Credentials (from `--username`/`$GITSYNC_PASSWORD`, `--credential`, `--askpass-url`, or the GitHub App token flow) are all funneled through `StoreCredentials`, which calls `git credential approve` with only `url`, `username`, `password`: [2](#0-1) [3](#0-2) [4](#0-3) 
- Without `credential.useHttpPath`, git's `credential-cache` helper indexes stored credentials by protocol+host only (per git's documented credential-matching behavior), so any URL under the same host will retrieve the same cached credential.
- `configureWorktree` unconditionally runs `git submodule update --init [--recursive]` against whatever `.gitmodules` content exists in the fetched commit — this is untrusted, attacker-influenced repo content that determines which URLs git will fetch using the cached credentials: [5](#0-4) 
- The README explicitly documents that submodules are expected to reuse the top-level, or `--credential`-supplied, username/password pairs, i.e. the trust boundary is meant to be "this specific repo URL", but the underlying mechanism only enforces "this host": [6](#0-5) 

This mirrors the reported MaviaToken pattern: a broadly-scoped, implicitly-trusted mechanism (the gateway mapping / here, the credential cache keyed by host) is used to authorize an action (moving tokens / here, presenting saved credentials) for a resource (any token holder / here, any path on the trusted host) that the actor did not explicitly approve for that specific counterpart.

### Impact Explanation
If the synced upstream repository can be influenced by a less-trusted party (e.g. accepted PRs, a compromised branch, or any commit reachable by `--ref`), that party can add a submodule pointing to `https://<same-host>/<attacker-controlled-path>`. On the next sync, git-sync's cached HTTP credentials (password, PAT, GitHub App installation token, or askpass-supplied secret) will be sent to that attacker-controlled path automatically, without any extra confirmation step, disclosing the credential/token to a destination the credential owner never explicitly authorized. This is credential/token disclosure — one of the explicitly accepted impacts.

### Likelihood Explanation
Requires: (1) `--submodules` not set to `off` (it defaults to `recursive`), (2) an HTTP(S) credential mechanism configured (`--username`/`--password[-file]`, `--credential`, `--askpass-url`, or GitHub App), and (3) the attacker being able to introduce a `.gitmodules` change that git-sync will fetch (e.g. via a merged/accepted commit, or any ref git-sync is configured to track). This is a realistic scenario for CI/CD sidecar deployments that track branches receiving external contributions, and does not require a malicious operator, leaked keys, or mocked-only conditions — it is reachable purely from attacker-influenced repo content plus default configuration.

### Recommendation
- Set `credential.useHttpPath = true` in `SetupDefaultGitConfigs` (or make submodule credentials strictly path-scoped) so cached credentials are only replayed to the exact URL they were approved for.
- Consider disabling credential reuse across submodule boundaries by default, and require explicit `--credential` entries (with exact URL match, already path-inclusive) for any submodule host+path combination instead of implicitly trusting same-host submodule URLs.
- Document/warn users that `--submodules` combined with a shared top-level credential is dangerous unless `useHttpPath` is enabled.

### Proof of Concept
Conceptual reproduction (not fully verified against a live git-cache implementation in this session — git's default `credential-cache` keying by protocol+host is standard documented behavior, but the exact end-to-end request/response over `file://` used in the test suite could not be executed here):
1. Configure git-sync: `--repo=https://git.example.com/org/legit-repo --username=svc --password-file=/secrets/pw --submodules=recursive`.
2. Attacker (with the ability to land a commit on the tracked ref, e.g. via accepted contribution) adds `.gitmodules` with `url = https://git.example.com/org/attacker-repo`.
3. On next sync, `configureWorktree` runs `git submodule update --init --recursive`, which for the new submodule issues a request to `https://git.example.com/org/attacker-repo`.
4. Because `credential.useHttpPath` is unset, git's cache helper returns the previously-approved `svc`/password pair for `https://git.example.com` regardless of path, sending the credential to the attacker's repository (which the attacker controls and can log the Basic-Auth header from). [1](#0-0) [5](#0-4) [2](#0-1)

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

**File:** main.go (L2160-2184)
```go
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

**File:** main.go (L2255-2271)
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

**File:** README.md (L616-624)
```markdown
            A variant of this is --askpass-url ($GITSYNC_ASKPASS_URL), which
            consults a URL (e.g. http://metadata) to get credentials on each
            sync.

            When using submodules it may be necessary to specify more than one
            username and password, which can be done with --credential
            ($GITSYNC_CREDENTIAL).  All of the username+password pairs, from
            both --username/$GITSYNC_PASSWORD and --credential are fed into
            'git credential approve'.
```
