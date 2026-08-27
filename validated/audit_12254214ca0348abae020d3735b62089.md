### Title
Git credentials cached in a long-lived helper process well beyond need — `credential.helper "cache --timeout 3600"` - ([File: main.go])

### Summary
git-sync configures git's global credential handling so that any password, `--askpass-url` secret, or short-lived GitHub App installation token is cached in plaintext by `git-credential-cache--daemon` for up to one hour after use, rather than being cleared immediately after the fetch/clone that needed it completes.

### Finding Description
`SetupDefaultGitConfigs` sets `credential.helper` to `cache --timeout 3600` globally for the process: [1](#0-0) 

Every credential path in git-sync — username/password, `--credential`, `--askpass-url`, and the GitHub App short-lived installation token — is fed through `StoreCredentials`, which calls `git credential approve`: [2](#0-1) 

`CallAskPassURL` and `RefreshGitHubAppToken` both funnel dynamically fetched secrets (including the GitHub App token, deliberately minted as short-lived, expiring in ~10 minutes per the JWT claims) into this same `StoreCredentials`/`credential approve` path: [3](#0-2) [4](#0-3) 

Because `git credential approve` with the `cache` helper hands the secret to a background `git-credential-cache--daemon` process that holds it in memory and serves it out over a Unix socket for the configured `--timeout` (here 3600s), the plaintext credential/token persists in a process's memory far longer than the single `git fetch`/`ls-remote` operation that needed it — this is architecturally the same "mnemonic stays in memory too long" class of bug: sensitive material is kept resident well past the window in which it is actually required, increasing the exposure surface (e.g., to a crash/core-dump, a debugging feature, or another local process that can reach the same socket) as described in the report's exploit scenario about heap-leaking crash reporters.

### Impact Explanation
If the git-sync process or the credential-cache daemon crashes or is inspected (core dump, `/proc/<pid>/mem`, container debug tools) within the 3600-second cache window, an attacker with access to the host/container internals could recover the git password, askpass-url secret, or (most notably) the short-lived GitHub App installation token that was otherwise designed to expire quickly. This is credential/token disclosure, one of the accepted impact categories.

### Likelihood Explanation
This is not attacker-triggerable purely via a pushed commit or ref — it requires some additional local access vector (crash, debug endpoint, or another local process reaching the credential-cache socket) to actually extract the cached secret. No such extraction primitive (e.g., an httppprof/heap-dump endpoint) was confirmed reachable in this codebase during review — the `--http-pprof` flag exists in git-sync's flags but its handler wiring was not fully verified within the available tool budget for this analysis. Absent that concrete leak channel, likelihood is best characterized as **low/moderate**: the extended in-memory/daemon-cached lifetime of credentials is a genuine design weakness matching the reported bug class, but full exploitability depends on an unverified secondary information-disclosure primitive that could not be confirmed with certainty here.

### Recommendation
- Do not set a broad, static `credential.helper "cache --timeout 3600"`; instead use `git credential approve`/`reject` more surgically or reduce the timeout to just cover the duration of a single fetch operation (or use `credential-cache --timeout` scoped per-invocation).
- For dynamically-fetched, intentionally short-lived secrets (GitHub App tokens, askpass-url responses), explicitly `git credential reject` / clear the cache entry immediately after the git operation completes rather than relying on the daemon's timeout to eventually expire it.
- Consider avoiding the persistent credential-cache daemon altogether for one-shot/short-lived tokens and instead pass credentials via a short-lived, single-use credential helper script invoked per operation.

### Proof of Concept
Not independently reproduced. This finding is derived directly from the code paths cited above (`SetupDefaultGitConfigs`, `StoreCredentials`, `CallAskPassURL`, `RefreshGitHubAppToken`) which show that all credential/token material passes through a git credential-cache daemon configured with a 3600-second retention window, matching the reported "sensitive data lingers longer than necessary" bug class. Full exploitation would require an additional, unverified local memory/socket-disclosure primitive that was not confirmed present in this codebase within the scope of this review.

### Citations

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

**File:** main.go (L2160-2182)
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
