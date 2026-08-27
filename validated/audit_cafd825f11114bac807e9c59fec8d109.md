### Title
Stale git-credential-cache entries are never invalidated when `--askpass-url` or `--credential` rotate tokens, allowing revoked/rotated credentials to remain usable for up to 1 hour - (File: main.go)

### Summary
`git-sync` stores HTTP credentials by shelling out to `git credential approve`, backed by a default `credential.helper = cache --timeout 3600`. On every sync cycle, `refreshCreds` re-fetches and re-approves new credentials via `CallAskPassURL`/`StoreCredentials`, but the code never issues a corresponding `git credential reject` for the credential it is replacing. This mirrors the reported `addLiquidity` pattern of an approval being granted but never reset/revoked when it is no longer the intended one in use, allowing a stale grant to persist and be consumed later.

### Finding Description
`SetupDefaultGitConfigs` configures the git credential subsystem to cache approved credentials in a background daemon (`git-credential-cache--daemon`) for one hour: [1](#0-0) 

Each sync cycle's `refreshCreds` closure re-derives credentials (from `--credential`, with optional `password-file` re-read to "pick up token rotation", or from `--askpass-url`) and calls `git.StoreCredentials`, which only ever runs `git credential approve`: [2](#0-1) [3](#0-2) 

`CallAskPassURL` fetches a fresh username/password from the configured URL and immediately approves it via `StoreCredentials`, again with no rejection of the previous credential for that URL: [4](#0-3) 

Because `git credential approve` only *adds* an entry to the cache helper (keyed by protocol/host, and by url granularity for the explicit `--credential` cases), the old (possibly rotated-out or revoked) password remains resident in the `credential-cache--daemon` memory for the full configured timeout (3600s by default), just as the Uniswap-analog issue left residual allowance because the "unused" portion was never reset. There is no `git credential reject` call anywhere in the codebase for either the askpass-URL path or the explicit `--credential` path.

### Impact Explanation
If an upstream token/password is rotated because it was compromised or intentionally revoked (the stated purpose of re-reading `password-file` "to pick up token rotation"), the previous credential is not evicted from the git credential cache. Any other `git` invocation that can reach the same credential-cache socket for that host during the cache window can still be handed the stale credential by the credential helper, and, in scenarios where the askpass URL later serves a bad/expired credential, git may still succeed using the previously-cached (stale) entry instead of surfacing the rotation as a hard failure. This is a credential/secret hygiene issue: the primary safety property (revoked/rotated credentials become unusable promptly) is violated, at least until the 3600s window elapses.

### Likelihood Explanation
This triggers on every configuration that uses `--askpass-url` or `--credential` with token rotation (a documented supported use case), during every rotation event to the same URL, with the default git config in place (`credential.helper = cache --timeout 3600`). No attacker interaction beyond controlling/observing the askpass-URL response sequence (already an explicit, in-scope trust boundary) is required; likelihood is moderate-to-high in long-running periodic-sync deployments.

### Recommendation
Before or after approving a new credential for a given URL/host, explicitly invalidate the previous one by invoking `git credential reject` with the prior `url`/`username` (or `git credential-cache exit` for that socket) so that stale, rotated-out secrets cannot linger in the cache for the remainder of the timeout window. Alternatively, reduce/parametrize the default `cache --timeout` and document that credential rotation is not fully honored until the cache entry naturally expires.

### Proof of Concept
1. Configure `git-sync` with `--askpass-url` pointing to a service that first returns `username=u/password=secret1`.
2. Let one sync cycle complete; `StoreCredentials` runs `git credential approve` with `secret1`, cached for 3600s by `credential.helper=cache --timeout 3600` set in `SetupDefaultGitConfigs`.
3. Rotate/revoke `secret1` upstream and have the askpass-URL service now return `password=secret2`.
4. `refreshCreds`/`CallAskPassURL` runs again and approves `secret2` — but no `git credential reject` is issued for `secret1`.
5. Because no rejection occurred, any process capable of querying the shared `git-credential-cache--daemon` socket for that host within the remaining cache window (up to 3600s from step 2) can still retrieve and use the now-revoked `secret1`, demonstrating the "approval not reset" analog. [1](#0-0) [3](#0-2) [4](#0-3)

### Citations

**File:** main.go (L977-1006)
```go
	// Craft a function that can be called to refresh credentials when needed.
	refreshCreds := func(ctx context.Context) error {
		// These should all be mutually-exclusive configs.
		for _, cred := range *flCredentials {
			password := cred.Password

			// If this credential has a password file, re-read it from disk
			// to pick up token rotation
			if cred.PasswordFile != "" {
				passwordFileBytes, err := os.ReadFile(cred.PasswordFile)
				if err != nil {
					return fmt.Errorf("can't read password file %q: %w", cred.PasswordFile, err)
				}
				password = string(passwordFileBytes)
				git.log.V(3).Info("read password from file", "file", cred.PasswordFile)
			}

			if err := git.StoreCredentials(ctx, cred.URL, cred.Username, password); err != nil {
				return err
			}
		}
		if *flAskPassURL != "" {
			// When using an auth URL, the credentials can be dynamic, and need
			// to be re-fetched each time.
			if err := git.CallAskPassURL(ctx); err != nil {
				metricAskpassCount.WithLabelValues(metricKeyError).Inc()
				return err
			}
			metricAskpassCount.WithLabelValues(metricKeySuccess).Inc()
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
