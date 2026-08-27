### Title
Excessive Credential Cache Lifetime via Hardcoded `credential.helper "cache --timeout 3600"` - ([File: main.go])

### Summary
`git-sync` configures the git credential helper with a fixed, non-configurable one-hour cache timeout regardless of how credentials are obtained (static `--credential`/`--password-file`, `--askpass-url`, or GitHub App tokens). This is the closest reachable analog to the reported "excessive session persistence" issue: authentication material remains usable for up to 3600 seconds after it is set, with no mechanism to invalidate the cached entry when the underlying credential is rotated or revoked.

### Finding Description
`SetupDefaultGitConfigs` unconditionally sets: [1](#0-0) 

```
credential.helper = "cache --timeout 3600"
```

This spins up `git-credential-cache--daemon`, which listens on a UNIX domain socket (by default under the user's runtime/cache directory) and serves any cached `username`/`password` pair to any process able to reach that socket for the full 3600-second window, independent of subsequent credential rotation.

`refreshCreds` re-stores credentials on each sync when a password file changes, when `--askpass-url` is set, or when a GitHub App token is close to expiry: [2](#0-1) 

`CallAskPassURL` fetches fresh credentials from a remote endpoint and calls `git.StoreCredentials` to feed them into the same `credential.helper` cache: [3](#0-2) 

`RefreshGitHubAppToken` mints a short-lived (typically ~1 hour) GitHub App installation token and also feeds it into the same cache via `StoreCredentials`: [4](#0-3) 

None of these refresh paths ever *evict* or `git credential reject` the previously cached entry before storing a new one, nor does the cache timeout track the actual expiry of the upstream credential (e.g., `appTokenExpiry`). This mirrors the report's "no idle timeout / extended auth lifetime" bug class: the effective "session" (cached credential) always lives for a full hour from the moment it is stored, regardless of subsequent revocation upstream (e.g., rotated `--password-file` content, revoked GitHub App installation, or an `--askpass-url` service that starts returning different/denied credentials).

### Impact Explanation
Any local process capable of reaching the credential-cache daemon's socket (any process sharing the container's UID/namespace — e.g., another container in the same pod with a shared process namespace, or anyone who can `exec` into the git-sync container) can retrieve the previously stored plaintext credentials for up to one hour after they should have been rotated or revoked. This is a credential-disclosure/extended-authorization-lifetime issue, matching the "Accept" criteria of credential/token disclosure due to persistent auth material outliving its intended validity.

### Likelihood Explanation
Requires only default git-sync operation with any credential-based auth mode (`--credential`/`--password-file`, `--askpass-url`, or GitHub App auth) — no attacker-controlled ref/commit content is needed, and no special flags beyond normal credential configuration are required, since `SetupDefaultGitConfigs` applies this setting unconditionally. The main precondition is local access to the container's credential-cache socket, which is realistic in shared-pod/sidecar deployments (git-sync's primary documented use case).

### Recommendation
- Make the credential cache timeout configurable and align it with the actual expected lifetime of the underlying credential (e.g., match GitHub App token TTL).
- Explicitly invalidate (`git credential-cache exit` or `git credential reject`) previously cached credentials before storing new ones in `refreshCreds`/`StoreCredentials`.
- Consider using `credential.helper=cache --timeout <short>` or a non-caching helper for highly dynamic credentials (askpass-url, GitHub App tokens) so stale secrets are not retrievable after rotation.

### Proof of Concept
1. Run git-sync with `--askpass-url` pointing at a service returning credential A.
2. After the first sync, `StoreCredentials` populates the `git-credential-cache--daemon` socket with credential A for 3600s (main.go:2276-2303, 2160-2184).
3. Rotate the askpass service to return credential B (simulating revocation of A).
4. Within the 3600s window, from a co-located process with access to the same cache socket, run `git credential fill` for the repo URL — the daemon still returns credential A even though it has been "revoked" upstream, demonstrating the extended-lifetime/stale-credential-disclosure analog of the reported session-persistence issue.

### Citations

**File:** main.go (L977-1018)
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

		if (*flGithubAppPrivateKeyFile != "" || *flGithubAppPrivateKey != "") && *flGithubAppInstallationID != 0 && (*flGithubAppApplicationID != 0 || *flGithubAppClientID != "") {
			if git.appTokenExpiry.Before(time.Now().Add(30 * time.Second)) {
				if err := git.RefreshGitHubAppToken(ctx, *flGithubBaseURL, *flGithubAppPrivateKey, *flGithubAppPrivateKeyFile, *flGithubAppClientID, *flGithubAppApplicationID, *flGithubAppInstallationID); err != nil {
					metricRefreshGitHubAppTokenCount.WithLabelValues(metricKeyError).Inc()
					return err
				}
				metricRefreshGitHubAppTokenCount.WithLabelValues(metricKeySuccess).Inc()
			}
		}

		return nil
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

**File:** main.go (L2263-2271)
```go
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
