### Title
`RefreshGitHubAppToken` records the new token expiry before the token is actually stored, causing stale-credential sync failures - ([File: main.go])

### Summary
`git.appTokenExpiry` is updated to the *new* token's expiration time before `StoreCredentials` has confirmed the new token was actually persisted to git's credential store. If `StoreCredentials` fails after the expiry field has already been mutated, subsequent sync loops will believe the (old, possibly already-invalid) credential is still fresh for up to ~10 minutes, and will not attempt to refresh it, causing git operations to fail with authentication errors on every following sync cycle.

### Finding Description
`RefreshGitHubAppToken` mints a JWT, exchanges it with GitHub for an installation access token, and is supposed to store that token as a git credential for subsequent `git fetch` calls: [1](#0-0) 

Note the ordering: `git.appTokenExpiry = tokenResponse.ExpiresAt` is executed at line 2263, **before** `git.StoreCredentials(...)` is called at line 2269. If `StoreCredentials` returns an error (e.g. the `git credential approve` subprocess fails, disk/credential-cache issue, context timeout, etc.), the function returns that error — but `git.appTokenExpiry` has already been permanently advanced to the new token's future expiry.

This field is the single gate that decides whether a refresh is attempted on the next sync cycle: [2](#0-1) 

Since `git.appTokenExpiry` now reflects the *new* (but never-stored) token's expiry, `refreshCreds` will see `git.appTokenExpiry.Before(time.Now().Add(30s))` as `false` and will skip calling `RefreshGitHubAppToken` again — even though the actual credential in git's credential store is still whatever was there before (either the old, soon/already-expired token, or nothing on first sync). Every subsequent `SyncRepo` call will then fail during `git fetch` with an authentication error, and no further attempt will be made to fix the credential until the previously-recorded (but never-applied) expiry passes.

This is the direct analog of the reported `setPrimeRate` bug: a piece of state that governs future behavior (`primeRate` / `appTokenExpiry`) is committed to storage *before* the dependent action that is supposed to make that state valid (recomputing accrued interest / actually storing the new credential) has completed. In both cases, an operation that should be atomic-or-none is split so that the "bookkeeping" update takes effect immediately while the underlying real state lags behind or never catches up, producing incorrect behavior for a window of time governed by stale/incorrect state.

### Impact Explanation
The result is a persistent sync-denial condition for GitHub App-authenticated repos: after a single transient `StoreCredentials` failure, git-sync will stop being able to authenticate against the remote repository and will keep failing every sync attempt (bounded by `--max-failures`, eventually causing the process to exit per the failure-count logic), without ever attempting to fix the actual root cause (a missing/stale stored credential), because the code believes the just-fetched-but-unstored token is still valid. This matches the "persistent sync denial" impact category.

### Likelihood Explanation
This requires GitHub App authentication mode to be configured (`--github-app-*` flags) and requires `StoreCredentials` (i.e. `git credential approve`) to fail on an otherwise successful token-fetch call — a scenario plausible under transient I/O errors, disk pressure, or context/timeout issues in the git subprocess invocation. This is not attacker-controlled in the sense of a malicious commit/ref, but it is a reachable, unprivileged operational failure mode triggered by ordinary error conditions in the running git-sync process, not requiring a malicious operator, leaked key, or malicious node.

### Recommendation
Only update `git.appTokenExpiry` after `StoreCredentials` has succeeded, e.g.:

```diff
-	git.appTokenExpiry = tokenResponse.ExpiresAt
-
 	// username must be non-empty
 	username := "-"
 	password := tokenResponse.Token
 
 	if err := git.StoreCredentials(ctx, git.repo, username, password); err != nil {
 		return err
 	}
+	git.appTokenExpiry = tokenResponse.ExpiresAt
 
 	return nil
```

This ensures the expiry bookkeeping only reflects a credential that has actually been committed to the git credential store, so a failed `StoreCredentials` call leaves `appTokenExpiry` untouched and the next sync cycle will retry the refresh.

### Proof of Concept
1. Configure git-sync with `--github-app-private-key-file`, `--github-app-application-id`/`--github-app-client-id`, `--github-app-installation-id`.
2. On the first sync, `RefreshGitHubAppToken` succeeds in fetching a token from GitHub (sets `git.appTokenExpiry` at line 2263) but `StoreCredentials` fails (e.g. simulate by making the `git credential approve` invocation fail — for instance via a full disk, a broken credential helper configuration, or a context cancellation between the two calls).
3. `RefreshGitHubAppToken` returns an error; `refreshCreds` returns an error via `SyncRepo`, so this sync attempt fails as expected.
4. On the next sync loop iteration, `refreshCreds` checks `git.appTokenExpiry.Before(time.Now().Add(30*time.Second))`, which is now `false` (since it holds a ~10-minute-future expiry from step 2), so `RefreshGitHubAppToken` is *not* invoked again.
5. `git fetch` in `SyncRepo` then fails authentication because no valid credential was ever stored, and this repeats every sync cycle until the stale `appTokenExpiry` value finally elapses (up to 10 minutes) — and even then, only a lucky retry restores service, since a single further storage failure regresses this again.

### Citations

**File:** main.go (L1008-1016)
```go
		if (*flGithubAppPrivateKeyFile != "" || *flGithubAppPrivateKey != "") && *flGithubAppInstallationID != 0 && (*flGithubAppApplicationID != 0 || *flGithubAppClientID != "") {
			if git.appTokenExpiry.Before(time.Now().Add(30 * time.Second)) {
				if err := git.RefreshGitHubAppToken(ctx, *flGithubBaseURL, *flGithubAppPrivateKey, *flGithubAppPrivateKeyFile, *flGithubAppClientID, *flGithubAppApplicationID, *flGithubAppInstallationID); err != nil {
					metricRefreshGitHubAppTokenCount.WithLabelValues(metricKeyError).Inc()
					return err
				}
				metricRefreshGitHubAppTokenCount.WithLabelValues(metricKeySuccess).Inc()
			}
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
