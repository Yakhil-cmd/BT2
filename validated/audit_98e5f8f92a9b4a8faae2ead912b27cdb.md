Confirmed root cause chain: `SyncRepo` calls `syncHooks.refreshCreds(ctx)` first thing [1](#0-0) , which — when `--askpass-url` or GitHub App auth is configured — makes a hard external network call with no fallback: `git.CallAskPassURL(ctx)` [2](#0-1)  or `git.RefreshGitHubAppToken(ctx, ...)` [3](#0-2) . Any non-2xx/timeout from that dependency returns an error that aborts the whole sync attempt before `git.fetch` even runs [4](#0-3) . In the main loop, that failure is counted and, since `--max-failures` defaults to `0` ("any sync failure will terminate git-sync") [5](#0-4) , the process calls `os.Exit(1)` on the very first failure by default [6](#0-5) .

### Title
Unhandled failure of external credential-refresh dependency (askpass-url/GitHub App token endpoint) causes persistent sync denial - (File: main.go)

### Summary
`refreshCreds`, invoked at the start of every `SyncRepo` iteration, performs a blocking HTTP call to an external, potentially transient dependency (the `--askpass-url` endpoint or GitHub's app-token API) with no retry/backoff/circuit-breaker logic of its own. Any single failure of that external endpoint propagates as a sync failure, and because `--max-failures` defaults to `0`, git-sync terminates the whole process on the very first such failure.

### Finding Description
`SyncRepo` unconditionally calls `syncHooks.refreshCreds(ctx)` before any fetch/checkout work [1](#0-0) . That closure, built in `main()`, performs two external network dependencies with no fallback path: `git.CallAskPassURL(ctx)` (a plain `http.Client` GET with a 1s timeout and no retry) [2](#0-1) , and `git.RefreshGitHubAppToken(ctx, ...)` (a POST to the GitHub App installation-token API, again with a single attempt) [7](#0-6) . Both simply `return err` on any non-success status or network error, with no try/catch-and-continue, cached-token fallback, or graceful degrade [8](#0-7) [9](#0-8) . That error is wrapped and bubbled all the way out of `SyncRepo` [10](#0-9) , and in the main sync loop it increments `failCount`; with the documented default `--max-failures=0` ("any sync failure will terminate git-sync") [11](#0-10) , the process calls `os.Exit(1)` on the very first transient outage of the askpass/GitHub-App endpoint [12](#0-11) .

### Impact Explanation
Unlike the referenced oracle example (where the underlying protocol merely pauses liquidations until Chainlink recovers), here the default behavior is worse: the sidecar container exits entirely and Kubernetes must restart the pod to retry. If the askpass URL or GitHub App API is briefly unreachable/rate-limited (a routine, non-malicious condition), the operator experiences persistent sync denial of the `--link` contract — the published data goes stale and no new commits are ever synced until the container is manually/automatically restarted, repeating the same failure if the outage persists across restarts.

### Likelihood Explanation
This is reachable with default configuration whenever `--askpass-url` or GitHub App authentication is used — both are documented, supported first-class authentication modes [4](#0-3) . Any transient blip of the credential-fetching dependency (metadata server hiccup, GitHub API rate limit/outage, DNS flake within the 1s askpass timeout) triggers it, and `--max-failures` defaults to `0`, so the process aborts immediately without operator intervention needed to trigger the bug — only the default configuration and a widely-used auth mode are required.

### Recommendation
Do not let a single credential-refresh failure be fatal under the default (`--max-failures=0`) configuration: either (a) make `--max-failures` default to a small positive retry budget so transient dependency failures don't immediately terminate the container, and/or (b) cache the last-known-good token/credentials and only fail the whole sync if the cached credential itself has expired, with clear error surfacing (via `--error-file`/metrics) rather than immediate `os.Exit(1)`. This preserves the existing atomic-symlink publish guarantee while avoiding unnecessary persistent denial from a single external dependency hiccup.

### Proof of Concept
1. Run `git-sync --repo=<repo> --root=<root> --link=link --askpass-url=http://127.0.0.1:9/creds` (a URL that refuses connections) with default flags (no `--max-failures` override).
2. On the first loop iteration, `refreshCreds` calls `git.CallAskPassURL`, which fails immediately (connection refused) [13](#0-12) .
3. `SyncRepo` returns the wrapped error before ever calling `git.fetch` [10](#0-9) .
4. In the main loop, `failCount` becomes `1`, `getMaxFailures()` returns `0` (default), so `1 >= 0` is true and git-sync logs "too many failures, aborting" and calls `os.Exit(1)` [12](#0-11) .
5. The container exits; no data is ever synced or re-synced unless something outside git-sync restarts it and the dependency has since recovered — demonstrating persistent sync denial triggered purely by a transient external dependency outage.

### Citations

**File:** main.go (L213-215)
```go
	flMaxFailures := pflag.Int("max-failures",
		envInt(0, "GITSYNC_MAX_FAILURES", "GIT_SYNC_MAX_FAILURES"),
		"the number of consecutive failures allowed before aborting (-1 will retry forever")
```

**File:** main.go (L998-1016)
```go
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
```

**File:** main.go (L1056-1063)
```go
		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
```

**File:** main.go (L1861-1866)
```go
func (git *repoSync) SyncRepo(ctx context.Context, syncHooks syncHooks) (bool, string, error) {
	git.log.V(3).Info("syncing", "repo", redactURL(git.repo))

	if err := syncHooks.refreshCreds(ctx); err != nil {
		return false, "", fmt.Errorf("credential refresh failed: %w", err)
	}
```

**File:** main.go (L2133-2159)
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
```

**File:** main.go (L2189-2253)
```go
func (git *repoSync) RefreshGitHubAppToken(ctx context.Context, githubBaseURL, privateKey, privateKeyFile, clientID string, appID, installationID int) error {
	git.log.V(3).Info("refreshing GitHub app token")

	privateKeyBytes := []byte(privateKey)
	if privateKey == "" {
		b, err := os.ReadFile(privateKeyFile)
		if err != nil {
			git.log.Error(err, "can't read private key file", "file", privateKeyFile)
			os.Exit(1)
		}

		privateKeyBytes = b
	}

	pkey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return err
	}

	now := time.Now()

	// either client ID or app ID can be used when minting JWTs
	issuer := clientID
	if issuer == "" {
		issuer = strconv.Itoa(appID)
	}

	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}

	jwt, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(pkey)
	if err != nil {
		return err
	}

	url, err := url.JoinPath(githubBaseURL, fmt.Sprintf("app/installations/%d/access_tokens", installationID))
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusCreated {
		errMessage, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("GitHub app installation endpoint returned status %d, failed to read body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("GitHub app installation endpoint returned status %d, body: %q", resp.StatusCode, string(errMessage))
	}
```

**File:** README.md (L442-446)
```markdown
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```
