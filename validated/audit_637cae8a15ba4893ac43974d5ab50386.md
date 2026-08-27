### Title
Overly long git credential cache timeout leaves stored auth tokens accessible without re-authentication - (File: main.go)

### Summary
`SetupDefaultGitConfigs` configures git globally to use `credential.helper = cache --timeout 3600`, meaning any username/password, `--askpass-url` response, or GitHub App token that git-sync stores via `git credential approve` (`StoreCredentials`) is cached in memory by the `git-credential-cache--daemon` for a full hour, and is retrievable via that daemon's Unix domain socket by any process able to reach it, with no equivalent of re-authentication or automatic lock after inactivity. [1](#0-0) 

### Finding Description
git-sync globally sets `credential.helper` to `cache --timeout 3600` as part of its default git configuration, applied once at startup before any sync. [2](#0-1) 
Credentials -- from `--credential`/`--username`+`--password-file`, from `--askpass-url` responses, or GitHub App installation tokens -- are all funneled into `StoreCredentials`, which pipes `url/username/password` into `git credential approve`. [3](#0-2) [4](#0-3) [5](#0-4) 
Because the configured helper is `cache` (not `store` to disk, but an in-memory daemon reachable over a Unix socket) with a 3600-second timeout, once any credential is approved it remains servable from the daemon's socket for up to an hour regardless of whether git-sync is actively syncing, analogous to a "wallet" that stays "unlocked" for a fixed window with no activity-based re-lock. This is the closest analog to "lack of auto-lock": there is no mechanism to shorten/invalidate the cache window based on inactivity, config, or event (e.g., after a sync failure, credential rotation, or process idle time) — the value is a fixed hard-coded constant.

### Impact Explanation
Any local process capable of connecting to the git-credential-cache Unix socket (which is scoped by UID/HOME under typical git implementations) during the 3600-second window can retrieve the cached username/password or GitHub App token without needing to trigger git-sync's own credential-fetch/refresh logic again. In multi-tenant or shared-filesystem/container scenarios where `--add-user`/UID sharing or shared `HOME` is used, or where a sidecar/exec-hook has local access, this extends the exposure window for tokens well beyond their operational need, and beyond git-sync's own explicit rotation checks (e.g. the 30-second-before-expiry refresh for GitHub App tokens performed in `refreshCreds`). [6](#0-5) 

### Likelihood Explanation
This requires local/process-level access to the same host/UID as the git-sync process to reach the credential-cache socket — it is not remotely exploitable and does not by itself allow arbitrary code execution, file write, or network-based credential disclosure. It is a hardening gap analogous to "no auto-lock," reachable only by an already-privileged local actor (e.g., another container/process sharing the pod's IPC/PID or filesystem namespace), which is a comparatively narrow attack surface.

### Recommendation
Make the `credential.helper` cache timeout configurable (e.g. via a new `--credential-cache-timeout` flag), default it to a much shorter value tied to the sync `--period`, and/or explicitly flush (`git credential-cache exit`) or re-approve credentials after each sync cycle so that no credential remains servable from the cache daemon longer than necessary between syncs.

### Proof of Concept
Not independently verifiable without a running multi-tenant/shared-HOME deployment; this is a configuration/design-level analog rather than a demonstrated exploit: the fixed `cache --timeout 3600` setting at [7](#0-6)  combined with `StoreCredentials` approving secrets into that cache [8](#0-7)  is the mechanism; exploitation would require local access to the credential-cache daemon socket during the cache window, which is outside the scope of what can be proven from the repository content alone.

### Citations

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

**File:** main.go (L2165-2182)
```go
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

**File:** main.go (L2265-2271)
```go
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
