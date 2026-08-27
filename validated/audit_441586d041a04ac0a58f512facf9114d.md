Based on investigation, there is a plausible analog in git-sync's credential handling: credentials are stored keyed by full URL via `git credential approve`, but git's credential matching for helpers (including the `cache` helper that git-sync configures) defaults to matching by **protocol + host only** unless `credential.useHttpPath` is enabled. git-sync never sets `credential.useHttpPath`, and it enables recursive submodule following on synced (attacker-influenced) content by default.

### Title
Git credentials configured for `--repo` are host-scoped and get replayed to attacker-controlled submodule URLs on the same host - ([File: main.go])

### Summary
git-sync stores the operator's git credentials (via `--username`/`$GITSYNC_PASSWORD`, `--credential`, or `--askpass-url`) using `git credential approve` against the `--repo` URL, then lets git recursively resolve and fetch submodules declared inside the synced (untrusted) repository content. Because `credential.useHttpPath` is never configured, git's credential subsystem matches stored credentials by protocol+host, not by full path, so any submodule URL that shares the same host as `--repo` will silently receive the same stored username/password or token when git fetches it.

### Finding Description
`SetupDefaultGitConfigs` sets `credential.helper` to `cache --timeout 3600` globally, with no `credential.useHttpPath` setting [1](#0-0) . Credentials are populated into that cache via `StoreCredentials`, which calls `git credential approve` with the operator-provided `url`, `username`, and `password` [2](#0-1) . These credentials come from `--username`/`$GITSYNC_PASSWORD`, `--credential` entries, `--askpass-url` responses, or GitHub App tokens, and are refreshed on every sync via `refreshCreds` [3](#0-2) .

Separately, `configureWorktree` runs `git submodule update --init [--recursive]` on every synced worktree whenever `--submodules` is not `off` (the default is `recursive`) [4](#0-3) . Submodule URLs come from `.gitmodules`, which is untrusted content controlled by whoever can push to the synced ref/branch of `--repo`.

Because git's built-in credential matching (used by the `cache` helper) defaults to protocol+host granularity, a stored credential for `https://github.com/org/private-repo` will also be handed to git when it fetches `https://github.com/attacker/public-repo` — any repo on `github.com` — unless `credential.useHttpPath=true` is set. git-sync's e2e tests even demonstrate multiple distinct credentials being approved per submodule URL to work around this ambiguity [5](#0-4) , but nothing in the codebase forces path-scoped matching to protect the operator's primary repo credential from being replayed to an attacker-introduced submodule on the same host.

### Impact Explanation
An attacker who can introduce or modify a `.gitmodules` entry in the synced repository/ref (e.g., via a merged PR, a writable branch, or a compromised low-privilege collaborator) can point a submodule at an attacker-controlled repository on the same git host as `--repo`. When git-sync recursively updates submodules, git will present the operator's cached `--repo` credentials (username/password, PAT, or short-lived GitHub App/askpass token) to the attacker's endpoint during the HTTP Basic-Auth exchange, disclosing them to the attacker. This is a credential/token disclosure vulnerability reachable purely from attacker-pushed repo content, matching the "credential or token disclosure" impact category.

### Likelihood Explanation
Requires: (1) `--submodules` not set to `off` (recursive is the default), (2) HTTP(S) authentication configured (`--username`/`--password-file`, `--credential`, or `--askpass-url`) rather than SSH, and (3) the attacker being able to influence `.gitmodules` content on the synced ref (e.g., contributor with push/PR-merge access, or a monitored ref that accepts external content) with a submodule URL sharing the host of `--repo`. This is a realistic scenario for CI/CD or GitOps pipelines syncing developer-writable repos with a broadly-scoped PAT, making likelihood moderate.

### Recommendation
Set `credential.useHttpPath=true` globally in `SetupDefaultGitConfigs`, or scope stored credentials strictly to the exact repo path (not just host) and disable submodule credential reuse across differing paths by default. Additionally, document/warn operators that `--submodules=recursive` combined with host-wide credentials (username/password, askpass, GitHub App tokens) can leak those credentials to any submodule hosted on the same domain, and recommend `--credential` with explicit per-URL scoping (as already supported) instead of a single broad `--username`/`--password-file` when recursive submodules are enabled on untrusted content.

### Proof of Concept
1. Configure git-sync against a repo the operator controls with a broadly-scoped token:
   `git-sync --repo=https://github.com/org/private-repo --username=x-access-token --password-file=/creds/token --submodules=recursive --root=/mnt/git`
2. An attacker with push/merge rights to a branch/ref being synced adds `.gitmodules` referencing `https://github.com/attacker/evil-repo` as a submodule and commits it.
3. On next sync, `configureWorktree` runs `git submodule update --init --recursive` [4](#0-3) ; git's credential cache (populated by `StoreCredentials` against `org/private-repo`) matches `github.com` by host and sends the same Basic-Auth credentials to `attacker/evil-repo`.
4. The attacker's git server logs the `Authorization` header, capturing the operator's token.

### Citations

**File:** main.go (L977-1019)
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

**File:** test_e2e.sh (L3400-3439)
```shellscript
    echo -ne "url=http://$ip_subsub/repo\nusername=test\npassword=test1\n" | git credential approve
    git -C "$submodule" submodule add -q "http://$ip_subsub/repo" "$nested_submodule_repo_name"
    git -C "$submodule" commit -aqm "add nested submodule"

    # Run a git-over-SSH server.  Use password "test2".
    # shellcheck disable=SC2016
    echo 'test:$apr1$vWBoWUBS$2H.WFxF8T7rH/gZF99Edl/' > "$WORK/htpasswd.2"
    local ctr_sub
    ctr_sub=$(docker_run \
        -v "$submodule":/git/repo:ro \
        -v "$WORK/htpasswd.2":/etc/htpasswd:ro \
        e2e/test/httpd)
    local ip_sub
    ip_sub=$(docker_ip "$ctr_sub")

    # Add the submodule to the main repo
    echo -ne "url=http://$ip_sub/repo\nusername=test\npassword=test2\n" | git credential approve
    git -C "$REPO" submodule add -q "http://$ip_sub/repo" "$submodule_repo_name"
    git -C "$REPO" commit -aqm "add submodule"
    git -C "$REPO" submodule update --recursive --remote > /dev/null 2>&1

    # Run a git-over-SSH server.  Use password "test3".
    # shellcheck disable=SC2016
    echo 'test:$apr1$oKP2oGwp$ESJ4FESEP/8Sisy02B/vM/' > "$WORK/htpasswd.3"
    local ctr
    ctr=$(docker_run \
        -v "$REPO":/git/repo:ro \
        -v "$WORK/htpasswd.3":/etc/htpasswd:ro \
        e2e/test/httpd)
    local ip
    ip=$(docker_ip "$ctr")

    GIT_SYNC \
        --period=100ms \
        --repo="http://$ip/repo" \
        --root="$ROOT" \
        --link="link" \
        --credential="{ \"url\": \"http://$ip_subsub/repo\", \"username\": \"test\", \"password\": \"test1\" }" \
        --credential="{ \"url\": \"http://$ip_sub/repo\", \"username\": \"test\", \"password\": \"test2\" }" \
        --credential="{ \"url\": \"http://$ip/repo\", \"username\": \"test\", \"password\": \"test3\" }" \
```
