### Title
Credential cache is scoped by host, not by full repo URL, allowing an attacker-controlled submodule on the same host to reuse git-sync's credentials - (File: main.go)

### Summary
`git-sync` stores HTTP(S) credentials by calling `git credential approve` and configures the credential backend as an in-memory cache with no host-path scoping, so any repository content (including a submodule URL defined inside the synced, attacker-influenced repo) that targets the same host as the primary `--repo` can retrieve and reuse those cached credentials.

### Finding Description
`repoSync.SetupDefaultGitConfigs` sets `credential.helper` to `cache --timeout 3600` globally, with no `credential.useHttpPath` setting [1](#0-0) . Git's credential subsystem, when `useHttpPath` is not enabled, matches stored credentials by `protocol://host[:port]` only — not by the full path/repo. `repoSync.StoreCredentials` approves credentials for a given URL by piping `url=...\nusername=...\npassword=...` into `git credential approve` [2](#0-1) . This is invoked both for the primary `--repo`/`--username`/`--password` flow and for the `--askpass-url` / GitHub App token flow, always keyed off `git.repo` (or a `--credential` entry's URL) [3](#0-2) [4](#0-3) [5](#0-4) .

Because the cache keys on host rather than the exact repo path, once a credential has been approved for `https://host/private-repo`, any other clone/fetch that git performs against `https://host/*` — including a submodule fetch — will match the cached entry and receive the same username/password or token. Submodule URLs are defined in `.gitmodules`, which is untrusted content that lives inside the very repository being synced. git-sync's own tests demonstrate multiple credentials being configured for different submodule URLs specifically to work around ambiguity in credential resolution [6](#0-5) , which corroborates that git-sync relies on the operator supplying distinct `--credential` entries per URL rather than relying on any code-level isolation — there is no host-path scoping enforced by git-sync itself.

This is the closest reachable analog to the reported bug class: the original report is about privileged state (`pendingGov`/`emergency_gov`) that is not fully cleared/scoped when access should be revoked, letting an outside actor reclaim access through a leftover credential path. Here, the "leftover, over-broad" credential state is the host-scoped `git credential cache`, and the "outside actor" is attacker-controlled repository content (a `.gitmodules` submodule URL) that can piggyback on credentials it was never meant to receive.

### Impact Explanation
If a repository being synced (or a submodule reachable from it) is attacker-influenced — e.g., an untrusted or compromised submodule dependency, or a repo owner adds a submodule pointing at another path on the same host as the primary credentialed repo — that submodule fetch will silently receive the operator's primary username/password, `--askpass-url` token, or GitHub App installation token. This can disclose credentials/tokens to a party who controls only the submodule reference, not the credentials themselves, and could be leveraged to access other private repositories on the same host. This aligns with "credential or token disclosure" as an accepted impact category.

### Likelihood Explanation
Likelihood is moderate and depends on operator configuration: it requires (a) HTTP(S) authentication configured via `--username`/`--password(-file)`, `--askpass-url`, or GitHub App auth, and (b) the synced repository containing (or later adding) a submodule that resolves to the same host as the credentialed repo but a different path/repo the operator did not intend to expose credentials to. Because submodule definitions are part of the tracked repository content, an attacker who can influence any commit that git-sync syncs (e.g., via a compromised branch/PR merged into the tracked ref, or a compromised transitive submodule) can introduce such a submodule URL without any special git-sync flags being required beyond normal HTTP(S) credential usage.

### Recommendation
- Set `credential.useHttpPath=true` in `SetupDefaultGitConfigs` (or when storing credentials) so cached credentials are scoped to the exact path, not just host, reducing cross-repo credential bleed. Note this is a behavior change and needs care since git-sync intentionally supports one credential covering multiple paths via `--credential`.
- Alternatively/additionally, restrict submodule recursion to explicitly allow-listed URLs (already the direction of the `--credential` object schema which requires an explicit URL) and warn/reject when an untrusted submodule URL shares a host with a credentialed URL it wasn't explicitly declared for.
- Document this credential-scoping behavior clearly for operators using submodules with `--username`/`--password` or `--askpass-url` on multi-tenant git hosts.

### Proof of Concept
1. Configure `git-sync` with `--repo=https://git.example.com/org/private-repo` and `--username=svc --password-file=/secret/token`.
2. `git.StoreCredentials` runs `git credential approve` for `url=https://git.example.com/org/private-repo` [2](#0-1) ; with the default `credential.helper=cache` and no `useHttpPath`, this is cached keyed on `https://git.example.com`.
3. An attacker who can add a commit to `org/private-repo` (e.g. via a merged PR) adds a `.gitmodules` entry pointing to `https://git.example.com/org/other-repo` — a repo the attacker controls or wants to read, on the same host.
4. On the next sync, `git submodule update` fetches `https://git.example.com/org/other-repo`; because host matches, git's credential cache returns the same `svc`/token credentials, which are transmitted to (and potentially logged/observed by) the attacker-controlled repo endpoint, disclosing the token.

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

**File:** main.go (L2166-2185)
```go
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

**File:** main.go (L2263-2274)
```go
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

**File:** test_e2e.sh (L3367-3446)
```shellscript
function e2e::submodule_sync_over_http_different_passwords() {
    # Init nested submodule repo
    local nested_submodule_repo_name="nested-sub"
    local nested_submodule="$WORK/$nested_submodule_repo_name"
    mkdir "$nested_submodule"

    git -C "$nested_submodule" init -q -b "$MAIN_BRANCH"
    echo "nested-submodule" > "$nested_submodule/nested-submodule.file"
    git -C "$nested_submodule" add nested-submodule.file
    git -C "$nested_submodule" commit -aqm "init nested-submodule.file"

    # Run a git-over-SSH server.  Use password "test1".
    # shellcheck disable=SC2016
    echo 'test:$apr1$cXiFWR90$Pmoz7T8kEmlpC9Bpj4MX3.' > "$WORK/htpasswd.1"
    local ctr_subsub
    ctr_subsub=$(docker_run \
        -v "$nested_submodule":/git/repo:ro \
        -v "$WORK/htpasswd.1":/etc/htpasswd:ro \
        e2e/test/httpd)
    local ip_subsub
    ip_subsub=$(docker_ip "$ctr_subsub")

    # Init submodule repo
    local submodule_repo_name="sub"
    local submodule="$WORK/$submodule_repo_name"
    mkdir "$submodule"

    git -C "$submodule" init -q -b "$MAIN_BRANCH"
    echo "submodule" > "$submodule/submodule.file"
    git -C "$submodule" add submodule.file
    git -C "$submodule" commit -aqm "init submodule.file"

    # Add nested submodule to submodule repo
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
        &
    wait_for_sync "${MAXWAIT}"
    assert_link_exists "$ROOT/link"
    assert_file_exists "$ROOT/link/file"
    assert_file_exists "$ROOT/link/$submodule_repo_name/submodule.file"
    assert_file_exists "$ROOT/link/$submodule_repo_name/$nested_submodule_repo_name/nested-submodule.file"
    assert_metric_eq "${METRIC_GOOD_SYNC_COUNT}" 1
```
