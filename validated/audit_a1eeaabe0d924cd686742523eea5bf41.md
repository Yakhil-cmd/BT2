### Title
Stale/overbroad credential approvals can be replayed against different repo paths on the same host due to missing `credential.useHttpPath` - (File: main.go)

### Summary
`git-sync` supports registering multiple username/password pairs (one for the main `--repo` and one or more via `--credential` for submodules) by calling `git credential approve` for each entry [1](#0-0) . All of these are handed to git's `credential.helper cache --timeout 3600`, configured once, globally, for the life of the process [2](#0-1) . `git-sync` never sets `credential.useHttpPath`, so the cache helper (like git's built-in credential matching) keys stored credentials by protocol+host only, not by full URL/path. This is directly analogous to the `OwnableSmartWallet` bug: a set of "approvals" (credentials) is granted for distinct intended recipients (URLs), but the underlying storage mechanism does not scope/revoke them precisely enough, so an approval granted for one target can be unexpectedly consumed by another target that shares the same "identity" (host) — just as User A's un-revoked approval for User C could be replayed once ownership returned to User A.

### Finding Description
- `refreshCreds` iterates over all `--credential` entries and the top-level `--username`/`--password`, calling `git.StoreCredentials` for each one, which runs `git credential approve` with `url=<value>` [3](#0-2) [1](#0-0) .
- The README explicitly documents this multi-credential mechanism as being for cases "using submodules it may be necessary to specify more than one username and password" [4](#0-3) .
- `SetupDefaultGitConfigs` sets `credential.helper` to `cache --timeout 3600` globally, but does **not** set `credential.useHttpPath` [2](#0-1) .
- Per git's documented credential-matching behavior, when `credential.useHttpPath` is unset (the default), `git credential fill`/the cache helper matches purely on `protocol`+`host`, ignoring the `path` component. This means once two different credentials are "approved" for two different paths on the *same host* (e.g. `https://git.example.com/org/main-repo` and `https://git.example.com/org/private-submodule`), git may hand out whichever cached credential matches host, not necessarily the one intended for that specific path — an unintended cross-use of an "approval," mirroring the `OwnableSmartWallet` pattern where the revocation/isolation of one approval does not fully account for other, still-valid approvals tied to the same actor.
- The end-to-end test suite even demonstrates the multi-credential submodule flow (`e2e::submodule_sync_over_http_different_passwords`) using different hosts (different container IPs) to avoid exactly this ambiguity [5](#0-4) , which implicitly confirms the host-only scoping assumption is relied upon and only avoided by test setup (different hosts), not by explicit code that enforces per-path isolation.

### Impact Explanation
If a synced repository (attacker-influenced content, since `--repo`/`.gitmodules` can point to submodules under attacker control) adds or updates a `.gitmodules` entry pointing to a different path on the *same host* as another `--credential` entry configured by the operator, git-sync's cached-by-host credentials could be sent to that new, attacker-chosen path. This is a credential/token disclosure to an unintended endpoint — one of the explicitly accepted impacts (credential or token disclosure) — reachable purely from repo content (a malicious `.gitmodules` submodule URL) that the operator did not intend to receive those credentials.

### Likelihood Explanation
Requires: (1) the operator to configure more than one `--credential`/`--username` pair (a documented, supported multi-credential/submodule use case), and (2) those distinct credentials to share a host but differ by path, and (3) attacker control (via a malicious commit/ref or malicious submodule addition) of a `.gitmodules` entry that repoints a submodule to a different path on that same host. This is a realistic scenario for submodule-heavy setups against a single git server (e.g., a self-hosted GitLab/Gitea instance hosting multiple repos under one host), making likelihood moderate rather than purely theoretical.

### Recommendation
Set `credential.useHttpPath = true` (or otherwise scope credential storage/lookup by full URL, not just host) in `SetupDefaultGitConfigs`, and/or store/approve credentials with an explicit host+path binding so that credentials supplied for one repository path cannot be replayed against another path on the same host merely because a submodule URL changes.

### Proof of Concept
1. Operator runs `git-sync` with two `--credential` entries for the same host but different paths, e.g.:
   - `--credential='{"url":"https://git.example.com/org/main-repo","username":"main-user","password-file":"/creds/main"}'`
   - `--credential='{"url":"https://git.example.com/org/private-submodule","username":"restricted-user","password-file":"/creds/restricted"}'`
2. Both are approved into the global `credential.helper cache` via `StoreCredentials` [1](#0-0) , with no `credential.useHttpPath` configured [2](#0-1) .
3. An attacker who can push a commit/ref to the synced main repo (or a submodule) modifies `.gitmodules` to add/point a submodule at `https://git.example.com/org/other-private-repo` (same host, different path) that they do not otherwise have credentials for.
4. During `git submodule update`, git's credential cache helper matches by host only and may supply the `main-user`/`restricted-user` credential to the attacker-chosen path, since path is not part of the cache lookup key without `credential.useHttpPath`.
5. The credential is now used against a path the operator never intended it for — a disclosure/misuse of an approved credential, analogous to User C's stale approval being exercised unexpectedly in the original report.

Note: I could not execute git or inspect the live cache-helper socket behavior in this environment to directly confirm the exact matching semantics at runtime; this analysis is based on the documented git credential-matching behavior (`credential.useHttpPath`) combined with the observed configuration in `SetupDefaultGitConfigs` and `StoreCredentials`. A Devin session with a sandbox could confirm this experimentally.

### Citations

**File:** main.go (L977-997)
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

**File:** README.md (L620-624)
```markdown
            When using submodules it may be necessary to specify more than one
            username and password, which can be done with --credential
            ($GITSYNC_CREDENTIAL).  All of the username+password pairs, from
            both --username/$GITSYNC_PASSWORD and --credential are fed into
            'git credential approve'.
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
