### Title
Credential Leakage to Attacker-Controlled Submodule URLs via Git's Host-Level Credential Matching - (File: main.go)

### Summary
`git-sync` stores HTTP credentials (from `--username`/`--password`, `--credential`, or `--askpass-url`) using `git credential approve`, scoped only to the configured `--repo` URL, and never sets `credential.useHttpPath`. When submodules are enabled, `git submodule update --init [--recursive]` fetches whatever URLs are declared in the tracked `.gitmodules` file — content that is fully attacker-controlled by anyone who can push a commit to the synced repository (or to a nested submodule repository). Because git's default credential-matching granularity is protocol+host (not full URL/path), any submodule URL on the same host as the main `--repo` will receive the same stored credentials, even though `updateOrder`-style re-validation of that target never occurs. This is a direct structural analog of the reported bug class: a value (`tokenOut` / the credentialed target) is validated once at "creation" time (when `--repo`/`--credential` is configured) but is silently redirected by attacker-controlled data before the privileged action (credential transmission / order fill) executes.

### Finding Description
`git-sync` configures credentials with: [1](#0-0) 

and refreshes them each sync cycle via `refreshCreds`, which calls `git.StoreCredentials(ctx, cred.URL, ...)` for each `--credential` entry and `git.CallAskPassURL` for the dynamic askpass case: [2](#0-1) [3](#0-2) 

The README documents that `--credential` exists specifically to support *multiple* username/password pairs "for specific URLs, for example when using submodules," and that all pairs are fed into `git credential approve`: [4](#0-3) [5](#0-4) 

Submodule checkout is performed unconditionally against whatever `.gitmodules` declares, with no validation that the submodule URL matches an expected host/path or the originally configured `--repo`/`--credential` set: [6](#0-5) 

Git's credential subsystem (`git credential fill`) by default matches stored credentials by **protocol and host only** — not the full path — unless `credential.useHttpPath` is explicitly enabled. `git-sync` never sets `credential.useHttpPath`. Consequently, if an attacker can modify `.gitmodules` in the synced repo (or in any nested submodule, since `submodules=recursive` walks arbitrarily deep) to point a submodule at a different repository path on the **same host** as a previously-credentialed URL (e.g., a different, attacker-owned repo on `github.com` or a shared self-hosted GitLab/Gitea instance), git will transparently send the stored username/password (or askpass-url-provided token) to that attacker-controlled repository during `submodule update --init`.

This mirrors the reported bug precisely: `order.tokenOut` was validated against `marginPos.baseAsset`/`quoteAsset` only at order creation, but `updateOrder` allowed it to be redirected to an arbitrary value before the privileged `fillOrder` action executed, with the executor's pre-existing approval being reused against the new target. Here, the credentials/"approval" (`git credential approve`) are established for one URL, but attacker-controlled repository content (`.gitmodules`, editable by anyone with push access or by a compromised/malicious nested submodule maintainer) can retarget which endpoint actually receives that approval at fetch time, because host-level matching means the approval is not re-validated against the originally intended path.

### Impact Explanation
Successful exploitation discloses git-sync's configured HTTP credentials (username/password, or a short-lived askpass/GitHub App token depending on configuration) to an attacker-controlled repository hosted on the same domain as the legitimate target. This is a credential/token disclosure impact, which is explicitly in-scope. Depending on the credential's actual scope (e.g., a broadly-scoped PAT rather than a repo-scoped deploy token), this could allow the attacker to pivot to reading/writing other private repositories accessible with that credential.

### Likelihood Explanation
Likelihood is moderate to high in realistic deployments: `--submodules` recursion is a supported, documented feature, `.gitmodules` content is fully attacker-influenced whenever the synced repo (or any transitively-included submodule) accepts contributions from a less-trusted party, and git's host-level credential matching is git's actual default behavior (git-sync does not opt into path-scoped matching). No special git-sync flags beyond `--submodules=recursive` (or the default non-off submodule mode) and credential-based auth are required.

### Recommendation
- Set `credential.useHttpPath = true` (or an equivalent per-URL credential scoping mechanism) when storing credentials via `git credential approve`, so that git only replays a credential for the exact URL/path it was issued for.
- Optionally, restrict/validate submodule URLs against an explicit allow-list (host or repo) before running `submodule update`, or require explicit opt-in for credential reuse across submodule hosts.
- Document clearly that using `--username`/`--password`, `--credential`, or `--askpass-url` in combination with recursive submodules can leak credentials to any repository on the same host referenced by `.gitmodules`.

### Proof of Concept
1. Configure `git-sync` with `--repo=https://git.example.com/org/main-repo`, `--submodules=recursive`, and credentials (e.g. `--username`/`$GITSYNC_PASSWORD`) for `https://git.example.com`.
2. An attacker with push access to `org/main-repo` (or to any nested submodule reachable via recursive submodule updates) adds/edits `.gitmodules` to declare a submodule pointing at `https://git.example.com/attacker/evil-repo`.
3. On the next sync cycle, `git-sync` calls `configureWorktree`, which runs `git submodule update --init --recursive` [6](#0-5)  against the attacker's repo path.
4. Because git matches stored credentials by host (protocol+host) and `credential.useHttpPath` is never set (see `StoreCredentials`, [1](#0-0) ), git transparently sends the stored username/password to `https://git.example.com/attacker/evil-repo`, which the attacker's server logs, disclosing the credential.

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

**File:** README.md (L249-268)
```markdown
    --credential <string>, $GITSYNC_CREDENTIAL
            Make one or more credentials available for authentication (see git
            help credential).  This is similar to --username and
            $GITSYNC_PASSWORD or --password-file, but for specific URLs, for
            example when using submodules.  The value for this flag is either a
            JSON-encoded object (see the schema below) or a JSON-encoded list
            of that same object type.  This flag may be specified more than
            once.

            Object schema:
              - url:            string, required
              - username:       string, required
              - password:       string, optional
              - password-file:  string, optional

            One of password or password-file must be specified.  Users should
            prefer password-file for better security.

            Example:
              --credential='{"url":"https://github.com", "username":"myname", "password-file":"/creds/mypass"}'
```

**File:** README.md (L620-624)
```markdown
            When using submodules it may be necessary to specify more than one
            username and password, which can be done with --credential
            ($GITSYNC_CREDENTIAL).  All of the username+password pairs, from
            both --username/$GITSYNC_PASSWORD and --credential are fed into
            'git credential approve'.
```
