### Title
Unsanitized GraphQL `viewer.login` username enables terminal escape-sequence injection into gh's trusted ErrOut messages - ([File: pkg/cmd/auth/switch/switch.go])

### Summary
`switchRun` writes the `username` value directly into `cs.Bold(username)` and then into `fmt.Fprintf(opts.IO.ErrOut, ...)` without any sanitization of control/escape bytes [1](#0-0) . This `username` is not limited to values the victim typed at the CLI — it can also be the value stored during `gh auth login`, which comes verbatim from the `viewer.login` field of a GraphQL response returned by whatever GitHub Enterprise host the victim points `gh` at [2](#0-1) . Since no username format/character validation exists anywhere in the login or switch code path, a malicious/compromised GHES host can return an attacker-chosen string containing raw ANSI/terminal escape sequences that later gets replayed unescaped by `gh auth switch` (and also by `gh auth login`) success/failure messages.

### Finding Description
- The username reaching `switch.go`'s `cs.Bold(username)` calls originates either from the `--user` flag (victim-controlled, not attacker-controlled) or from `cfg.Authentication().UsersForHost(host)` — usernames persisted to the local config during `gh auth login` [3](#0-2) .
- During `gh auth login --with-token`, the username is fetched via `shared.GetCurrentLogin`, which issues a raw GraphQL `UserCurrent{viewer{login}}` query and decodes `result.Data.Viewer.Login` directly from the HTTP response body with no validation of its contents [2](#0-1) . The same unvalidated pattern is repeated in `api.CurrentLoginName` [4](#0-3) .
- That username is then persisted verbatim via `authCfg.Login(hostname, username, ...)` and echoed to the terminal in the login success message: `fmt.Fprintf(opts.IO.ErrOut, "%s Logged in as %s\n", cs.SuccessIcon(), cs.Bold(username))` (as seen in the `login_flow_test.go` expected output `"✓ Logged in as monalisa"`).
- I searched the codebase for any username validation (regex, allowlist of GitHub-username characters) and found none in the login/config/switch code paths — the only matches for "ValidateUsername" were unrelated to codespaces RPC.
- `cs.Bold()` in `pkg/iostreams/color.go` simply wraps the string with ANSI bold codes; it performs no stripping/escaping of embedded control bytes in the input string itself.
- Consequently, if a victim runs `gh auth login --hostname evil.example.com --with-token` (or interactively authenticates against an attacker-controlled/compromised GHE Server the victim has chosen to trust) and the attacker's GraphQL endpoint returns `{"viewer":{"login":"monalisa\u001b[2K\rFAKE TRUSTED MESSAGE"}}`, that raw string is stored as the account's username and is later replayed unsanitized both immediately at login time and every time the user runs `gh auth switch` thereafter, allowing the attacker to inject arbitrary terminal control sequences (cursor movement, line clearing, color resets) into `gh`'s own "trusted" stderr output stream.

### Impact Explanation
This allows terminal output spoofing/injection: an attacker who controls a self-hosted GitHub Enterprise Server endpoint that the victim has configured `gh` to authenticate against can inject ANSI/control sequences into `gh auth switch` and `gh auth login` success/failure messages, potentially overwriting or hiding prior terminal lines, faking a different (benign) success message, or hiding indications that switching to the wrong/malicious host and account occurred. This falls into the "spoofing of gh's own trusted output" / terminal injection class rather than direct code execution, credential exfiltration, or file write — it is a lower-severity output-integrity issue rather than a full compromise, since it does not itself execute code or overwrite files outside intended paths, and it requires the victim to have already deliberately configured trust in the attacker's host.

### Likelihood Explanation
Requires the victim to authenticate `gh` against a host that returns attacker-controlled data for the `viewer.login` GraphQL field — i.e., either a GHES instance the attacker fully controls (which the victim has explicitly pointed `gh auth login --hostname` at) or a compromised/malicious mirror of github.com's GraphQL API reachable under a different hostname the victim trusts. Real github.com enforces username character restrictions server-side, so this is not exploitable against github.com itself; it is only reachable via non-github.com hosts under attacker control, which is within the stated allowed attacker model ("controls responses from a host the victim points gh at"). Feasibility is otherwise high and fully repeatable once that precondition is met, since there is no client-side sanitization anywhere in the pipeline.

### Recommendation
Sanitize/validate usernames before persisting them to config and before interpolating them into any `cs.Bold()`/`fmt.Fprintf` terminal output: strip or reject non-printable/control characters (e.g., anything outside `[A-Za-z0-9-]` consistent with GitHub's actual username policy) in `shared.GetCurrentLogin`, `api.CurrentLoginName`/`CurrentLoginNameAndOrgs`, and `internal/config/migration/multi_account.go`'s `getUsername`, or alternatively apply a generic terminal-escape-stripping helper on any user-supplied/API-supplied string before writing it to `IO.ErrOut`/`IO.Out`.

### Proof of Concept
```go
func TestSwitchRun_UsernameEscapeInjection(t *testing.T) {
    ios, _, _, stderr := iostreams.Test()
    ios.SetStderrTTY(true)

    cfg, _ := config.NewIsolatedTestConfig(t, "")
    // Simulate a username persisted from a malicious host's GraphQL viewer.login response
    maliciousUsername := "monalisa\x1b[2K\rFAKE TRUSTED MESSAGE"
    _, err := cfg.Authentication().Login("evil.example.com", maliciousUsername, "token", "https", false)
    require.NoError(t, err)
    _, err = cfg.Authentication().Login("evil.example.com", "other-user", "token2", "https", false)
    require.NoError(t, err)

    opts := &SwitchOptions{
        IO:       ios,
        Config:   func() (gh.Config, error) { return cfg, nil },
        Hostname: "evil.example.com",
        Username: maliciousUsername,
    }

    err = switchRun(opts)
    require.NoError(t, err)

    // Assert: raw ESC (0x1b) / control bytes should NOT appear unescaped in ErrOut
    require.NotContains(t, stderr.String(), "\x1b[2K")
}
```
Expected (current, vulnerable) behavior: the test fails because `stderr.String()` contains the raw `\x1b[2K\r` sequence, proving the escape bytes reach the terminal-bound output unsanitized.

### Citations

**File:** pkg/cmd/auth/switch/switch.go (L97-121)
```go
		if username != "" {
			knownUsers := cfg.Authentication().UsersForHost(hostname)
			if !slices.Contains(knownUsers, username) {
				return fmt.Errorf("not logged in to %s account %s", hostname, username)
			}
		}
	}

	var candidates candidates

	for _, host := range knownHosts {
		if hostname != "" && host != hostname {
			continue
		}
		hostActiveUser, err := authCfg.ActiveUser(host)
		if err != nil {
			return err
		}
		knownUsers := cfg.Authentication().UsersForHost(host)
		for _, user := range knownUsers {
			if username != "" && user != username {
				continue
			}
			candidates = append(candidates, hostUser{host: host, user: user, active: user == hostActiveUser})
		}
```

**File:** pkg/cmd/auth/switch/switch.go (L164-176)
```go
	cs := opts.IO.ColorScheme()

	if err := authCfg.SwitchUser(hostname, username); err != nil {
		fmt.Fprintf(opts.IO.ErrOut, "%s Failed to switch account for %s to %s\n",
			cs.FailureIcon(), hostname, cs.Bold(username))

		return err
	}

	fmt.Fprintf(opts.IO.ErrOut, "%s Switched active account for %s to %s\n",
		cs.SuccessIcon(), hostname, cs.Bold(username))

	return nil
```

**File:** pkg/cmd/auth/shared/login_flow.go (L253-285)
```go
func GetCurrentLogin(httpClient httpClient, hostname, authToken string) (string, error) {
	query := `query UserCurrent{viewer{login}}`
	reqBody, err := json.Marshal(map[string]interface{}{"query": query})
	if err != nil {
		return "", err
	}
	result := struct {
		Data struct{ Viewer struct{ Login string } }
	}{}
	apiEndpoint, err := safeurl.JoinPathWithHostPrefix(ghinstance.GraphQLEndpoint(hostname))
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", apiEndpoint.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+authToken)
	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode > 299 {
		return "", api.HandleHTTPError(res)
	}
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&result)
	if err != nil {
		return "", err
	}
	return result.Data.Viewer.Login, nil
}
```

**File:** api/queries_user.go (L7-15)
```go
func CurrentLoginName(client *Client, hostname string) (string, error) {
	var query struct {
		Viewer struct {
			Login string
		}
	}
	err := client.Query(hostname, "UserCurrent", &query, nil)
	return query.Viewer.Login, err
}
```
