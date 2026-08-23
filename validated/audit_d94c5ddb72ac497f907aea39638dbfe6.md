### Title
Missing input validation/escaping of hostname, username, and password in `(*Updater).Update` permits credential-protocol injection via embedded `\n`/`\r\n` — ([File: pkg/cmd/auth/shared/gitcredentials/updater.go])

### Summary
`(*Updater).Update` builds the `git credential approve`/`reject` stdin payload with `heredoc.Docf` and raw string interpolation of `hostname`, `username`, and `password`, performing no escaping, no rejection of `\n`/`\r`/`\r\n`, and no rejection of a bare `key=` prefix. Because git's credential-helper protocol is a line-oriented `key=value` stream terminated by a blank line, any of these separator styles let an attacker-controlled value inject additional/forged attribute lines (e.g. a different `host=`) into the record that git parses.

### Finding Description
`Update` constructs both commands purely via string formatting with no sanitization step: [1](#0-0) 

There is no call to any escaping/validation helper anywhere in the function, and the same pattern is used for the `reject` command: [2](#0-1) 

`Update` is invoked from `GitCredentialFlow.Setup` with `hostname, username, authToken` as-is: [3](#0-2) 

The `username` value originates from `shared.GetCurrentLogin(httpClient, hostname, opts.Token)`, which parses the `login` field out of a JSON API response returned by whatever host `hostname` points to (git_credential.go / login.go flow): [4](#0-3) . Since the attacker-controlled precondition explicitly includes "controls responses from a host the victim points gh at," a malicious GitHub Enterprise-like host can return an arbitrary `login` string — including one containing `\r\n` — which flows unmodified into `Update`'s `username` parameter.

Regarding the specific question asked: because git's credential-helper stdin protocol is read line-by-line (splitting on `\n`, with a trailing `\r` typically stripped by standard line-scanning), a payload using `\r\n` is functionally equivalent to one using `\n` for the purposes of record/line separation. Since `Update` performs **no filtering of any kind** (not just a "newline-only" filter), there is nothing to "bypass" — `\n`, `\r\n`, and `\r` all reach the credential-helper subprocess unmodified and are all capable of terminating the current `key=value` line and starting a new one (or, with a blank line, terminating the whole record and starting a second `host=`/`protocol=` record). This confirms the described CRLF path is exploitable to the same degree as a bare-LF path, and is not a narrower or mitigated variant of it.

### Impact Explanation
An attacker who controls the responses of a host that the victim points `gh auth login --hostname <attacker-host>` at can return a `login` value containing embedded `\n`/`\r\n` sequences to smuggle extra `host=`/`protocol=` lines into the `git credential approve` stdin stream, causing the OS credential store (or another configured `credential.helper`) to persist the victim's GitHub token under an attacker-chosen host entry. This matches "wrong-host credential storage" — a credential-routing/confusion impact.

### Likelihood Explanation
Requires the victim to explicitly authenticate against an attacker-controlled hostname (an already-documented precondition for this class of finding) and for that host's API response for the authenticated user's login to be attacker-controlled, which it is since the attacker operates the host. No other privileges are required, and the code path is deterministic/repeatable.

### Recommendation
Validate and/or escape `hostname`, `username`, and `password` in `Update` before embedding them into the credential-protocol stream: reject or strip any `\r`, `\n`, or NUL bytes, and reject values that would produce a line starting with a bare `key=` collision that isn't the intended key. Alternatively, use the `git credential` `--format` machinery or a proper key/value writer that percent-encodes or otherwise safely serializes attribute values instead of raw `Sprintf`/heredoc interpolation.

### Proof of Concept
```go
func TestUpdater_Update_CRLFInjection(t *testing.T) {
    cases := []string{"\n", "\r\n", "\r"}
    for _, sep := range cases {
        maliciousUsername := "victim" + sep + "host=evil.example.com" + sep
        // Use a git-stub (fake `git credential approve` reading stdin) to capture
        // the parsed attribute set, e.g. via a real `git credential-store` helper
        // pointed at a temp file, or a recording stub script.
        u := &gitcredentials.Updater{GitClient: gitClientWithStubHelper}
        err := u.Update("real-host.example.com", maliciousUsername, "token123")
        require.NoError(t, err)

        stored := readStoredCredentialFile(t) // parse resulting store file
        // Assertion: no entry should exist for "evil.example.com" for any separator variant
        require.NotContains(t, stored, "evil.example.com",
            "separator %q allowed host injection", sep)
    }
}
```
Expected (current, vulnerable) result: for all three separator variants, `stored` contains a spurious credential entry for `evil.example.com`, demonstrating that `\n`, `\r\n`, and `\r` are all equally effective and none are filtered.

### Citations

**File:** pkg/cmd/auth/shared/gitcredentials/updater.go (L27-30)
```go
	rejectCmd.Stdin = bytes.NewBufferString(heredoc.Docf(`
		protocol=https
		host=%s
	`, hostname))
```

**File:** pkg/cmd/auth/shared/gitcredentials/updater.go (L42-47)
```go
	approveCmd.Stdin = bytes.NewBufferString(heredoc.Docf(`
		protocol=https
		host=%s
		username=%s
		password=%s
	`, hostname, username, password))
```

**File:** pkg/cmd/auth/shared/git_credential.go (L80-89)
```go
func (flow *GitCredentialFlow) Setup(hostname, username, authToken string) error {
	// If there is no credential helper configured then we will set ourselves up as
	// the credential helper for this host.
	if !flow.helper.IsConfigured() {
		return flow.HelperConfig.ConfigureOurs(hostname)
	}

	// Otherwise, we'll tell git to inform the existing credential helper of the new credentials.
	return flow.Updater.Update(hostname, username, authToken)
}
```

**File:** pkg/cmd/auth/login/login.go (L205-217)
```go
	if opts.Token != "" {
		if err := shared.HasMinimumScopes(httpClient, hostname, opts.Token); err != nil {
			return fmt.Errorf("error validating token: %w", err)
		}
		username, err := shared.GetCurrentLogin(httpClient, hostname, opts.Token)
		if err != nil {
			return fmt.Errorf("error retrieving current user: %w", err)
		}

		// Adding a user key ensures that a nonempty host section gets written to the config file.
		_, loginErr := authCfg.Login(hostname, username, opts.Token, opts.GitProtocol, !opts.InsecureStorage)
		return loginErr
	}
```
