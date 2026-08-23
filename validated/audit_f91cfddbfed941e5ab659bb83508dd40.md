### Title
Attacker-controlled Git host can inject credential fields via unsanitized `username`/`password` in `credential approve` stdin - ([File: pkg/cmd/auth/shared/gitcredentials/updater.go])

### Summary
`(*Updater).Update` builds the stdin payload for `git credential approve` with raw, unvalidated `username`/`password` values via `heredoc.Docf`, without checking for embedded newlines. Because `username` (and in the GHE case, the `login` field returned by a GraphQL API call) originates from the response of whatever host the victim points `gh auth login --hostname` at, a malicious/attacker-controlled GitHub Enterprise host can return a `login` value containing `\n` to inject arbitrary `protocol=`/`host=`/`path=` lines into the credential-helper input.

### Finding Description
`Update` constructs the approve payload as:
```go
approveCmd.Stdin = bytes.NewBufferString(heredoc.Docf(`
    protocol=https
    host=%s
    username=%s
    password=%s
`, hostname, username, password))
``` [1](#0-0) 
No validation is performed on `username`/`password` for newline characters before formatting them into the line-oriented `git-credential` protocol.

The call chain is: `shared.Login` obtains `username` either from `authflow.AuthFlow` (which calls `getViewer` → `api.CurrentLoginName`, a GraphQL `viewer.login` query against the target host) [2](#0-1)  or, in the token flow, from `shared.GetCurrentLogin` against the same host. This `username`/`authToken` pair is then passed unchanged to `GitCredentialFlow.Setup`, which calls `flow.Updater.Update(hostname, username, authToken)` [3](#0-2) , which is reached from `shared.Login` at the point `opts.CredentialFlow.Setup(hostname, username, authToken)` is invoked [4](#0-3) .

Because `gh auth login --hostname <host>` lets a user point at any GraphQL/API endpoint (this includes Enterprise Server instances that a user might configure to point at an attacker-controlled server), the attacker who controls that host's API responses fully controls the string returned as the "login"/username, with no server-side format constraint enforced client-side. There is no regex validation (e.g., `^[A-Za-z0-9-]+$`) applied to `username` or `authToken` anywhere in this path before it reaches `Updater.Update`.

If a value like `monalisa\nprotocol=http\nhost=attacker.example.com\npassword=stolen` is returned as the username, the resulting stdin fed to `git credential approve` would contain extra, attacker-chosen `protocol=`/`host=`/`path=` key lines, which many credential helpers (e.g. `git-credential-store`) will parse as legitimate lines and could result in the victim's real OAuth token being persisted under an attacker-chosen host entry, or the injected lines could otherwise corrupt the credential record git associates with `github.com`/the real host.

### Impact Explanation
This maps to a credential storage/exfiltration-adjacent issue: it can cause the git credential helper to persist the just-obtained OAuth token under a different (attacker-chosen) `host=`/`path=` entry than intended, meaning a subsequent `git push`/`fetch` to that attacker-controlled host could automatically present the victim's GitHub token to the attacker's server via the credential helper's normal lookup behavior. Scoped impact is "wrong-host credential routing" via the git-credential-store side channel, not remote code execution.

### Likelihood Explanation
Exploitation requires the victim to run `gh auth login` (or `gh auth refresh`) against a hostname whose API responses are attacker-controlled, i.e. the victim configures `gh` to point at an attacker-supplied GitHub Enterprise-style host. This is one of the explicitly allowed attacker capabilities in this exercise ("controls responses from a host the victim points gh at"), but note it still requires the victim to actively add/trust that host as their `gh` auth target — it does not work against `github.com` itself, since GitHub server-side enforces username character restrictions (`^[A-Za-z0-9-]+$`) that would prevent a legitimate `viewer.login` value from containing a newline. So on the primary `github.com` path this is not exploitable; it is only reachable through attacker-controlled/self-hosted hosts.

### Recommendation
Validate `username` and `password`/`authToken` before formatting them into the `git credential` protocol payload in `Updater.Update` — reject or escape values containing `\n`, `\r`, or NUL bytes, and additionally enforce that `username` matches GitHub's legal login character set (`^[A-Za-z0-9-]+$`) before it is used anywhere in credential-helper input construction (both here and in `login_flow.go`/`authflow`).

### Proof of Concept
Extend `updater_test.go` with a fuzz/unit test asserting stdin line integrity:
```go
func TestUpdateRejectsNewlineInjection(t *testing.T) {
    git.IsolateConfig(t)
    configureStoreCredentialHelper(t)

    u := &gitcredentials.Updater{GitClient: &git.Client{}}
    maliciousUser := "monalisa\nprotocol=http\nhost=attacker.example.com"
    err := u.Update("github.com", maliciousUser, "password")
    // Expect either an error (validation) or that the resulting credential-store file
    // for "github.com" does NOT contain a second entry for "attacker.example.com".
    require.NoError(t, err) // current behavior: no validation error
    out := fillCredentials(t)
    require.NotContains(t, out, "attacker.example.com")
}
```
Running this against current code demonstrates that `heredoc.Docf` performs no escaping, and the injected `protocol=http`/`host=attacker.example.com` line is fed verbatim to `git credential approve` stdin.

### Citations

**File:** pkg/cmd/auth/shared/gitcredentials/updater.go (L42-47)
```go
	approveCmd.Stdin = bytes.NewBufferString(heredoc.Docf(`
		protocol=https
		host=%s
		username=%s
		password=%s
	`, hostname, username, password))
```

**File:** internal/authflow/flow.go (L100-105)
```go
	userLogin, err := getViewer(httpClient, oauthHost, token.Token)
	if err != nil {
		return "", "", err
	}

	return token.Token, userLogin, nil
```

**File:** pkg/cmd/auth/shared/git_credential.go (L80-88)
```go
func (flow *GitCredentialFlow) Setup(hostname, username, authToken string) error {
	// If there is no credential helper configured then we will set ourselves up as
	// the credential helper for this host.
	if !flow.helper.IsConfigured() {
		return flow.HelperConfig.ConfigureOurs(hostname)
	}

	// Otherwise, we'll tell git to inform the existing credential helper of the new credentials.
	return flow.Updater.Update(hostname, username, authToken)
```

**File:** pkg/cmd/auth/shared/login_flow.go (L207-212)
```go
	if opts.CredentialFlow.ShouldSetup() {
		err := opts.CredentialFlow.Setup(hostname, username, authToken)
		if err != nil {
			return err
		}
	}
```
