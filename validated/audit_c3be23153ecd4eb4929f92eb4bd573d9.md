### Title
Git-credential protocol injection via unsanitized GraphQL `login` field in credential approve/reject stdin - ([File: pkg/cmd/auth/shared/gitcredentials/updater.go])

### Summary
When `gh` authenticates a user against a host (including a GitHub Enterprise Server the user is instructed to add, e.g. `gh auth login --hostname <host>`), the username returned by that host's GraphQL API is written **unescaped** into the raw, line-oriented `git-credential` helper protocol (`protocol=...\nhost=...\nusername=...\npassword=...\n`) that is piped to `git credential approve`/`reject`. A malicious or compromised host can return a `login` value containing embedded newlines, letting it inject arbitrary extra `key=value` lines into that protocol stream — the same "attacker-controlled field is interpolated unescaped into a line-based protocol" root cause as the GitLab webhook-token CRLF injection into the Redis wire protocol.

### Finding Description
`shared.GetCurrentLogin` fetches the current user's login name straight from the target host's GraphQL response and returns it without any validation: [1](#0-0) 

This `username` (together with `hostname` and the OAuth `authToken`) is later handed to `GitCredentialFlow.Setup`, which — when the user has a pre-existing (non-`gh`) git credential helper configured — calls `Updater.Update(hostname, username, authToken)`: [2](#0-1) 

`Updater.Update` builds the credential-protocol payload by direct string substitution and feeds it as stdin to `git credential reject`/`git credential approve`: [3](#0-2) 

None of `hostname`, `username`, or `password` are checked for embedded `\n` characters before being placed into the `key=value` lines of this text protocol. Because the git-credential protocol is parsed line-by-line until a blank line, a `login` value such as:
```
attacker
host=github.com
username=x-access-token
password=ATTACKER_KNOWN_TOKEN
```
returned by the (attacker-controlled) host's `UserCurrent` GraphQL query causes `Update()`'s stdin to be reinterpreted by `git credential approve`, letting the attacker override the `host` (and other) fields sent to the victim's real credential store (git-credential-store, osxkeychain, wincred, Git Credential Manager, etc.). This is the exact vulnerability class from the referenced report: attacker-controlled content containing newline characters is concatenated unescaped into a line-delimited protocol, causing protocol/command smuggling downstream.

### Impact Explanation
An attacker who controls (or has compromised) a host that a victim is persuaded to authenticate to via `gh auth login -h <attacker-host>` (a normal, unprivileged, remote-attacker-reachable flow — no local access or MITM required) can smuggle extra `key=value` lines into the git-credential protocol used to persist that host's OAuth token in the victim's system credential store. This allows overwriting the `host` field so that credentials get stored/associated with a different, legitimate host (e.g. `github.com`) than the one being authenticated against, causing the victim's git client to trust and use attacker-supplied/attacker-known credentials for a host the victim did not intend to authenticate against — a credential-store poisoning / verification-bypass condition affecting subsequent git operations.

### Likelihood Explanation
Adding a custom hostname during `gh auth login` (GHES/self-hosted support) is an explicitly supported and common workflow, and the vulnerable code path (`Updater.Update`) is exercised whenever the user has a non-`gh` git credential helper already configured and opts in to updating it — a very common default on macOS (osxkeychain), Windows (wincred/GCM), and many Linux setups (store). The `login` value is fully attacker-controlled JSON content from the host being authenticated to, with no length or character restrictions enforced client-side, making the newline injection trivial to produce.

### Recommendation
Reject or strip control characters (`\r`, `\n`) from `hostname`, `username`, and `password`/token values before constructing the git-credential protocol payload in `Updater.Update` (and similarly in `pkg/cmd/auth/gitcredential/helper.go`'s `helperRun`, which has the same unescaped `fmt.Fprintf(..., "%s\n", ...)` pattern). At minimum, validate that the `login` field returned from `GetCurrentLogin`/`CurrentLoginName` contains no newline characters, and fail authentication if it does.

### Proof of Concept
1. Set up a malicious/compromised GraphQL endpoint that responds to the `UserCurrent` query with:
```json
{"data":{"viewer":{"login":"monalisa\nhost=github.com\nusername=x-access-token\npassword=EVIL_TOKEN"}}}
```
2. Victim runs `gh auth login --hostname evil-ghes.example` and completes the token-based or web flow, choosing to configure their existing git credential helper (e.g. `osxkeychain`) when prompted "Authenticate Git with your GitHub credentials?".
3. `shared.GetCurrentLogin` returns the poisoned multi-line string as `username`.
4. `Updater.Update("evil-ghes.example", poisonedUsername, authToken)` builds the stdin for `git credential approve` (see [4](#0-3) ), producing:
```
protocol=https
host=evil-ghes.example
username=monalisa
host=github.com
username=x-access-token
password=EVIL_TOKEN
password=<real authToken>
```
5. The victim's system credential helper parses this stream and stores/overwrites credentials keyed to `github.com` with attacker-influenced values, corrupting the credential entry used for subsequent legitimate `git` operations against `github.com`.

### Citations

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

**File:** pkg/cmd/auth/shared/gitcredentials/updater.go (L16-55)
```go
// Update updates the git credentials for a given hostname, first by rejecting any existing credentials and then
// approving the new credentials.
func (u *Updater) Update(hostname, username, password string) error {
	ctx := context.TODO()

	// clear previous cached credentials
	rejectCmd, err := u.GitClient.Command(ctx, "credential", "reject")
	if err != nil {
		return err
	}

	rejectCmd.Stdin = bytes.NewBufferString(heredoc.Docf(`
		protocol=https
		host=%s
	`, hostname))

	_, err = rejectCmd.Output()
	if err != nil {
		return err
	}

	approveCmd, err := u.GitClient.Command(ctx, "credential", "approve")
	if err != nil {
		return err
	}

	approveCmd.Stdin = bytes.NewBufferString(heredoc.Docf(`
		protocol=https
		host=%s
		username=%s
		password=%s
	`, hostname, username, password))

	_, err = approveCmd.Output()
	if err != nil {
		return err
	}

	return nil
}
```
