### Title
`gh api --paginate` follows attacker-controlled `Link` header URLs to arbitrary hosts, enabling SSRF and confused-deputy credential attachment - ([File: pkg/cmd/api/pagination.go])

### Summary
`findNextPage` in `pkg/cmd/api/pagination.go` extracts the raw URL from the server-supplied `Link` response header with no host/scheme restriction, and `apiRun`'s pagination loop in `pkg/cmd/api/api.go` reassigns `requestPath` to that value and passes it straight into `httpRequest`. Because `httpRequest` treats any string containing `://` as an already-fully-qualified URL and dispatches it verbatim, an attacker who controls the API responses of a host the victim points `gh api --paginate` at can redirect every subsequent page request to an arbitrary host of their choosing, and the CLI's own auth transport may silently attach a stored token if that host happens to match one the victim is already authenticated to.

### Finding Description
- `findNextPage` blindly captures group 1 of `linkRE` (`<([^>]+)>;\s*rel="([^"]+)"`) from the `Link` header and returns it as the next request path with no validation: [1](#0-0) .
- In `apiRun`'s pagination loop, this attacker-controlled value is assigned directly to `requestPath` and fed into `httpRequest` on the very next iteration: [2](#0-1) .
- `httpRequest` special-cases any path containing `://` and uses it as-is for `requestURL`, explicitly bypassing `safeurl`/host normalization with a comment that assumes `p` is "taken verbatim from the user" — an assumption that is false for pagination follow-up requests, since `p` here originates from the remote server's `Link` header, not the user: [3](#0-2) .
- The resulting `http.Request` is dispatched through `client.Do(req)`, whose transport chain includes `AddAuthTokenHeader`. That function determines whether to attach an `Authorization` token purely by looking at `getHost(req)` of the *current* outgoing request and querying `cfg.ActiveToken(hostname)` for that host — it only skips attaching the token when `req.Response != nil && req.Response.Request != nil` (i.e., only during a client-followed HTTP redirect within the same `Do` call). Because the pagination loop issues a brand-new top-level request rather than a redirect, `req.Response` is always `nil`, so this "same-host" guard never engages for pagination hops: [4](#0-3) .
- Net effect: if the victim has previously authenticated to some other host that the `Link` header happens to name (e.g. `github.com`, or an enterprise host present in their `hosts.yml`), that host's real token is automatically attached to the attacker-redirected request. Even without a token match, the request itself is still an SSRF primitive — the CLI, running with the victim's local network position, will fetch whatever URL the attacker names (e.g. `http://169.254.169.254/latest/meta-data/...` or `http://localhost:<port>/...`), and the response is written back to `bodyWriter`/stdout via `processResponse`, which is impactful when `gh api --paginate` output is captured, logged, or forwarded (CI logs, scripts, extensions).

### Impact Explanation
This maps to GitHub's "SSRF" and "wrong-host credential exposure" bounty impact classes: an unprivileged host operator can pivot the CLI's outbound HTTP requests to arbitrary internal or external targets, and depending on the victim's stored auth configuration, can cause the CLI to attach a real GitHub token to a request targeting a host of the attacker's choosing rather than the one the user intended. The exfiltration path depends on the response being observable by the attacker (e.g., CI log capture, output redirection, or an extension that reads stdout), so this is not a direct credential exfiltration to the attacker's server, but a credential misrouting and SSRF primitive.

### Likelihood Explanation
Preconditions: the victim must run `gh api --paginate` (GET only) against a host under attacker control or influence (e.g., `--hostname` pointed at attacker infra, or a compromised/malicious API endpoint recommended by an extension or third party), and the pagination loop must reach at least a second page. No additional privileges, MITM, or token leakage are required to trigger the redirect — the attacker only needs to control one `Link` response header on a host the victim already chose to query. The scenario is fully reproducible with an `httpmock`/`httptest` server returning a crafted `Link: <...>; rel="next"` header.

### Recommendation
In `findNextPage`/`apiRun`, restrict pagination follow-up URLs to the same scheme+host as the original request (or re-derive only the path/query and re-apply it through the same `ghinstance.RESTPrefix(hostname)` construction), rejecting or warning on `Link` values that resolve to a different host. Additionally, `AddAuthTokenHeader` should not rely solely on the redirect-chain check (`req.Response != nil`) to gate token attachment for manually issued follow-up requests; the pagination code path should track the original host explicitly and refuse to forward the token if the resolved request host differs.

### Proof of Concept
```go
func TestApiRun_PaginationLinkHeaderRedirectsHost(t *testing.T) {
    // httptest server A (the host the victim points gh at) returns a Link header
    // pointing at httptest server B (a different host acting as "attacker target"
    // or a stand-in for an internal/SSRF target).
    serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Link", `<`+serverBURL+`/internal-secret>; rel="next"`)
        w.Write([]byte(`[]`))
    }))
    serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        capturedAuthHeader = r.Header.Get("Authorization")
        w.Write([]byte(`[]`))
    }))

    cfg := tinyConfig{
        strings.TrimPrefix(serverBURL, "http://") + ":oauth_token": "REAL-TOKEN-FOR-B",
    }
    // Run gh api --paginate against serverA with --hostname pointing at serverA host.
    // Assert: serverB receives a request (SSRF/cross-host follow), and
    // capturedAuthHeader == "token REAL-TOKEN-FOR-B" even though the user
    // never targeted serverB directly — demonstrating credential misrouting
    // driven entirely by the attacker-controlled Link header on serverA.
}
```
Expected assertions: (1) `serverB` receives a request even though the user invoked `gh api` only against `serverA`; (2) if a token is configured for `serverB`'s host in the victim's `hosts.yml`, `Authorization` is attached to that cross-host request without user intent, confirming the confused-deputy/SSRF path through `findNextPage` → `apiRun` → `httpRequest` → `AddAuthTokenHeader`.

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

**File:** pkg/cmd/api/api.go (L429-438)
```go
	for hasNextPage {
		resp, err := httpRequest(httpClient, host, method, requestPath, requestBody, requestHeaders)
		if err != nil {
			return err
		}

		if !isGraphQL {
			requestPath, hasNextPage = findNextPage(resp)
			requestBody = nil // prevent repeating GET parameters
		}
```

**File:** pkg/cmd/api/http.go (L16-27)
```go
func httpRequest(client *http.Client, hostname string, method string, p string, params interface{}, headers []string) (*http.Response, error) {
	isGraphQL := p == "graphql"
	var requestURL string
	if strings.Contains(p, "://") {
		requestURL = p
	} else if isGraphQL {
		requestURL = ghinstance.GraphQLEndpoint(hostname)
	} else {
		// Note that the gh api command takes the path verbatim from the user, so we
		// intentionally do not route it through safeurl and do not escape it here.
		requestURL = ghinstance.RESTPrefix(hostname) + strings.TrimPrefix(p, "/")
	}
```

**File:** api/http_client.go (L151-171)
```go
// AddAuthTokenHeader adds an authentication token header for the host specified by the request.
func AddAuthTokenHeader(rt http.RoundTripper, cfg tokenGetter) http.RoundTripper {
	return &funcTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		// If the header is already set in the request, don't overwrite it.
		if req.Header.Get(authorization) == "" {
			var redirectHostnameChange bool
			if req.Response != nil && req.Response.Request != nil {
				redirectHostnameChange = getHost(req) != getHost(req.Response.Request)
			}
			// Only set header if an initial request or redirect request to the same host as the initial request.
			// If the host has changed during a redirect do not add the authentication token header.
			if !redirectHostnameChange {
				hostname := ghauth.NormalizeHostname(getHost(req))
				if token, _ := cfg.ActiveToken(hostname); token != "" {
					req.Header.Set(authorization, fmt.Sprintf("token %s", token))
				}
			}
		}
		return rt.RoundTrip(req)
	}}
}
```
