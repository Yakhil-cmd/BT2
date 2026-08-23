I found a concrete analog in `pkg/cmd/agent-task/capi/client.go`.

### Title
CAPI transport attaches the user's GitHub OAuth Bearer token to every request regardless of destination host - ([File: pkg/cmd/agent-task/capi/client.go])

### Summary
The Copilot Agent Task client (`capi.CAPIClient`) wraps the shared `http.Client` with a custom `capiTransport` whose `RoundTrip` unconditionally sets an `Authorization: Bearer <token>` header on **every outgoing request** made through that client, regardless of which host the request is destined for. The only host check that exists (`req.URL.Host == ct.capiHost`) gates the `Copilot-Integration-Id` / `X-GitHub-Api-Version` headers, not the token itself. `capiBaseURL` is not a static, hardcoded GitHub endpoint — it is resolved dynamically via a GraphQL query (`viewer.copilotEndpoints.api`) returned by the authenticated host [1](#0-0) , similar to how the original finding's `_market` address was accepted and trusted without validating it actually points to a legitimate, expected destination.

### Finding Description
`NewCAPIClient` mutates the caller-provided `httpClient` in place, installing `capiTransport` as its `Transport` [2](#0-1) . That transport's `RoundTrip` does this on every call:

```go
func (ct *capiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+ct.token)
	if req.URL.Host == ct.capiHost {
		req.Header.Add("Copilot-Integration-Id", "copilot-4-cli")
		req.Header.Set("X-GitHub-Api-Version", "2026-01-09")
	}
	return ct.rp.RoundTrip(req)
}
``` [3](#0-2) 

The token is set unconditionally, before the host check. `ct.capiHost` is derived from parsing `capiBaseURL`, which itself is not a fixed, code-reviewed constant — it comes from a live GraphQL response (`resp.Viewer.CopilotEndpoints.Api`) [4](#0-3) . This mirrors the root cause pattern in the original report: an externally-influenced destination value (`_market` there, `capiBaseURL`/API responses here) is trusted to be the intended recipient of privileged material (funds there, an OAuth bearer token here) without independent verification that it belongs to an expected, hardcoded trust boundary.

Practically, because the same `httpClient`/transport combination underlies `CreateJob`, `GetJob`, `GetPullRequestDatabaseID`, session listing, etc. [5](#0-4) , any code path that builds a request URL from a different host — e.g. a redirect, a maliciously-crafted `capiBaseURL` (from a compromised or spoofed enterprise host, or a MITM'd GraphQL response) — would still receive `Authorization: Bearer <token>` for that host, because the header is set before, and independent of, the host match.

### Impact Explanation
If an attacker can influence the value returned for `copilotEndpoints.api` (e.g., a malicious or compromised GHE Cloud tenant instance, or any host under attacker control that the CLI is pointed at) or force a redirect during CAPI/job-related requests, the user's live OAuth token would be sent in the `Authorization` header to that attacker-controlled host — a direct credential exfiltration, analogous to the original report's "attacker steals the collected value" because a user-supplied/externally-resolved endpoint is trusted implicitly.

### Likelihood Explanation
This requires the attacker to control or influence the resolved `capiBaseURL` (which is fetched over the authenticated GraphQL API of the user's configured GitHub host) or to force the HTTP client toward another host during one of these calls. It is not exploitable by a fully passive third party without some ability to influence DNS/host resolution, a compromised GHE Cloud environment, or a redirect in the request chain — comparable in exploitability class to the standard "authenticated request sent to attacker host" category, though it is a narrower/harder-to-trigger primitive than a fully open, unvalidated user parameter.

### Recommendation
Only attach the bearer token when `req.URL.Host` matches an allow-listed set of expected hosts (the resolved GitHub API host and the resolved Copilot API host), mirroring the redirect-safe pattern already used in `api.AddAuthTokenHeader` (which explicitly strips the Authorization header on cross-host redirects) [6](#0-5) . Move the `Authorization` header assignment inside the same host-check branch that already guards the Copilot-specific headers, and validate `capiBaseURL`'s host against the expected GitHub-owned domain pattern before trusting it.

### Proof of Concept
1. `gh agent-task create` (or any `agent-task`/`copilot` subcommand) resolves `capiBaseURL` via `resolveCapiURL` from the authenticated GraphQL endpoint [7](#0-6) .
2. If that response is attacker-influenced (compromised host, MITM, or malicious enterprise instance) to return an attacker-controlled `api` URL, `capi.NewCAPIClient` wires up `capiTransport` with that value as `capiHost` and the token.
3. Any request made through `c.httpClient` — including ones whose URL host differs from `capiHost` due to redirects or additional calls built from that same client — still receives `Authorization: Bearer <token>` because the header set in `RoundTrip` (line 65) is unconditional, sending the live OAuth token to a host that was never independently verified as trustworthy.

Note: I could not fully verify from static reading alone whether any additional guardrails elsewhere (e.g., in `f.HttpClient()` construction, or TLS/host validation on the `capiBaseURL`) further constrain this before it reaches `NewCAPIClient`; a Devin session with terminal/test-execution access would be needed to confirm exploitability end-to-end (e.g., by writing a test that forces `capiBaseURL` to an arbitrary host and observing the resulting request headers).

### Citations

**File:** pkg/cmd/agent-task/shared/capi.go (L38-41)
```go
		capiBaseURL, err := resolveCapiURL(cachedClient, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve Copilot API URL: %w", err)
		}
```

**File:** pkg/cmd/agent-task/shared/capi.go (L47-68)
```go
// resolveCapiURL queries the GitHub API for the Copilot API endpoint URL.
func resolveCapiURL(httpClient *http.Client, host string) (string, error) {
	apiClient := api.NewClientFromHTTP(httpClient)

	var resp struct {
		Viewer struct {
			CopilotEndpoints struct {
				Api string `graphql:"api"`
			} `graphql:"copilotEndpoints"`
		} `graphql:"viewer"`
	}

	if err := apiClient.Query(host, "CopilotEndpoints", &resp, nil); err != nil {
		return "", err
	}

	if resp.Viewer.CopilotEndpoints.Api == "" {
		return "", errors.New("empty Copilot API URL returned")
	}

	return resp.Viewer.CopilotEndpoints.Api, nil
}
```

**File:** pkg/cmd/agent-task/capi/client.go (L11-21)
```go
// CapiClient defines the methods used by the caller. Implementations
// may be replaced with test doubles in unit tests.
type CapiClient interface {
	ListLatestSessionsForViewer(ctx context.Context, limit int) ([]*Session, error)
	CreateJob(ctx context.Context, owner, repo, problemStatement, baseBranch string, customAgent string) (*Job, error)
	GetJob(ctx context.Context, owner, repo, jobID string) (*Job, error)
	GetSession(ctx context.Context, id string) (*Session, error)
	GetSessionLogs(ctx context.Context, id string) ([]byte, error)
	ListSessionsByResourceID(ctx context.Context, resourceType string, resourceID int64, limit int) ([]*Session, error)
	GetPullRequestDatabaseID(ctx context.Context, hostname string, owner string, repo string, number int) (int64, string, error)
}
```

**File:** pkg/cmd/agent-task/capi/client.go (L36-43)
```go
func NewCAPIClient(httpClient *http.Client, token string, host string, capiBaseURL string) *CAPIClient {
	httpClient.Transport = newCAPITransport(token, capiBaseURL, httpClient.Transport)
	return &CAPIClient{
		httpClient:  httpClient,
		host:        host,
		capiBaseURL: capiBaseURL,
	}
}
```

**File:** pkg/cmd/agent-task/capi/client.go (L64-77)
```go
func (ct *capiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+ct.token)

	// Since this RoundTrip is reused for both Copilot API and
	// GitHub API requests, we conditionally add the integration
	// ID only when performing requests to the Copilot API.
	if req.URL.Host == ct.capiHost {
		req.Header.Add("Copilot-Integration-Id", "copilot-4-cli")

		// Ensure we are not using GitHub API versions while targeting CAPI.
		req.Header.Set("X-GitHub-Api-Version", "2026-01-09")
	}
	return ct.rp.RoundTrip(req)
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
