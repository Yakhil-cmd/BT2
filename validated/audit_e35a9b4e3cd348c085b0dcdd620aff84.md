Based on the investigation, I found a concrete analog to the reported bug class — "credentials/context persisted across calls without re-validating the destination" — in `hirayap/cli--013`'s Copilot Agent Task API (CAPI) transport.

### Title
Copilot bearer token is attached to every outbound request regardless of destination host, unlike GitHub token attachment which is host-scoped - (File: `pkg/cmd/agent-task/capi/client.go`)

### Summary
The `BoringBatchable`/`MIMOProxy` bug class is: a privileged value (`msg.value`/`msg.sender`) is carried through every iteration of a delegated call without being re-checked against the current call target, so it can be replayed against unintended recipients. In `gh`, `capiTransport.RoundTrip` reproduces the same pattern for the Copilot API bearer token: it unconditionally sets the `Authorization` header on **every** request that flows through the shared `http.Client`, without checking whether the request's destination host is actually the Copilot API host.

### Finding Description
`NewCAPIClient` mutates a caller-supplied `*http.Client`'s `Transport` in place, wrapping the existing transport chain in `capiTransport`: [1](#0-0) 

`capiTransport.RoundTrip` sets `Authorization: Bearer <token>` unconditionally, before delegating to the wrapped transport, and only gates the *additional* Copilot-specific headers (`Copilot-Integration-Id`, API version) on a host match: [2](#0-1) 

This is inconsistent with the codebase's own established, correct pattern for token scoping. `AddAuthTokenHeader` (used for the ordinary GitHub token) explicitly detects a host change (including across redirects) and refuses to attach the token if the request's host doesn't match: [3](#0-2) 

and this behavior is specifically tested: [4](#0-3) 

`capiTransport` has no equivalent host check for the `Authorization` header it sets — it always emits the Copilot bearer token, and because it runs first in the chain, `AddAuthTokenHeader`'s own "don't overwrite if already set" logic never gets a chance to enforce scoping either (`req.Header.Get(authorization) == ""` is already false by the time it's called).

The client this transport is installed on comes from `CapiClientFunc`, which reuses the exact same `*http.Client` object across all subsequent calls made through `capi.CapiClient` (`CreateJob`, `GetJob`, `GetSession`, `GetSessionLogs`, `ListSessionsByResourceID`, and notably `GetPullRequestDatabaseID`, which accepts an explicit, caller-supplied `hostname` parameter): [5](#0-4) [6](#0-5) 

Because `GetPullRequestDatabaseID` takes `hostname` as a parameter rather than being pinned to the resolved Copilot/GitHub host, any code path that derives a hostname from user- or attacker-influenced input (e.g., parsing a pasted URL) and passes it into this client would cause the Copilot bearer token to be sent to that host, since `capiTransport` does not check `req.URL.Host` before attaching `Authorization`.

### Impact Explanation
If a caller of this shared, mutated `http.Client` ever issues a request to a host other than the resolved Copilot API host (whether via a redirect, a mis-scoped call, or a hostname derived from external/untrusted input), the Copilot bearer token is exfiltrated to that host in the clear `Authorization` header. This is analogous to the reported finding's core mechanism: a sensitive value that should be scoped per-call/per-destination is instead persisted and blindly reapplied across the life of a shared execution context.

### Likelihood Explanation
The comment in the source acknowledges the risk implicitly ("this RoundTrip is reused for both Copilot API and GitHub API requests") but does not add a host check for the `Authorization` header itself, only for the supplementary headers. I was not able to fully trace, within the available iterations, whether `GetPullRequestDatabaseID`'s `hostname` argument (or any other code path using this shared client) can be populated from untrusted/attacker-influenced input in a real `gh agent-task` invocation — that would be needed to fully confirm remote exploitability versus a purely internal (GitHub-host-only) usage today. This is the primary uncertainty in this analog.

### Recommendation
Add an explicit host check in `capiTransport.RoundTrip`, mirroring `AddAuthTokenHeader`'s pattern, so the Copilot bearer token is only attached when `req.URL.Host == ct.capiHost` (or a well-defined GitHub host allowlist), rather than unconditionally on every request through the shared client.

### Proof of Concept
Conceptual (not executed, since this requires code changes to demonstrate, which is outside ask-only scope):
1. Obtain a `*http.Client` returned by `shared.CapiClientFunc(f)()`.
2. Issue a plain `client.Do(req)` (or trigger any code path using this client) where `req.URL.Host` is neither the GitHub API host nor the Copilot API host.
3. Observe that `Authorization: Bearer <copilot token>` is present on the outbound request to the unrelated host, per `capiTransport.RoundTrip` at [7](#0-6) , since no host comparison is performed before setting this header.

### Citations

**File:** pkg/cmd/agent-task/capi/client.go (L13-21)
```go
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

**File:** api/http_client_test.go (L212-244)
```go
func TestHTTPClientRedirectAuthenticationHeaderHandling(t *testing.T) {
	var request *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request = r
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	var redirectRequest *http.Request
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectRequest = r
		http.Redirect(w, r, server.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	client, err := NewHTTPClient(HTTPClientOptions{
		Config: tinyConfig{
			fmt.Sprintf("%s:oauth_token", strings.TrimPrefix(redirectServer.URL, "http://")): "REDIRECT-TOKEN",
			fmt.Sprintf("%s:oauth_token", strings.TrimPrefix(server.URL, "http://")):         "TOKEN",
		},
	})
	require.NoError(t, err)

	req, err := http.NewRequest("GET", redirectServer.URL, nil)
	require.NoError(t, err)

	res, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, "token REDIRECT-TOKEN", redirectRequest.Header.Get(authorization))
	assert.Equal(t, "", request.Header.Get(authorization))
	assert.Equal(t, 204, res.StatusCode)
}
```

**File:** pkg/cmd/agent-task/shared/capi.go (L21-45)
```go
func CapiClientFunc(f *cmdutil.Factory) func() (capi.CapiClient, error) {
	return func() (capi.CapiClient, error) {
		cfg, err := f.Config()
		if err != nil {
			return nil, err
		}

		httpClient, err := f.HttpClient()
		if err != nil {
			return nil, err
		}

		authCfg := cfg.Authentication()
		host, _ := authCfg.DefaultHost()
		token, _ := authCfg.ActiveToken(host)

		cachedClient := api.NewCachedHTTPClient(httpClient, time.Minute*10)
		capiBaseURL, err := resolveCapiURL(cachedClient, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve Copilot API URL: %w", err)
		}

		return capi.NewCAPIClient(httpClient, token, host, capiBaseURL), nil
	}
}
```
