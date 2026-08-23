Root cause found: the `capiBaseURL` used to decide whether the Bearer token is safe to send is derived from a value **fetched at runtime from the GitHub GraphQL API** (`resolveCapiURL` in `pkg/cmd/agent-task/shared/capi.go`), and the `httpClient` passed into `capi.NewCAPIClient` is the user's normal `f.HttpClient()` — the same client used elsewhere for arbitrary GitHub API/HTTP calls. `capiTransport.RoundTrip` in `pkg/cmd/agent-task/capi/client.go` unconditionally does:

```go
req.Header.Set("Authorization", "Bearer "+ct.token)
```

for *every* request that flows through this transport, regardless of `req.URL.Host`. Only the extra Copilot-specific headers (`Copilot-Integration-Id`, `X-GitHub-Api-Version`) are gated on `req.URL.Host == ct.capiHost` [1](#0-0) .

This mirrors the StakedToken bug class exactly: a security-relevant check ("only send credentials to X") is applied to the *wrong* condition. The Copilot-Integration-Id/API-version headers are correctly scoped to `capiHost`, but the actual sensitive material (the bearer token) is not — the "restriction" (host scoping) exists in the code but is applied to the low-value header, not the credential itself, just as the original bug validated `caller` but not `owner`.

Because `httpClient` here is the shared `f.HttpClient()` (comment explicitly warns "should not be reused elsewhere" — implying it normally *is* the general-purpose client) and its `Transport` field is mutated in place by `NewCAPIClient` [2](#0-1) , any subsequent or concurrent request issued through that same `*http.Client` — including one that undergoes an HTTP redirect to an attacker-controlled/third-party host, or any call made via `apiClient.Query` inside `resolveCapiURL` itself using `cachedClient` built from the same transport chain — will have the GitHub Bearer token attached even though the destination is not the Copilot API host.

I was not able to fully verify (due to running out of tool iterations) whether `f.HttpClient()`'s underlying `http.Client.CheckRedirect` policy disables cross-host redirects, or whether this exact `httpClient` instance is guaranteed never to be reused for external requests. That gap in verification means this is a **plausible but not fully proven** exploitable path — the missing piece is confirming a concrete reachable code path where this specific mutated client is handed a request to a non-GitHub, non-CAPI host (e.g., via redirect from the CAPI endpoint or reuse elsewhere in `agent-task` command flows).

### Title
Bearer token attached to all requests regardless of destination host - (File: pkg/cmd/agent-task/capi/client.go)

### Summary
`capiTransport.RoundTrip` sets the `Authorization: Bearer <token>` header on every HTTP request that passes through the wrapped transport, without checking that the request's destination host matches the intended Copilot API host (`capiHost`). Only the non-sensitive `Copilot-Integration-Id` and `X-GitHub-Api-Version` headers are gated on the host check.

### Finding Description
`NewCAPIClient` wraps the caller-supplied `*http.Client`'s existing `Transport` with `capiTransport`, mutating the client in place rather than creating an isolated client [2](#0-1) . The wrapped `RoundTrip` unconditionally injects the bearer token:

```go
func (ct *capiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+ct.token)
	if req.URL.Host == ct.capiHost {
		req.Header.Add("Copilot-Integration-Id", "copilot-4-cli")
		req.Header.Set("X-GitHub-Api-Version", "2026-01-09")
	}
	return ct.rp.RoundTrip(req)
}
``` [1](#0-0) 

The `capiHost` used for comparison is parsed from `capiBaseURL`, which is itself fetched dynamically from the GitHub GraphQL `copilotEndpoints.api` field via `resolveCapiURL` [3](#0-2) . The client construction path in `CapiClientFunc` takes the general-purpose `f.HttpClient()`, resolves the CAPI URL using a *cached copy* of that same client, then passes the **original, unwrapped** `httpClient` into `NewCAPIClient`, which mutates its `Transport` [4](#0-3) . This is architecturally identical to the reported StakedToken issue: a restriction (“only attach privileged data when the destination is the trusted `capiHost`”) is enforced on the wrong artifact (the low-sensitivity headers) while the actually sensitive artifact (the bearer token) bypasses the check entirely.

### Impact Explanation
If any request routed through this mutated `http.Client`/transport is redirected to, or otherwise directed at, a host controlled by an attacker (e.g., a malicious `copilotEndpoints.api` response from a compromised/MITM'd GraphQL response, or reuse of the same client for a different HTTP call elsewhere in `gh`), the user's GitHub bearer token would be sent to that non-GitHub, non-Copilot host in the `Authorization` header — resulting in credential exfiltration to an attacker-controlled host.

### Likelihood Explanation
Exploitability depends on whether `capiBaseURL`/`req.URL.Host` can be influenced by an attacker (e.g., via a malicious or spoofed GraphQL response for `copilotEndpoints.api`, since this value comes directly from server data and is not restricted to `*.githubcopilot.com` or similar) and whether the same client instance is later reused for a request to a different host. I could not confirm within the available tool budget whether `capiBaseURL` is validated against an allow-list of trusted domains before being trusted as `capiHost`, nor whether this specific `http.Client` is guaranteed to be single-purpose in all callers.

### Recommendation
- Do not gate any header-setting logic (including the sensitive `Authorization` header) purely on the derived `capiHost` without an allow-list of trusted domains for `capiBaseURL`.
- Move the `Authorization` header assignment inside the same `if req.URL.Host == ct.capiHost` conditional as the other Copilot-specific headers, so the token is only ever attached to requests actually destined for the resolved Copilot API host.
- Avoid mutating a shared, reusable `*http.Client`'s `Transport` in place; construct an isolated `http.Client` dedicated to CAPI traffic instead.
- Validate `capiBaseURL` against a known-good domain suffix before trusting it as the host to attach credentials to.

### Proof of Concept
Not able to construct a concrete end-to-end PoC within the available investigation — this requires confirming (1) whether `resolveCapiURL`'s response can be attacker-influenced or point to an untrusted host, and (2) a reachable code path where the wrapped `http.Client` is reused or redirected to a non-`capiHost`, non-GitHub destination. Conceptually: a unit test analogous to `TestHTTPClientRedirectAuthenticationHeaderHandling` in `api/http_client_test.go` (which validates that the general GitHub API client strips the `Authorization` header across a cross-host redirect) is notably absent for `capiTransport`, and the current logic in `pkg/cmd/agent-task/capi/client.go` lines 64-76 would fail such a test by design, since it unconditionally sets `Authorization` before the host check.

### Citations

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

**File:** pkg/cmd/agent-task/capi/client.go (L64-76)
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
