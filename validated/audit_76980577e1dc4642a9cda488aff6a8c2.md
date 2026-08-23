### Title
Unbounded `io.ReadAll` on attacker-controlled `BundleURL` response enables memory-exhaustion DoS - ([File: pkg/cmd/attestation/api/client.go])

### Summary
`LiveClient.getBundle` reads the entire HTTP response body from an attacker-influenced `BundleURL` into memory via `io.ReadAll(resp.Body)` with no maximum size cap, `Content-Length` check, or `io.LimitReader` before passing the data to `snappy.Decode`. A malicious or compromised bundle-hosting endpoint can stream an extremely large or effectively unbounded response body, causing the `gh attestation verify`/`download` process to exhaust memory.

### Finding Description
In `getBundle` ( [1](#0-0) ), the flow is: `fetchBundleFromAttestations` calls `c.getBundle(safeurl.NewImmutableSafeURL(a.BundleURL))` using the `BundleURL` field returned by the GitHub Attestations API response ( [2](#0-1) ). Inside `getBundle`, `c.externalHttpClient.Get(url.String())` fetches the bundle, and the response body is read fully with `io.ReadAll(resp.Body)` with no size limit before being handed to `snappy.Decode`. `safeurl` is used only to validate/normalize the URL structure (host/scheme parsing), not to cap response size, so it does not mitigate this. There is no `http.MaxBytesReader`, no `io.LimitReader`, and the `externalHttpClient` (constructed via `NewLiveClient`) is a generic `httpClient` interface wrapping a standard `*http.Client`, which by default has no response body size limit — only (if set) a connection/request `Timeout`, which does not bound the number of bytes a slow/streaming attacker server can send within that timeout, nor does it fully prevent large-but-fast responses.

### Impact Explanation
This matches a memory-exhaustion Denial-of-Service impact class. Since `BundleURL` originates from attestation metadata that can point to storage under less-trusted control (blob storage returned by the GitHub Attestations API for a given digest), and `fetchBundleFromAttestations` fans this out across all attestations for a digest, an attacker who can influence this response field can cause `gh attestation verify`/`download` to load an arbitrarily large payload into process memory, potentially crashing or hanging the invoking machine. This is scoped strictly to DoS — no code execution, no credential exfiltration, and no verification bypass results directly from this issue.

### Likelihood Explanation
Requires that the attacker control (or the response from) the `bundle_url` endpoint referenced in attestation data for a digest the victim decides to verify — a realistic precondition per the threat model (attacker publishes/points victim at malicious content). No authentication or special privilege is needed beyond controlling that endpoint's HTTP responses, and the exploit is fully repeatable with a simple `httptest` server that streams data indefinitely or returns a very large `Content-Length` body.

### Recommendation
Wrap `resp.Body` with `io.LimitReader(resp.Body, maxBundleSize)` (or use `http.MaxBytesReader`-style enforcement) before calling `io.ReadAll`, choosing a sane maximum bundle size (e.g., a few MB), and treat truncation/oversized responses as a hard error. Additionally, set an explicit timeout via context on the external HTTP request to bound total latency for slow-streaming attackers.

### Proof of Concept
```go
func TestGetBundle_UnboundedBodySize(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        flusher, _ := w.(http.Flusher)
        buf := make([]byte, 1<<20) // 1MB chunks
        for i := 0; i < 100000; i++ { // stream ~100GB
            w.Write(buf)
            if flusher != nil {
                flusher.Flush()
            }
        }
    }))
    defer srv.Close()

    client := &LiveClient{
        externalHttpClient: srv.Client(),
        logger:             ioconfig.NewHandler(nil, nil),
    }

    done := make(chan struct{})
    go func() {
        _, _ = client.getBundle(safeurl.NewImmutableSafeURL(srv.URL))
        close(done)
    }()

    select {
    case <-done:
        // Expected: getBundle should return an error (e.g., "response too large")
        // once a max-size limit is enforced, well before the full body is read.
    case <-time.After(5 * time.Second):
        t.Fatal("getBundle did not enforce a body size cap; test process memory grew unbounded")
    }
}
```
Expected assertion after the fix: `getBundle` returns an error such as "bundle response exceeds maximum allowed size" instead of attempting to buffer the entire streamed body via `io.ReadAll`.

### Citations

**File:** pkg/cmd/attestation/api/client.go (L199-221)
```go
func (c *LiveClient) fetchBundleFromAttestations(attestations []*Attestation) ([]*Attestation, error) {
	fetched := make([]*Attestation, len(attestations))
	g := errgroup.Group{}
	for i, a := range attestations {
		g.Go(func() error {
			if a.Bundle == nil && a.BundleURL == "" {
				return fmt.Errorf("attestation has no bundle or bundle URL")
			}

			// for now, we fall back to the bundle field if the bundle URL is empty
			if a.BundleURL == "" {
				c.logger.VerbosePrintf("Bundle URL is empty. Falling back to bundle field\n\n")
				fetched[i] = &Attestation{
					Bundle: a.Bundle,
				}
				return nil
			}

			// otherwise fetch the bundle with the provided URL
			b, err := c.getBundle(safeurl.NewImmutableSafeURL(a.BundleURL))
			if err != nil {
				return fmt.Errorf("failed to fetch bundle with URL: %w", err)
			}
```

**File:** pkg/cmd/attestation/api/client.go (L237-256)
```go
func (c *LiveClient) getBundle(url safeurl.SafeURL) (*bundle.Bundle, error) {
	c.logger.VerbosePrintf("Fetching attestation bundle with bundle URL\n\n")

	var sgBundle *bundle.Bundle
	bo := backoff.NewConstantBackOff(getAttestationRetryInterval)
	err := backoff.Retry(func() error {
		resp, err := c.externalHttpClient.Get(url.String())
		if err != nil {
			return fmt.Errorf("request to fetch bundle from URL failed: %w", err)
		}

		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return fmt.Errorf("attestation bundle with URL %s returned status code %d", url.String(), resp.StatusCode)
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read blob storage response body: %w", err)
		}
```
