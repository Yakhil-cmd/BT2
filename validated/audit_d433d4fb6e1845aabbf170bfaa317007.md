### Title
Unbounded memory allocation from attacker-controlled bundle content via `getBundle` (`io.ReadAll` + `snappy.Decode`) - ([File: pkg/cmd/attestation/api/client.go])

### Summary
`(*LiveClient).getBundle` reads the full HTTP response body from an attestation's `BundleURL` with `io.ReadAll` and then decompresses it with `snappy.Decode(out, body)` using a `nil` destination buffer, without any cap on response size or decoded size. An attacker who controls a public repository's attestation bundle content (or who controls the host referenced by `BundleURL`) can serve a small, highly compressed snappy stream (or simply an oversized raw body) that forces the victim's `gh` process to allocate excessive memory, causing a denial of service.

### Finding Description
The relevant code path is: [1](#0-0) 

`getBundle` calls `c.externalHttpClient.Get(url.String())` where `url` comes directly from `a.BundleURL` on the `Attestation` struct returned by the GitHub attestations API: [2](#0-1) [3](#0-2) 

There is no `Content-Length` check, `io.LimitReader`, or maximum-size cap applied to `resp.Body` before `io.ReadAll` consumes it fully into memory, and `snappy.Decode(out, body)` is called with `out` as a nil slice, meaning the decompression buffer is sized purely according to the length declared inside the attacker-supplied snappy stream itself, independent of the actual number of bytes transferred over the wire. Because attestation bundle bytes for a repository are attacker-controllable content (an attacker who owns a public repo can attach an attestation whose bundle payload/URL response they fully control), this path is reachable by an ordinary `gh attestation verify` invocation against an attacker's repository or artifact, without any elevated privileges. No allowlist, size limit, or streaming/bounded decoder exists to stop an oversized or maliciously declared body from being fully buffered and then expanded by `snappy.Decode`.

### Impact Explanation
This maps to a denial-of-service impact: an unprivileged remote actor publishing a repository/attestation can cause a victim's `gh` process to allocate memory unbounded by the wire size of the response (via the snappy length header) or simply supply an oversized raw body, exhausting memory/CPU on the victim host during `gh attestation verify`.

### Likelihood Explanation
The precondition is that the attacker can get a victim to run `gh attestation verify` (or similar) against an artifact/repo they control, which is the normal, expected usage pattern of the attestation feature and requires no special access — only that the victim chooses to verify content coming from the attacker's repo. The vulnerability is deterministic and repeatable each time the malicious `BundleURL` content is fetched.

### Recommendation
- Wrap `resp.Body` in `io.LimitReader` with a sane maximum bundle size before `io.ReadAll`, and reject bodies exceeding that limit.
- Use a bounded destination buffer for `snappy.Decode` (or `snappy.DecodedLen` to pre-check declared size against a maximum) instead of passing `nil`, rejecting streams whose declared decompressed length exceeds an acceptable bundle size threshold.
- Fail fast (return an error) if `snappy.DecodedLen(body)` exceeds the configured maximum before allocating/decoding.

### Proof of Concept
Go test plan using `httptest`/mock `externalHttpClient`:
1. Craft a minimal snappy stream whose leading varint declares a very large decoded length (e.g., hundreds of MB) but whose actual compressed payload is only a few KB (a "snappy bomb").
2. Configure a mock `httpClient.Get` (via the existing `mock_httpClient_test.go` pattern) to return this payload for `BundleURL`.
3. Call `(*LiveClient).getBundle` with this mock and assert via `runtime.MemStats` (or `testing.AllocsPerRun`) that memory allocation spikes proportional to the attacker-declared length rather than the actual transferred byte count, or assert that no error/size-limit is triggered.
4. Expected fixed behavior: `getBundle` should return an error (e.g., "bundle exceeds maximum allowed size") before or during decode, and memory allocation should be bounded regardless of the declared snappy length or response body size.

### Citations

**File:** pkg/cmd/attestation/api/client.go (L199-220)
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
```

**File:** pkg/cmd/attestation/api/client.go (L237-262)
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

		var out []byte
		decompressed, err := snappy.Decode(out, body)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("failed to decompress with snappy: %w", err))
		}
```

**File:** pkg/cmd/attestation/api/attestation.go (L13-17)
```go
type Attestation struct {
	Bundle    *bundle.Bundle `json:"bundle"`
	BundleURL string         `json:"bundle_url"`
	Initiator string         `json:"initiator"`
}
```
