### Title
Unbounded body read and snappy decompression allow memory-exhaustion DoS via attacker-controlled attestation bundle - ([File: pkg/cmd/attestation/api/client.go])

### Summary
`LiveClient.getBundle` reads the entire `BundleURL` response with `io.ReadAll(resp.Body)` and then calls `snappy.Decode(out, body)` with `out` as a nil slice, imposing no size cap on either the compressed input or the decompressed output before allocation. Since an unprivileged attacker who publishes attestations for their own repo controls the raw bytes stored at the blob-storage location `BundleURL` points to, they can supply a small compressed payload whose snappy header declares an extremely large decoded length, or simply an oversized raw body, causing the victim's `gh attestation verify` process to allocate excessive memory.

### Finding Description
The call path is `GetByDigest` → `fetchBundleFromAttestations` → `getBundle` [1](#0-0) . `getBundle` fetches `a.BundleURL` and reads the full response body without any `io.LimitReader`/`http.MaxBytesReader` or `Content-Length` check, then decompresses it: `var out []byte; decompressed, err := snappy.Decode(out, body)` [2](#0-1) . `snappy.Decode` allocates its destination buffer using the declared decoded-length header embedded in `body`, which is fully attacker-controlled data (the attacker's own attestation blob), independent of the compressed payload's actual size — a classic decompression-bomb pattern. Neither the HTTP read nor the decode step enforces any maximum size, and `BundleURL` is fetched via a generic `httpClient.Get` with no evident response size limiting configured in this package. `bundle_url` itself is returned by the trusted GitHub API, but the bytes it points to (blob storage content) are supplied by whoever created the attestation, i.e., the attacker for their own repo/artifact.

### Impact Explanation
This maps to a denial-of-service class impact: an attacker who publishes a repository/artifact with a crafted attestation can cause the victim's `gh attestation verify` invocation to consume excessive memory/CPU or crash (OOM) while processing ordinary attacker-published content. It does not by itself achieve code execution, credential exfiltration, or file write outside intended paths — impact is scoped to resource exhaustion/crash of the CLI process.

### Likelihood Explanation
Feasible and repeatable: the only precondition is that the victim runs `gh attestation verify` against an attacker-controlled/published repo or artifact digest that has an associated attestation with a `BundleURL`. The attacker fully controls the content served from that URL (their own uploaded bundle bytes), and no server-side or client-side size validation is applied before `io.ReadAll` or `snappy.Decode`. This requires no elevated privileges beyond publishing content, matching the stated attacker model.

### Recommendation
Bound the response body size before reading, e.g., wrap `resp.Body` with `io.LimitReader` or use `http.MaxBytesReader` with a sane maximum bundle size, and reject responses exceeding that cap. Additionally, cap the snappy decompressed size (e.g., check `snappy.DecodedLen(body)` against a maximum before decoding, or use a decoder API that limits allocation) instead of passing a nil `out` and letting the library allocate an arbitrary size.

### Proof of Concept
Go test using `httptest`/`httpmock`:
1. Stand up a test `httpClient` mock (or `httptest.Server`) that returns a snappy-compressed body whose header advertises a very large decoded length (e.g., several GB) but only a few bytes of literal compressed payload (crafted via the snappy block format: varint decoded-length header followed by minimal literal/copy tags).
2. Call `LiveClient.getBundle` with a `safeurl.SafeURL` pointing at this mock server.
3. Assert that either: (a) `getBundle` returns an error due to a size-limit check before allocation (expected after fix), or (b) without a fix, the test observes unbounded memory allocation (e.g., via `runtime.MemStats` before/after, or by using `-memprofile` / a memory-limited test harness) confirming multi-GB allocation from a payload of only a few KB.
4. A complementary fuzz test (`go test -fuzz`) over crafted snappy headers with increasing declared decoded sizes should assert that `getBundle`/decode path enforces a hard upper bound and returns an error rather than attempting the allocation.

### Citations

**File:** pkg/cmd/attestation/api/client.go (L199-235)
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
			fetched[i] = &Attestation{
				Bundle: b,
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return fetched, nil
}
```

**File:** pkg/cmd/attestation/api/client.go (L253-262)
```go
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
