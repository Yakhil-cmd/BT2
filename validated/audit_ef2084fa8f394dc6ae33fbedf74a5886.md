I have enough evidence to confirm this bug class analog. The `getBundle` function in `pkg/cmd/attestation/api/client.go` fetches attestation bundles from a URL retrieved from the GitHub attestations API response (`BundleURL`), which points to external blob storage, and reads/decompresses the response without any size limit — directly analogous to the covenant-signer unbounded-request-size DoS.

### Title
Unbounded memory consumption when fetching attestation bundles during `gh attestation verify`/`download` - ([File: pkg/cmd/attestation/api/client.go])

### Summary
`gh attestation verify` and `gh attestation download` fetch a Sigstore bundle from an externally-hosted `BundleURL` returned by the GitHub attestations API, then read the entire HTTP response body into memory and snappy-decompress it, with no bound on either the compressed response size or the decompressed output size.

### Finding Description
`getBundle` issues `c.externalHttpClient.Get(url.String())` against `a.BundleURL`, a URL supplied inside the attestation record itself rather than a value under gh's control [1](#0-0) . The full response body is buffered with `io.ReadAll(resp.Body)` with no `io.LimitReader`/`http.MaxBytesReader` guard, and the resulting bytes are passed to `snappy.Decode(out, body)` with a `nil` destination buffer, which allocates a buffer sized by the (attacker-controlled) uncompressed-length header embedded in the snappy stream before any further validation occurs [2](#0-1) . Because bundle fetches for multiple attestations are dispatched concurrently via `errgroup.Group` in `fetchBundleFromAttestations`, an attacker can multiply the effect further by supplying many attestations, each pointing at a large/blob-bomb payload [3](#0-2) . This mirrors the reported bug class exactly: an unbounded read of content originating from a party the caller does not fully trust, leading to uncontrolled memory growth and process termination by the OS OOM killer.

The attestation record supplying `BundleURL` is obtained from `getAttestations`, which queries `/repos/{owner}/{repo}/attestations/{digest}` or `/orgs/{owner}/attestations/{digest}` [4](#0-3) . Any account able to push an attestation to a repository (including a public repository an attacker fully controls) can shape the `bundle_url` value returned by that endpoint, so a user or CI job that runs `gh attestation verify`/`download` against an attacker-controlled repo/artifact digest reaches this code path.

### Impact Explanation
A successful attack causes the local `gh` process (frequently running inside CI/CD pipelines that perform automated supply-chain verification) to exhaust available memory and be killed, denying the verification step. Since attestation verification is often a security gate in build pipelines, an availability failure here can block releases or, if uncontrolled/inconsistently handled, encourage disabling the check — the same category of impact as the original covenant-signer report ("Impact Explanation" in the original: denial of service against an availability-critical remote-facing operation), translated here into gh's local execution during a routine command.

### Likelihood Explanation
Likelihood is limited by the requirement that a target user or CI job invoke `gh attestation verify`/`download` against an artifact/repo an attacker controls (e.g., a public repository with attacker-authored attestations, or convincing a victim to verify an attacker-supplied digest/repo pair). This is lower than the original report's "any known public server" scenario, but still qualifies as an unprivileged-remote-attacker path since the attacker only needs to publish content (an attestation with a crafted `bundle_url`) that a victim later chooses to verify — no compromise of GitHub or the victim's credentials is required.

### Recommendation
Wrap `resp.Body` with `io.LimitReader` (or `http.MaxBytesReader`) before calling `io.ReadAll` in `getBundle`, and enforce a maximum decompressed size when invoking `snappy.Decode` (e.g., pre-check the declared uncompressed length via `snappy.DecodedLen` and reject if it exceeds a sane bundle-size ceiling) before allocating the destination buffer, mirroring the `RequestSize` middleware fix applied server-side for the covenant-signer service.

### Proof of Concept
1. Publish attestations to a repository controlled by the attacker (or fork a public repo) such that the GitHub attestations API response's `bundle_url` field for a given digest points to an attacker-hosted HTTP endpoint.
2. Host a response at that URL that is a valid snappy stream whose header declares an extremely large uncompressed length (or which simply streams gigabytes of compressible data), independent of true content.
3. Have a victim run `gh attestation verify --owner <attacker-org> <artifact>` (or `gh attestation download`) against the corresponding digest.
4. `getBundle` calls `io.ReadAll` and `snappy.Decode` unbounded, driving the `gh` process's memory usage until the OS OOM killer terminates it, mirroring the crash observed against `covenant-signer` in the original report.

### Citations

**File:** pkg/cmd/attestation/api/client.go (L104-140)
```go
func (c *LiveClient) buildRequestURL(params FetchParams) (safeurl.SafeURL, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}

	var u *safeurl.MutableSafeURL
	if params.Repo != "" {
		// check if Repo is set first because if Repo has been set, Owner will be set using the value of Repo.
		// If Repo is not set, the field will remain empty. It will not be populated using the value of Owner.
		owner, name, err := safeurl.RepoPartsFromNWO(params.Repo)
		if err != nil {
			return nil, err
		}
		u, err = safeurl.JoinPath("repos", owner, name, "attestations", params.Digest)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		u, err = safeurl.JoinPath("orgs", params.Owner, "attestations", params.Digest)
		if err != nil {
			return nil, err
		}
	}

	perPage := params.Limit
	if perPage > maxLimitForFetch {
		perPage = maxLimitForFetch
	}

	// ref: https://github.com/cli/go-gh/blob/d32c104a9a25c9de3d7c7b07a43ae0091441c858/example_gh_test.go#L96
	u.SetQuery("per_page", strconv.Itoa(perPage))
	if params.PredicateType != "" {
		u.SetQuery("predicate_type", params.PredicateType)
	}
	return u, nil
}
```

**File:** pkg/cmd/attestation/api/client.go (L199-228)
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
