### Title
Unbounded memory allocation when reading attestation bundle layers from an attacker-controlled OCI registry - (File: pkg/cmd/attestation/artifact/oci/client.go)

### Summary
`LiveClient.GetAttestations` reads an entire OCI image layer into memory with `io.ReadAll(layer0)` without any size cap, before the bytes are ever validated as a sigstore bundle. Because the registry (and thus the declared layer size and returned byte stream) is fully attacker-controlled in the "self-hosted registry" scenario, an attacker can serve an arbitrarily large blob for the referrer layer and force the `gh` client to allocate unbounded memory, resulting in a client-side denial of service.

### Finding Description
In `GetAttestations`, after `remote.Referrers` returns the referrers manifest, the code filters by `refDesc.ArtifactType` prefix and then fetches the referrer image via `remote.Image(ref.Context().Digest(refDesc.Digest.String()), ...)` [1](#0-0) . It then reads the first layer fully into memory: [2](#0-1) 

`layers[0].Uncompressed()` returns a reader whose declared size/digest come from the manifest served by the (attacker-controlled) registry; `go-containerregistry`'s verifying reader only confirms the hash/size after the stream has been fully consumed, so nothing stops the transport from streaming a very large blob. `io.ReadAll` has no bound, so the process will buffer the entire attacker-supplied blob in memory before `bundle.UnmarshalJSON` ever gets a chance to reject it as malformed. There is no `io.LimitReader` or size pre-check anywhere in this path [3](#0-2) .

Regarding the other sub-claims in the question:
- `ref.Context().Digest(refDesc.Digest.String())` only replaces the digest component of the reference that was already derived from the reference the victim supplied (`ref`); `Context()` keeps the original registry host and repository path, so a malicious `refDesc.Digest` value cannot redirect the fetch to a different repository or registry. This part of the hypothesis is not supported by the code.
- The `strings.HasPrefix(refDesc.ArtifactType, "application/vnd.dev.sigstore.bundle")` check is only a routing filter over data the attacker registry itself already fully controls; since the attacker also controls the bundle bytes returned for any digest it advertises, there is no meaningful "bypass" — the attacker doesn't need to spoof the prefix to control what's parsed, they already control everything served.

### Impact Explanation
An attacker who runs (or spoofs) an OCI registry that a victim explicitly points `gh attestation verify oci://...` at can force unbounded memory allocation on the victim machine, leading to process/host resource exhaustion (denial of service). This is a client-side DoS, not code execution, credential leak, or verification bypass — the sigstore bundle content is still validated via `bundle.UnmarshalJSON`/policy checks after being fully read, so no attestation soundness is broken.

### Likelihood Explanation
Requires the victim to intentionally target a registry under attacker control (e.g., `gh attestation verify oci://attacker-registry/...`), which is an accepted precondition here (self-hosted malicious registry) but still requires the victim to choose to trust/query that host. Given that precondition, the exploit is trivial and fully repeatable: the attacker just needs to serve a referrers manifest with a huge declared layer size/blob for any digest.

### Recommendation
Bound the read with `io.LimitReader(layer0, maxBundleSize)` (and/or check `layers[0].Size()` against a sane maximum before calling `Uncompressed()`), returning an error if the layer exceeds the expected sigstore bundle size, before buffering it fully into memory.

### Proof of Concept
Add a test that stubs `remote.Referrers`/`remote.Image`/layer access (via an interface fake or a local test registry using `httptest`) to return a referrer image whose single layer is a valid-gzip stream of e.g. several GB of repeated bytes with a declared size matching. Assert that `GetAttestations`:
1. Currently: allocates memory proportional to the attacker-declared size (observable via `io.ReadAll` return length equal to the injected size, or via a memory/time-based test using a smaller but clearly oversized value plus a `t.Fatal` if the read isn't bounded by a constant cap).
2. After fix: returns an error once the read exceeds `maxBundleSize` without buffering the full attacker payload.

### Citations

**File:** pkg/cmd/attestation/artifact/oci/client.go (L84-92)
```go
	for _, refDesc := range refManifest.Manifests {
		if !strings.HasPrefix(refDesc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
			continue
		}

		refImg, err := remote.Image(ref.Context().Digest(refDesc.Digest.String()), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return attestations, fmt.Errorf("error getting referrer image: %w", err)
		}
```

**File:** pkg/cmd/attestation/artifact/oci/client.go (L98-112)
```go
		if len(layers) > 0 {
			layer0, err := layers[0].Uncompressed()
			if err != nil {
				return attestations, fmt.Errorf("error getting referrer image: %w", err)
			}
			defer layer0.Close()

			bundleBytes, err := io.ReadAll(layer0)

			if err != nil {
				return attestations, fmt.Errorf("error getting referrer image: %w", err)
			}

			b := &bundle.Bundle{}
			err = b.UnmarshalJSON(bundleBytes)
```
