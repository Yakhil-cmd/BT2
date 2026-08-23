### Title
Unbounded processing of OCI referrer manifests during attestation verification enables resource-exhaustion DoS - (File: `pkg/cmd/attestation/artifact/oci/client.go`)

### Summary
`LiveClient.GetAttestations` iterates over every entry in a `Referrers` manifest fetched from a (potentially attacker-controlled) OCI registry and, for each entry whose `ArtifactType` matches the sigstore bundle prefix, performs a full remote image fetch (`remote.Image`), reads all layers, and unmarshals bundle content — with no cap on how many referrer entries or matching entries can be processed.

### Finding Description
When a user runs `gh attestation verify <image> --bundle-from-oci`, the code path calls `GetOCIAttestations` → `LiveClient.GetAttestations`: [1](#0-0) 

The function fetches the referrers index for the given digest and then loops over `refManifest.Manifests` with no bound on the number of entries and no limit on how many matching (`application/vnd.dev.sigstore.bundle*`) entries it will fetch and decode: [2](#0-1) 

Every matching referrer triggers an additional network round trip (`remote.Image`), full layer download, `io.ReadAll` buffering, and JSON unmarshalling into a `bundle.Bundle`. Because the registry (and thus the referrers index content) is attacker-controlled when the user points `gh attestation verify` at an untrusted or attacker-published image/registry, an attacker can publish an image whose referrers index contains an arbitrarily large number of entries with the sigstore bundle artifact type. There is no `MAX_DELEGATES`-style cap analogous to what `VotingEscrow.sol` enforces on `_moveTokenDelegates`/`_moveAllDelegates`; the loop here has no equivalent limit on iteration count, network calls, or aggregate memory used by the growing `attestations` slice.

This mirrors the reported bug class: an attacker-controlled, unbounded collection (delegated token IDs in the original report; OCI referrer manifests here) is fully iterated and processed during a routine, unprivileged operation, with per-item cost (network fetch + decode) multiplying attacker-supplied item counts into large aggregate cost.

### Impact Explanation
A malicious or compromised registry/image can force `gh attestation verify --bundle-from-oci` to perform an unbounded number of network fetches and memory allocations, hanging the CLI invocation or exhausting local memory/network resources — a denial-of-service against the invoking user's environment. Because the invocation is triggered by ordinary use of the documented `--bundle-from-oci` verification flow, no special privilege is required by the attacker beyond controlling the OCI registry/image content being verified.

### Likelihood Explanation
Likelihood is moderate: the attacker must control (or get the victim to verify) an OCI image/registry, which is the intended and documented trust boundary for `--bundle-from-oci`. The report class calls this out because the pattern is unprivileged/remote — the attacker only needs to publish content, not compromise the client. Actual severity depends on how permissive OCI registries are about oversized referrers indexes, but nothing in the client code guards against it.

### Recommendation
Bound the number of referrer entries processed (e.g., cap `len(refManifest.Manifests)` and/or the number of matching sigstore-bundle entries fetched), enforce a maximum aggregate size/time budget for the referrer-fetch loop, and fail fast with a clear error once the bound is exceeded, similar to how `walkTree`'s `maxTreeDepth` bounds recursive API calls elsewhere in the codebase (`internal/skills/discovery/discovery.go`).

### Proof of Concept
1. Publish (or simulate via a test OCI registry) an image whose `Referrers` index contains N (e.g., 10,000+) manifest entries with `ArtifactType` prefixed `application/vnd.dev.sigstore.bundle`.
2. Run `gh attestation verify oci://<attacker-registry>/<image> --bundle-from-oci` (or any code path invoking `oci.LiveClient.GetAttestations`).
3. Observe that the CLI issues N sequential `remote.Image` calls and decodes N bundle payloads with no limit, causing excessive network/CPU/memory usage and a long-hanging or resource-exhausted client process, matching the "unbounded attacker-controlled collection processed on every normal operation" bug class from the source report.

### Citations

**File:** pkg/cmd/attestation/artifact/oci/client.go (L71-123)
```go
func (c LiveClient) GetAttestations(ref name.Reference, digest string) ([]*api.Attestation, error) {
	attestations := make([]*api.Attestation, 0)

	transportOpts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	referrers, err := remote.Referrers(ref.Context().Digest(digest), transportOpts...)
	if err != nil {
		return attestations, fmt.Errorf("error getting referrers: %w", err)
	}
	refManifest, err := referrers.IndexManifest()
	if err != nil {
		return attestations, fmt.Errorf("error getting referrers manifest: %w", err)
	}

	for _, refDesc := range refManifest.Manifests {
		if !strings.HasPrefix(refDesc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
			continue
		}

		refImg, err := remote.Image(ref.Context().Digest(refDesc.Digest.String()), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return attestations, fmt.Errorf("error getting referrer image: %w", err)
		}
		layers, err := refImg.Layers()
		if err != nil {
			return attestations, fmt.Errorf("error getting referrer image: %w", err)
		}

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

			if err != nil {
				return attestations, fmt.Errorf("error unmarshalling bundle: %w", err)
			}

			a := api.Attestation{Bundle: b}
			attestations = append(attestations, &a)
		} else {
			return attestations, fmt.Errorf("error getting referrer image: no layers found")
		}
	}
```
