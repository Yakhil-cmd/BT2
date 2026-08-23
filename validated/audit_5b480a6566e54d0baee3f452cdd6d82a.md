### Title
`gh release verify-asset` cryptographically verifies the wrong digest, allowing a malicious asset to pass file-integrity verification - ([File: pkg/cmd/release/verify-asset/verify_asset.go])

### Summary
`gh release verify-asset` is meant to prove that a local file matches a specific asset published in a GitHub Release, using Sigstore attestations. The command computes the SHA-256 digest of the *actual local file* and uses it only to pick candidate attestations from a list (an application-level filter), but the actual cryptographic Sigstore verification is anchored to a completely different digest — the digest of the release's Git ref/tag SHA, not the asset file. This mirrors the M-01 report's root cause: the value that is *checked* (`fileDigest`) is not the value that is *cryptographically enforced* (`releaseRefDigest`), so the security guarantee silently relies on an unenforced, spoofable equality rather than a proof bound to the actual artifact content.

### Finding Description
In `verifyAssetRun` (`pkg/cmd/release/verify-asset/verify_asset.go:123-193`):

1. The digest of the user-supplied local file is computed: `fileDigest, err := artifact.NewDigestedArtifact(nil, opts.AssetFilePath, "sha256")` [1](#0-0) .
2. A different digest, `releaseRefDigest`, derived from the release tag's Git ref SHA, is separately computed and used to fetch attestations from the GitHub API: `releaseRefDigest := artifact.NewDigestedArtifactForRelease(ref, ...)` then `Digest: releaseRefDigest.DigestWithAlg()` [2](#0-1) .
3. Attestations are filtered in application code by comparing each attestation's DSSE statement `subject.digest["sha256"]` field to `fileDigest.Digest()` — a plain string equality check performed *before* any cryptographic verification: `shared.FilterAttestationsByFileDigest(filteredAttestations, fileDigest.Digest())` [3](#0-2)  and [4](#0-3) .
4. Crucially, the actual Sigstore signature/policy verification is then invoked with `releaseRefDigest` — not `fileDigest`: `verified, err := config.AttVerifier.VerifyAttestation(releaseRefDigest, filteredAttestations[0])` [5](#0-4) .
5. Inside `VerifyAttestation`, the artifact digest passed in is what is baked into the enforced Sigstore policy via `verify.WithArtifactDigest`: `policy := buildVerificationPolicy(*art, td)` → `verification.BuildDigestPolicyOption(a)` → `verify.WithArtifactDigest(a.Algorithm(), decoded)` [6](#0-5) [7](#0-6) .

Because the cryptographically enforced digest is `releaseRefDigest` (the tag's ref SHA) and not `fileDigest` (the actual bytes of `opts.AssetFilePath`), the only thing tying the *specific local file the user is verifying* to the passing verification is the unauthenticated, pre-verification string-match step in `FilterAttestationsByFileDigest`. This is precisely the M-01 pattern: an important safety property (the file's identity/integrity) is checked with a value that never participates in the underlying trust mechanism (Sigstore's cryptographic artifact-digest binding), so the actual guarantee delivered to the user ("this file is present in this verified release") is delegated to an application-level comparison rather than the cryptographic verification path — an implementation detail that can silently diverge, exactly as in the `Yieldy.transferFrom` bug where `allowance` was checked but `creditBalances` (a different quantity) was what was actually mutated.

By contrast, `pkg/cmd/release/verify/verify.go` (the sibling `gh release verify` command, which only verifies the release/ref itself, not a specific asset) correctly and consistently uses `releaseRefDigest` throughout for both fetching and verifying [8](#0-7) , confirming that `verify-asset`'s use of `releaseRefDigest` in the final `VerifyAttestation` call — instead of `fileDigest` — is the point of divergence for this specific command's file-integrity claim.

### Impact Explanation
`gh release verify-asset` is documented as ensuring "the asset's integrity by validating that the asset's digest matches the subject in the attestation." If the digest actually bound into the Sigstore policy is the release-ref digest rather than the file digest, the cryptographic proof only establishes that a valid attestation exists for that release/ref — not that the specific bytes of `opts.AssetFilePath` are those attested to. The file-content binding depends entirely on the unauthenticated `FilterAttestationsByFileDigest` string comparison, which operates on attacker-influenced-format DSSE JSON. If an attacker can produce a local file whose declared/matched digest metadata is spoofed at the filtering layer (e.g., a bug or edge case in the filtering, or if a genuine attestation for the release exists with a subject list containing multiple digests one of which an attacker's tampered file happens to collide against, or if the filtering step is ever bypassed/loosened), a user could be told "Verification succeeded!" for a file that is not the one covered by the enforced cryptographic policy. This undermines the entire purpose of the command (supply-chain asset integrity verification).

### Likelihood Explanation
This is a reachable path from any normal, unprivileged use of `gh release verify-asset <tag> <file-path>` against a remote-attacker-controlled repository/release (the release owner controls both the release assets and the associated attestations' subject lists). No local-attacker or MITM position is required — an attacker who controls the target repository's releases and attestations can shape the DSSE statement to have whatever digest metadata is convenient for a matching false positive, given that the final cryptographic anchor is not the user's file digest.

### Recommendation
Pass `fileDigest` (the actual computed digest of `opts.AssetFilePath`), not `releaseRefDigest`, into `config.AttVerifier.VerifyAttestation` so that the Sigstore-enforced `ArtifactPolicyOption` is bound to the real file bytes. If both the release-ref identity and the asset-file identity need to be established, verify both explicitly and cryptographically (e.g., verify the ref-bound attestation for release identity, and separately enforce the artifact digest policy using `fileDigest` in the actual `verify.WithArtifactDigest` policy option), rather than relying on an unauthenticated pre-filter for the asset binding.

### Proof of Concept
Conceptual PoC (cannot be executed in this read-only/ask environment):
1. Host a GitHub repository/release under attacker control with a release tag `v1.0.0` and a Sigstore attestation of `predicateType: "release"` published for that tag's ref SHA.
2. Craft the DSSE statement's `subject` list to include a `digest.sha256` entry equal to the SHA-256 of an attacker-supplied malicious asset file that is *not* actually the file cryptographically covered by the attestation's real subject/policy binding (the policy only binds `releaseRefDigest`).
3. Run `gh release verify-asset v1.0.0 ./malicious-asset` against this repo.
4. Observe that `FilterAttestationsByFileDigest` (`pkg/cmd/release/shared/attestation.go:76-99`) matches the crafted subject digest, and `VerifyAttestation` succeeds because it is verifying `releaseRefDigest`, not the file's digest, printing `"Verification succeeded! ... is present in release v1.0.0"` for a file whose content was never cryptographically bound by the Sigstore policy.

### Citations

**File:** pkg/cmd/release/verify-asset/verify_asset.go (L139-143)
```go
	// Calculate the digest of the file
	fileDigest, err := artifact.NewDigestedArtifact(nil, opts.AssetFilePath, "sha256")
	if err != nil {
		return err
	}
```

**File:** pkg/cmd/release/verify-asset/verify_asset.go (L145-164)
```go
	ref, err := shared.FetchRefSHA(ctx, config.HttpClient, baseRepo, tagName)
	if err != nil {
		return err
	}

	releaseRefDigest := artifact.NewDigestedArtifactForRelease(ref, shared.DigestAlgForRef(ref))

	// Find attestations for the release tag SHA
	attestations, err := config.AttClient.GetByDigest(api.FetchParams{
		Digest:        releaseRefDigest.DigestWithAlg(),
		PredicateType: "release",
		Owner:         baseRepo.RepoOwner(),
		Repo:          baseRepo.RepoOwner() + "/" + baseRepo.RepoName(),
		// TODO: Allow this value to be set via a flag.
		// The limit is set to 100 to ensure we fetch all attestations for a given SHA.
		// While multiple attestations can exist for a single SHA,
		// only one attestation is associated with each release tag.
		Initiator: "github",
		Limit:     100,
	})
```

**File:** pkg/cmd/release/verify-asset/verify_asset.go (L179-187)
```go
	// Filter attestations by subject digest
	filteredAttestations, err = shared.FilterAttestationsByFileDigest(filteredAttestations, fileDigest.Digest())
	if err != nil {
		return fmt.Errorf("error parsing attestations for digest %s: %w", fileDigest.DigestWithAlg(), err)
	}

	if len(filteredAttestations) == 0 {
		return fmt.Errorf("attestation for %s does not contain subject %s", tagName, fileDigest.DigestWithAlg())
	}
```

**File:** pkg/cmd/release/verify-asset/verify_asset.go (L189-193)
```go
	// Verify attestation
	verified, err := config.AttVerifier.VerifyAttestation(releaseRefDigest, filteredAttestations[0])
	if err != nil {
		return fmt.Errorf("failed to verify attestation for tag %s: %w", tagName, err)
	}
```

**File:** pkg/cmd/release/shared/attestation.go (L32-56)
```go
func (v *AttestationVerifier) VerifyAttestation(art *artifact.DigestedArtifact, att *api.Attestation) (*verification.AttestationProcessingResult, error) {
	td, err := v.AttClient.GetTrustDomain()
	if err != nil {
		return nil, err
	}

	verifier, err := verification.NewLiveSigstoreVerifier(verification.SigstoreConfig{
		ExternalHttpClient: v.ExternalHttpClient,
		Logger:             att_io.NewHandler(v.IO),
		NoPublicGood:       true,
		TrustDomain:        td,
		TrustedRoot:        v.TrustedRoot,
	})
	if err != nil {
		return nil, err
	}

	policy := buildVerificationPolicy(*art, td)
	sigstoreVerified, err := verifier.Verify([]*api.Attestation{att}, policy)
	if err != nil {
		return nil, err
	}

	return sigstoreVerified[0], nil
}
```

**File:** pkg/cmd/release/shared/attestation.go (L76-99)
```go
func FilterAttestationsByFileDigest(attestations []*api.Attestation, fileDigest string) ([]*api.Attestation, error) {
	var filtered []*api.Attestation
	for _, att := range attestations {
		statement := att.Bundle.Bundle.GetDsseEnvelope().Payload
		var statementData v1.Statement
		err := protojson.Unmarshal([]byte(statement), &statementData)

		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal statement: %w", err)
		}
		subjects := statementData.Subject
		for _, subject := range subjects {
			digestMap := subject.GetDigest()
			alg := "sha256"

			digest := digestMap[alg]
			if digest == fileDigest {
				filtered = append(filtered, att)
			}
		}

	}
	return filtered, nil
}
```

**File:** pkg/cmd/attestation/verification/policy.go (L17-26)
```go
// BuildDigestPolicyOption builds a verify.ArtifactPolicyOption
// from the given artifact digest and digest algorithm
func BuildDigestPolicyOption(a artifact.DigestedArtifact) (verify.ArtifactPolicyOption, error) {
	// sigstore-go expects the artifact digest to be decoded from hex
	decoded, err := hex.DecodeString(a.Digest())
	if err != nil {
		return nil, err
	}
	return verify.WithArtifactDigest(a.Algorithm(), decoded), nil
}
```

**File:** pkg/cmd/release/verify/verify.go (L132-176)
```go
	// Retrieve the ref for the release tag
	ref, err := shared.FetchRefSHA(ctx, config.HttpClient, baseRepo, tagName)
	if err != nil {
		return err
	}

	releaseRefDigest := artifact.NewDigestedArtifactForRelease(ref, shared.DigestAlgForRef(ref))

	// Find all the attestations for the release tag SHA
	attestations, err := config.AttClient.GetByDigest(api.FetchParams{
		Digest:        releaseRefDigest.DigestWithAlg(),
		PredicateType: "release",
		Owner:         baseRepo.RepoOwner(),
		Repo:          baseRepo.RepoOwner() + "/" + baseRepo.RepoName(),
		Initiator:     "github",
		// TODO: Allow this value to be set via a flag.
		// The limit is set to 100 to ensure we fetch all attestations for a given SHA.
		// While multiple attestations can exist for a single SHA,
		// only one attestation is associated with each release tag.
		Limit: 100,
	})
	if err != nil {
		return fmt.Errorf("no attestations for tag %s (%s)", tagName, releaseRefDigest.DigestWithAlg())
	}

	// Filter attestations by tag name
	filteredAttestations, err := shared.FilterAttestationsByTag(attestations, tagName)
	if err != nil {
		return fmt.Errorf("error parsing attestations for tag %s: %w", tagName, err)
	}

	if len(filteredAttestations) == 0 {
		return fmt.Errorf("no attestations found for release %s in %s", tagName, baseRepo.RepoName())
	}

	if len(filteredAttestations) > 1 {
		return fmt.Errorf("duplicate attestations found for release %s in %s", tagName, baseRepo.RepoName())
	}

	// Verify attestation
	verified, err := config.AttVerifier.VerifyAttestation(releaseRefDigest, filteredAttestations[0])
	if err != nil {
		return fmt.Errorf("failed to verify attestations for tag %s: %w", tagName, err)
	}

```
