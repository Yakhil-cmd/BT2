### Title
`gh release verify-asset` cryptographically verifies the release ref digest instead of the asset file digest, bypassing asset-to-attestation binding - (File: pkg/cmd/release/verify-asset/verify_asset.go)

### Summary
`gh release verify-asset` is documented to validate "that the asset's digest matches the subject in the attestation" [1](#0-0) . In practice, the asset's own digest (`fileDigest`) is only used for an unauthenticated, plaintext JSON match against candidate attestations, while the actual cryptographic Sigstore policy check — the only step that proves the digest is genuinely part of the signed content — is built against a completely different value, `releaseRefDigest` (the release tag's git SHA), not the asset file's digest. This is the same bug class as the reported vault issue: a slippage/threshold check is computed against one value, but the value actually used/enforced on the security-relevant path is a different one.

### Finding Description
In `verifyAssetRun`, the digest of the local asset file is computed as `fileDigest` [2](#0-1) , and separately the release ref SHA digest is computed as `releaseRefDigest` [3](#0-2) .

Attestations are fetched by `releaseRefDigest`, then filtered by tag name, and then filtered again using `shared.FilterAttestationsByFileDigest(filteredAttestations, fileDigest.Digest())` [4](#0-3) . That helper only unmarshals the DSSE envelope payload as plain JSON and string-compares the subject digest field — it performs no cryptographic verification at this point [5](#0-4) .

The cryptographic verification step that follows is the only place that actually proves the bundle is validly signed and matches a specific digest via Sigstore's artifact-digest policy option: [6](#0-5) 

But it is called with `releaseRefDigest`, not `fileDigest`. Internally, `VerifyAttestation` builds the enforced policy from whatever `*artifact.DigestedArtifact` it receives: [7](#0-6) [8](#0-7) 

`BuildDigestPolicyOption` translates that same `*artifact.DigestedArtifact` into a `verify.WithArtifactDigest(...)` policy option [9](#0-8) , which is what Sigstore's verifier actually enforces against the signed DSSE statement's subject list. Because `releaseRefDigest` is passed here instead of `fileDigest`, the cryptographic policy enforced is "the attestation contains the release-ref SHA as a subject," never "the attestation contains this specific asset file's sha256 as a subject." The binding between the concrete local file on disk and the cryptographically-verified attestation content is therefore never actually asserted by the signature-verification code path; it only ever existed as an unauthenticated plaintext match performed earlier in `FilterAttestationsByFileDigest`.

This directly mirrors the reported bug class: a slippage/threshold value is validated against one quantity (`assets`/here `fileDigest`) while the value that is actually transferred/enforced on a particular code path is a different quantity (`liquidation_amount`/here `releaseRefDigest`).

### Impact Explanation
The command's core security promise — "verify that a given asset originated from a release" by cryptographically tying the asset bytes to a GitHub-signed attestation — is not actually delivered by the cryptographic verification step. The step that consumers should trust (`VerifyAttestation`, which runs full Sigstore/Fulcio/Rekor verification) only proves that a validly signed attestation exists for the *release ref*, not that the signed attestation's subject list actually, verifiably contains the digest of the file the user pointed at. The asset-to-digest correlation is left to an un-verified JSON parse (`FilterAttestationsByFileDigest`) executed before any signature check. If that pre-filter logic has any parsing edge case, or if the object fed into it is not identical byte-for-byte to what is later verified (e.g. future refactors that change the attestation object between the filter and verify calls), the command can report "Verification succeeded!" for an asset whose digest was never cryptographically confirmed. This undermines the guarantee that operators/users of `gh release verify-asset` (used in supply-chain / CI gating scenarios) rely on to decide whether to trust a downloaded artifact.

### Likelihood Explanation
This is a latent verification-bypass in the intended security control path rather than an input-validation crash — every invocation of `gh release verify-asset` uses this code path, so triggering the divergent variable use requires no attacker action; the flaw is structural. Exploiting it to defeat asset verification requires an attacker who can influence what the plaintext pre-filter matches (e.g., by controlling additional subjects listed in a GitHub-issued attestation covering a release with multiple assets) or relies on future code changes that decouple the filtered attestation object from the one passed to verification. This is a design/logic defect independent of any privileged access, matching the "verification bypass" category explicitly in scope.

### Recommendation
Pass `fileDigest` (not `releaseRefDigest`) into `config.AttVerifier.VerifyAttestation` so the Sigstore artifact-digest policy is built and enforced against the actual asset's digest:
```go
verified, err := config.AttVerifier.VerifyAttestation(fileDigest, filteredAttestations[0])
```
If binding to the release ref is also required, add a distinct, additional cryptographic policy check (e.g. verifying the ref digest is present as a separate subject) rather than substituting it for the asset digest check. Remove reliance on `FilterAttestationsByFileDigest`'s unauthenticated plaintext match as the sole source of asset-digest assurance, or re-validate the matched subject post-signature-verification against `fileDigest.Digest()` explicitly.

### Proof of Concept
Not independently reproducible without live GitHub attestation infrastructure and API access. The root-cause code path is deterministic and directly inspectable:
1. `fileDigest` = sha256 of local asset file [2](#0-1) .
2. `releaseRefDigest` = digest of the release tag's git ref SHA [3](#0-2) .
3. Attestations are filtered using `fileDigest` via plaintext JSON parsing only [5](#0-4) .
4. The actual cryptographic verification call uses `releaseRefDigest` instead of `fileDigest` [6](#0-5) , so the Sigstore policy built via `BuildDigestPolicyOption` never asserts anything about the asset file's own digest [9](#0-8) .

Note: due to index size limits, some related test or helper files (e.g. `shared.FetchRefSHA`, `shared.DigestAlgForRef`) were not fully available for inspection; starting a Devin session would allow full-repo access to confirm there is no additional post-verification digest comparison elsewhere that mitigates this.

### Citations

**File:** pkg/cmd/release/verify-asset/verify_asset.go (L49-50)
```go
  			This command checks that the asset you provide matches a valid attestation for the specified release (or the latest release, if no tag is given).
			It ensures the asset's integrity by validating that the asset's digest matches the subject in the attestation and that the attestation is associated with the release.
```

**File:** pkg/cmd/release/verify-asset/verify_asset.go (L139-143)
```go
	// Calculate the digest of the file
	fileDigest, err := artifact.NewDigestedArtifact(nil, opts.AssetFilePath, "sha256")
	if err != nil {
		return err
	}
```

**File:** pkg/cmd/release/verify-asset/verify_asset.go (L145-150)
```go
	ref, err := shared.FetchRefSHA(ctx, config.HttpClient, baseRepo, tagName)
	if err != nil {
		return err
	}

	releaseRefDigest := artifact.NewDigestedArtifactForRelease(ref, shared.DigestAlgForRef(ref))
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

**File:** pkg/cmd/release/shared/attestation.go (L101-114)
```go
// buildVerificationPolicy constructs a verification policy for GitHub releases
func buildVerificationPolicy(a artifact.DigestedArtifact, trustDomain string) verify.PolicyBuilder {
	// If no trust domain is specified, default to "dotcom"
	if trustDomain == "" {
		trustDomain = "dotcom"
	}
	// SAN must match the GitHub releases domain. No issuer extension (match anything)
	sanMatcher, _ := verify.NewSANMatcher("", fmt.Sprintf("^https://%s\\.releases\\.github\\.com$", trustDomain))
	issuerMatcher, _ := verify.NewIssuerMatcher("", ".*")
	certId, _ := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{})

	artifactDigestPolicyOption, _ := verification.BuildDigestPolicyOption(a)
	return verify.NewPolicy(artifactDigestPolicyOption, verify.WithCertificateIdentity(certId))
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
