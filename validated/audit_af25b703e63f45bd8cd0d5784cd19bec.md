[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** pkg/cmd/attestation/artifact/artifact.go (L86-89)
```go
// DigestWithAlg returns the digest:algorithm of the artifact
func (a *DigestedArtifact) DigestWithAlg() string {
	return fmt.Sprintf("%s:%s", a.digestAlg, a.digest)
}
```

**File:** pkg/cmd/attestation/verification/sigstore.go (L245-267)
```go
func (v *LiveSigstoreVerifier) verify(attestation *api.Attestation, policy verify.PolicyBuilder) (*AttestationProcessingResult, error) {
	issuer, err := getBundleIssuer(attestation.Bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle issuer: %v", err)
	}

	// determine which verifier should attempt verification against the bundle
	verifier, err := v.chooseVerifier(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to choose verifier based on provided bundle issuer: %v", err)
	}

	v.Logger.VerbosePrintf("Attempting verification against issuer \"%s\"\n", issuer)
	// attempt to verify the attestation
	result, err := verifier.Verify(attestation.Bundle, policy)
	// if verification fails, create the error and exit verification early
	if err != nil {
		v.Logger.VerbosePrint(v.Logger.ColorScheme.Redf(
			"Failed to verify against issuer \"%s\" \n\n", issuer,
		))

		return nil, fmt.Errorf("verifying with issuer \"%s\"", issuer)
	}
```

**File:** pkg/cmd/attestation/verification/sigstore.go (L281-312)
```go
func (v *LiveSigstoreVerifier) Verify(attestations []*api.Attestation, policy verify.PolicyBuilder) ([]*AttestationProcessingResult, error) {
	if len(attestations) == 0 {
		return nil, ErrNoAttestationsVerified
	}

	results := make([]*AttestationProcessingResult, len(attestations))
	var verifyCount int
	var lastError error
	totalAttestations := len(attestations)
	for i, a := range attestations {
		v.Logger.VerbosePrintf("Verifying attestation %d/%d against the configured Sigstore trust roots\n", i+1, totalAttestations)

		apr, err := v.verify(a, policy)
		if err != nil {
			lastError = err
			// move onto the next attestation in the for loop if verification fails
			continue
		}
		// otherwise, add the result to the results slice and increment verifyCount
		results[verifyCount] = apr
		verifyCount++
	}

	if verifyCount == 0 {
		return nil, lastError
	}

	// truncate the results slice to only include verified attestations
	results = results[:verifyCount]

	return results, nil
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

**File:** pkg/cmd/attestation/verification/sigstore_integration_test.go (L74-91)
```go
	t.Run("with 2/3 verified attestations", func(t *testing.T) {
		verifier, err := NewLiveSigstoreVerifier(SigstoreConfig{
			ExternalHttpClient: http.DefaultClient,
			Logger:             io.NewTestHandler(),
			TUFMetadataDir:     o.Some(t.TempDir()),
		})
		require.NoError(t, err)

		invalidBundle := getAttestationsFor(t, "../test/data/sigstore-js-2.1.0-bundle-v0.1.json")
		attestations := getAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		attestations = append(attestations, invalidBundle[0])
		require.Len(t, attestations, 3)

		results, err := verifier.Verify(attestations, publicGoodPolicy(t))

		require.Len(t, results, 2)
		require.NoError(t, err)
	})
```

**File:** pkg/cmd/attestation/verify/attestation_integration_test.go (L85-108)
```go
	t.Run("attestations fail to verify when cert extensions don't match enforcement criteria", func(t *testing.T) {
		sgjAttestation := getAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		reusableWorkflowAttestations := getAttestationsFor(t, "../test/data/reusable-workflow-attestation.sigstore.json")
		attestations := []*api.Attestation{sgjAttestation[0], reusableWorkflowAttestations[0], sgjAttestation[1]}
		require.Len(t, attestations, 3)

		rwfResult := verification.BuildMockResult(reusableWorkflowAttestations[0].Bundle, "", "", "https://github.com/malancas", "", verification.GitHubOIDCIssuer)
		sgjResult := verification.BuildSigstoreJsMockResult(t)
		mockResults := []*verification.AttestationProcessingResult{&sgjResult, &rwfResult, &sgjResult}
		mockSgVerifier := verification.NewMockSigstoreVerifierWithMockResults(t, mockResults)

		// we want to test that attestations that pass Sigstore verification but fail
		// cert extension verification are filtered out properly in the second step
		// in verifyAttestations. By using a mock Sigstore verifier, we can ensure
		// that the call to verification.VerifyCertExtensions in verifyAttestations
		// is filtering out attestations as expected
		results, errMsg, err := verifyAttestations(*a, attestations, mockSgVerifier, ec)
		require.NoError(t, err)
		require.Zero(t, errMsg)
		require.Len(t, results, 2)
		for _, result := range results {
			require.NotEqual(t, result.Attestation.Bundle, reusableWorkflowAttestations[0].Bundle)
		}
	})
```
