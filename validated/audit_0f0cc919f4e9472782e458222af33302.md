### Title
`gh release verify` never checks the attestation certificate's source-repository identity, relying solely on server-side digest lookup for repo binding - ([File: pkg/cmd/release/shared/attestation.go])

### Finding Description
`NewCmdVerify` / `verifyRun` in `pkg/cmd/release/verify/verify.go` resolves the release tag to a git ref SHA via `shared.FetchRefSHA` and then calls `config.AttClient.GetByDigest` with `Digest`, `Owner`, and `Repo` set from `baseRepo` [1](#0-0) . The returned attestations are filtered only by the `tag` field inside the DSSE predicate via `shared.FilterAttestationsByTag`, never by repository or owner [2](#0-1) .

The actual cryptographic policy used to verify the bundle, `buildVerificationPolicy`, only checks two things: the artifact digest, and that the certificate's SAN matches the fixed, repo-agnostic string `^https://<trustdomain>\.releases\.github\.com$`, with an issuer matcher that accepts `.*` and an **empty** `certificate.Extensions{}` [3](#0-2) . Unlike `gh attestation verify` (`pkg/cmd/attestation/verify/policy.go`), which explicitly enforces `SourceRepositoryOwnerURI`, `SourceRepositoryURI`, `Issuer`, etc. via `verification.EnforcementCriteria` and `VerifyCertExtensions` [4](#0-3) , `gh release verify` performs **no local check at all** that the attestation's certificate actually names the victim's repo/owner. The entire repo-binding trust boundary is pushed onto the server-side `GetByDigest` owner/repo filter and the assumption that the digest (a git object SHA) is unique to the victim's commit.

That assumption is weak in a realistic scenario: git object SHAs are content-addressed and identical across forks that share commit history. An attacker who forks a victim's public repository shares the exact same commit SHAs as the upstream. If GitHub's attestation store indexes primarily by digest (with owner/repo used only as a soft filter, or if that filter is bypassable/misconfigured on the server), an attestation legitimately produced for the attacker's own fork/release at the identical commit SHA could satisfy the digest lookup for the victim's owner/repo query. Because the local Sigstore policy performs no independent verification of `SourceRepositoryURI`/`SourceRepositoryOwnerURI` in the certificate, the client has no defense-in-depth check to catch this — it would print "Release verified!" for a release backed by an attestation belonging to a different repository.

### Impact Explanation
If the server-side digest/owner/repo scoping ever mismatches (fork SHA reuse, API bug, GHES misconfiguration), `gh release verify` would report a release as verified when the underlying attestation was not actually produced for that repository/owner — a supply-chain verification bypass matching the "attestation or authorization bypass" impact class. This is meaningfully lower assurance than the sibling `gh attestation verify` command, which independently re-validates repo/owner identity from the certificate itself.

### Likelihood Explanation
Exploitability from a purely unprivileged, no-MITM, no-server-bug standpoint could **not be confirmed** with the code available in this repo: the actual enforcement of the `Owner`/`Repo` filter happens inside GitHub's server-side attestation API (`api.Client.GetByDigest`), which is outside this codebase and cannot be inspected or proven to be bypassable here. Local client code alone does not give an attacker a way to force `baseRepo` (used for the API query) to point at their own artifact, since `baseRepo` is derived from the victim's own `f.BaseRepo()` context, not attacker input. Fork-based SHA collision is a plausible but unverified precondition; without evidence that GitHub's server fails to enforce owner/repo scoping, this remains a defense-in-depth gap rather than a demonstrated, reproducible bypass purely from client code.

### Recommendation
Add an explicit, local certificate-extension check in `buildVerificationPolicy` (`pkg/cmd/release/shared/attestation.go`) that verifies `SourceRepositoryOwnerURI` and `SourceRepositoryURI` against `baseRepo`, mirroring the `verification.EnforcementCriteria`/`VerifyCertExtensions` pattern already used by `gh attestation verify`, so that repo/owner identity is enforced client-side and does not depend solely on server-side digest/owner filtering.

### Proof of Concept
Not reproducible purely with current repo code/tests, since the critical trust decision (whether `GetByDigest` can return a cross-repo attestation for a colliding digest) lives in GitHub's server implementation, not in this client codebase. A concrete PoC would require:
1. A test double for `api.Client.GetByDigest` that returns a genuine bundle whose certificate's `SourceRepositoryURI`/`SourceRepositoryOwnerURI` point to a different repo than `baseRepo`, with matching tag/digest.
2. Assert `config.AttVerifier.VerifyAttestation` (using `shared.AttestationVerifier`/`buildVerificationPolicy`) still returns `verified == true`, demonstrating the missing local repo-identity check, e.g. extending `pkg/cmd/release/shared/attestation_test.go` if present with a bundle built via `certificate.Summary{SourceRepositoryOwnerURI: "https://github.com/attacker", ...}` and confirming `buildVerificationPolicy`'s empty `certificate.Extensions{}` does not reject it.

### Citations

**File:** pkg/cmd/release/verify/verify.go (L141-152)
```go
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
```

**File:** pkg/cmd/release/shared/attestation.go (L58-74)
```go
func FilterAttestationsByTag(attestations []*api.Attestation, tagName string) ([]*api.Attestation, error) {
	var filtered []*api.Attestation
	for _, att := range attestations {
		statement := att.Bundle.Bundle.GetDsseEnvelope().Payload
		var statementData v1.Statement
		err := protojson.Unmarshal([]byte(statement), &statementData)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal statement: %w", err)
		}
		tagValue := statementData.Predicate.GetFields()["tag"].GetStringValue()

		if tagValue == tagName {
			filtered = append(filtered, att)
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

**File:** pkg/cmd/attestation/verification/extensions.go (L43-72)
```go
func verifyCertExtensions(given, expected certificate.Summary) error {
	if !strings.EqualFold(expected.SourceRepositoryOwnerURI, given.SourceRepositoryOwnerURI) {
		return fmt.Errorf("expected SourceRepositoryOwnerURI to be %s, got %s", expected.SourceRepositoryOwnerURI, given.SourceRepositoryOwnerURI)
	}

	// if repo is set, compare the SourceRepositoryURI fields
	if expected.SourceRepositoryURI != "" && !strings.EqualFold(expected.SourceRepositoryURI, given.SourceRepositoryURI) {
		return fmt.Errorf("expected SourceRepositoryURI to be %s, got %s", expected.SourceRepositoryURI, given.SourceRepositoryURI)
	}

	// compare the OIDC issuers. If not equal, return an error depending
	// on if there is a partial match
	if !strings.EqualFold(expected.Issuer, given.Issuer) {
		if strings.Index(given.Issuer, expected.Issuer+"/") == 0 {
			return fmt.Errorf("expected Issuer to be %s, got %s -- if you have a custom OIDC issuer policy for your enterprise, use the --cert-oidc-issuer flag with your expected issuer", expected.Issuer, given.Issuer)
		}
		return fmt.Errorf("expected Issuer to be %s, got %s", expected.Issuer, given.Issuer)
	}

	if expected.BuildSignerDigest != "" && !strings.EqualFold(expected.BuildSignerDigest, given.BuildSignerDigest) {
		return fmt.Errorf("expected BuildSignerDigest to be %s, got %s", expected.BuildSignerDigest, given.BuildSignerDigest)
	}
	if expected.SourceRepositoryDigest != "" && !strings.EqualFold(expected.SourceRepositoryDigest, given.SourceRepositoryDigest) {
		return fmt.Errorf("expected SourceRepositoryDigest to be %s, got %s", expected.SourceRepositoryDigest, given.SourceRepositoryDigest)
	}
	if expected.SourceRepositoryRef != "" && !strings.EqualFold(expected.SourceRepositoryRef, given.SourceRepositoryRef) {
		return fmt.Errorf("expected SourceRepositoryRef to be %s, got %s", expected.SourceRepositoryRef, given.SourceRepositoryRef)
	}

	return nil
```
