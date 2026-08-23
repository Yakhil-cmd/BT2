### Title
Unescaped `trustDomain` injected into regex for SAN certificate matching allows attestation verification bypass - (File: pkg/cmd/release/shared/attestation.go)

### Summary
`buildVerificationPolicy` builds a Sigstore SAN‑matching regex with `fmt.Sprintf("^https://%s\\.releases\\.github\\.com$", trustDomain)` without escaping `trustDomain` via `regexp.QuoteMeta`. Since `trustDomain` originates from the untrusted `meta` API response of the host that `gh` is pointed at (`c.githubAPI.REST(c.host, ...)` in `GetTrustDomain`), an attacker who controls that host's response can inject regex metacharacters and turn the SAN check into a match-anything pattern, defeating certificate-identity verification.

### Finding Description
`AttestationVerifier.VerifyAttestation` calls `v.AttClient.GetTrustDomain()` [1](#0-0)  which performs an unauthenticated-content REST GET to `<host>/meta` and returns `resp.Domains.ArtifactAttestations.TrustDomain` verbatim from the JSON body [2](#0-1) , with no validation on its character set [3](#0-2) .

That raw string is fed directly into `buildVerificationPolicy`, which builds the SAN regex with `fmt.Sprintf` and no `regexp.QuoteMeta` escaping before calling `verify.NewSANMatcher`: [4](#0-3) 

Because Go's `regexp.MatchString`/`FindString` semantics treat unanchored alternatives as matching anywhere in the string, an attacker-supplied `trustDomain` such as `x$|.*` produces the compiled pattern `^https://x$|.*\.releases\.github\.com$`, whose middle-like unanchored branch (`.*`) matches virtually any string. This effectively disables the SAN identity check performed by `verify.NewCertificateIdentity`/`verify.NewPolicy` at line 110-113, meaning any certificate — regardless of its actual SAN — can satisfy the policy, as long as the digest and other identity constraints (which are separately/loosely enforced, e.g. `issuerMatcher` is already `.*`) also pass.

### Impact Explanation
This maps to an attestation/verification-bypass class impact: `gh release verify-asset` (and any caller of `AttestationVerifier.VerifyAttestation`, e.g. `pkg/cmd/release/verify`) could accept a release-asset attestation whose Fulcio certificate SAN does not actually correspond to `releases.github.com`, undermining the guarantee that a downloaded release asset was produced by GitHub's release pipeline. Impact is scoped specifically to hosts where the attacker can control the `/meta` API response (tenancy/enterprise host resolution path), matching the question's stated scope.

### Likelihood Explanation
Exploitation requires that `f.BaseRepo()`/`opts.Hostname` resolves to a host whose `meta` endpoint response is attacker-influenced — this is a non-trivial precondition (the victim must be pointed at an attacker-controlled/spoofable enterprise or tenancy host) rather than something reachable from a plain fork/PR/release on github.com. Given that precondition, exploitation is deterministic and repeatable: any crafted `trust_domain` JSON value containing unescaped regex metacharacters (e.g. `.*`, `|`, `$`) is fetched once per verification call and used unescaped every time.

### Recommendation
Escape `trustDomain` with `regexp.QuoteMeta` before interpolating it into the SAN pattern in `buildVerificationPolicy`:
```go
sanMatcher, _ := verify.NewSANMatcher("", fmt.Sprintf("^https://%s\\.releases\\.github\\.com$", regexp.QuoteMeta(trustDomain)))
```
Additionally validate `trustDomain` against an expected character set (e.g. `^[a-zA-Z0-9-]+$`) as defense in depth, and apply the same fix anywhere else a fetched trust domain is interpolated into a regex (check `pkg/cmd/attestation/verify/verify.go` and `pkg/cmd/attestation/trustedroot/trustedroot.go`, which also consume `GetTrustDomain()`).

### Proof of Concept
```go
func TestBuildVerificationPolicy_RegexInjection(t *testing.T) {
    maliciousTrustDomain := `evil$|.*`
    policy := buildVerificationPolicy(someDigestedArtifact, maliciousTrustDomain)

    // Craft/mock a certificate whose SAN is completely unrelated,
    // e.g. "https://attacker.example/not-a-release-domain"
    cert := certWithSAN("https://attacker.example/not-a-release-domain")

    // Expected (secure) behavior: policy verification should reject this cert
    // Actual (vulnerable) behavior: due to unescaped ".*" alternative, the
    // SAN matcher matches unconditionally and verification succeeds.
    err := policy.VerifyCertificate(cert) // or via verify.Verify(...)
    require.Error(t, err, "SAN matcher should reject unrelated SAN but injected regex bypasses it")
}
```
This can be run as a unit test directly against `verify.NewSANMatcher("", fmt.Sprintf("^https://%s\\.releases\\.github\\.com$", maliciousTrustDomain))`, asserting `sanMatcher.Matches("https://attacker.example/not-a-release-domain")` returns `true` when it should be `false`, confirming the bypass.

### Citations

**File:** pkg/cmd/release/shared/attestation.go (L32-36)
```go
func (v *AttestationVerifier) VerifyAttestation(art *artifact.DigestedArtifact, att *api.Attestation) (*verification.AttestationProcessingResult, error) {
	td, err := v.AttClient.GetTrustDomain()
	if err != nil {
		return nil, err
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

**File:** pkg/cmd/attestation/api/client.go (L293-325)
```go
// GetTrustDomain returns the current trust domain. If the default is used
// the empty string is returned
func (c *LiveClient) GetTrustDomain() (string, error) {
	u, err := safeurl.JoinPath(MetaPath)
	if err != nil {
		return "", err
	}
	return c.getTrustDomain(u)
}

func (c *LiveClient) getTrustDomain(u safeurl.SafeURL) (string, error) {
	var resp MetaResponse

	bo := backoff.NewConstantBackOff(getAttestationRetryInterval)
	err := backoff.Retry(func() error {
		restErr := c.githubAPI.REST(c.host, http.MethodGet, u.String(), nil, &resp)
		if restErr != nil {
			if shouldRetry(restErr) {
				return restErr
			} else {
				return backoff.Permanent(restErr)
			}
		}

		return nil
	}, backoff.WithMaxRetries(bo, 3))

	if err != nil {
		return "", err
	}

	return resp.Domains.ArtifactAttestations.TrustDomain, nil
}
```

**File:** pkg/cmd/attestation/api/trust_domain.go (L1-17)
```go
package api

const MetaPath = "meta"

type ArtifactAttestations struct {
	TrustDomain string `json:"trust_domain"`
}

type Domain struct {
	ArtifactAttestations ArtifactAttestations `json:"artifact_attestations"`
}

type MetaResponse struct {
	Domains Domain `json:"domains"`
}


```
