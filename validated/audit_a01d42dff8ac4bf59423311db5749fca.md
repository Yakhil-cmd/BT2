### Title
Nil pointer dereference panic in `FilterAttestationsByTag`/`FilterAttestationsByFileDigest` via attacker-controlled attestation bundle missing DSSE envelope - ([File: pkg/cmd/release/shared/attestation.go])

### Summary
`FilterAttestationsByTag` and `FilterAttestationsByFileDigest` call `att.Bundle.Bundle.GetDsseEnvelope().Payload` without checking whether `GetDsseEnvelope()` returns `nil`. Since `att.Bundle` (`*bundle.Bundle`) is populated directly from the JSON attestation response returned by the GitHub API for a given digest/repo, an attacker who controls the attestation content associated with their own repository's release (a release they publish) can supply a bundle JSON that omits the `dsseEnvelope` field, causing a nil pointer dereference and crashing `gh release verify-asset` for any victim who runs it against that release.

### Finding Description
The call chain is `verifyAssetRun` (pkg/cmd/release/verify-asset/verify_asset.go:153-183) → `config.AttClient.GetByDigest(...)` which deserializes the GitHub attestations API response into `[]*api.Attestation`, where `Attestation.Bundle` is a `*bundle.Bundle` field populated straight from the `bundle` JSON key [1](#0-0) . This slice is passed unchecked into `shared.FilterAttestationsByTag` and then `shared.FilterAttestationsByFileDigest` [2](#0-1) .

Both filter functions dereference the DSSE envelope's `Payload` field without a nil check: [3](#0-2) [4](#0-3) 

`GetDsseEnvelope()` is a protobuf-generated getter that safely returns `nil` if the underlying `dsseEnvelope` field is absent from the deserialized bundle, but the subsequent `.Payload` is a direct struct field access on that (possibly nil) pointer — this is not a nil-safe getter call and will panic with a nil pointer dereference if the envelope is missing.

Notably, the codebase already demonstrates awareness of this exact hazard: `api.FilterAttestations` in the same package tree explicitly guards against a nil DSSE envelope before dereferencing it (`dsseEnvelope := each.Bundle.GetDsseEnvelope(); if dsseEnvelope != nil { ... }`) [5](#0-4) , but this guard is missing in `pkg/cmd/release/shared/attestation.go`.

Since the attestation bundle content is served by the GitHub attestations API for a repository/release that the attacker controls (their own repo and release), and no schema validation enforces the presence of `dsseEnvelope` before this code path is reached, an attacker can craft/omit this field to trigger the crash whenever a victim runs `gh release verify-asset` against that release.

### Impact Explanation
This is a denial-of-service: any victim invoking `gh release verify-asset` (or `gh release verify`, which shares this code path via `shared.FilterAttestationsByTag`/`FilterAttestationsByFileDigest`) against an attacker-controlled repository/release will crash the `gh` process with an unrecovered panic, rather than receiving a clean verification failure. This maps to a DoS/availability impact class rather than code execution or credential exposure — no memory corruption is possible in Go from a nil pointer dereference, only an unhandled panic/crash.

### Likelihood Explanation
Highly feasible and repeatable: the attacker only needs control over the attestation bundle JSON associated with their own release (attainable by publishing attestations for a repo they own, since the `bundle` field is attacker/repo controlled data returned by the API for that repo's digest). No victim credentials, MITM, or special privileges are required beyond the victim choosing to run `gh release verify-asset`/`gh release verify` against the attacker's repository and tag.

### Recommendation
Add nil checks for `att.Bundle`, `att.Bundle.Bundle`, and the result of `GetDsseEnvelope()` in both `FilterAttestationsByTag` and `FilterAttestationsByFileDigest`, returning a descriptive error (e.g., "attestation bundle is missing a DSSE envelope") instead of dereferencing a nil pointer, mirroring the existing guard pattern already used in `api.FilterAttestations`.

### Proof of Concept
```go
func TestFilterAttestationsByTag_NilDsseEnvelope(t *testing.T) {
    att := &api.Attestation{
        Bundle: &bundle.Bundle{
            Bundle: &protobundle.Bundle{
                // Content field intentionally nil/unset -> GetDsseEnvelope() returns nil
            },
        },
    }
    filtered, err := shared.FilterAttestationsByTag([]*api.Attestation{att}, "v1.0.0")
    // Expected: err != nil, no panic
    require.Error(t, err)
    require.Nil(t, filtered)
}
```
Running this test against current code produces a `panic: runtime error: invalid memory address or nil pointer dereference` at `att.Bundle.Bundle.GetDsseEnvelope().Payload` instead of a returned error.

### Citations

**File:** pkg/cmd/attestation/api/attestation.go (L13-17)
```go
type Attestation struct {
	Bundle    *bundle.Bundle `json:"bundle"`
	BundleURL string         `json:"bundle_url"`
	Initiator string         `json:"initiator"`
}
```

**File:** pkg/cmd/attestation/api/attestation.go (L31-32)
```go
		dsseEnvelope := each.Bundle.GetDsseEnvelope()
		if dsseEnvelope != nil {
```

**File:** pkg/cmd/release/verify-asset/verify_asset.go (L169-183)
```go
	// Filter attestations by tag name
	filteredAttestations, err := shared.FilterAttestationsByTag(attestations, tagName)
	if err != nil {
		return fmt.Errorf("error parsing attestations for tag %s: %w", tagName, err)
	}

	if len(filteredAttestations) == 0 {
		return fmt.Errorf("no attestations found for release %s in %s/%s", tagName, baseRepo.RepoOwner(), baseRepo.RepoName())
	}

	// Filter attestations by subject digest
	filteredAttestations, err = shared.FilterAttestationsByFileDigest(filteredAttestations, fileDigest.Digest())
	if err != nil {
		return fmt.Errorf("error parsing attestations for digest %s: %w", fileDigest.DigestWithAlg(), err)
	}
```

**File:** pkg/cmd/release/shared/attestation.go (L58-66)
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
```

**File:** pkg/cmd/release/shared/attestation.go (L76-85)
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
```
