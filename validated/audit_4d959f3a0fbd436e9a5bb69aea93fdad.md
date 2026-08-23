No global panic recovery exists in the attestation command path, so an unhandled panic in `getOrgAndRepo` would crash the `gh` process rather than being silently caught and falling back to an "insecure default."

### Title
Out-of-bounds slice index panic in `getOrgAndRepo` via attacker-controlled attestation predicate - (File: pkg/cmd/attestation/inspect/bundle.go)

### Summary
`getOrgAndRepo` splits the `workflow.repository` string from an attestation's Sigstore bundle predicate and unconditionally indexes `parts[1]` without checking the slice length. An attacker who publishes an artifact with a crafted attestation bundle (e.g. `workflow.repository = "https://github.com/onlyorg"`) can cause `parts` to have length 1, triggering an index-out-of-range panic when a victim runs `gh attestation verify`/`inspect` against that artifact.

### Finding Description
`getAttestationDetail` unmarshals the attacker-controlled bundle predicate JSON and passes `predicate.BuildDefinition.ExternalParameters.Workflow.Repository` directly into `getOrgAndRepo`, with no upstream validation of its shape [1](#0-0) . Inside `getOrgAndRepo`, the code strips the `https://github.com/` (or tenant) prefix and splits the remainder on `/`, then reads `parts[0]` and `parts[1]` without validating `len(parts) >= 2` [2](#0-1) . If the predicate's `workflow.repository` field contains only an org segment (e.g. `https://github.com/onlyorg` with no trailing repo path, or `https://github.com/` with an empty suffix producing `[""]`), `strings.Split` returns a slice of length 1, and the access to `parts[1]` panics with "index out of range". This predicate value originates entirely from the Sigstore bundle's in-toto statement, which is embedded in the artifact/attestation published by the attacker and is not signed against a repo-path-length invariant — Sigstore verification confirms the *signature* over the statement, not that fields inside it are well-formed. Since there is no `recover()` in the call chain for the attestation `inspect`/`verify` commands, this results in an unhandled panic crashing the `gh` process.

### Impact Explanation
This is a denial-of-service against the `gh` CLI process invoked by a victim inspecting or verifying an attacker-published attestation/artifact — the command panics and terminates ungracefully instead of failing closed with a clean error. It does not, by itself, lead to code execution, credential exfiltration, or a verification bypass; the existing `err != nil` check in `getAttestationDetail` shows intent to fail closed on malformed input, but the missing bounds check defeats that intent via a crash rather than a graceful error return.

### Likelihood Explanation
Highly feasible and repeatable: exploitation only requires publishing an artifact with a Sigstore bundle whose in-toto statement predicate sets `buildDefinition.externalParameters.workflow.repository` to a value with fewer than two path segments after the `https://github.com/` (or `https://<tenant>.ghe.com/`) prefix. Any victim running `gh attestation inspect` or `gh attestation verify` against that artifact triggers the panic deterministically.

### Recommendation
Validate `len(parts) >= 2` in `getOrgAndRepo` before indexing, returning the existing `fmt.Errorf("failed to get org and repo from %s", repoURL)` error (or similar) when the split does not yield exactly the expected org/repo segments, so malformed predicate data fails closed with a normal error instead of panicking.

### Proof of Concept
```go
func TestGetOrgAndRepo_ShortPath(t *testing.T) {
    // Simulates a malicious attestation predicate with a repository URL
    // containing no repo segment.
    org, repo, err := getOrgAndRepo("", "https://github.com/onlyorg")
    require.Error(t, err)
    require.Zero(t, org)
    require.Zero(t, repo)
}
```
Running this against the current implementation causes a runtime panic (`index out of range [1] with length 1`) rather than returning the expected error, demonstrating the missing bounds check [3](#0-2) .

### Citations

**File:** pkg/cmd/attestation/inspect/bundle.go (L57-75)
```go
func getOrgAndRepo(tenant, repoURL string) (string, string, error) {
	var after string
	var found bool
	if tenant == "" {
		after, found = strings.CutPrefix(repoURL, "https://github.com/")
		if !found {
			return "", "", fmt.Errorf("failed to get org and repo from %s", repoURL)
		}
	} else {
		after, found = strings.CutPrefix(repoURL,
			fmt.Sprintf("https://%s.ghe.com/", tenant))
		if !found {
			return "", "", fmt.Errorf("failed to get org and repo from %s", repoURL)
		}
	}

	parts := strings.Split(after, "/")
	return parts[0], parts[1], nil
}
```

**File:** pkg/cmd/attestation/inspect/bundle.go (L88-99)
```go
	var predicate Predicate
	predicateJson, err := json.Marshal(statement.Predicate)
	if err != nil {
		return AttestationDetail{}, fmt.Errorf("failed to marshal predicate: %v", err)
	}

	err = json.Unmarshal(predicateJson, &predicate)
	if err != nil {
		return AttestationDetail{}, fmt.Errorf("failed to unmarshal predicate: %v", err)
	}

	org, repo, err := getOrgAndRepo(tenant, predicate.BuildDefinition.ExternalParameters.Workflow.Repository)
```
