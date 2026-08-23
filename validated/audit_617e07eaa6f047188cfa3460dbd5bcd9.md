### Title
Panic (index out of range) in `getOrgAndRepo` when parsing malformed `workflow.repository` field from an attestation bundle - ([File: pkg/cmd/attestation/inspect/bundle.go])

### Summary
`getOrgAndRepo` splits the portion of `repoURL` after the `https://github.com/` (or tenant) prefix on `/` and unconditionally accesses `parts[0]` and `parts[1]` without checking the slice length. Since `repoURL` comes from `predicate.BuildDefinition.ExternalParameters.Workflow.Repository`, a field taken directly from the attestation's DSSE statement predicate, an attacker who crafts/publishes a malicious attestation bundle can supply a value like `https://github.com/onlyonepart` (no second path segment) to trigger a panic.

### Finding Description
`getAttestationDetail` unmarshals the predicate JSON from the attestation bundle's signed statement and passes the untrusted `Workflow.Repository` string straight into `getOrgAndRepo`: [1](#0-0) 

Inside `getOrgAndRepo`, after stripping the `https://github.com/` prefix, the remainder is split on `/` and both `parts[0]` and `parts[1]` are accessed without a length check: [2](#0-1) 

If `repoURL` is `https://github.com/onlyonepart`, `after` becomes `"onlyonepart"`, `strings.Split(after, "/")` returns a single-element slice `["onlyonepart"]`, and the access to `parts[1]` panics with `index out of range`. There is no upstream validation elsewhere in this code path that the `workflow.repository` field conforms to `owner/repo` format before reaching this function — the only check performed is the prefix strip (`strings.CutPrefix`), which succeeds regardless of the number of path segments that follow.

This predicate content is attacker-controlled to the extent that the attacker crafts/signs (or gets signed via a compromised/attacker-controlled build, e.g. a malicious GitHub Actions workflow producing a real Sigstore-signed bundle) an attestation and publishes it (e.g., as a release asset, OCI artifact, or bundle file) for the victim to run `gh attestation inspect` against. Since `inspect` intentionally supports inspecting bundles without full policy verification in some paths, the JSON predicate parsing occurs before/regardless of trust validation of the specific field content.

### Impact Explanation
This results in a denial-of-service (unhandled panic/crash) of the `gh attestation inspect` command when the victim inspects an attacker-supplied attestation bundle whose predicate contains a malformed `workflow.repository` value. It does not provide code execution, credential exfiltration, or authorization bypass — it is a crash bug reachable via attacker-controlled bundle content.

### Likelihood Explanation
Feasible and repeatable: an attacker needs only to publish an attestation bundle (or have one generated via a workflow they control) whose predicate's `buildDefinition.externalParameters.workflow.repository` field is set to a string that, after the `https://github.com/` prefix, contains zero or one `/`-delimited segments. Any victim running `gh attestation inspect` on that bundle/artifact will crash deterministically. No special privileges beyond publishing content are required.

### Recommendation
Validate `len(parts)` in `getOrgAndRepo` before indexing, returning a descriptive error (e.g., `fmt.Errorf("unexpected repository format: %s", repoURL)`) instead of panicking when `len(parts) < 2`.

### Proof of Concept
```go
func TestGetOrgAndRepo_MalformedInput(t *testing.T) {
    // repoURL missing the repo segment
    org, repo, err := getOrgAndRepo("", "https://github.com/onlyonepart")
    // Current behavior: panics with "index out of range [1] with length 1"
    // Expected behavior: err != nil, org == "", repo == ""
    if err == nil {
        t.Fatalf("expected error, got org=%q repo=%q", org, repo)
    }
}
```
Running this test against the current implementation demonstrates the panic (or can be wrapped with `recover()`/`assert.Panics` to confirm crash behavior), reproducing the vulnerability triggered via `getAttestationDetail` when processing an attacker-supplied attestation predicate.

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
