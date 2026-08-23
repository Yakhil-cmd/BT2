### Title
Panic (index out of range) in `getOrgAndRepo` on attacker-controlled predicate `workflow.Repository` field - ([File: pkg/cmd/attestation/inspect/bundle.go])

### Summary
`getOrgAndRepo` splits the portion of `workflow.Repository` after the expected host prefix on `/` and unconditionally accesses `parts[0]` and `parts[1]` without checking that the split produced at least two elements. An attacker who controls the predicate content of an attestation bundle (e.g., a published attestation/bundle a victim is asked to inspect with `gh attestation inspect`) can supply a `workflow.Repository` value such as `https://github.com/onlyorg` (no `/repo` segment) or `https://github.com/` (empty remainder), causing `strings.Split` to return a slice of length < 2 and triggering an index-out-of-range panic.

### Finding Description
`getAttestationDetail` unmarshals the predicate JSON directly from the attacker-supplied attestation bundle into the `Predicate` struct, and passes `predicate.BuildDefinition.ExternalParameters.Workflow.Repository` straight into `getOrgAndRepo` with no validation: [1](#0-0) 

Inside `getOrgAndRepo`, after stripping the `https://github.com/` (or tenant `https://<tenant>.ghe.com/`) prefix, the remainder is split on `/` and indexed without a length check: [2](#0-1) 

If `after` contains no `/` (e.g., the value is just `orgname` with nothing following, or the string is exactly `https://github.com/orgname`), `strings.Split(after, "/")` returns a single-element slice, and `parts[1]` panics with `index out of range [1] with length 1`. There is no length check (`if len(parts) < 2`) guarding this access, and no recovery mechanism was found wrapping the `inspect` command's execution path or the `bundle.go` call chain, so the panic propagates and crashes the `gh` process.

Note: the specific exploit primitives named in the prompt (embedded control characters, megabyte-scale strings, Unicode homoglyphs) do not themselves cause additional harm here — `strings.Split`/prefix-stripping handle arbitrary bytes and large inputs without memory-safety issues in Go, and no length cap is actually required to prevent memory corruption. The concretely reachable bug is the missing bounds check on `parts[1]`, which is trivially triggered by a short, malformed `workflow.Repository` value.

### Impact Explanation
This is a denial-of-service against the invoking `gh` process: any user who runs `gh attestation inspect` (or any codepath that calls `getAttestationDetail`) against an attacker-published bundle/attestation with a malformed `workflow.Repository` predicate field will experience an unhandled panic and process crash. This matches a low-severity availability/DoS impact class (crash of the CLI on attacker-controlled input) — there is no code execution, credential exposure, or file write/read impact demonstrated.

### Likelihood Explanation
Highly feasible and fully repeatable: the attacker only needs to publish an attestation bundle (e.g., attached to a public repo/release/artifact) with a crafted predicate JSON containing a `workflow.Repository` value lacking a second `/`-delimited segment after the recognized prefix. Any victim who inspects that bundle with `gh attestation inspect` triggers the crash deterministically, with no other preconditions (no auth, no admin rights).

### Recommendation
Add a length check after `strings.Split` in `getOrgAndRepo` and return an error instead of indexing unconditionally, e.g.:
```go
parts := strings.Split(after, "/")
if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
    return "", "", fmt.Errorf("failed to get org and repo from %s", repoURL)
}
return parts[0], parts[1], nil
```

### Proof of Concept
```go
func TestGetOrgAndRepo_PanicOnShortPath(t *testing.T) {
    // No repo segment after org — triggers index out of range panic
    sourceURL := "https://github.com/orgonly"
    org, repo, err := getOrgAndRepo("", sourceURL)
    // Expected (after fix): err != nil, org == "", repo == ""
    // Actual (current code): panics with "index out of range [1] with length 1"
    _ = org
    _ = repo
    _ = err
}
```
Running this test with the current implementation panics; an equivalent end-to-end PoC is to craft a sigstore bundle JSON whose predicate sets `buildDefinition.externalParameters.workflow.repository` to `"https://github.com/orgonly"` and run it through `verification.GetLocalAttestations` + `getAttestationDetail`, which will crash the `gh attestation inspect` command.

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

**File:** pkg/cmd/attestation/inspect/bundle.go (L94-102)
```go
	err = json.Unmarshal(predicateJson, &predicate)
	if err != nil {
		return AttestationDetail{}, fmt.Errorf("failed to unmarshal predicate: %v", err)
	}

	org, repo, err := getOrgAndRepo(tenant, predicate.BuildDefinition.ExternalParameters.Workflow.Repository)
	if err != nil {
		return AttestationDetail{}, fmt.Errorf("failed to parse attestation content: %v", err)
	}
```
