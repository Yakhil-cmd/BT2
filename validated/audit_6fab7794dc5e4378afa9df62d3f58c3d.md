### Title
Insufficient validation of attestation predicate repository URL causes index-out-of-range panic in `gh attestation inspect` - ([File: pkg/cmd/attestation/inspect/bundle.go])

### Summary
`getOrgAndRepo` in the `gh attestation inspect` command parses the `buildDefinition.externalParameters.workflow.repository` field from an attacker-influenced attestation predicate. It validates only that the string has the expected host prefix, then blindly indexes the result of `strings.Split` without checking that a second path segment exists, causing an unhandled panic (crash) rather than a graceful error.

### Finding Description
`getAttestationDetail` decodes the SLSA predicate from an attestation bundle (loaded from a local file via `GetLocalAttestations`, or from the GitHub API/OCI registry) and passes the attacker-influenced `Workflow.Repository` string straight into `getOrgAndRepo`: [1](#0-0) 

`getOrgAndRepo` only validates that the string starts with the expected `https://github.com/` (or tenant) prefix, then splits the remainder on `/` and unconditionally accesses `parts[0]` and `parts[1]`: [2](#0-1) 

This mirrors the reported bug class exactly: a validation function (`validateAuctionPriceParameters`-equivalent here is the prefix check) accepts a value as "valid" while leaving a downstream computation (`getCurrentPrice`-equivalent is the `parts[1]` index access) unguarded against edge-case inputs that pass the shallow check but still crash. If `repoURL` is `"https://github.com/onlyowner"` (no slash after the owner) or `"https://github.com/"` (empty remainder), `strings.CutPrefix` succeeds, `strings.Split(after, "/")` returns a slice of length 1 (or `[""]`), and `parts[1]` panics with "index out of range".

The predicate content, including `Workflow.Repository`, originates from the DSSE envelope/statement inside the Sigstore bundle: [3](#0-2) 

Notably, `runInspect` deliberately proceeds to extract predicate/statement data even for bundles that fail cryptographic verification against the unsafe policy, explicitly to allow inspecting bundles the user does not (yet) trust: [4](#0-3) 

Since `gh attestation inspect` is documented to operate on bundles "downloaded to disk" and does not require the bundle to be cryptographically authentic to be inspected, a bundle file supplied or influenced by an attacker (e.g., distributed alongside a malicious artifact, or an attacker-controlled release asset a victim downloads and inspects) can carry an unverified/forged predicate whose `workflow.repository` field is fully attacker-controlled.

### Impact Explanation
An unprivileged remote attacker who can get a victim to run `gh attestation inspect <bundle>` on a crafted or malformed bundle file (e.g., an attacker-hosted release asset, or a bundle obtained from an untrusted source) can trigger a Go runtime panic, crashing the `gh` process. This is a Denial-of-Service condition analogous to the reported issue: input that passes a superficial validation check causes an unhandled failure in a downstream computation.

### Likelihood Explanation
The `--format=json` machine consumption path and general "inspect before you trust" workflow of this command make it plausible that a user would run `gh attestation inspect` on an unverified/untrusted bundle obtained from a third party, since inspection is explicitly documented as not requiring authenticity. Crafting the malformed repository string requires no special privileges — only the ability to produce/modify a bundle file (e.g., by controlling the predicate JSON prior to signing, or simply supplying an unsigned/invalid bundle since the certificate/verification failure does not stop `runInspect` from parsing the predicate).

### Recommendation
In `getOrgAndRepo`, validate that `strings.Split(after, "/")` yields at least two non-empty elements before indexing, and return a descriptive error (matching the existing error-return pattern) instead of allowing an out-of-bounds panic:
```go
parts := strings.Split(after, "/")
if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
    return "", "", fmt.Errorf("failed to get org and repo from %s", repoURL)
}
return parts[0], parts[1], nil
```
More broadly, audit other predicate-parsing paths that consume attestation content prior to (or independent of) verification for similar unchecked indexing/parsing on attacker-influenced strings.

### Proof of Concept
1. Construct a Sigstore bundle (JSON or JSONL) whose DSSE envelope statement predicate contains:
   ```json
   {
     "buildDefinition": {
       "externalParameters": {
         "workflow": { "repository": "https://github.com/onlyowner" }
       }
     }
   }
   ```
   (i.e., a repository URL with the correct `https://github.com/` prefix but no `/repo` segment.)
2. Run `gh attestation inspect <path-to-bundle>` (or `gh attestation inspect <path-to-bundle> --format=json`).
3. `runInspect` → `getAttestationDetail` → `getOrgAndRepo` executes `strings.Split("onlyowner", "/")`, producing `["onlyowner"]`; the subsequent `parts[1]` access panics, crashing the `gh` process instead of returning a handled error.

Note: I was unable to fully confirm from the indexed code whether `getAttestationDetail`/`getOrgAndRepo` is invoked directly inside `runInspect`'s main loop (the visible snippet of `inspect.go` cuts off before that call), and I could not locate `extractAttestationDetail` in `verify.go` in the returned index content to compare its guard logic; a background agent with full repository access should verify the exact call sites and confirm whether `verify.go`'s equivalent function has the same or a different (possibly already-fixed) validation.

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

**File:** pkg/cmd/attestation/inspect/bundle.go (L77-102)
```go
func getAttestationDetail(tenant string, attr api.Attestation) (AttestationDetail, error) {
	envelope, err := attr.Bundle.Envelope()
	if err != nil {
		return AttestationDetail{}, fmt.Errorf("failed to get envelope from bundle: %v", err)
	}

	statement, err := envelope.EnvelopeContent().Statement()
	if err != nil {
		return AttestationDetail{}, fmt.Errorf("failed to get statement from envelope: %v", err)
	}

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
	if err != nil {
		return AttestationDetail{}, fmt.Errorf("failed to parse attestation content: %v", err)
	}
```

**File:** pkg/cmd/attestation/inspect/inspect.go (L169-182)
```go
	for _, a := range attestations {
		inspectedBundle := BundleInspection{}

		// we ditch the verificationResult to avoid even implying that it is "verified"
		// you can't meaningfully "verify" a bundle with such an Unsafe policy!
		_, err := opts.SigstoreVerifier.Verify([]*api.Attestation{a}, unsafeSigstorePolicy)

		// food for thought for later iterations:
		// if the err is present, we keep on going because we want to be able to
		// inspect bundles we might not have trusted materials for.
		// but maybe we should print the error?
		if err == nil {
			inspectedBundle.Authentic = true
		}
```
