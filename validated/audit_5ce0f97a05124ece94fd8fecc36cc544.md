Found a strong analog: `pkg/cmd/attestation/inspect/bundle.go` `getOrgAndRepo` performs `strings.Split(after, "/")` and then unconditionally accesses `parts[0]` and `parts[1]` without checking `len(parts) >= 2`, exactly the same class of bug as the Solidity report — trusting that parsed/attacker-influenced data has a fixed shape and indexing into it without a length check, causing an out-of-bounds panic.

### Title
Unchecked slice-length assumption causes index-out-of-range panic when parsing attestation-derived repository URL - ([File: pkg/cmd/attestation/inspect/bundle.go])

### Summary
`getOrgAndRepo` in `pkg/cmd/attestation/inspect/bundle.go` splits a URL string on `/` and always accesses `parts[0]` and `parts[1]` without verifying the slice actually has at least two elements, mirroring the H-19 pattern of indexing into an unchecked-length collection derived from user/attacker-influenced input.

### Finding Description
`getOrgAndRepo` strips a known prefix (`https://github.com/` or a tenant-specific GHE.com host) from `repoURL` and then does: [1](#0-0) 
```
parts := strings.Split(after, "/")
return parts[0], parts[1], nil
```
There is no check that `len(parts) >= 2`. If the remainder after the prefix strip contains zero slashes (e.g., `repoURL` is exactly `https://github.com/` or `https://github.com/onlyowner`), `parts` will have length 1, and `parts[1]` will panic with an index-out-of-range error.

`repoURL` here is `BuildConfigURI`/`BuildSignerURI`, a value extracted from the Fulcio certificate embedded in a Sigstore bundle attestation — data that originates from an OIDC certificate extension populated when a workflow signs an attestation. This same helper style is used in `pkg/cmd/attestation/verify/verify.go`'s `extractAttestationDetail`, which is invoked while printing verification results for `gh attestation verify`. An attacker who can produce or influence such a URI-shaped extension value (e.g., a repository owner controlling their own workflow certificate's build config URI, or a malformed/incomplete provenance value) can trigger a crash whenever a victim inspects/verifies that attestation with `gh attestation inspect` or `gh attestation verify`.

### Impact Explanation
This causes a denial-of-service crash of the `gh` CLI process during a normal, security-relevant operation (inspecting or verifying supply-chain attestations). Unlike the Solidity report's "permanently locked funds," a CLI crash is a bounded availability impact — it interrupts the verification command but doesn't cause persistent state corruption. It's an unprivileged-remote-attacker analog only if the URL value is attacker-controlled and consumed automatically during a normal `gh attestation verify`/`inspect` invocation.

### Likelihood Explanation
Likelihood is low-to-moderate: this path only runs when `--format` output requires source-repo extraction and the underlying URI does not match the expected `https://github.com/<owner>/<repo>...` or `https://<tenant>.ghe.com/<owner>/<repo>...` shape after prefix-stripping. Since typical GitHub-issued certificates well-formed URIs, exploitation requires crafting or obtaining an attestation whose certificate extension has an unusual/truncated repository URI, which is plausible for a self-controlled or malicious workflow producing attestations that a victim is asked to verify.

### Recommendation
Add an explicit length check after the split and return a descriptive error instead of indexing unconditionally, e.g.:
```go
parts := strings.Split(after, "/")
if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
    return "", "", fmt.Errorf("failed to get org and repo from %s", repoURL)
}
return parts[0], parts[1], nil
```

### Proof of Concept
1. Craft or obtain a Sigstore bundle whose certificate `BuildConfigURI`/`SourceRepositoryURI` extension is set to a value like `https://github.com/onlyonepart` (no second `/`-separated segment) instead of the expected `https://github.com/<owner>/<repo>/...`.
2. Have a user run `gh attestation inspect` (or `gh attestation verify`, which calls the analogous `extractAttestationDetail`) against an artifact whose attestation bundle contains this malformed URI. [2](#0-1) 
3. `getOrgAndRepo`/`extractAttestationDetail` calls `strings.Split(after, "/")`, producing a 1-element slice, then indexes `parts[1]`, causing an index-out-of-range panic and crashing the `gh` process mid-verification.

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

**File:** pkg/cmd/attestation/verify/verify.go (L319-334)
```go
	opts.Logger.Printf("The following %s matched the policy criteria\n\n", text.Pluralize(len(verified), "attestation"))

	// Otherwise print the results to the terminal
	for i, v := range verified {
		buildConfigURI := v.VerificationResult.Signature.Certificate.Extensions.BuildConfigURI
		sourceRepoAndOrg, sourceWorkflow, err := extractAttestationDetail(opts.Tenant, buildConfigURI)
		if err != nil {
			opts.Logger.Println(opts.Logger.ColorScheme.Red("failed to parse build config URI"))
			return err
		}
		builderSignerURI := v.VerificationResult.Signature.Certificate.Extensions.BuildSignerURI
		signerRepoAndOrg, signerWorkflow, err := extractAttestationDetail(opts.Tenant, builderSignerURI)
		if err != nil {
			opts.Logger.Println(opts.Logger.ColorScheme.Red("failed to parse build signer URI"))
			return err
		}
```
