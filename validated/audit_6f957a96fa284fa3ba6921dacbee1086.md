### Title
Attestation identity verification keyed on mutable GitHub login name instead of immutable owner/repository ID enables verification bypass after account rename/reuse - ([File: pkg/cmd/attestation/verification/extensions.go])

### Summary
`gh attestation verify` establishes the "actor identity" of an attestation purely from the certificate's `SourceRepositoryOwnerURI`/`SourceRepositoryURI` extensions, which are derived from the GitHub org/user *login name* at the time the workflow token was issued. The CLI's own enforcement criteria (`--owner`, `--repo`) are likewise built from the caller-supplied login string, not from GitHub's immutable numeric owner/repository IDs (which the codebase already knows about and surfaces elsewhere, but never uses for enforcement). Because GitHub logins can be renamed and reused by a different account, this identity binding can silently point at a different, attacker-controlled account after a rename, without changing the string that a downstream policy trusts.

### Finding Description
`verifyCertExtensions` in `pkg/cmd/attestation/verification/extensions.go` performs the actual identity check as a case-insensitive string comparison of `SourceRepositoryOwnerURI` and `SourceRepositoryURI`: [1](#0-0) 

These "expected" values come from `newEnforcementCriteria` in `pkg/cmd/attestation/verify/policy.go`, which simply string-formats the user-supplied `--owner`/`--repo` flag values into a GitHub URL: [2](#0-1) [3](#0-2) 

The "given" side of the comparison — the certificate's `SourceRepositoryOwnerURI`/`SourceRepositoryURI` extensions — are populated by Fulcio/GitHub Actions OIDC based on the *current login* of the repository/org at signing time, not a stable ID. Elsewhere in the same package tree, the codebase demonstrates that GitHub attestations actually carry immutable numeric identifiers (`RepositoryOwnerId`, `RepositoryID`) inside the predicate, which `gh attestation inspect` extracts: [4](#0-3) [5](#0-4) 

However, `gh attestation verify`'s policy enforcement path (`verifyCertExtensions`, `newEnforcementCriteria`, `buildCertificateIdentityOption`) never consults these immutable IDs — the entire trust decision rests on the mutable owner/repo login strings. The CLI itself acknowledges GitHub logins are mutable and reusable elsewhere: `gh repo rename` explicitly supports renaming a repository and documents that ownership/name changes are possible: [6](#0-5) 

If an organization or user renames away from a login (or an account is deleted/renamed), that login becomes available for a different party to register. Any pinned policy that was written as `gh attestation verify artifact --owner <old-login>` (or `--repo <old-login>/<repo>`) will continue to succeed for artifacts signed by workflows now controlled by whoever holds the reused login — because the verification logic never checks that the identity is still bound to the same underlying, immutable account/repository.

### Impact Explanation
This is a verification-bypass class of bug matching the referenced report's root cause: an identity/ownership check anchored to a value that is not permanently bound to a single principal (mutable `recipient`/`operatorKey`-derived address in the original report vs. mutable GitHub login-derived URI here). Organizations that rely on `gh attestation verify --owner ORG` (or `--repo`) as a supply-chain trust gate in CI/CD or release-verification scripts can be silently bypassed if the referenced login is ever renamed and reused, allowing an unprivileged remote attacker who registers the freed name to have their attacker-signed artifacts pass verification as if produced by the originally trusted org.

### Likelihood Explanation
Low likelihood, mirroring the original report's severity: it requires a prior rename/vacating of a specific GitHub login and its subsequent registration by an attacker, plus a downstream consumer that pinned verification policy to that login rather than to a `--cert-identity`/immutable identifier. This is a known general GitHub username/org-squatting risk, but here it is baked into the CLI's core attestation trust primitive rather than mitigated by using the immutable IDs the codebase already parses in the `inspect` path.

### Recommendation
When enforcing `--owner`/`--repo` policy in `pkg/cmd/attestation/verify/policy.go` and `pkg/cmd/attestation/verification/extensions.go`, resolve and pin the immutable `RepositoryOwnerId`/`RepositoryID` (already parsed by `pkg/cmd/attestation/inspect/bundle.go`) as part of enforcement criteria, or clearly warn users that login-based `--owner`/`--repo` policies do not survive account renames and recommend resolving/caching the numeric owner/repo ID for long-lived trust policies.

### Proof of Concept
Not applicable as a runnable exploit within static analysis — the bypass requires an external GitHub account-rename/registration sequence (out of scope for local reproduction), but the code path is demonstrated by:
1. `newEnforcementCriteria` building `SourceRepositoryOwnerURI` solely from `opts.Owner` (a login string): [3](#0-2) 
2. `verifyCertExtensions` comparing only these login-derived URIs, with no fallback to immutable IDs: [1](#0-0) 
3. The existing `inspect` command proving immutable IDs (`RepositoryOwnerId`, `RepositoryID`) are available in the attestation predicate but are not used by `verify`: [5](#0-4)

### Citations

**File:** pkg/cmd/attestation/verification/extensions.go (L43-51)
```go
func verifyCertExtensions(given, expected certificate.Summary) error {
	if !strings.EqualFold(expected.SourceRepositoryOwnerURI, given.SourceRepositoryOwnerURI) {
		return fmt.Errorf("expected SourceRepositoryOwnerURI to be %s, got %s", expected.SourceRepositoryOwnerURI, given.SourceRepositoryOwnerURI)
	}

	// if repo is set, compare the SourceRepositoryURI fields
	if expected.SourceRepositoryURI != "" && !strings.EqualFold(expected.SourceRepositoryURI, given.SourceRepositoryURI) {
		return fmt.Errorf("expected SourceRepositoryURI to be %s, got %s", expected.SourceRepositoryURI, given.SourceRepositoryURI)
	}
```

**File:** pkg/cmd/attestation/verify/policy.go (L36-47)
```go
	// set the owner value by checking the repo and owner options
	var owner string
	if opts.Repo != "" {
		// we expect the repo argument to be in the format <OWNER>/<REPO>
		splitRepo := strings.Split(opts.Repo, "/")
		// if Repo is provided but owner is not, set the OWNER portion of the Repo value
		// to Owner
		owner = splitRepo[0]
	} else {
		// otherwise use the user provided owner value
		owner = opts.Owner
	}
```

**File:** pkg/cmd/attestation/verify/policy.go (L89-90)
```go
	// Set the SourceRepositoryOwnerURI extension using owner and tenant if provided
	c.Certificate.SourceRepositoryOwnerURI = expandToGitHubURL(opts.Tenant, owner)
```

**File:** pkg/cmd/attestation/inspect/bundle.go (L47-55)
```go
// AttestationDetail captures attestation source details
// that will be returned by the inspect command
type AttestationDetail struct {
	OrgName        string `json:"orgName"`
	OrgID          string `json:"orgId"`
	RepositoryName string `json:"repositoryName"`
	RepositoryID   string `json:"repositoryId"`
	WorkflowID     string `json:"workflowId"`
}
```

**File:** pkg/cmd/attestation/inspect/bundle.go (L104-110)
```go
	return AttestationDetail{
		OrgName:        org,
		OrgID:          predicate.BuildDefinition.InternalParameters.GitHub.RepositoryOwnerId,
		RepositoryName: repo,
		RepositoryID:   predicate.BuildDefinition.InternalParameters.GitHub.RepositoryID,
		WorkflowID:     predicate.RunDetails.Metadata.InvocationID,
	}, nil
```

**File:** pkg/cmd/repo/rename/rename.go (L51-66)
```go
		Use:   "rename [<new-name>]",
		Short: "Rename a repository",
		Long: heredoc.Docf(`
			Rename a GitHub repository.

			%[1]s<new-name>%[1]s is the desired repository name without the owner.

			By default, the current repository is renamed. Otherwise, the repository specified
			with %[1]s--repo%[1]s is renamed.

			To transfer repository ownership to another user account or organization,
			you must follow additional steps on %[1]sgithub.com%[1]s.

			For more information on transferring repository ownership, see:
			<https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository>
			`, "`"),
```
