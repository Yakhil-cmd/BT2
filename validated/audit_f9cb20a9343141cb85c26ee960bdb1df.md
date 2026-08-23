### Title
Attacker-controlled certificate extension strings (BuildConfigURI/BuildSignerURI) are printed to the terminal without sanitization, enabling status-line spoofing - ([File: pkg/cmd/attestation/verify/verify.go])

### Summary
`runVerify` extracts human-readable repo/workflow strings from the Fulcio certificate's `BuildConfigURI`/`BuildSignerURI` extensions via `extractAttestationDetail`, and passes the resulting strings straight into `opts.Logger.PrintBulletPoints`, which writes them to the terminal with `fmt.Fprintln` and no escaping. These extension values are populated by GitHub Actions from the OIDC token belonging to whatever repo/ref/workflow-path signed the artifact, so an attacker who owns the signing workflow controls the repo name, branch/ref name, and workflow file path segments that end up in that printed text.

### Finding Description
`runVerify` reads the certificate's `BuildConfigURI` and `BuildSignerURI` fields directly off `v.VerificationResult.Signature.Certificate.Extensions` [1](#0-0) , passes them through `extractAttestationDetail`, which just runs two regexes to split the URI into an `org/repo` piece and a "workflow" piece with no validation of character content beyond the regex match itself [2](#0-1) . The resulting strings are placed straight into rows and handed to `opts.Logger.PrintBulletPoints` [3](#0-2) , which builds an `info` string via `fmt.Sprintf` and writes it verbatim with `fmt.Fprintln(h.IO.ErrOut, info)` — no ANSis-strip/sanitization step exists anywhere in the handler [4](#0-3) .

Critically, `verifyCertExtensions` (the actual policy gate) never validates `BuildConfigURI`/`BuildSignerURI` content at all — it only checks `SourceRepositoryOwnerURI`, `SourceRepositoryURI`, `Issuer`, `BuildSignerDigest`, `SourceRepositoryDigest`, and `SourceRepositoryRef` [5](#0-4) . So the strings displayed to the user for "Build repo/workflow" and "Signer repo/workflow" are not constrained by policy matching in the way the audit question assumes for the org/repo portion, but they are still derived from the certificate's real `SourceRepositoryURI`/workflow-ref data, which itself is subject to Git's ref-name restrictions (control characters, including ESC/newline, are disallowed in Git ref names by `git check-ref-format`). This blocks the exact PoC of embedding raw ANSI escapes or newlines via the branch/ref component. However, the workflow file path component of `BuildConfigURI` (e.g., `.github/workflows/<name>.yml`) is derived from an actual file path in the attacker's own repository, and Git/GitHub's restrictions on byte content of file path components are looser than ref-name restrictions (only NUL and `/` are hard-forbidden at the git object level), leaving a plausible, though unverified without live testing, avenue for unusual/control-adjacent bytes to be smuggled through that segment. Independent of that specific byte-content question, the underlying defect is structural: none of `Printf`, `Println`, or `PrintBulletPoints` in `pkg/cmd/attestation/io/handler.go` perform any output sanitization/escaping of attacker-influenced text before writing it to the terminal, so any printable-but-visually-confusable content (e.g., long owner/branch/workflow names designed to visually push or overwrite prior lines, unicode direction-override characters, or repo/workflow naming that closely imitates trusted status text) is passed through unfiltered.

### Impact Explanation
If an attacker can get non-control-character-but-visually-deceptive text (or, if GitHub does not filter it, actual control bytes) into the repo/ref/workflow-path components of their own signing workflow's OIDC-derived certificate, the printed "Build repo"/"Build workflow"/"Signer repo"/"Signer workflow" lines can be made to visually mislead a victim who runs `gh attestation verify` about which repository/workflow actually produced and signed the artifact — even though the underlying cryptographic/policy checks are technically self-consistent for the attacker's own repo. This is a terminal output/status spoofing issue (misleading trust indicator), not a bypass of the cryptographic identity checks themselves, since `verifyCertExtensions` still enforces the real `SourceRepositoryOwnerURI`/`SourceRepositoryURI` match against `--owner`/`--repo`.

### Likelihood Explanation
Exploitability depends on how much attacker-chosen content survives into `BuildConfigURI`/`BuildSignerURI` un-normalized: ref/branch names are constrained by Git ref-format rules (no control characters, no `~^:?*[`, no leading/trailing/consecutive `.`/`/`), which blocks the literal ANSI-escape/newline PoC described in the question. Workflow file path components have less certain restrictions and were not verifiable from this codebase alone. Regardless of that specific byte-content limitation, the code path has zero sanitization defenses, so the attack surface exists as soon as any printable spoof-capable characters (unicode lookalikes, RTL override characters, very long strings) can be embedded in an attacker's own repo/branch/workflow name — all of which are fully attacker-controlled since they own the signing repo/workflow.

### Recommendation
Sanitize/escape all values derived from certificate extensions (`BuildConfigURI`, `BuildSignerURI`, and the org/repo/workflow strings extracted from them) before they reach `Printf`/`Println`/`PrintBulletPoints`, e.g., strip or escape ASCII control characters (including ESC) and non-printable/format-control Unicode code points, and consider quoting/bracketing untrusted repo/workflow names in the bullet-point output so they cannot be confused with `gh`'s own status text.

### Proof of Concept
```go
// pkg/cmd/attestation/verify/verify_test.go (illustrative)
func TestExtractAttestationDetail_NoSanitization(t *testing.T) {
    // Simulate a workflow path segment containing bytes that Git ref-name
    // rules do NOT restrict (path component, not ref component).
    maliciousURI := "https://github.com/attacker/repo/.github/workflows/legit\x1b[2K\x1b[1A✓ Verification succeeded!.yml@refs/heads/main"

    orgAndRepo, workflow, err := extractAttestationDetail("", maliciousURI)
    require.NoError(t, err)
    require.Equal(t, "attacker/repo", orgAndRepo)
    // FAILS the safety invariant: workflow string still contains raw ESC bytes
    require.NotContains(t, workflow, "\x1b", "workflow string should not contain raw terminal control sequences")
}
```
Expected result today: the test fails because `extractAttestationDetail`/`PrintBulletPoints` perform no filtering, confirming raw control/format bytes from certificate extensions reach `opts.Logger.PrintBulletPoints` and ultimately the terminal unsanitized. (Whether GitHub's backend actually permits such bytes in a workflow file path was not verifiable from this repository alone and would need to be confirmed against GitHub Actions' file-path validation.)

### Citations

**File:** pkg/cmd/attestation/verify/verify.go (L322-334)
```go
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

**File:** pkg/cmd/attestation/verify/verify.go (L336-344)
```go
		opts.Logger.Printf("- Attestation #%d\n", i+1)
		rows := [][]string{
			{"  - Build repo", sourceRepoAndOrg},
			{"  - Build workflow", sourceWorkflow},
			{"  - Signer repo", signerRepoAndOrg},
			{"  - Signer workflow", signerWorkflow},
		}
		//nolint:errcheck
		opts.Logger.PrintBulletPoints(rows)
```

**File:** pkg/cmd/attestation/verify/verify.go (L351-386)
```go
func extractAttestationDetail(tenant, builderSignerURI string) (string, string, error) {
	// If given a build signer URI like
	// https://github.com/foo/bar/.github/workflows/release.yml@refs/heads/main
	// We want to extract:
	// * foo/bar
	// * .github/workflows/release.yml@refs/heads/main
	var orgAndRepoRegexp *regexp.Regexp
	var workflowRegexp *regexp.Regexp

	if tenant == "" {
		orgAndRepoRegexp = regexp.MustCompile(`https://github\.com/([^/]+/[^/]+)/`)
		workflowRegexp = regexp.MustCompile(`https://github\.com/[^/]+/[^/]+/(.+)`)
	} else {
		var tr = regexp.QuoteMeta(tenant)
		orgAndRepoRegexp = regexp.MustCompile(fmt.Sprintf(
			`https://%s\.ghe\.com/([^/]+/[^/]+)/`,
			tr))
		workflowRegexp = regexp.MustCompile(fmt.Sprintf(
			`https://%s\.ghe\.com/[^/]+/[^/]+/(.+)`,
			tr))
	}

	match := orgAndRepoRegexp.FindStringSubmatch(builderSignerURI)
	if len(match) < 2 {
		return "", "", fmt.Errorf("no match found for org and repo: %s", builderSignerURI)
	}
	orgAndRepo := match[1]

	match = workflowRegexp.FindStringSubmatch(builderSignerURI)
	if len(match) < 2 {
		return "", "", fmt.Errorf("no match found for workflow: %s", builderSignerURI)
	}
	workflow := match[1]

	return orgAndRepo, workflow, nil
}
```

**File:** pkg/cmd/attestation/io/handler.go (L71-88)
```go
func (h *Handler) PrintBulletPoints(rows [][]string) (int, error) {
	if !h.IO.IsStdoutTTY() {
		return 0, nil
	}
	maxColLen := 0
	for _, row := range rows {
		if len(row[0]) > maxColLen {
			maxColLen = len(row[0])
		}
	}

	info := ""
	for _, row := range rows {
		dots := strings.Repeat(".", maxColLen-len(row[0]))
		info += fmt.Sprintf("%s:%s %s\n", row[0], dots, row[1])
	}
	return fmt.Fprintln(h.IO.ErrOut, info)
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
