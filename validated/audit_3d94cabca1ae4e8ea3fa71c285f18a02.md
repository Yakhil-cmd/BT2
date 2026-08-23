### Title
Unsanitized cert-extension URI values printed via `PrintBulletPoints` allow terminal escape-sequence injection in `gh attestation verify` output - (File: pkg/cmd/attestation/verify/verify.go)

### Summary
`runVerify` extracts `sourceRepoAndOrg`/`sourceWorkflow`/`signerRepoAndOrg`/`signerWorkflow` from the Fulcio certificate's `BuildConfigURI`/`BuildSignerURI` extensions via `extractAttestationDetail` and writes them to the terminal with `opts.Logger.PrintBulletPoints`, which performs plain `fmt.Fprintln`/`fmt.Sprintf` formatting with no ANSI/control-character sanitization. Elsewhere in this same codebase (e.g. `pkg/iostreams/untrusted.go`, `pkg/cmd/skills/list/list.go`'s `sanitizeForTerminal`, and `pkg/cmd/run/view`'s log copying) untrusted external text is explicitly wrapped through an `asciisanitizer`/`Untrusted` type before hitting the terminal, but the attestation-verify detail path has no equivalent guard.

### Finding Description
In `runVerify`, after the sigstore verification result is obtained, the code pulls certificate extension fields directly: [1](#0-0) 

`extractAttestationDetail` only anchors on the literal `https://github.com/` prefix via regexp and returns the remainder of the string (org/repo and workflow-path+ref segments) verbatim: [2](#0-1) 

These four raw strings are placed into `rows` and handed to `opts.Logger.PrintBulletPoints(rows)`, whose implementation does no escaping of the content — it only checks `IsStdoutTTY` and then formats/writes directly to `IO.ErrOut`: [3](#0-2) 

This is materially different from other places in the codebase that were hardened against exactly this class of bug: `pkg/iostreams/untrusted.go`'s `Untrusted` type sanitizes any external string routed through `fmt`, and `pkg/cmd/skills/list/list.go`'s `sanitizeForTerminal` explicitly strips control sequences from external frontmatter before printing, and `run/view`'s log copier was hardened per `TestCopyLogWithLinePrefix_TerminalEscapeSequences`. The attestation-verify detail-row path uses none of these mitigations.

The workflow-path/ref segment of `BuildConfigURI`/`BuildSignerURI` is derived from the repository's own workflow file path and git ref, both of which are set by whoever controls the repository that produced the signed workflow run — i.e., an attacker who owns/forks a repo and names a workflow file (or crafts the corresponding path segment) with embedded ANSI/OSC escape sequences. If GitHub's build-provenance pipeline does not itself reject non-printable/control bytes in that path before embedding it in the Fulcio certificate extension (this repository's code cannot confirm or deny that upstream behavior), the raw bytes flow unmodified through `extractAttestationDetail` into `PrintBulletPoints`.

### Impact Explanation
An attacker-controlled ANSI/OSC payload in the printed "Build workflow"/"Signer workflow" rows could manipulate the victim's terminal: cursor movement/line-clear sequences can visually overwrite or obscure previously printed lines (including the earlier `✓ Verification succeeded!` banner or subsequent policy detail rows), and OSC sequences can rewrite the terminal title bar, misleading the human operator inspecting the output of `gh attestation verify`. This is a terminal-spoofing / output-integrity issue (matching GitHub's "spoofing"/output-injection impact class) rather than code execution or credential theft — its scoped impact is deceiving the human reviewer of an attestation-verification result.

### Likelihood Explanation
Requires only an unprivileged attacker who controls a repository/workflow whose build provenance is embedded in a signed attestation the victim chooses to verify (e.g., via `--owner`/`--repo` scoping) interactively at a TTY, since `PrintBulletPoints` is a no-op when stdout isn't a TTY. Feasibility hinges on whether GitHub's attestation-issuance backend permits control bytes in the workflow-path/ref components of the cert extension URI — a detail external to this repository that could not be verified from the CLI code alone, so likelihood is only best assessed as plausible if that byte-level restriction is absent upstream.

### Recommendation
Wrap the four extracted detail values (and any other cert-extension-derived string reaching the terminal in this command) in the existing `iostreams.Untrusted` sanitization type (or route them through `asciisanitizer`/`sanitizeForTerminal`, as already done in `pkg/cmd/skills/list/list.go`) before building `rows` and calling `PrintBulletPoints`, and/or add sanitization directly inside `PrintBulletPoints`/`Handler` so any caller printing external strings is protected by default.

### Proof of Concept
```go
func TestExtractAttestationDetail_ANSIInjection(t *testing.T) {
    esc := "\x1b"
    buildConfigURI := "https://github.com/org/repo/.github/workflows/" +
        esc + "]0;HIJACKED" + esc + "\\evil.yml@refs/heads/main"

    orgAndRepo, workflow, err := extractAttestationDetail("", buildConfigURI)
    require.NoError(t, err)

    // Currently fails: raw ESC byte passes through unsanitized.
    require.NotContains(t, workflow, esc)
    require.NotContains(t, orgAndRepo, esc)
}
```
Extend with an integration test that feeds `rows` containing the payload into `Handler.PrintBulletPoints` against a TTY-backed `iostreams.Test()` buffer and assert `buf.String()` does not contain `"\x1b"`, mirroring the existing `TestCopyLogWithLinePrefix_TerminalEscapeSequences` pattern in `pkg/cmd/run/view/view_test.go`.

### Citations

**File:** pkg/cmd/attestation/verify/verify.go (L322-345)
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

		opts.Logger.Printf("- Attestation #%d\n", i+1)
		rows := [][]string{
			{"  - Build repo", sourceRepoAndOrg},
			{"  - Build workflow", sourceWorkflow},
			{"  - Signer repo", signerRepoAndOrg},
			{"  - Signer workflow", signerWorkflow},
		}
		//nolint:errcheck
		opts.Logger.PrintBulletPoints(rows)
	}
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
