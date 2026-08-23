### Title
Unsanitized Fulcio certificate `BuildConfigURI`/`BuildSignerURI` values allow ANSI/terminal escape injection into `gh attestation verify` output - ([File: pkg/cmd/attestation/verify/verify.go])

### Summary
`runVerify` extracts the repo/workflow portions of the certificate's `BuildConfigURI` and `BuildSignerURI` extensions via `extractAttestationDetail` and prints them unsanitized through `opts.Logger.PrintBulletPoints`, which writes raw bytes to the terminal with `fmt.Fprintln`. Neither the regex extraction nor the print path strips ANSI/control characters, so an attacker who controls a portion of these URI strings (e.g. a workflow file path or ref name in their own repo) can inject terminal escape sequences that visually spoof the verification output.

### Finding Description
In `pkg/cmd/attestation/verify/verify.go`, after cryptographic verification succeeds, the code extracts human-readable strings from certificate extensions: [1](#0-0) 

`extractAttestationDetail` uses `[^/]+/[^/]+` for the org/repo capture and `(.+)` for the workflow path capture — both of which permit arbitrary bytes, including ASCII control characters such as ESC (`0x1B`): [2](#0-1) 

These raw strings are passed straight into `PrintBulletPoints`, which builds a string with `fmt.Sprintf` and writes it with `fmt.Fprintln(h.IO.ErrOut, info)` — no escaping or stripping of control characters occurs anywhere in this path: [3](#0-2) 

The repo already has an untrusted-content sanitization utility (`pkg/iostreams/untrusted.go`) that is used in several other display paths (e.g. gist/view, issue display, pr/list) to strip escape sequences from server-supplied text, but it is not applied here.

The `BuildConfigURI`/`BuildSignerURI` values originate from the GitHub Actions OIDC token used during Sigstore/Fulcio certificate issuance, and they encode the workflow file path and git ref of the job that produced the signature (e.g. `https://github.com/org/repo/.github/workflows/<filename>@<ref>`). An attacker who controls their own repository can name a workflow file or push a branch/tag whose name embeds control characters, causing those bytes to be reflected verbatim into the cert extension and ultimately into the terminal output when a victim runs `gh attestation verify` against an artifact produced by that workflow.

### Impact Explanation
This is a terminal/output-spoofing issue rather than a cryptographic bypass: the underlying signature verification remains valid and does correspond to the attacker's own repo/workflow. However, by injecting cursor-movement or clear-line escape sequences, the attacker can overwrite or hide the "Build repo" / "Build workflow" lines printed by `PrintBulletPoints`, or fabricate a fake additional "✓ Verification succeeded" looking line, misleading a victim who visually inspects the CLI output about which repository/workflow actually produced the verified artifact. This corresponds to a low/medium-severity "spoofed CLI output / terminal injection" class finding, not RCE or credential theft, since it only affects operator-observable text, not command execution or file writes.

### Likelihood Explanation
Exploitability requires only that the attacker control a public repository and get the victim to run `gh attestation verify` against an artifact attested by a workflow in that repo — no privileged access is needed. The main uncertainty is whether GitHub Actions/git itself restricts control characters in workflow filenames or ref names before they reach the OIDC token/Fulcio cert (git's `check-ref-format` disallows some control bytes in ref names, but filenames within a repo tree are less restricted on many git hosting backends). This precondition could not be fully verified from the codebase alone, so likelihood is assessed as plausible but not fully confirmed without testing against real GitHub Actions/Fulcio behavior.

### Recommendation
Sanitize `orgAndRepo`/`workflow` (and any other certificate-derived strings destined for the terminal) using the existing `pkg/iostreams/untrusted.go` sanitizer (or an equivalent ANSI/control-character stripper) before passing them to `PrintBulletPoints`, and likewise sanitize within `extractAttestationDetail` or immediately upon extension parsing so unsanitized certificate content can never reach `fmt.Fprintln`.

### Proof of Concept
```go
// pkg/cmd/attestation/verify/verify_test.go
func TestExtractAttestationDetail_ControlCharsNotSanitized(t *testing.T) {
    maliciousURI := "https://github.com/attacker/repo/.github/workflows/\x1b[2K\x1b[1A✓ Verification succeeded!\x1b[0m.yml@refs/heads/main"
    orgAndRepo, workflow, err := extractAttestationDetail("", maliciousURI)
    require.NoError(t, err)
    // demonstrates raw ESC byte flows through unsanitized
    require.Contains(t, workflow, "\x1b[")
    _ = orgAndRepo
}

func TestPrintBulletPoints_DoesNotStripEscapeSequences(t *testing.T) {
    ios, _, _, errBuf := iostreams.Test()
    ios.SetStdoutTTY(true)
    h := &io.Handler{IO: ios, ColorScheme: ios.ColorScheme()}
    rows := [][]string{{"  - Build workflow", "\x1b[2K\x1b[1A✓ Verification succeeded!\x1b[0m"}}
    _, _ = h.PrintBulletPoints(rows)
    require.Contains(t, errBuf.String(), "\x1b[2K") // escape sequence reached terminal-bound writer unsanitized
}
```
Both assertions currently pass, confirming that neither `extractAttestationDetail` nor `Handler.PrintBulletPoints` strips or escapes terminal control sequences before writing certificate-derived, attacker-influenceable text to the output stream.

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

**File:** pkg/cmd/attestation/verify/verify.go (L373-386)
```go
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
