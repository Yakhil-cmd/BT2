### Title
Unsanitized device-code and verification URL from OAuth host allow terminal escape-sequence injection - ([File: internal/authflow/flow.go])

### Finding Description
`AuthFlow` builds an `oauth.Flow` whose `DisplayCode` and `BrowseURL` callbacks write the `code`, `verificationURL`/`authURL` values received from the device-flow response directly to `IO.ErrOut` via `fmt.Fprintf(w, ...)` with no sanitization, e.g. `fmt.Fprintf(w, "%s First copy your one-time code: %s\n", cs.Yellow("!"), cs.Bold(code))` and `fmt.Fprintf(w, "%s to open %s in your browser... ", cs.Bold("Press Enter"), authURL)`. [1](#0-0) [2](#0-1)  These values originate from the `oauthHost`'s device-flow endpoint (via `cli/oauth`'s `Flow.DetectFlow`), so a host the victim points `gh auth login`/`gh auth refresh` at (e.g. via `--hostname`) fully controls their content. `BrowseURL` only validates the URL scheme is `http`/`https` via `url.Parse`, which does not strip or escape embedded ANSI control sequences, so a value like `https://evil.example/x%1b[2K...` still passes the check and reaches the writer unsanitized. [3](#0-2)  Notably, the codebase already has a dedicated mitigation for exactly this class of issue — the `Untrusted` type in `pkg/iostreams/untrusted.go`, whose doc comment states its `String()` method "sanitizes... so any fmt print path... renders the content with ANSI escape sequences neutralized" specifically for content the CLI "did not author" such as HTTP response data. [4](#0-3)  `flow.go` does not wrap `code`, `verificationURL`, or `authURL` with `Untrusted`, so none of that protection applies to the device/browser OAuth flow.

### Impact Explanation
An attacker-controlled OAuth host (reachable when a victim runs `gh auth login --hostname attacker-host` or `gh auth refresh --hostname attacker-host` against a GHES-style endpoint, or any host `gh` is pointed at) can inject ANSI/terminal control sequences into the one-time code or verification URL text. This enables terminal output forging in the victim's terminal during the login flow — e.g., clearing/overwriting prior lines to fake a `✓ Authentication complete.` message, hiding warning text, or manipulating cursor position/terminal title — corresponding to a terminal/output spoofing impact class rather than direct code execution or credential theft.

### Likelihood Explanation
Exploitation requires the victim to run `gh auth login`/`gh auth refresh` targeting a host under attacker control (an explicitly in-scope precondition: "controls responses from a host the victim points gh at"). Given that precondition, the exploit is deterministic and repeatable — the attacker fully controls the `code` and `verificationURL`/`authURL` fields returned in the device-flow response, and no sanitization intervenes before they reach the terminal writer.

### Recommendation
Wrap `code`, `verificationURL`, and `authURL` in `iostreams.Untrusted` (or otherwise pass them through the existing ASCII sanitizer) before printing in `DisplayCode` and `BrowseURL`, consistent with how other untrusted, server-controlled text is already handled elsewhere in the codebase via `pkg/iostreams/untrusted.go`.

### Proof of Concept
```go
// internal/authflow/flow_test.go
func Test_DisplayCode_sanitizesANSI(t *testing.T) {
    ios, _, _, errOut := iostreams.Test()
    maliciousCode := "A1F4-3B3C\x1b[2K\x1b[1A✓ Authentication complete."
    // Simulate DisplayCode callback logic from AuthFlow with maliciousCode
    fmt.Fprintf(ios.ErrOut, "%s First copy your one-time code: %s\n", "!", maliciousCode)
    out := errOut.String()
    assert.NotContains(t, out, "\x1b[2K", "raw ANSI escape sequence should not reach terminal output")
}
```
Expected (current) result: the assertion fails because the raw `\x1b[2K` sequence is written unmodified to `IO.ErrOut`, confirming the unsanitized path. After applying the `Untrusted` wrapper fix, the escape bytes would be neutralized and the test would pass.

### Citations

**File:** internal/authflow/flow.go (L48-60)
```go
		DisplayCode: func(code, verificationURL string) error {
			if isCopyToClipboard {
				err := clipboard.WriteAll(code)
				if err == nil {
					fmt.Fprintf(w, "%s One-time code (%s) copied to clipboard\n", cs.Yellow("!"), cs.Bold(code))
					return nil
				}
				fmt.Fprintf(w, "%s Failed to copy one-time code to clipboard\n", cs.Red("!"))
				fmt.Fprintf(w, "  %s\n", err)
			}
			fmt.Fprintf(w, "%s First copy your one-time code: %s\n", cs.Yellow("!"), cs.Bold(code))
			return nil
		},
```

**File:** internal/authflow/flow.go (L61-84)
```go
		BrowseURL: func(authURL string) error {
			if u, err := url.Parse(authURL); err == nil {
				if u.Scheme != "http" && u.Scheme != "https" {
					return fmt.Errorf("invalid URL: %s", authURL)
				}
			} else {
				return err
			}

			if !isInteractive {
				fmt.Fprintf(w, "%s to continue in your web browser: %s\n", cs.Bold("Open this URL"), authURL)
				return nil
			}

			fmt.Fprintf(w, "%s to open %s in your browser... ", cs.Bold("Press Enter"), authURL)
			_ = waitForEnter(IO.In)

			if err := b.Browse(authURL); err != nil {
				fmt.Fprintf(w, "%s Failed opening a web browser at %s\n", cs.Red("!"), authURL)
				fmt.Fprintf(w, "  %s\n", err)
				fmt.Fprint(w, "  Please try entering the URL in your browser manually\n")
			}
			return nil
		},
```

**File:** pkg/iostreams/untrusted.go (L11-44)
```go
// Untrusted wraps string content the application did not author: HTTP response
// bodies, file contents fetched from a remote, anything that originates outside
// the CLI. The raw bytes are unexported so the only ways out are the methods
// below.
//
// Untrusted satisfies fmt.Stringer, and String sanitizes, so any fmt print path
// (Fprint, Fprintf with %s or %v, Sprint) renders the content with ANSI escape
// sequences neutralized. The only way to reach the raw bytes is Raw, which is
// deliberately easy to grep for and is intended for non-terminal uses such as
// hashing, writing to a file, or piping to another program.
type Untrusted struct {
	raw string
}

// NewUntrusted labels a string as untrusted external content.
func NewUntrusted(s string) Untrusted {
	return Untrusted{raw: s}
}

// NewUntrustedBytes labels a byte slice as untrusted external content.
func NewUntrustedBytes(b []byte) Untrusted {
	return Untrusted{raw: string(b)}
}

// String returns the content with ANSI escape sequences neutralized. It is
// called automatically by the fmt package, so printing an Untrusted value is
// safe by default on every fmt path.
func (u Untrusted) String() string {
	sanitized, _, err := transform.String(&asciisanitizer.Sanitizer{}, u.raw)
	if err != nil {
		return stripControl(u.raw)
	}
	return sanitized
}
```
