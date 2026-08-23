### Title
Unsanitized attacker-controlled device-code/verification-URL text written to terminal via `oauth.Flow.DisplayCode`/`BrowseURL` - ([File: internal/authflow/flow.go])

### Summary
`AuthFlow` wires `DisplayCode` and `BrowseURL` callbacks that write the `code`, `verificationURL`, and `authURL` strings returned by the device/OAuth flow directly to `IO.ErrOut` via `fmt.Fprintf`, with no ANSI/control-sequence sanitization. Since `oauthHost` can be an arbitrary Enterprise or custom host the user points `gh auth login --hostname` at, that host's OAuth/device-authorization response fully controls these strings.

### Finding Description
In `internal/authflow/flow.go`, the `DisplayCode` callback prints the `code` value straight into `fmt.Fprintf(w, "%s First copy your one-time code: %s\n", ...)` [1](#0-0) , and `BrowseURL` prints `authURL` directly via `fmt.Fprintf(w, "%s to continue in your web browser: %s\n", cs.Bold("Open this URL"), authURL)` and similar lines [2](#0-1) . `w` is `IO.ErrOut`, a raw `fileWriter` [3](#0-2) , which is not passed through the sanitizing `ContentOut` writer that the codebase uses elsewhere for untrusted external text (`newContentWriter`/`asciisanitizer`) [4](#0-3) . The codebase has an established pattern — `iostreams.Untrusted` / `iostreams.ContainsEscapeSequence` / `CopyGuardedContent` — specifically for wrapping externally-sourced text before it reaches a terminal writer (used in gist view, PR diff, `repo read-file`, `gh api`, release download) [5](#0-4) [6](#0-5) , but this pattern is not applied in `authflow/flow.go`. The `code` and `authURL`/`verificationURL` values originate from the OAuth device-flow exchange with `oauthHost` (via the `cli/oauth` package's `Flow.DetectFlow`), which for Enterprise/custom hosts is a server the victim configures but does not control the responses of — an attacker who operates or compromises that GHE-compatible endpoint (or performs a wrong-host routing trick) fully controls the device code and displayed URL text returned to the client. `BrowseURL` does parse the URL with `url.Parse` and reject non-http(s) schemes [7](#0-6) , but this only validates the scheme, not the full string printed (query strings, fragments, or embedded escape bytes in the URL are unrestricted), and `code` has no validation at all before printing.

### Impact Explanation
This enables terminal-output forging in the victim's `gh auth login` session (e.g. hiding the real one-time code, injecting a fake "Authentication complete"/prompt line, manipulating terminal title/cursor via OSC/CSI sequences) — matching a terminal-injection / spoofed-prompt impact class. It does not directly yield code execution or token exfiltration by itself; the concrete exploitable impact is limited to output spoofing/UI deception during the auth flow, which could be leveraged to social-engineer the victim (e.g., pasting a wrong code, following a fake instruction) but does not on its own bypass token/credential handling.

### Likelihood Explanation
Requires the victim to run `gh auth login` (or equivalent) against a host under attacker control or influence (e.g., `--hostname` pointed at an attacker's GHE-compatible endpoint, or a compromised/misdirected enterprise OAuth server). This is a real but narrower precondition than a fully unprivileged remote attacker acting via ordinary published GitHub content (repos/PRs/issues) — it specifically requires the victim to authenticate against an attacker-influenced host, which is a normal but non-default `gh auth login` usage pattern for Enterprise users.

### Recommendation
Wrap `code`, `verificationURL`, and `authURL` in `iostreams.NewUntrusted(...)` (or run them through the same `asciisanitizer` transform used for `ContentOut`) before writing to `w` in `DisplayCode` and `BrowseURL`, consistent with the sanitization pattern already established in `pkg/iostreams/untrusted.go` and `pkg/iostreams/content.go`.

### Proof of Concept
```go
// internal/authflow/flow_test.go
func TestDisplayCode_sanitizesEscapeSequences(t *testing.T) {
    ios, _, _, errBuf := iostreams.Test()
    maliciousCode := "ABCD-1234\x1b[2J\x1b]0;FAKE TITLE\x07"
    // Simulate what AuthFlow's DisplayCode closure does today:
    fmt.Fprintf(ios.ErrOut, "%s First copy your one-time code: %s\n", "!", maliciousCode)
    assert.NotContains(t, errBuf.String(), "\x1b") // currently FAILS, demonstrating the raw escape passes through
}
```
Expected: with the current implementation, the assertion fails because the ESC byte (`\x1b`) is present unsanitized in `errBuf`. After applying `iostreams.NewUntrusted(maliciousCode).String()` before printing, the assertion passes.

### Citations

**File:** internal/authflow/flow.go (L31-31)
```go
	w := IO.ErrOut
```

**File:** internal/authflow/flow.go (L58-59)
```go
			fmt.Fprintf(w, "%s First copy your one-time code: %s\n", cs.Yellow("!"), cs.Bold(code))
			return nil
```

**File:** internal/authflow/flow.go (L61-68)
```go
		BrowseURL: func(authURL string) error {
			if u, err := url.Parse(authURL); err == nil {
				if u.Scheme != "http" && u.Scheme != "https" {
					return fmt.Errorf("invalid URL: %s", authURL)
				}
			} else {
				return err
			}
```

**File:** internal/authflow/flow.go (L70-83)
```go
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
```

**File:** pkg/iostreams/iostreams.go (L499-508)
```go
// newContentWriter returns the writer to wire up as ContentOut. When
// sanitize is true it inserts an asciisanitizer in front of the underlying
// writer; otherwise it returns the underlying writer directly so writes
// reach stdout unchanged.
func newContentWriter(out io.Writer, sanitize bool) io.Writer {
	if !sanitize {
		return out
	}
	return transform.NewWriter(out, &asciisanitizer.Sanitizer{})
}
```

**File:** pkg/iostreams/untrusted.go (L11-20)
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
```

**File:** pkg/iostreams/content.go (L16-20)
```go
// ContainsEscapeSequence reports whether b contains an ANSI escape byte (0x1B),
// which can manipulate a terminal when printed.
func ContainsEscapeSequence(b []byte) bool {
	return bytes.IndexByte(b, 0x1B) >= 0
}
```
