### Title
Terminal escape sequence injection via unsanitized `targetUrl` printed by `gh codespace jupyter` - (File: pkg/cmd/codespace/jupyter.go)

### Summary
`App.Jupyter` prints the codespace-provided Jupyter server URL directly to the terminal with `fmt.Fprintln(a.io.Out, targetUrl)` without any escape-sequence sanitization. Since `serverUrl` originates from `invoker.StartJupyterServer`, an RPC response controlled by whatever backend/codespace the user connects to, a malicious or compromised codespace host can embed ANSI/OSC 8 escape sequences in that URL to forge terminal output or hide the real destination from the user.

### Finding Description
In `pkg/cmd/codespace/jupyter.go`, `serverUrl` is obtained from `invoker.StartJupyterServer(ctx)` [1](#0-0)  and is only string-substituted for the port before being printed verbatim to stdout: [2](#0-1) 

No call to any sanitization routine (e.g. `stripControl`, the `Untrusted` wrapper found elsewhere in the codebase at `pkg/iostreams/untrusted_test.go`) is made on `serverUrl`/`targetUrl` before `fmt.Fprintln`. Unlike other parts of the CLI that use an `Untrusted` type to strip control/escape bytes before printing untrusted network-derived strings (see `pkg/iostreams/untrusted_test.go` lines 12-35), the codespace Jupyter path has no such guard. If the codespace connection RPC (attacker-influenced host/codespace) returns a `ServerUrl` containing OSC 8 hyperlink escape sequences (`\x1b]8;;http://evil.com\x1b\\displayed-text\x1b]8;;\x1b\\`), those raw bytes flow unmodified into the victim's terminal.

### Impact Explanation
This allows terminal escape/hyperlink injection: an attacker who controls the codespace RPC response (e.g., a compromised or malicious codespace backend or environment) can rewrite what the user's terminal displays for a "trusted" gh CLI URL, hide or disguise the real target host, and lure the user into manually clicking a link that goes to `evil.com` while an authentication token intended for the legitimate Jupyter server may be exposed. This falls under output/terminal spoofing and social-engineering-enabling escape injection — a lower-severity but real CLI output-integrity issue (credential/token URL disclosure paired with UI spoofing).

### Likelihood Explanation
Requires the attacker to control the value returned as `ServerUrl` by the codespace RPC/backend that the victim's `gh codespace jupyter` invocation talks to (i.e., the victim connects to an attacker-controlled or compromised codespace environment). Given that codespaces are attacker-controllable environments in some threat models (e.g., a malicious codespace image/config a victim opens), this is plausible though it depends on the RPC/backend trust boundary, which I could not fully verify because I was unable to retrieve the full contents of `internal/codespaces/rpc/invoker.go` (specifically `isJupyterServerURLValid`) to confirm whether any format validation there would already reject control characters embedded in the URL.

### Recommendation
Sanitize `targetUrl` before printing (and before passing to the browser) by stripping ANSI/OSC control sequences — reuse the existing `Untrusted`/`stripControl` mechanism in `pkg/iostreams/untrusted_test.go`/`pkg/iostreams` — and ensure `isJupyterServerURLValid` in `internal/codespaces/rpc/invoker.go` rejects any URL containing non-printable/control characters, not just malformed URL syntax.

### Proof of Concept
```go
// pkg/cmd/codespace/jupyter_test.go
func TestJupyter_SanitizesEscapeSequencesInServerUrl(t *testing.T) {
    const esc = "\x1b"
    maliciousUrl := "http://localhost:8080/lab?token=abc" + esc + "]8;;http://evil.com" + esc + "\\CLICK ME" + esc + "]8;;" + esc + "\\"
    // Stub invoker.StartJupyterServer to return maliciousUrl, run App.Jupyter,
    // capture a.io.Out, and assert the printed output does NOT contain esc bytes:
    assert.NotContains(t, capturedOutput, esc)
}
```
Note: I was unable to fully inspect `internal/codespaces/rpc/invoker.go`'s `isJupyterServerURLValid` implementation within the available context to confirm it lacks control-character filtering; this should be verified directly, as it may already partially mitigate the issue (e.g., via `net/url.Parse` rejecting certain byte sequences in the host component), though it would not protect the path/query/fragment components where OSC 8 payloads are typically embedded.

### Citations

**File:** pkg/cmd/codespace/jupyter.go (L64-66)
```go
		serverPort, serverUrl, err = invoker.StartJupyterServer(ctx)
		return
	})
```

**File:** pkg/cmd/codespace/jupyter.go (L90-97)
```go
	// Server URL contains an authentication token that must be preserved
	targetUrl := strings.Replace(serverUrl, fmt.Sprintf("%d", serverPort), fmt.Sprintf("%d", destPort), 1)
	err = a.browser.Browse(targetUrl)
	if err != nil {
		return fmt.Errorf("failed to open JupyterLab in browser: %w", err)
	}

	fmt.Fprintln(a.io.Out, targetUrl)
```
