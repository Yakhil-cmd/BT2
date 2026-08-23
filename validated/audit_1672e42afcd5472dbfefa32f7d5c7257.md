### Title
Unsanitized attacker-controlled RPC error message printed to terminal, allowing ANSI escape sequence injection - ([File: pkg/cmd/codespace/jupyter.go])

### Finding Description
`(i *invoker) StartJupyterServer` in `internal/codespaces/rpc/invoker.go` builds its error via `fmt.Errorf("failed to start JupyterLab: %s", response.Message)` when the RPC response indicates failure, and `response.Message` originates from the codespace's `JupyterServerHost.GetRunningServer` gRPC response — a field fully controlled by the codespace backend. [1](#0-0)  This error is returned up through `App.Jupyter` in `pkg/cmd/codespace/jupyter.go`, which calls `invoker.StartJupyterServer(ctx)` inside `RunWithProgress` and simply returns the error unmodified on failure. [2](#0-1)  That error ultimately reaches `internal/ghcmd/cmd.go`'s top-level error handling, where `printError` does a raw `fmt.Fprintln(out, err)` with no ANSI/control-character sanitization before writing to stderr. [3](#0-2) 

This is architecturally significant because the codebase has an established, deliberate pattern for exactly this class of risk: the `iostreams.Untrusted` type and `iostreams.ContainsEscapeSequence`/`CopyGuardedContent` helpers exist specifically to sanitize or refuse externally-sourced text before it reaches a terminal writer (see `pkg/iostreams/untrusted.go`, `pkg/iostreams/content.go`, and their use in `gist/view`, `pr/diff`, `release/download`, and `repo/read-file`). [4](#0-3) [5](#0-4)  The Jupyter RPC error path does not use `Untrusted`, does not check `ContainsEscapeSequence`, and is not routed through `opts.IO.ContentOut` (the only IOStreams writer that auto-sanitizes). Instead, `response.Message` is interpolated directly into a plain `error` via `fmt.Errorf`, which is printed with `fmt.Fprintln(out, err)` — a path with no sanitization step anywhere in the chain.

### Impact Explanation
A malicious or compromised codespace backend (or a codespace whose `JupyterServerHost` service the attacker controls, e.g. via a crafted devcontainer/backend a victim connects `gh cs jupyter` to) can embed ANSI/OSC escape sequences (e.g., terminal title-setting `\x1b]0;...\x07`, cursor manipulation, or screen-clearing sequences) in `response.Message`. When `gh codespace jupyter` fails to start the server, this text is printed verbatim to the victim's terminal, enabling terminal escape sequence injection — potentially forging misleading prompts, hiding/altering visible output, or manipulating terminal state (title bar spoofing, etc.). This matches a terminal/output-injection impact class, though it is a lower-severity issue since it requires the victim to already be pointing `gh` at an attacker-influenced codespace/backend and does not by itself achieve code execution or credential theft.

### Likelihood Explanation
Preconditions: the attacker must control the codespace's `JupyterServerHost.GetRunningServer` RPC response — i.e., the attacker controls (or has compromised) the backend the victim's `gh codespace jupyter` connects to. Given that precondition, triggering the bug is trivial and deterministic: any failed start response with `Result=false` and a crafted `Message` reaches the terminal unsanitized on every invocation. The harder part is achieving the precondition (control over the codespace RPC backend), which is a nontrivial but plausible scenario (e.g., a codespace configured by the attacker that the victim is lured into opening).

### Recommendation
Wrap `response.Message` in `iostreams.NewUntrusted(...)` before embedding it into the error string, or sanitize it with `iostreams.ContainsEscapeSequence`/an ASCII sanitizer before use in `fmt.Errorf`, consistent with the pattern already used in `gist/view`, `pr/diff`, and `repo/read-file`. Alternatively, apply sanitization centrally in `printError` (`internal/ghcmd/cmd.go`) for all error text written to `stderr`, since arbitrary error messages elsewhere in the codebase (e.g., other RPC/API error bodies) could carry the same risk.

### Proof of Concept
```go
// internal/codespaces/rpc/invoker_test.go
func TestStartJupyterServer_MessageWithEscapeSequenceIsNotSanitized(t *testing.T) {
    maliciousMsg := "\x1b]0;HIJACKED_TITLE\x07boom"
    // Stub GetRunningServer to return Result: false, Message: maliciousMsg
    // (using existing mock in jupyter_server_host_service.v1.proto.mock.go)
    _, _, err := invoker.StartJupyterServer(context.Background())
    require.Error(t, err)
    // Demonstrates the vulnerability: the raw ESC byte survives into the error text
    assert.Contains(t, err.Error(), "\x1b")
}
```
Expected (secure) behavior: `err.Error()` should NOT contain the raw `\x1b` byte — the message should be sanitized/stripped before being embedded in the error, matching the `TestUntrusted_fmt_paths_never_leak` pattern already used elsewhere in the codebase (`pkg/iostreams/untrusted_test.go`). [6](#0-5)

### Citations

**File:** internal/codespaces/rpc/invoker_test.go (L1-1)
```go
package rpc
```

**File:** pkg/cmd/codespace/jupyter.go (L58-71)
```go
	err = a.RunWithProgress("Starting JupyterLab on codespace", func() (err error) {
		invoker, err = rpc.CreateInvoker(ctx, fwd)
		if err != nil {
			return
		}

		serverPort, serverUrl, err = invoker.StartJupyterServer(ctx)
		return
	})
	if invoker != nil {
		defer safeClose(invoker, &err)
	}
	if err != nil {
		return err
```

**File:** internal/ghcmd/cmd.go (L282-293)
```go
func printError(out io.Writer, err error, cmd *cobra.Command, debug bool) {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		fmt.Fprintf(out, "error connecting to %s\n", dnsError.Name)
		if debug {
			fmt.Fprintln(out, dnsError)
		}
		fmt.Fprintln(out, "check your internet connection or https://githubstatus.com")
		return
	}

	fmt.Fprintln(out, err)
```

**File:** pkg/iostreams/untrusted.go (L11-23)
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
```

**File:** pkg/iostreams/content.go (L52-63)
```go
// CopyGuardedContent writes external content from r to w under the safety model
// used by byte-moving commands: binary content is refused when w targets a
// terminal and streamed verbatim otherwise, while textual content is refused when
// it carries terminal escape sequences. Binary content streams without buffering;
// only textual content is buffered, so its escapes are caught before any byte is
// written. On refusal the output stream is left untouched; otherwise it receives
// the full content. isTTY reports whether w targets the user's terminal.
//
// It returns [BinaryTerminalError] or [ErrEscapeSequence] so callers can add
// command-specific guidance. Callers that must stream verbatim (an explicit
// opt-out, or output bound for a file) should copy directly instead.
func CopyGuardedContent(w io.Writer, r io.Reader, isTTY bool) error {
```

**File:** pkg/iostreams/untrusted_test.go (L22-35)
```go
func TestUntrusted_fmt_paths_never_leak(t *testing.T) {
	u := NewUntrusted("x" + esc + "]0;title" + esc + "\\")
	cases := map[string]string{
		"%s":     fmt.Sprintf("%s", u),
		"%v":     fmt.Sprintf("%v", u),
		"Sprint": fmt.Sprint(u),
		"woven":  fmt.Sprintf("by %s here", u),
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, out, esc)
		})
	}
}
```
