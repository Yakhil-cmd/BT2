### Title
ANSI/terminal escape sequence injection via unsanitized `pr.Body` in `printRawPrPreview` - ([File: pkg/cmd/pr/view/view.go])

### Summary
`gh pr view` in non-TTY mode (piped output) writes the attacker-controlled PR body directly to `out` via `fmt.Fprintln(out, pr.Body)` with zero sanitization, unlike other content-emitting code paths in the same codebase (`gist view`, `pr diff`, `release download`) which explicitly guard against embedded terminal escape sequences. This creates a real sanitization gap that can be exploited by a PR author to inject terminal control sequences into piped `gh pr view` output.

### Finding Description
In `viewRun` at [1](#0-0) , when stdout is not a TTY, the function calls `printRawPrPreview(opts.IO, pr)` instead of the TTY-only `printHumanPrPreview`, which is the only branch that routes the body through `markdown.Render` at [2](#0-1) .

`printRawPrPreview` writes `pr.Body` completely raw: [3](#0-2) 

`pr.Body` originates from `shared.PRFinder.Find` (GraphQL API response), which is fully attacker-controlled: any user can open a PR (on their own fork/branch) with a body containing raw ANSI/OSC/DCS escape bytes (e.g. `\x1b[6n`, OSC 52 clipboard write, OSC 8 hyperlink spoofing, cursor-manipulation sequences, etc.). No validation, stripping, or escaping is applied anywhere in this call chain.

This is a real behavioral inconsistency with the rest of the codebase: the repo has a dedicated primitive, `iostreams.CopyGuardedContent` / `ContainsEscapeSequence`, at [4](#0-3)  and [5](#0-4) , which refuses to emit textual content containing byte `0x1B` (`ErrEscapeSequence`). This guard is used by `pkg/cmd/gist/view/view.go`, `pkg/cmd/api/api.go`, `pkg/cmd/release/download/download.go`, and `pkg/cmd/repo/read-file/read_file.go`. Similarly, `pkg/cmd/pr/diff/diff.go` uses `github.com/cli/go-gh/v2/pkg/asciisanitizer` (an `AllowEscapeSequences` opt-in flag) to strip/guard escapes in diff output at [6](#0-5) . `printRawPrPreview` has none of these protections, meaning `pr.Body`, `pr.Title`, `pr.Milestone.Title`, and other string fields printed via `fmt.Fprintf`/`fmt.Fprintln` in this function are all emitted verbatim regardless of terminal state.

### Impact Explanation
When a victim runs `gh pr view <n>` with stdout redirected/piped (e.g., into a log file, another CLI, a terminal multiplexer, or a downstream tool that itself writes to a real terminal), the raw escape bytes from the PR body pass through unfiltered. Depending on the downstream consumer, this can enable: terminal title/clipboard manipulation (OSC sequences), cursor/text overwrite tricks used for spoofing displayed content, or terminal capability probing (device status report responses can be read back by malicious scripts that capture stdin). This matches GitHub's bounty "terminal escape sequence / output injection" impact class — it is a real, unauthenticated content-injection primitive reachable by any unprivileged user who can open a PR with a crafted body, though actual harm depends on what the victim pipes the output into.

### Likelihood Explanation
Attack requires only opening a PR (no special repo permissions) and having a victim pipe `gh pr view` output to a non-TTY consumer — a common workflow (logging, scripting, tmux capture-pane, CI log viewers, IDE-integrated terminals). The exploit is fully repeatable and deterministic since `printRawPrPreview` unconditionally prints `pr.Body` with no gating logic at all.

### Recommendation
Route `pr.Body` (and other free-text PR fields) in `printRawPrPreview` through the same escape-sequence guard used elsewhere in the codebase — either reuse `iostreams.ContainsEscapeSequence`/`CopyGuardedContent` to strip or refuse output containing `0x1B`, or apply `asciisanitizer` as done in `pr/diff/diff.go`, ensuring parity between the TTY and non-TTY rendering paths.

### Proof of Concept
```go
func TestPrintRawPrPreview_EscapeSequenceInBody(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    ios.SetStdoutTTY(false) // force non-TTY branch

    pr := &api.PullRequest{
        Title: "test",
        Body:  "malicious\x1b]52;c;ZXZpbA==\x07payload", // OSC 52 clipboard-write escape
    }

    err := printRawPrPreview(ios, pr)
    require.NoError(t, err)

    // Demonstrates the raw escape byte reaches the writer unsanitized,
    // in contrast to iostreams.ContainsEscapeSequence(out.Bytes()) == true
    // which would be rejected by CopyGuardedContent-guarded paths (gist/diff).
    require.True(t, iostreams.ContainsEscapeSequence(out.Bytes()))
    require.Contains(t, out.String(), "\x1b]52;c;ZXZpbA==\x07")
}
```
Expected result: assertion passes, confirming `printRawPrPreview` emits the raw `0x1B` byte sequence unmodified, whereas the same content passed through `iostreams.CopyGuardedContent` (as used by `gist view`/`release download`) would return `ErrEscapeSequence` and refuse to write.

### Citations

**File:** pkg/cmd/pr/view/view.go (L129-138)
```go
	if connectedToTerminal {
		return printHumanPrPreview(opts, baseRepo, pr)
	}

	if opts.Comments {
		fmt.Fprint(opts.IO.Out, shared.RawCommentList(pr.Comments, pr.DisplayableReviews()))
		return nil
	}

	return printRawPrPreview(opts.IO, pr)
```

**File:** pkg/cmd/pr/view/view.go (L176-177)
```go
	fmt.Fprintln(out, "--")
	fmt.Fprintln(out, pr.Body)
```

**File:** pkg/cmd/pr/view/view.go (L264-276)
```go
	// Body
	var md string
	var err error
	if pr.Body == "" {
		md = fmt.Sprintf("\n  %s\n\n", cs.Muted("No description provided"))
	} else {
		md, err = markdown.Render(pr.Body,
			markdown.WithTheme(opts.IO.TerminalTheme()),
			markdown.WithWrap(opts.IO.TerminalWidth()))
		if err != nil {
			return err
		}
	}
```

**File:** pkg/iostreams/content.go (L16-20)
```go
// ContainsEscapeSequence reports whether b contains an ANSI escape byte (0x1B),
// which can manipulate a terminal when printed.
func ContainsEscapeSequence(b []byte) bool {
	return bytes.IndexByte(b, 0x1B) >= 0
}
```

**File:** pkg/iostreams/content.go (L63-92)
```go
func CopyGuardedContent(w io.Writer, r io.Reader, isTTY bool) error {
	head := make([]byte, contentSniffLen)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	head = head[:n]

	if mime, ok := BinaryContentType(head); ok {
		if isTTY {
			return BinaryTerminalError{MIME: mime}
		}
		if _, err := w.Write(head); err != nil {
			return err
		}
		_, err := io.Copy(w, r)
		return err
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	content := append(head, rest...)
	if ContainsEscapeSequence(content) {
		return ErrEscapeSequence
	}
	_, err = w.Write(content)
	return err
}
```

**File:** pkg/cmd/pr/diff/diff.go (L25-44)
```go
	"github.com/cli/go-gh/v2/pkg/asciisanitizer"
	"github.com/spf13/cobra"
	"golang.org/x/text/transform"
)

type DiffOptions struct {
	HttpClient func() (*http.Client, error)
	IO         *iostreams.IOStreams
	Browser    browser.Browser

	Finder shared.PRFinder

	SelectorArg string
	UseColor    bool
	Patch       bool
	NameOnly    bool
	BrowserMode bool
	Exclude     []string

	AllowEscapeSequences bool
```
