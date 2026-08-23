### Title
Unsanitized ANSI/OSC escape sequences from PR/issue titles and branch labels reach the terminal via `PrintHeader`/`PrintMessage`/`printPrs` - (File: pkg/cmd/pr/shared/display.go, pkg/cmd/pr/status/status.go)

### Summary
`shared.PrintHeader` and `shared.PrintMessage` write directly to `io.Out` with `fmt.Fprintln`, and `printPrs` writes `pr.Title` and `pr.HeadLabel()` directly with `fmt.Fprintf`, none of which pass through the `iostreams.Untrusted` sanitizer or `CopyGuardedContent`. Since `api.PullRequest` fields such as `Title` and the head branch name are plain Go `string`s populated straight from the GraphQL API response, an attacker who controls a PR's title or head branch name can embed raw ANSI/OSC escape bytes that reach the victim's terminal unmodified when they run `gh pr status`.

### Finding Description
`pkg/cmd/pr/shared/display.go:58-64` defines:
```go
func PrintHeader(io *iostreams.IOStreams, s string) {
	fmt.Fprintln(io.Out, io.ColorScheme().Bold(s))
}
func PrintMessage(io *iostreams.IOStreams, s string) {
	fmt.Fprintln(io.Out, io.ColorScheme().Muted(s))
}
``` [1](#0-0) 

These take a raw `string`, not an `iostreams.Untrusted`, and `io.ColorScheme().Bold`/`Muted` only wrap the string with SGR color codes — they do not sanitize existing escape bytes. `pkg/cmd/pr/status/status.go:printPrs` (lines 231-240) writes `pr.Title` (via `text.Truncate`/`text.RemoveExcessiveWhitespace`, neither of which strip control/escape bytes, per `internal/text/text.go:30-40`) and `pr.HeadLabel()` directly into `fmt.Fprintf(w, ...)`:
```go
fmt.Fprintf(w, "  %s  %s %s", prStateColorFunc(prNumber), text.Truncate(50, text.RemoveExcessiveWhitespace(pr.Title)), cs.Cyan("["+pr.HeadLabel()+"]"))
``` [2](#0-1) 

The codebase already has a purpose-built defense for exactly this class of bug: `iostreams.Untrusted.String()` sanitizes ANSI escapes via `asciisanitizer.Sanitizer` on every `fmt` print path, and `iostreams.CopyGuardedContent` refuses textual content containing escape sequences before writing to a terminal [3](#0-2) [4](#0-3) . However, these guards are only wired into a few callers (gist content, skills discovery, agent-task logs) — a search of `api/*.go` confirms `Untrusted` is never used to type PR/Issue title or branch-name fields, so `pr.Title` and `pr.HeadLabel()` remain plain, unsanitized `string`s sourced from GraphQL responses that an unprivileged repo/PR author fully controls.

### Impact Explanation
An attacker who opens a PR with a title or head branch name containing OSC sequences (e.g. `\x1b]0;pwned\x07`, or terminal-emulator-specific OSC 52 clipboard-write / OSC 133 shell-integration sequences) can hijack the victim's terminal title, write to the clipboard, or in vulnerable terminal emulators trigger command-injection-adjacent behavior, when the victim simply runs `gh pr status` (or `gh issue status`, `gh pr status`'s counterpart, using the same `shared.PrintHeader`/`PrintMessage` helpers) against the attacker's repo/PR. This matches a "terminal escape sequence injection leading to spoofing / clipboard or terminal state manipulation" class of impact.

### Likelihood Explanation
Fully attacker-controlled and requires no privilege beyond opening a PR (or, for the head-label case, having any branch name in a fork) in a repo the victim later runs `gh pr status` against, or having an issue/PR the victim's own `gh issue status`/`gh pr status` surfaces (e.g., a PR requesting review from the victim, which needs no acceptance by the victim). This is trivially repeatable and requires no timing race or special server behavior.

### Recommendation
Route `pr.Title` and `pr.HeadLabel()` (and any other API-sourced free text reaching `PrintHeader`/`PrintMessage`) through `iostreams.NewUntrusted(...).String()` before formatting, or change `PrintHeader`/`PrintMessage`'s parameter type to `iostreams.Untrusted` so callers are forced to sanitize, mirroring the pattern already used in `pkg/cmd/gist/shared/shared.go` and `internal/skills/discovery/discovery.go`.

### Proof of Concept
```go
func TestPrintPrs_SanitizesEscapeSequences(t *testing.T) {
	io, _, out, _ := iostreams.Test()
	pr := api.PullRequest{
		Number: 1,
		Title:  "evil\x1b]0;pwned\x07title",
		State:  "OPEN",
		HeadRefName: "evil\x1b]0;pwned\x07branch",
	}
	printPrs(io, 1, pr)
	if bytes.IndexByte(out.Bytes(), 0x1b) >= 0 {
		t.Fatalf("expected no ESC byte in output, got: %q", out.String())
	}
}
```
Expected (current) result: the assertion fails — the ESC byte (0x1b) from `Title`/`HeadRefName` is present verbatim in `out`, confirming the escape sequence reaches `io.Out` unsanitized.

### Citations

**File:** pkg/cmd/pr/shared/display.go (L58-64)
```go
func PrintHeader(io *iostreams.IOStreams, s string) {
	fmt.Fprintln(io.Out, io.ColorScheme().Bold(s))
}

func PrintMessage(io *iostreams.IOStreams, s string) {
	fmt.Fprintln(io.Out, io.ColorScheme().Muted(s))
}
```

**File:** pkg/cmd/pr/status/status.go (L231-240)
```go
func printPrs(io *iostreams.IOStreams, totalCount int, prs ...api.PullRequest) {
	w := io.Out
	cs := io.ColorScheme()

	for _, pr := range prs {
		prNumber := fmt.Sprintf("#%d", pr.Number)

		prStateColorFunc := cs.ColorFromString(shared.ColorForPRState(pr))

		fmt.Fprintf(w, "  %s  %s %s", prStateColorFunc(prNumber), text.Truncate(50, text.RemoveExcessiveWhitespace(pr.Title)), cs.Cyan("["+pr.HeadLabel()+"]"))
```

**File:** pkg/iostreams/untrusted.go (L35-44)
```go
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
