### Title
ANSI/OSC escape sequence passthrough in raw comment rendering - ([File: pkg/cmd/pr/shared/comments.go])

### Finding Description
`RawCommentList` (pkg/cmd/pr/shared/comments.go:29) iterates over `api.Comments`/`api.PullRequestReviews` and calls `formatRawComment` for each entry, which writes `comment.AuthorLogin()`, `comment.Association()`, and — critically — `comment.Content()` verbatim into a `strings.Builder` via `fmt.Fprintln(&b, comment.Content())` [1](#0-0) . `comment.Content()` is attacker-controlled: it is the raw body of an issue/PR comment, review, or description authored by any remote GitHub user who can open an issue/PR against a repo the victim views.

The codebase has an established, consistently-applied defense-in-depth pattern for exactly this class of data: the `iostreams.Untrusted` wrapper type, whose `String()` method runs content through `asciisanitizer.Sanitizer` (or a `stripControl` fallback) so that any `fmt` print path is automatically neutralized [2](#0-1) , and the `IOStreams.ContentOut` writer, which wraps `Out` in an `asciisanitizer` transform for any content the application did not author [3](#0-2) . Other code paths handling untrusted remote text — gist file viewing, `gh api` raw body output, `gh repo read-file`, workflow log viewing — all route through one of these mechanisms or explicitly refuse output containing `0x1B` bytes unless `--allow-escape-sequences` is passed [4](#0-3) [5](#0-4) .

`RawCommentList`/`formatRawComment`, however, never wraps `comment.Content()` in `Untrusted`, never routes it through `ContentOut`, and never checks for `0x1B`/control bytes before returning the string. The caller (`pkg/cmd/pr/view/view.go`, `pkg/cmd/issue/view/view.go`) subsequently writes this string to `opts.IO.Out`. This breaks the codebase-wide invariant that all remote/attacker-authored text reaching the terminal must be sanitized or explicitly gated behind an opt-out flag.

### Impact Explanation
An attacker who opens an issue/PR, posts a comment, or submits a review containing OSC 52 (clipboard write), OSC 7 (working-directory/title spoofing), DCS, or other C1/ANSI sequences can have those sequences emitted raw to the victim's terminal when the victim runs `gh pr view --comments` (or equivalent issue-view raw path) against the attacker's content. This can spoof terminal output/prompts, hijack the terminal title, or write attacker-chosen data to the system clipboard (OSC 52), potentially leading to prompt/confirmation spoofing or credential capture in follow-on victim actions. This matches "High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation."

### Likelihood Explanation
Trivial precondition: any unprivileged GitHub user can create an issue/PR/comment with arbitrary body text, including raw escape bytes (GitHub does not strip escape sequences from stored text/comment bodies). The victim only needs to run a normal `gh pr view` (or `gh issue view`) with the comments flag against that repository — a completely ordinary workflow with no additional privileges or interaction from the attacker. This is a fully repeatable, deterministic exploit path.

### Recommendation
Wrap `comment.Content()` (and `comment.AuthorLogin()`, `comment.Association()` for defense-in-depth) in `iostreams.NewUntrusted(...)` before formatting in `formatRawComment`, or pass the final string through the same `asciisanitizer.Sanitizer` transform used by `ContentOut`/`Untrusted` elsewhere in the codebase, consistent with the pattern already applied to gist file content, `gh api` response bodies, and `gh repo read-file`.

### Proof of Concept
```go
package shared

import (
    "strings"
    "testing"

    "github.com/cli/cli/v2/api"
)

func TestRawCommentList_StripsEscapeSequences(t *testing.T) {
    malicious := "hello \x1b]52;c;ZXZpbCBjbGlwYm9hcmQ=\x07 world"
    comments := api.Comments{
        Nodes: []*api.Comment{
            {Author: api.CommentAuthor{Login: "attacker"}, Body: malicious},
        },
    }
    out := RawCommentList(comments, api.PullRequestReviews{})

    if strings.ContainsRune(out, 0x1b) {
        t.Fatalf("raw ESC byte leaked into rendered comment output: %q", out)
    }
}
```
Expected: currently fails, since `formatRawComment` prints `comment.Content()` unmodified, so the ESC (`0x1B`) byte and OSC 52 payload appear verbatim in the returned string. After applying the fix (wrapping content in `iostreams.Untrusted` or sanitizing via `asciisanitizer`), the test should pass.

### Citations

**File:** pkg/cmd/pr/shared/comments.go (L38-51)
```go
func formatRawComment(comment Comment) string {
	if comment.IsHidden() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "author:\t%s\n", comment.AuthorLogin())
	fmt.Fprintf(&b, "association:\t%s\n", strings.ToLower(comment.Association()))
	fmt.Fprintf(&b, "edited:\t%t\n", comment.IsEdited())
	fmt.Fprintf(&b, "status:\t%s\n", formatRawCommentStatus(comment.Status()))
	fmt.Fprintln(&b, "--")
	fmt.Fprintln(&b, comment.Content())
	fmt.Fprintln(&b, "--")
	return b.String()
}
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

**File:** pkg/iostreams/iostreams.go (L490-508)
```go
// SetContentSanitization toggles ANSI escape sanitization on ContentOut.
// Commands should call this with false when an explicit opt-out flag (e.g.
// --allow-escape-sequences) is set, so subsequent writes of external content
// pass through unmodified.
func (s *IOStreams) SetContentSanitization(enabled bool) {
	s.sanitizeContent = enabled
	s.ContentOut = newContentWriter(s.Out, enabled)
}

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

**File:** pkg/cmd/gist/view/view.go (L183-196)
```go
		// Raw dump. On a terminal, ContentOut renders escape sequences inert.
		// When the output is piped, refuse content carrying escape sequences
		// rather than silently rewriting the bytes; --allow-escape-sequences
		// forces raw.
		if !opts.AllowEscapeSequences && !opts.IO.IsStdoutTTY() {
			if iostreams.ContainsEscapeSequence(content.RawBytes()) {
				return errors.New("gist file contains terminal escape sequences; pass --allow-escape-sequences to view it anyway")
			}
			opts.IO.SetContentSanitization(false)
		}
		raw := content.Raw()
		if _, err := fmt.Fprint(opts.IO.ContentOut, raw); err != nil {
			return err
		}
```
