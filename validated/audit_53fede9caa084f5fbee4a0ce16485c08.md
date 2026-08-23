### Title
Unsanitized PR comment bodies written raw to non-TTY output allows terminal escape-sequence injection - ([File: pkg/cmd/pr/shared/comments.go])

### Summary
When `gh pr view --comments` is run with stdout not connected to a terminal, `viewRun` calls `shared.RawCommentList(pr.Comments, pr.DisplayableReviews())` and writes the result directly via `fmt.Fprint(opts.IO.Out, ...)`. `RawCommentList`/`formatRawComment` print `comment.Content()` (the attacker-controlled comment/review body) verbatim with no escape-sequence sanitization, unlike the codebase's own `iostreams.Untrusted` type which exists specifically to neutralize ANSI/OSC sequences in untrusted content.

### Finding Description
`viewRun` in [1](#0-0)  branches on `connectedToTerminal` (`opts.IO.IsStdoutTTY()`). In the interactive/TTY branch it calls `printHumanPrPreview`, which renders comment bodies through `markdown.Render` inside `shared.CommentList`/`formatComment` ( [2](#0-1) ). But in the non-TTY branch, when `opts.Comments` is set, it instead calls `shared.RawCommentList` and does a bare `fmt.Fprint`.

`RawCommentList` and its helper `formatRawComment` write `comment.Content()` — the raw PR/review/comment body string returned from the GitHub API — directly into a `strings.Builder` with `fmt.Fprintln(&b, comment.Content())`, with no escape stripping at all: [3](#0-2) .

The repository already contains a purpose-built defense for exactly this class of issue: `iostreams.Untrusted`, whose `String()` method runs content through `asciisanitizer.Sanitizer` to strip/neutralize ANSI/OSC escape sequences whenever it's passed through a `fmt` print path ( [4](#0-3) ). However, `comment.Content()` in `pkg/cmd/pr/shared/comments.go` is a plain `string`, not wrapped in `Untrusted`, and `RawCommentList` never routes through this or any other sanitizer — confirmed by the absence of any `Untrusted`/sanitize usage in `pkg/cmd/pr/**`. A malicious PR/issue comment or review body containing CSI/OSC escape sequences will therefore reach the victim's raw terminal/log/pager unmodified whenever `gh pr view -c` (or `gh issue view -c`, which shares the same `RawCommentList` helper per `pkg/cmd/issue/view/view.go`) is piped or redirected.

### Impact Explanation
An unprivileged attacker who can post a comment or review on any PR/issue the victim later inspects can embed terminal escape sequences (e.g., to rewrite terminal title, hide/replace displayed text, or attempt to manipulate terminal emulators/log viewers that don't sanitize input) that get emitted verbatim to the victim's log/pipe when they run `gh pr view <n> --comments | some-log-viewer` or redirect output to a file later `cat`'d to a terminal. This matches a terminal escape-sequence / output-injection impact class — not remote code execution, but forging of terminal/log-viewer state that can facilitate spoofing, hidden content, or (depending on the terminal emulator) more severe consequences.

### Likelihood Explanation
Fully attacker-controlled and easily triggerable: any GitHub user can post a comment on a public issue/PR without special privileges. The only precondition is that the victim runs `gh pr view --comments` (or `gh issue view --comments`) in a non-TTY context, which is common in scripts, CI pipelines, and piped invocations. No MITM, no token, no social engineering beyond commenting on the target's PR/issue.

### Recommendation
Wrap comment/review body content in `iostreams.Untrusted` (or otherwise pass it through `asciisanitizer.Sanitizer`) before printing in `formatRawComment`/`RawCommentList` in `pkg/cmd/pr/shared/comments.go`, so raw/non-TTY output is sanitized the same way other untrusted external content is handled elsewhere in the codebase, regardless of terminal connection state.

### Proof of Concept
```go
// pkg/cmd/pr/shared/comments_test.go
func TestRawCommentList_SanitizesEscapeSequences(t *testing.T) {
    evil := "\x1b]0;PWNED\x07Look here\x1b[8mhidden\x1b[0m"
    comments := api.Comments{Nodes: []*api.Comment{
        {Author: api.Author{Login: "attacker"}, Body: evil, CreatedAt: time.Now()},
    }}
    out := RawCommentList(comments, api.PullRequestReviews{})
    // Expected (currently fails): no raw ESC (0x1b) bytes should be present.
    require.NotContains(t, out, "\x1b", "raw ANSI/OSC escape sequences must not reach non-TTY output")
}
```
Running this against the current implementation shows the raw `\x1b` bytes pass through unchanged, confirming the missing sanitization on the `RawCommentList` path.

### Citations

**File:** pkg/cmd/pr/view/view.go (L129-136)
```go
	if connectedToTerminal {
		return printHumanPrPreview(opts, baseRepo, pr)
	}

	if opts.Comments {
		fmt.Fprint(opts.IO.Out, shared.RawCommentList(pr.Comments, pr.DisplayableReviews()))
		return nil
	}
```

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

**File:** pkg/cmd/pr/shared/comments.go (L121-134)
```go
	// Body
	var md string
	var err error
	if comment.Content() == "" {
		md = fmt.Sprintf("\n  %s\n\n", cs.Muted("No body provided"))
	} else {
		md, err = markdown.Render(comment.Content(),
			markdown.WithTheme(io.TerminalTheme()),
			markdown.WithWrap(io.TerminalWidth()))
		if err != nil {
			return "", err
		}
	}
	fmt.Fprint(&b, md)
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
