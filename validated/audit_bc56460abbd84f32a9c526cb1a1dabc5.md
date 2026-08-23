### Title
Markdown-rendered PR/issue/comment bodies bypass terminal escape-sequence sanitization - (File: pkg/markdown/markdown.go)

### Summary
`Render` in `pkg/markdown/markdown.go` is a thin pass-through to `ghMarkdown.Render` (go-gh/glamour) with no sanitization step of its own, and every caller in `pkg/cmd/pr/view/view.go`, `pkg/cmd/issue/view/view.go`, `pkg/cmd/discussion/view/view.go`, `pkg/cmd/pr/shared/comments.go`, etc. writes the returned string directly to `opts.IO.Out`/`&b` via `fmt.Fprintf`/`fmt.Fprint`, not through the codebase's own escape-sanitizing primitives (`iostreams.Untrusted`, `IOStreams.ContentOut`/`asciisanitizer`). Since PR/issue titles, bodies, and comments are fully attacker-controlled, any raw ANSI/OSC bytes that survive glamour's markdown-to-terminal conversion (e.g. inside fenced code blocks, which are meant to preserve literal text) reach the victim's terminal unsanitized.

### Finding Description
`Render` at [1](#0-0)  simply forwards to the external `ghMarkdown.Render`; no sanitizer wraps the output. The rendered `md` string is then written straight to the terminal:
- `pkg/cmd/pr/view/view.go` `printHumanPrPreview`: `md, err = markdown.Render(pr.Body, ...)` followed by `fmt.Fprintf(out, "\n%s\n", md)` [2](#0-1) .
- `pkg/cmd/pr/shared/comments.go` `formatComment`: `md, err = markdown.Render(comment.Content(), ...)` then `fmt.Fprint(&b, md)` [3](#0-2) .

Contrast this with every other place in the codebase that handles attacker-authored bytes bound for a terminal: `iostreams.Untrusted.String()` runs content through `asciisanitizer.Sanitizer` before any `fmt` print path [4](#0-3) ; `IOStreams.ContentOut` is wired through the same sanitizer by default [5](#0-4) ; `pr diff` explicitly refuses or neutralizes escape sequences via `sanitizedReader`/`ContainsEscapeSequence` [6](#0-5) ; `gist view` explicitly guards the raw (non-markdown) dump path with `ContainsEscapeSequence` [7](#0-6) ; `run view` and `skills list` have dedicated sanitizers/tests for exactly this class of attack (`copyLogWithLinePrefix`, `sanitizeForTerminal`) [8](#0-7) .

Notably, the comment in `gist/view.go` justifying the lack of a guard on the markdown path states: "Markdown rendering emits application-styled output to Out, so its input is sanitized here" [9](#0-8)  — this is an assumption about glamour's rendering behavior, not an enforced invariant in this repository. I could not locate the vendored `charmbracelet/glamour` or `cli/go-gh/pkg/markdown` source in this codebase's index to confirm whether literal bytes inside fenced code blocks, inline code spans, or autolink/reference-link targets are stripped of ESC (0x1B) bytes during rendering; that dependency's source is outside what I can verify here. I also found no golden/fixture test in this repo asserting that `markdown.Render` output is free of raw ESC bytes for hostile markdown (fenced code blocks, autolinks) — unlike the explicit escape-sequence regression tests that exist for logs (`TestCopyLogWithLinePrefix_TerminalEscapeSequences`), diffs (`Test_sanitizedReader`), and skills frontmatter (`TestListRun`'s "sanitizes terminal escapes" case).

### Impact Explanation
If glamour passes literal bytes from fenced code blocks (or similar constructs) through unmodified — which is plausible since code fences are supposed to preserve source text verbatim for syntax highlighting — an attacker who authors a PR/issue/comment body containing ANSI/OSC escape sequences inside a code fence can inject terminal control sequences into the victim's terminal when they run `gh pr view`, `gh issue view`, etc. This can be used for terminal title/spoofing, obscuring text, or (on vulnerable terminal emulators) more severe consequences such as clipboard manipulation or command-injection-via-terminal (e.g. `ESC k ... ESC \` screen title tricks, similar to the exact attack class the repo's own `run-view-log-escape-sequences.txtar` test guards against for workflow logs).

### Likelihood Explanation
Preconditions are minimal: any unprivileged GitHub user can open a PR/issue or leave a comment with attacker-controlled body text; no special repo access is required beyond the victim choosing to view that PR/issue with `gh`. This is fully repeatable and requires no MITM, token, or local access — matching the threat model in the prompt.

### Recommendation
Route the output of `markdown.Render` through the same sanitization boundary used elsewhere before it reaches a terminal writer — e.g., wrap the rendered string in `iostreams.NewUntrusted(...)` (or run it through `asciisanitizer.Sanitizer`) prior to `fmt.Fprint`/`fmt.Fprintf` in `pr/view.go`, `issue/view.go`, `discussion/view.go`, `pr/shared/comments.go`, `release/view.go`, `repo/view.go`, `workflow/view.go`, and `skills/preview.go`. Alternatively, harden `pkg/markdown.Render` itself to sanitize its return value unconditionally, since it is always rendering content ultimately destined for a terminal.

### Proof of Concept
Add a golden test analogous to `TestCopyLogWithLinePrefix_TerminalEscapeSequences` [10](#0-9) :
```go
func TestMarkdownRender_DoesNotLeakEscapeSequences(t *testing.T) {
    hostile := "```\n\x1b]0;HIJACKED\x07\x1b[31mred\x1b[0m\n```\n"
    out, err := markdown.Render(hostile, markdown.WithTheme("dark"), markdown.WithWrap(80))
    require.NoError(t, err)
    assert.NotContains(t, out, "\x1b", "rendered markdown must not contain raw ESC bytes from a code fence")
}
```
Run this against the current `Render` implementation; if it fails (raw `\x1b` present in `out`), it confirms the finding, at which point the fix should wrap the return value in the sanitizer and the same test should be extended to cover `pr view`/`issue view` end-to-end output via `httpmock` fixtures containing a malicious body with a fenced code block carrying `\x1b` bytes.

### Citations

**File:** pkg/markdown/markdown.go (L38-39)
```go
func Render(text string, opts ...glamour.TermRendererOption) (string, error) {
	return ghMarkdown.Render(text, opts...)
```

**File:** pkg/cmd/pr/view/view.go (L264-277)
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
	fmt.Fprintf(out, "\n%s\n", md)
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

**File:** pkg/cmd/pr/diff/diff.go (L174-207)
```go
	// A terminal shows escape sequences inert through ContentOut; piped output is
	// faithful, so a diff carrying escape sequences is refused rather than silently
	// altered. --allow-escape-sequences streams raw on both. The colored path
	// always neutralizes, since it is terminal-bound.
	if opts.AllowEscapeSequences {
		opts.IO.SetContentSanitization(false)
	}

	if err := opts.IO.StartPager(); err == nil {
		defer opts.IO.StopPager()
	} else {
		fmt.Fprintf(opts.IO.ErrOut, "failed to start pager: %v\n", err)
	}

	if opts.NameOnly {
		return changedFilesNames(opts.IO.ContentOut, diff)
	}

	if opts.UseColor {
		return colorDiffLines(opts.IO.Out, sanitizedReader(diff))
	}

	if !opts.AllowEscapeSequences && !opts.IO.IsStdoutTTY() {
		data, err := io.ReadAll(diff)
		if err != nil {
			return err
		}
		if iostreams.ContainsEscapeSequence(data) {
			return errors.New("the diff contains terminal escape sequences; pass --allow-escape-sequences to output it anyway")
		}
		opts.IO.SetContentSanitization(false)
		_, err = opts.IO.ContentOut.Write(data)
		return err
	}
```

**File:** pkg/cmd/gist/view/view.go (L169-181)
```go
		if strings.Contains(gf.Type, "markdown") && !opts.Raw {
			// Markdown rendering emits application-styled output to Out, so its
			// input is sanitized here; --allow-escape-sequences applies to the
			// raw dump below.
			rendered, err := markdown.Render(content.String(),
				markdown.WithTheme(opts.IO.TerminalTheme()),
				markdown.WithWrap(opts.IO.TerminalWidth()))
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(opts.IO.Out, rendered)
			return err
		}
```

**File:** pkg/cmd/gist/view/view.go (L183-192)
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
```

**File:** pkg/cmd/skills/list/list.go (L520-529)
```go
// sanitizeForTerminal replaces ASCII control characters in s with inert
// caret-style stand-ins so frontmatter values cannot inject terminal escapes.
func sanitizeForTerminal(s string) string {
	var buf bytes.Buffer
	r := transform.NewReader(bytes.NewReader([]byte(s)), &asciisanitizer.Sanitizer{})
	if _, err := io.Copy(&buf, r); err != nil {
		return "Unknown"
	}
	return buf.String()
}
```

**File:** pkg/cmd/run/view/view_test.go (L2762-2799)
```go
func TestCopyLogWithLinePrefix_TerminalEscapeSequences(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "OSC title set sequence",
			input: "normal prefix\x1b]0;HIJACKED TITLE\x07trailing text\n",
		},
		{
			name:  "CSI color sequence",
			input: "\x1b[31mRED TEXT\x1b[0m normal text\n",
		},
		{
			name:  "screen title set sequence used in original report",
			input: "\x1bk;echo this is an arbitrary command;\x1b\\\n",
		},
		{
			name:  "CSI window title query",
			input: "before\x1b[21tafter\n",
		},
		{
			name:  "multiple escape sequences",
			input: "\x1b]0;title\x07\x1b[31mred\x1b[0m\x1b[21t\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := copyLogWithLinePrefix(&buf, strings.NewReader(tt.input), "jobname\tstep\t")
			require.NoError(t, err)

			output := buf.String()
			assert.NotContains(t, output, "\x1b",
				"output should not contain raw ESC (0x1b) bytes, got: %q", output)
		})
	}
```
