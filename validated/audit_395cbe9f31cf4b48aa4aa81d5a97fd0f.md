### Title
ANSI/OSC escape passthrough in markdown-rendered issue/PR/comment/release bodies via `WithoutIndentation`/`Render` in `pkg/markdown/markdown.go` — (File: pkg/markdown/markdown.go)

### Summary
`pkg/markdown/markdown.go` thinly wraps `github.com/cli/go-gh/v2/pkg/markdown` (backed by `glamour`/`goldmark`) and is called directly with attacker-controlled `issue.Body`, `pr.Body`, `comment.Content()`, `release.Body`, and discussion body text, with the rendered result written straight to `opts.IO.Out` via `fmt.Fprint`/`fmt.Fprintf`. Unlike other code paths in this codebase that explicitly treat remote content as untrusted and strip control/escape sequences before it reaches a terminal, no such sanitization step wraps these markdown render call sites.

### Finding Description
`WithoutIndentation` in [1](#0-0)  and `Render` in [2](#0-1)  simply delegate to `ghMarkdown` (glamour) with no sanitization pass over the input or output bytes.

This function is invoked directly on server-supplied text in multiple `gh` view commands:
- PR body: [3](#0-2) 
- PR/issue comments: [4](#0-3) 
- Issue body: [5](#0-4) 
- Discussion body/comments: [6](#0-5)  and [7](#0-6) 
- Release body: [8](#0-7) 

In every one of these call sites, the raw string field from the GraphQL/REST API response is passed to `markdown.Render` and the result is written with `fmt.Fprint(out, md)`/`fmt.Fprintf(out, ...)` directly to `opts.IO.Out`, never through `opts.IO.ContentOut` (the sanitizing writer) and never wrapped in `iostreams.NewUntrusted(...)`.

This contrasts sharply with the deliberate security model applied elsewhere in this same codebase for external content:
- `pkg/iostreams/untrusted.go` defines `Untrusted`, whose `String()` method runs the content through `asciisanitizer.Sanitizer` specifically so that "any fmt print path... renders the content with ANSI escape sequences neutralized" [9](#0-8) .
- `pkg/iostreams/content.go`'s `CopyGuardedContent` and `ContainsEscapeSequence` explicitly refuse or guard textual content containing ESC (0x1B) bytes before it reaches a terminal [10](#0-9) [11](#0-10) .
- `gh gist view`, `gh api`, `gh release download`, and `gh repo read-file` all explicitly check `ContainsEscapeSequence`/route through `ContentOut`/`Untrusted` before printing raw remote bytes: [12](#0-11) [13](#0-12) [14](#0-13) .
- Even `gh run view --log` and `gh agent-task` log rendering treat log/log-derived text as needing escape stripping, with dedicated tests asserting ESC bytes never survive: [15](#0-14) .
- The `gh skills list` command sanitizes frontmatter fields specifically because they can "inject terminal escapes": [16](#0-15) .

None of this guarding logic (asciisanitizer, `ContainsEscapeSequence`, `Untrusted`) is applied to the markdown-rendering path used for issue/PR/comment/discussion/release bodies. The design intent throughout the rest of the codebase is that "the application is not the author of the bytes" for such content and must sanitize it [17](#0-16) , yet `markdown.Render`'s output is written to `opts.IO.Out` (the unsanitized, application-styled stream), not `ContentOut`.

`glamour`/`goldmark` (the underlying renderer) is a markdown-to-ANSI formatter — its job is to interpret markdown syntax and add its own ANSI styling codes, not to strip or neutralize arbitrary literal control bytes that already exist verbatim inside text nodes (e.g., inside a paragraph, list item, or plain inline text) of the source markdown. Literal ESC/OSC/DCS byte sequences embedded in an issue title, PR body, comment, or release note are therefore very likely carried through to the styled ANSI output unchanged, since the renderer's transformation operates on markdown syntax nodes, not on sanitizing raw byte content within those nodes.

### Impact Explanation
If an attacker embeds OSC 52 (clipboard write), OSC 7 (working directory report), DCS, or terminal title-injection escape sequences in a public issue title/body, PR body, comment, or release description, a victim running `gh pr view`, `gh issue view`, `gh release view`, or `gh discussion view` against that content in an interactive terminal could have those sequences interpreted by their terminal emulator. Depending on terminal capability this can result in clipboard exfiltration/poisoning, terminal title spoofing (which can be used for social-engineering / prompt spoofing to trick the user into approving a destructive action), or other terminal-emulator-specific side effects. This matches "Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation."

### Likelihood Explanation
Preconditions are minimal: the attacker needs only to be able to author a public/private-but-shared issue, PR, comment, or release that the victim later views with an ordinary `gh` command — a fully unprivileged, remote action requiring no special permissions, tokens, or MITM. This is a common workflow (viewing external contributions), making the vulnerability highly reachable and repeatable.

### Recommendation
Sanitize C0/C1 control and ANSI/OSC/DCS escape sequences out of the body/comment/release text before (or immediately after) passing it to `markdown.Render`, consistent with the pattern already established via `asciisanitizer`/`iostreams.Untrusted` elsewhere in the codebase. Concretely: wrap `issue.Body`, `pr.Body`, `comment.Content()`, `release.Body`, and discussion body/comment text in `iostreams.NewUntrusted(...)` (or run them through the `asciisanitizer.Sanitizer` transform) before calling `markdown.Render`, and/or apply the same sanitizer to the string returned from `markdown.Render` before it is written to `opts.IO.Out`.

### Proof of Concept
Add a golden test analogous to the existing `TestCopyLogWithLinePrefix_TerminalEscapeSequences` test [18](#0-17) , but targeting `markdown.Render`:

```go
func TestMarkdownRender_StripsEscapeSequences(t *testing.T) {
    input := "normal text\x1b]0;HIJACKED_TITLE\x07 more text\x1b[31mred\x1b[0m"
    out, err := markdown.Render(input, markdown.WithWrap(80))
    require.NoError(t, err)
    assert.NotContains(t, out, "\x1b",
        "rendered markdown should not contain raw ESC bytes, got: %q", out)
}
```

Additionally, an integration-style test can be built following `TestPRView_tty_Comments` [19](#0-18) , stubbing a PR body/comment containing `\x1b]52;c;BASE64\x07` or `\x1b]0;TITLE\x07` and asserting `output.String()` does not contain `\x1b`. Expect this assertion to fail against the current implementation, confirming the passthrough.

**Note:** I was unable to inspect the vendored source of `github.com/cli/go-gh/v2/pkg/markdown` and `glamour`/`goldmark` directly (external dependency, not indexed in this repo), so I could not 100% confirm at the byte level that literal control characters inside plain text nodes are never escaped/stripped by the renderer itself. The finding is based on (a) the clear absence of any sanitization call at every markdown-render call site for issue/PR/comment/release bodies, and (b) the consistent, deliberate sanitization pattern applied everywhere else in this codebase for external content, which is conspicuously missing here. Confirming the precise renderer behavior requires running the PoC test above.

### Citations

**File:** pkg/markdown/markdown.go (L11-13)
```go
func WithoutIndentation() glamour.TermRendererOption {
	return ghMarkdown.WithoutIndentation()
}
```

**File:** pkg/markdown/markdown.go (L38-40)
```go
func Render(text string, opts ...glamour.TermRendererOption) (string, error) {
	return ghMarkdown.Render(text, opts...)
}
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

**File:** pkg/cmd/issue/view/view.go (L300-313)
```go
	// Body
	var md string
	var err error
	if issue.Body == "" {
		md = fmt.Sprintf("\n  %s\n\n", cs.Muted("No description provided"))
	} else {
		md, err = markdown.Render(issue.Body,
			markdown.WithTheme(opts.IO.TerminalTheme()),
			markdown.WithWrap(opts.IO.TerminalWidth()))
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "\n%s\n", md)
```

**File:** pkg/cmd/discussion/view/view.go (L374-386)
```go
	var md string
	if d.Body == "" {
		md = fmt.Sprintf("\n  %s\n\n", cs.Muted("No description provided"))
	} else {
		var err error
		md, err = markdown.Render(d.Body,
			markdown.WithTheme(opts.IO.TerminalTheme()),
			markdown.WithWrap(opts.IO.TerminalWidth()))
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "\n%s\n", md)
```

**File:** pkg/cmd/discussion/view/view.go (L515-526)
```go
	if c.Body != "" {
		md, err := markdown.Render(c.Body,
			markdown.WithTheme(opts.IO.TerminalTheme()),
			markdown.WithWrap(opts.IO.TerminalWidth()))
		if err != nil {
			return err
		}
		if indent != "" {
			md = text.Indent(md, indent)
		}
		fmt.Fprint(out, md)
	}
```

**File:** pkg/cmd/release/view/view.go (L147-153)
```go
	renderedDescription, err := markdown.Render(release.Body,
		markdown.WithTheme(io.TerminalTheme()),
		markdown.WithWrap(io.TerminalWidth()))
	if err != nil {
		return err
	}
	fmt.Fprintln(w, renderedDescription)
```

**File:** pkg/iostreams/untrusted.go (L16-20)
```go
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

**File:** pkg/iostreams/content.go (L63-91)
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

**File:** pkg/cmd/api/api.go (L530-543)
```go
		// A raw non-JSON body is the only response the transport does not sanitize.
		// It is faithful byte output, so binary bound for a terminal and text
		// carrying escape sequences are refused; the opt-out flag and discarded
		// output stream verbatim.
		if !isJSON && !opts.AllowEscapeSequences && bodyWriter != io.Discard {
			err = iostreams.CopyGuardedContent(bodyWriter, responseBody, opts.IO.IsStdoutTTY())
			if binErr, ok := errors.AsType[iostreams.BinaryTerminalError](err); ok {
				err = fmt.Errorf("%w; redirect or pipe stdout to save it, or pass --allow-escape-sequences to output it anyway", binErr)
			} else if errors.Is(err, iostreams.ErrEscapeSequence) {
				err = errors.New("the response contains terminal escape sequences; pass --allow-escape-sequences to output it anyway")
			}
		} else {
			_, err = io.Copy(bodyWriter, responseBody)
		}
```

**File:** pkg/cmd/repo/read-file/read_file.go (L196-200)
```go
	// Refuse terminal escape sequences unless --allow-escape-sequences, in both TTY and non-TTY modes,
	// so a malicious file cannot manipulate a downstream terminal.
	if !opts.AllowEscapeSequences && iostreams.ContainsEscapeSequence(file.Content) {
		return errors.New("file contains terminal escape sequences; use --allow-escape-sequences to read anyway")
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

**File:** pkg/iostreams/iostreams.go (L58-63)
```go
	// ContentOut is the writer for external content (HTTP response bodies,
	// gist files, etc.) where the application is not the author of the bytes.
	// By default it sanitizes ANSI escape sequences before they reach the
	// underlying stdout. SetContentSanitization toggles the sanitization at
	// the command layer (e.g. via an --allow-escape-sequences flag).
	ContentOut io.Writer
```

**File:** pkg/cmd/pr/view/view_test.go (L668-694)
```go
func TestPRView_tty_Comments(t *testing.T) {
	tests := map[string]struct {
		branch          string
		cli             string
		fixtures        map[string]string
		expectedOutputs []string
		wantsErr        bool
	}{
		"without comments flag": {
			branch: "master",
			cli:    "123",
			fixtures: map[string]string{
				"PullRequestByNumber":   "./fixtures/prViewPreviewSingleComment.json",
				"ReviewsForPullRequest": "./fixtures/prViewPreviewReviews.json",
			},
			expectedOutputs: []string{
				`some title OWNER/REPO#12`,
				`1 \x{1f615} • 2 \x{1f440} • 3 \x{2764}\x{fe0f}`,
				`some body`,
				`———————— Not showing 9 comments ————————`,
				`marseilles \(Collaborator\) • Jan  9, 2020 • Newest comment`,
				`4 \x{1f389} • 5 \x{1f604} • 6 \x{1f680}`,
				`Comment 5`,
				`Use --comments to view the full conversation`,
				`View this pull request on GitHub: https://github.com/OWNER/REPO/pull/12`,
			},
		},
```
