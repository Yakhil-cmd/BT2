### Title
Issue/PR body text is rendered to the terminal without ANSI/OSC sanitization, unlike gist content - (File: pkg/cmd/issue/view/view.go, pkg/cmd/pr/view/view.go)

### Summary
`printHumanIssuePreview` and `printHumanPrPreview` pass `issue.Body`/`pr.Body` — plain `string` fields populated directly from the GitHub API — straight into `markdown.Render` and then `fmt.Fprintf(out, ...)` without ever wrapping them in `iostreams.Untrusted`. This is inconsistent with `pkg/cmd/gist/view/view.go`, which explicitly wraps remote content in `iostreams.NewUntrusted` and calls `.String()` (which runs the `asciisanitizer` transform) before handing it to `markdown.Render`.

### Finding Description
In `pkg/cmd/issue/view/view.go`, `printHumanIssuePreview` does: [1](#0-0) 
and in `pkg/cmd/pr/view/view.go`, `printHumanPrPreview` does the analogous thing: [2](#0-1) 

`issue.Body` and `pr.Body` are ordinary `string` fields coming from `issueShared.FindIssueOrPR` / `shared.Finder.Find`, which populate them from GraphQL/REST API responses — fully attacker-controlled if the attacker authors the issue/PR body. Neither value is ever passed through `iostreams.NewUntrusted`.

By contrast, `pkg/cmd/gist/view/view.go` explicitly treats remote gist content as untrusted before markdown rendering: [3](#0-2) 
There, `content.String()` (the sanitizing method of `Untrusted`) is fed into `markdown.Render`, guaranteeing ANSI/OSC/CSI bytes are neutralized via `asciisanitizer` before glamour ever sees them: [4](#0-3) 

`markdown.Render` itself is a thin wrapper around `go-gh`'s glamour-based renderer and performs no ANSI stripping of its own: [5](#0-4) 
Glamour/goldmark parse markdown *syntax*; raw control bytes embedded in text nodes (e.g., inside a paragraph or code span) are not markdown syntax, so they are not stripped, escaped, or otherwise neutralized — they are passed through as literal text content and re-emitted in the rendered ANSI-styled output. Since `issue.Body`/`pr.Body` bypass `Untrusted` entirely, no sanitization pass ever runs on this text before it reaches `opts.IO.Out`, which is the real terminal/os.Stdout on a TTY.

The `Untrusted` type's design intent, per its own doc comment, is that "the raw bytes are unexported so the only ways out are the methods below" and "any fmt print path... renders the content with ANSI escape sequences neutralized" — but that protection only applies when a value is actually wrapped in `Untrusted`, which issue/PR body text is not.

### Impact Explanation
An attacker who opens a public issue or PR with a body containing raw OSC/CSI escape sequences (e.g., `\x1b]0;evil\x07` to rewrite the terminal title, or more elaborate CSI sequences to manipulate cursor position/clear-screen to hide output, or terminal-emulator-specific escape codes) can have those bytes reach the victim's terminal verbatim when the victim runs `gh issue view <n>` or `gh pr view <n>` on a TTY. This matches the "terminal escape sequence injection" bounty class: spoofing terminal titles/prompts, hiding malicious command remnants, or exploiting known terminal-emulator escape-sequence vulnerabilities (some terminal emulators support OSC 52 clipboard write, hyperlink OSC 8 abuse, etc.). It does not achieve direct RCE by itself but is a legitimate output-sanitization gap with concrete terminal-spoofing impact.

### Likelihood Explanation
High feasibility and fully unprivileged: any GitHub user can open an issue or PR with an arbitrary body on any public repository. The only precondition is that the victim runs `gh issue view` or `gh pr view` interactively (TTY) against that issue/PR — a completely ordinary, common action for maintainers reviewing incoming issues/PRs. No comment/approval/merge is required; only viewing the issue/PR is needed.

### Recommendation
Wrap `issue.Body` and `pr.Body` (and comment bodies rendered via `prShared.CommentList`/`RawCommentList`, if not already sanitized) in `iostreams.NewUntrusted(...)` and use `.String()` when passing to `markdown.Render`, mirroring the pattern already used in `pkg/cmd/gist/view/view.go`. This ensures the `asciisanitizer` transform strips/neutralizes ESC/OSC/CSI bytes before they reach glamour and, ultimately, `opts.IO.Out`.

### Proof of Concept
```go
func TestPrintHumanIssuePreview_StripsEscapeSequences(t *testing.T) {
    ios, _, stdout, _ := iostreams.Test()
    ios.SetStdoutTTY(true)
    ios.SetStdinTTY(true)

    issue := &api.Issue{
        Title: "test",
        Body:  "hello \x1b]0;evil\x07 world",
    }
    opts := &ViewOptions{IO: ios, Now: time.Now}
    baseRepo := ghrepo.New("OWNER", "REPO")

    err := printHumanIssuePreview(opts, baseRepo, issue)
    require.NoError(t, err)

    out := stdout.String()
    require.NotContains(t, out, "\x1b]0;evil\x07",
        "raw OSC escape sequence from issue body must not reach stdout")
}
```
Run equivalently for `printHumanPrPreview` with `pr.Body` set to the same payload. Both assertions currently fail because `issue.Body`/`pr.Body` are never passed through `iostreams.NewUntrusted` before `markdown.Render`, so the byte `0x1B` (and the full OSC sequence) survives into `stdout`.

### Citations

**File:** pkg/cmd/issue/view/view.go (L303-313)
```go
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

**File:** pkg/cmd/pr/view/view.go (L265-277)
```go
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

**File:** pkg/cmd/gist/view/view.go (L148-180)
```go
	render := func(gf *shared.GistFile) error {
		// Treat the file content as untrusted external bytes. The truncated
		// path fetches the full content from the raw URL.
		content := iostreams.NewUntrusted(gf.Content)
		if gf.Truncated {
			fullContent, err := shared.GetRawGistFile(client, safeurl.NewImmutableSafeURL(gf.RawURL))
			if err != nil {
				return err
			}

			content = fullContent
		}

		if shared.IsBinaryContents(content.RawBytes()) {
			if len(gist.Files) == 1 || opts.Filename != "" {
				return fmt.Errorf("error: file is binary")
			}
			_, err = fmt.Fprintln(opts.IO.Out, cs.Muted("(skipping rendering binary content)"))
			return nil
		}

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

**File:** pkg/markdown/markdown.go (L38-40)
```go
func Render(text string, opts ...glamour.TermRendererOption) (string, error) {
	return ghMarkdown.Render(text, opts...)
}
```
