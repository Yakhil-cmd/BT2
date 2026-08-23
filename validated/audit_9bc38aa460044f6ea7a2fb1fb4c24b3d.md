### Title
Issue body raw preview writes attacker-controlled bytes unsanitized to non-TTY stdout, allowing terminal escape-sequence injection - (File: `pkg/cmd/issue/view/view.go`)

### Summary
`printRawIssuePreview` writes `issue.Body` directly to `out` via `fmt.Fprintln(out, issue.Body)` with no escape-sequence check, even though `viewRun` invokes this exact function on the non-TTY path [1](#0-0) . This differs from `pkg/cmd/gist/view/view.go`, which explicitly checks `iostreams.ContainsEscapeSequence` and refuses to print raw content containing ESC bytes unless `--allow-escape-sequences` is passed [2](#0-1) .

### Finding Description
`viewRun` fetches an issue via `issueShared.FindIssueOrPR` and, when stdout is not a TTY and `--comments` is not set, calls `printRawIssuePreview(opts.IO.Out, issue)` [1](#0-0) . Inside that function, `issue.Body` — a field fully controlled by the issue author (an unprivileged remote GitHub user) — is written verbatim with `fmt.Fprintln(out, issue.Body)` [3](#0-2) . No call to `iostreams.ContainsEscapeSequence` or wrapping in `iostreams.NewUntrusted`/`Untrusted` occurs anywhere in this path.

By contrast, `pkg/cmd/gist/view/view.go`'s raw-dump path explicitly treats file content as untrusted (`iostreams.NewUntrusted(gf.Content)`), and before writing to stdout in non-TTY mode it checks `iostreams.ContainsEscapeSequence(content.RawBytes())`, refusing output and returning an error unless the user passes `--allow-escape-sequences` [4](#0-3) . This guard mirrors the more general `CopyGuardedContent` helper in `pkg/iostreams/content.go`, which explicitly documents that "textual content is refused when it carries terminal escape sequences" [5](#0-4) .

The issue view path never invokes this guard for the body text, so any ESC (0x1B) or other control bytes embedded in an issue body reach stdout unmodified. This affects `gh issue view N` when its output is piped to a non-terminal consumer (log aggregator, terminal multiplexer status line, CI log viewer, editor plugin, etc.).

### Impact Explanation
This is an escape-sequence/terminal-injection issue, not a memory-safety or code-execution bug in `gh` itself. Concrete impact depends entirely on the downstream consumer of the piped output (e.g., ANSI sequences that manipulate terminal state, hide/spoof text, change window titles, or in vulnerable terminal emulators/multiplexers trigger further exploitation). It does not, by itself, achieve remote code execution, credential exfiltration, file overwrite, or authorization bypass within `gh` — it is bounded to "escape-sequence injection into downstream consumers of piped gh output," matching the audit's own scoped-impact statement. Given the project's existing precedent of explicitly guarding against this exact scenario in the gist-view raw path, this is a legitimate output-sanitization gap, but its severity is inherently limited by the low-trust nature of raw terminal ANSI injection (commonly treated as low/informational unless chained with a specific vulnerable terminal).

### Likelihood Explanation
Fully attacker-reachable with no special privileges: any GitHub user can open an issue with a body containing raw ESC bytes (issue bodies are free-form markdown/text, not sanitized server-side for control characters). The victim only needs to run `gh issue view <N>` with stdout piped/redirected (the common, or even default, invocation pattern for scripting `gh issue view` output). No comments flag, no `--json`, and no TTY are required — this is the default path once stdout is not a terminal.

### Recommendation
Apply the same guard used in `pkg/cmd/gist/view/view.go` to `printRawIssuePreview` (and any other raw/non-TTY text output paths using untrusted API fields): before writing `issue.Body` to `out`, check `iostreams.ContainsEscapeSequence([]byte(issue.Body))` and either strip/refuse the escape sequences or route the body through `iostreams.NewUntrusted(...)` and a guarded writer (e.g., `CopyGuardedContent`) consistent with the rest of the codebase's untrusted-content handling model.

### Proof of Concept
```go
// pkg/cmd/issue/view/view_test.go (illustrative)
func TestViewRun_RawEscapeSequenceInBody(t *testing.T) {
    ios, _, stdout, _ := iostreams.Test()
    ios.SetStdoutTTY(false) // non-TTY path

    httpmock // ... stub issue lookup response with Body: "hello\x1b[31mRED\x1b[0m"

    err := viewRun(opts) // opts.IO wraps ios, IssueNumber points at stubbed issue
    assert.NoError(t, err)

    // Expected (vulnerable) behavior: raw ESC byte (0x1B) is present in stdout.
    assert.True(t, bytes.Contains(stdout.Bytes(), []byte{0x1B}))

    // Compare to gist view's guarded raw path, which would instead return
    // iostreams.ErrEscapeSequence / a "contains terminal escape sequences" error
    // for the same input when !opts.AllowEscapeSequences && !opts.IO.IsStdoutTTY().
}
```
Expected assertion: raw `0x1B` bytes are emitted verbatim to stdout via `printRawIssuePreview`, whereas the equivalent gist-view raw-dump path (`pkg/cmd/gist/view/view.go`, lines 183-192) would reject the same content with `iostreams.ErrEscapeSequence`/`ContainsEscapeSequence` unless `--allow-escape-sequences` is passed.

### Citations

**File:** pkg/cmd/issue/view/view.go (L185-194)
```go
	if opts.IO.IsStdoutTTY() {
		return printHumanIssuePreview(opts, baseRepo, issue)
	}

	if opts.Comments {
		fmt.Fprint(opts.IO.Out, prShared.RawCommentList(issue.Comments, api.PullRequestReviews{}))
		return nil
	}

	return printRawIssuePreview(opts.IO.Out, issue)
```

**File:** pkg/cmd/issue/view/view.go (L235-237)
```go
	fmt.Fprintln(out, "--")
	fmt.Fprintln(out, issue.Body)
	return nil
```

**File:** pkg/cmd/gist/view/view.go (L148-196)
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
		}

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

**File:** pkg/iostreams/content.go (L52-61)
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
```
