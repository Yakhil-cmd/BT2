### Title
PR body and release body written raw to `io.Out` instead of the sanitizing `io.ContentOut`, allowing ANSI/escape-sequence injection - ([File: pkg/cmd/pr/view/view.go], [File: pkg/cmd/release/view/view.go])

### Summary
`gh pr view` and `gh release view` print attacker-controlled `pr.Body` / `release.Body` directly to `opts.IO.Out` (via `fmt.Fprintln`/`fmt.Fprint`, in both the TTY-rendered path and the plain/raw path), never through `io.ContentOut`, `iostreams.Untrusted`, or an `iostreams.ContainsEscapeSequence` check. This is exactly the class of bug the sanitization model (`io.ContentOut`, `Untrusted.String()`) exists to prevent, and other equivalent commands (`gist view`, `pr diff`, `repo read-file`) implement the guard correctly while these two do not.

### Finding Description
`pkg/iostreams/iostreams.go` establishes `ContentOut` as the designated writer for untrusted external content, sanitizing ANSI escapes via `asciisanitizer` unless explicitly disabled [1](#0-0) , and `newContentWriter`/`SetContentSanitization` implement that toggle [2](#0-1) . Commands that render remote content correctly route through this: `gist view` wraps file content in `iostreams.NewUntrusted`, checks `ContainsEscapeSequence` for non-TTY output, and writes via `opts.IO.ContentOut` [3](#0-2) ; `pr diff` does the same for diff bytes [4](#0-3) .

`pkg/cmd/pr/view/view.go`'s `printRawPrPreview` (used for the non-TTY path) writes `pr.Body` straight to `io.Out` with `fmt.Fprintln(out, pr.Body)`, with no `Untrusted` wrapping and no escape-sequence check [5](#0-4) . The TTY path `printHumanPrPreview` also renders `pr.Body` through `markdown.Render` and writes the result to plain `out` (`opts.IO.Out`, not `ContentOut`) [6](#0-5) ; markdown rendering does not strip raw ANSI escape bytes, and no sanitizer sits between the PR body (fetched via GraphQL as a plain `string` field, not `iostreams.Untrusted`) and the terminal.

Likewise `pkg/cmd/release/view/view.go`'s `renderReleasePlain` writes `release.Body` directly: `fmt.Fprint(w, release.Body)` [7](#0-6) , and `renderReleaseTTY` renders `release.Body` through `markdown.Render` then `fmt.Fprintln(w, renderedDescription)` where `w := io.Out` [8](#0-7) . Neither path uses `ContentOut`, `Untrusted`, or `ContainsEscapeSequence`; a search across the release/pr view packages confirms `Untrusted` is never referenced there.

The attacker input is fully external and unprivileged: any GitHub user can open a pull request against a public repo (or push a PR branch attacker controls the description of) or publish a release on a repo they control/fork, setting the body to contain raw ANSI escape sequences (e.g., `ESC]0;title\a`, cursor-hiding, screen-clearing, or terminal answerback/query sequences). When the victim runs `gh pr view <attacker-pr>` or `gh release view` against the attacker's release, the escape sequences reach the terminal unmodified.

### Impact Explanation
This enables terminal escape-sequence injection: title-bar spoofing, screen manipulation to hide or forge text (prompt/output forgery), cursor repositioning to overwrite prior trusted output, and on vulnerable terminal emulators, more dangerous OSC sequences (e.g., clipboard write via OSC 52, or answerback queries that can be relayed back into the shell). This matches the "arbitrary file write/read is not required — output-integrity/terminal injection" impact class the sanitization mechanism (`iostreams.Untrusted`, `ContentOut`) was specifically built to close, and is inconsistent with how equivalent commands (`gist view`, `pr diff`) already treat this exact same threat.

### Likelihood Explanation
High feasibility and full repeatability: no privileges beyond opening a PR or publishing a release are required, no host allowlist or GraphQL-side sanitization filters the `body`/`Body` field before it reaches the CLI, and the vulnerable code path (`gh pr view <num>`, `gh release view [tag]`) is one of the most common commands run against untrusted/community-submitted content.

### Recommendation
Wrap `pr.Body` and `release.Body` in `iostreams.NewUntrusted(...)` at the point they are fetched (or immediately before display), and route all writes of that content through `opts.IO.ContentOut` instead of `opts.IO.Out`, mirroring the pattern already used in `pkg/cmd/gist/view/view.go` and `pkg/cmd/pr/diff/diff.go` (including the non-TTY `ContainsEscapeSequence` refusal/`--allow-escape-sequences` opt-out where applicable). This includes both the TTY-rendered markdown output and the raw/plain non-TTY output paths in `pkg/cmd/pr/view/view.go` and `pkg/cmd/release/view/view.go`.

### Proof of Concept
Go test using `httpmock` to stub the PR/release GraphQL or REST response with a body containing `\x1b]0;PWNED\x07` (or `\x1b[2J\x1b[H` to clear/overwrite), run `pr view <num>` / `release view <tag>` with `iostreams.Test()` capturing stdout into a `*bytes.Buffer`, and assert:
```go
io, _, stdout, _ := iostreams.Test()
io.SetStdoutTTY(true) // and separately test false
// ... configure mocks so pr.Body / release.Body == "\x1b]0;PWNED\x07malicious"
err := viewRun(opts)
require.NoError(t, err)
require.False(t, iostreams.ContainsEscapeSequence(stdout.Bytes()),
    "raw ESC byte reached stdout, sanitizer bypassed")
```
Expected current behavior: assertion fails (raw `0x1B` byte is present in `stdout.Bytes()`), confirming the sanitizer is bypassed for these two commands, in contrast to an equivalent test against `gist view` or `pr diff` which passes.

### Citations

**File:** pkg/iostreams/iostreams.go (L58-63)
```go
	// ContentOut is the writer for external content (HTTP response bodies,
	// gist files, etc.) where the application is not the author of the bytes.
	// By default it sanitizes ANSI escape sequences before they reach the
	// underlying stdout. SetContentSanitization toggles the sanitization at
	// the command layer (e.g. via an --allow-escape-sequences flag).
	ContentOut io.Writer
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

**File:** pkg/cmd/pr/diff/diff.go (L174-210)
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

	_, err = io.Copy(opts.IO.ContentOut, diff)
	return err
```

**File:** pkg/cmd/pr/view/view.go (L176-177)
```go
	fmt.Fprintln(out, "--")
	fmt.Fprintln(out, pr.Body)
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

**File:** pkg/cmd/release/view/view.go (L131-153)
```go
func renderReleaseTTY(io *iostreams.IOStreams, release *shared.Release) error {
	cs := io.ColorScheme()
	w := io.Out

	fmt.Fprintf(w, "%s\n", cs.Bold(release.TagName))
	if release.IsDraft {
		fmt.Fprintf(w, "%s • ", cs.Red("Draft"))
	} else if release.IsPrerelease {
		fmt.Fprintf(w, "%s • ", cs.Yellow("Pre-release"))
	}
	if release.IsDraft {
		fmt.Fprintln(w, cs.Mutedf("%s created this %s", release.Author.Login, text.FuzzyAgo(time.Now(), release.CreatedAt)))
	} else {
		fmt.Fprintln(w, cs.Mutedf("%s released this %s", release.Author.Login, text.FuzzyAgo(time.Now(), *release.PublishedAt)))
	}

	renderedDescription, err := markdown.Render(release.Body,
		markdown.WithTheme(io.TerminalTheme()),
		markdown.WithWrap(io.TerminalWidth()))
	if err != nil {
		return err
	}
	fmt.Fprintln(w, renderedDescription)
```

**File:** pkg/cmd/release/view/view.go (L194-198)
```go
	fmt.Fprint(w, "--\n")
	fmt.Fprint(w, release.Body)
	if !strings.HasSuffix(release.Body, "\n") {
		fmt.Fprintf(w, "\n")
	}
```
