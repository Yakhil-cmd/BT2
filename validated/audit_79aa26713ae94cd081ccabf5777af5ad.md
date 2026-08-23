### Title
Unsanitized PR title/body/metadata reach the pager unfiltered - ([File: pkg/cmd/pr/view/view.go])

### Summary
`viewRun` in `pkg/cmd/pr/view/view.go` starts a pager and then prints `pr.Title`, label names, milestone titles, and (in the raw/non-TTY path) `pr.Body` via `fmt.Fprintf`/`fmt.Fprintln` directly to `opts.IO.Out`, which is unconditionally the sanitizing-free stream. This is inconsistent with the rest of the codebase's established security model for untrusted remote text.

### Finding Description
The codebase has a well-defined pattern for handling attacker-controlled remote text: wrap it in `iostreams.Untrusted` (whose `String()` runs it through `asciisanitizer.Sanitizer` before any `fmt` verb can emit it) [1](#0-0) , or write it through `opts.IO.ContentOut`, which by default wraps the underlying writer with the same sanitizer [2](#0-1) . Commands such as `gist view` [3](#0-2) , `pr diff` [4](#0-3) , and `repo read-file` [5](#0-4)  all explicitly route remote bytes through this Untrusted/ContentOut/escape-refusal machinery before they can reach `opts.IO.Out` (which becomes the pager's stdin once `StartPager` runs).

`viewRun`, however, calls `opts.IO.StartPager()` and then in `printHumanPrPreview` prints `pr.Title` — an attacker-controlled field set by any PR author — directly to `out` (`opts.IO.Out`) with no `Untrusted` wrapping and no `ContentOut` routing: [6](#0-5) 
The same applies to `printRawPrPreview`, which writes `pr.Title` and `pr.Body` straight to `out` with `fmt.Fprintf`/`fmt.Fprintln`: [7](#0-6) 
Only `pr.Body` in the TTY path goes through `markdown.Render`, and even that renderer is not guaranteed to strip raw ESC bytes embedded as literal text inside markdown (it targets markdown syntax, not terminal-escape neutralization) [8](#0-7) . None of `pr.Title`, label names (`prLabelList`), milestone titles, or project names go through any sanitizer at all before being written to `opts.IO.Out`, which is the stream that feeds the external pager once `StartPager` has redirected it.

This means a PR title such as `\x1bk;malicious command;\x1b\\` (screen/tmux title-injection, matching the class of payload the repo already tests for in `run view --log`) [9](#0-8)  would be forwarded byte-for-byte into the pager's stdin from `gh pr view`, unlike the equivalent code paths for gist contents, diffs, and file reads, which explicitly guard against exactly this.

### Impact Explanation
Terminal escape sequences from an attacker-authored PR title (or label/milestone name, if the attacker has write access to set those) can manipulate the pager/terminal — e.g. set a terminal/tmux/screen title containing a crafted "prompt," rewrite the visible prompt, or in vulnerable pager/terminal-emulator combinations, trigger clipboard writes or other terminal escape abuse. This matches "Terminal output/prompt spoofing" impact — an unprivileged remote actor (any user who can open a PR) can inject content that reaches the victim's pager unsanitized purely by having the victim run `gh pr view`.

### Likelihood Explanation
High feasibility: opening a PR with a crafted title requires no special privileges (fork + PR), and `gh pr view` is a routine command victims run against arbitrary/untrusted repos and PR numbers. The only precondition is `--comments`/interactive TTY view (the common case), which triggers `printHumanPrPreview` and the pager. No additional bypass of host allowlists or auth is needed since this is purely an output-sanitization gap, not a request-routing issue.

### Recommendation
Route `pr.Title`, `pr.Body` (in `printRawPrPreview`), label names, milestone titles, project titles, and reviewer/assignee display names through `iostreams.NewUntrusted(...).String()` or `opts.IO.ContentOut` before writing to `opts.IO.Out` in both `printHumanPrPreview` and `printRawPrPreview`, consistent with the pattern already used in `gist/view/view.go`, `pr/diff/diff.go`, and `repo/read-file/read_file.go`.

### Proof of Concept
```go
func TestPRView_TitleEscapeSequenceSanitizedForPager(t *testing.T) {
    // pr.Title crafted by an attacker-controlled PR author
    pr := &api.PullRequest{
        Title: "safe \x1bk;malicious-title;\x1b\\ text",
        Body:  "body",
    }
    ios, _, stdout, _ := iostreams.Test()
    ios.SetStdoutTTY(true)
    opts := &ViewOptions{IO: ios, Now: time.Now}

    // stub a pager so StartPager writes into a controllable buffer instead of exec'ing `less`
    ios.SetPager("cat") // or an in-process stub writer

    err := printHumanPrPreview(opts, ghrepo.New("OWNER", "REPO"), pr)
    require.NoError(t, err)

    // Expected (currently failing): stdout must not contain the raw ESC byte
    assert.NotContains(t, stdout.String(), "\x1b",
        "PR title escape sequence reached pager/output unsanitized")
}
```
Expected result with current code: the assertion fails because `pr.Title` is written raw via `fmt.Fprintf(out, ...)` at `pkg/cmd/pr/view/view.go:187`, confirming the unsanitized-bytes-to-pager path.

### Citations

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

**File:** pkg/cmd/repo/read-file/read_file.go (L181-200)
```go
	// read-file does its own escape-sequence guarding below, so it writes raw
	// bytes through ContentOut in passthrough mode. Leaving sanitization on
	// would corrupt binary files and strip the escapes that
	// --allow-escape-sequences explicitly allows.
	opts.IO.SetContentSanitization(false)

	if mime, ok := iostreams.BinaryContentType(file.Content); ok {
		if opts.IO.IsStdoutTTY() {
			return fmt.Errorf("binary file (%s, %s); use --output to save to a file or pipe stdout",
				mime, text.FormatSize(int64(file.Size)))
		}
		_, err = opts.IO.ContentOut.Write(file.Content)
		return err
	}

	// Refuse terminal escape sequences unless --allow-escape-sequences, in both TTY and non-TTY modes,
	// so a malicious file cannot manipulate a downstream terminal.
	if !opts.AllowEscapeSequences && iostreams.ContainsEscapeSequence(file.Content) {
		return errors.New("file contains terminal escape sequences; use --allow-escape-sequences to read anyway")
	}
```

**File:** pkg/cmd/pr/view/view.go (L150-177)
```go
	fmt.Fprintf(out, "title:\t%s\n", pr.Title)
	fmt.Fprintf(out, "state:\t%s\n", prStateWithDraft(pr))
	fmt.Fprintf(out, "author:\t%s\n", pr.Author.DisplayName())
	fmt.Fprintf(out, "labels:\t%s\n", labels)
	fmt.Fprintf(out, "assignees:\t%s\n", assignees)
	fmt.Fprintf(out, "reviewers:\t%s\n", reviewers)
	fmt.Fprintf(out, "projects:\t%s\n", projects)
	var milestoneTitle string
	if pr.Milestone != nil {
		milestoneTitle = pr.Milestone.Title
	}
	fmt.Fprintf(out, "milestone:\t%s\n", milestoneTitle)
	fmt.Fprintf(out, "number:\t%d\n", pr.Number)
	fmt.Fprintf(out, "url:\t%s\n", pr.URL)
	fmt.Fprintf(out, "additions:\t%s\n", cs.Green(strconv.Itoa(pr.Additions)))
	fmt.Fprintf(out, "deletions:\t%s\n", cs.Red(strconv.Itoa(pr.Deletions)))
	var autoMerge string
	if pr.AutoMergeRequest == nil {
		autoMerge = "disabled"
	} else {
		autoMerge = fmt.Sprintf("enabled\t%s\t%s",
			pr.AutoMergeRequest.EnabledBy.Login,
			strings.ToLower(pr.AutoMergeRequest.MergeMethod))
	}
	fmt.Fprintf(out, "auto-merge:\t%s\n", autoMerge)

	fmt.Fprintln(out, "--")
	fmt.Fprintln(out, pr.Body)
```

**File:** pkg/cmd/pr/view/view.go (L182-187)
```go
func printHumanPrPreview(opts *ViewOptions, baseRepo ghrepo.Interface, pr *api.PullRequest) error {
	out := opts.IO.Out
	cs := opts.IO.ColorScheme()

	// Header (Title and State)
	fmt.Fprintf(out, "%s %s#%d\n", cs.Bold(pr.Title), ghrepo.FullName(baseRepo), pr.Number)
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

**File:** acceptance/testdata/workflow/run-view-log-escape-sequences.txtar (L40-70)
```text
# View the logs and check that raw ESC bytes (0x1b) are NOT present in output.
# If this assertion fails, it means terminal escape sequences from the workflow
# log are being passed through to the user's terminal unsanitised.
exec gh run view $RUN_ID --log

# The output should contain the safe/visible text but not raw ESC bytes.
# \x1b is the ESC byte - it must not appear in the output.
! stdout '\x1b'

# The log output should still contain the non-escape parts of the log lines.
stdout 'ESCAPE_MARKER_START'
stdout 'ESCAPE_MARKER_END'

-- workflow.yml --
name: Escape Sequence PoC

on:
  workflow_dispatch:

jobs:
  emit-escape-sequences:
    runs-on: ubuntu-latest
    steps:
      - name: Emit terminal escape sequences
        run: |
          # OSC title set: \x1b]0;TITLE\x07
          printf 'ESCAPE_MARKER_START \033]0;HIJACKED_TITLE\007 ESCAPE_MARKER_END\n'
          # CSI color: \x1b[31m ... \x1b[0m
          printf 'ESCAPE_MARKER_START \033[31mRED_TEXT\033[0m ESCAPE_MARKER_END\n'
          # Screen title set (from original PoC): \x1bk ... \x1b\\
          printf 'ESCAPE_MARKER_START \033k;malicious command;\033\\ ESCAPE_MARKER_END\n'
```
