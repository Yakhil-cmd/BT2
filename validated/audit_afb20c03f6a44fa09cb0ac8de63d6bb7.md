### Title
Unsanitized PR title/body written to raw preview output allows terminal escape sequence injection - (File: pkg/cmd/pr/view/view.go)

### Summary
`printRawPrPreview` writes `pr.Title` and `pr.Body` directly to `io.Out` via `fmt.Fprintf`/`fmt.Fprintln` without passing through any escape-sequence sanitization, unlike other content paths in this codebase (`iostreams.Untrusted`, `ContentOut`, `asciisanitizer`) that explicitly guard attacker-controlled text before it reaches a terminal.

### Finding Description
`viewRun` calls `printRawPrPreview(opts.IO, pr)` when stdout is not a TTY [1](#0-0) . Inside `printRawPrPreview`, `pr.Title` is printed with `fmt.Fprintf(out, "title:\t%s\n", pr.Title)` and `pr.Body` is printed with `fmt.Fprintln(out, pr.Body)`, both writing straight to `io.Out` (the raw `iostreams.IOStreams.Out` writer), not `io.ContentOut` [2](#0-1) .

The codebase has an established pattern for handling attacker-controlled text before it reaches a terminal: the `iostreams.Untrusted` type sanitizes via `asciisanitizer.Sanitizer` on every `String()`/`fmt` path [3](#0-2) , and `IOStreams.ContentOut` wraps the underlying writer with the same sanitizer when `sanitizeContent` is enabled [4](#0-3) . Other raw/pipe-friendly display paths such as `gist view --raw` and `pr diff` explicitly route attacker content through `ContentOut` or explicit `ContainsEscapeSequence` checks before printing [5](#0-4) [6](#0-5) .

`printRawPrPreview`, however, bypasses all of this: `pr.Title` and `pr.Body` are plain `string` fields populated straight from the GraphQL API response (as seen in the plain `string`-typed fields in `api/queries_pr.go`), and are written with vanilla `fmt.Fprintf`/`fmt.Fprintln` to `io.Out` directly — never wrapped in `Untrusted`, never checked with `iostreams.ContainsEscapeSequence`, and never routed through `ContentOut`. Any control/escape sequence (CSI, OSC, DCS) an attacker embeds in a PR title or body reaches the terminal verbatim when a maintainer runs `gh pr view <number>` with stdout piped or redirected (the non-TTY branch), which is a common workflow (e.g. `gh pr view N | less`, capturing output in scripts, or terminals that still interpret escapes even when "piped" through certain pagers/terminal multiplexers).

### Impact Explanation
An attacker who opens a PR/issue with a title or body containing OSC/CSI/DCS payloads can manipulate the victim's terminal when the victim runs `gh pr view` in non-interactive/piped mode — e.g., spoofing prompts, rewriting terminal titles, or (on vulnerable terminal emulators) triggering command injection via terminal escape abuse (e.g., OSC 52 clipboard write, DCS-based command execution in legacy terminals). This matches the "Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation" impact class described in the question.

### Likelihood Explanation
Trivial precondition: attacker only needs to open an issue/PR on any repo the victim later inspects with `gh pr view`, no special privileges required. Exploitability depends on the victim's terminal/pager honoring the raw bytes (many terminals process escape sequences even through pipes/pagers), so real-world impact varies with the victim's environment, but the code path itself performs no sanitization at all, unlike sibling display paths in the same codebase.

### Recommendation
Wrap `pr.Title` and `pr.Body` (and any other externally-authored PR fields printed in `printRawPrPreview`) in `iostreams.Untrusted` before printing, or route the writes through `io.ContentOut` with sanitization enabled, consistent with the pattern already used in `gist view` and `pr diff`. Alternatively, apply `iostreams.ContainsEscapeSequence` and refuse/strip escapes before writing raw output.

### Proof of Concept
```go
func TestPrintRawPrPreview_SanitizesControlSequences(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    pr := &api.PullRequest{
        Title: "evil\x1b]0;HIJACKED\x07title",
        Body:  "body\x1bk;rm -rf ~;\x1b\\ end",
        // ... minimal required fields
    }
    err := printRawPrPreview(ios, pr)
    require.NoError(t, err)
    assert.NotContains(t, out.String(), "\x1b",
        "raw PR preview should not leak raw ESC bytes to a non-TTY stdout")
}
```
This test currently fails because `printRawPrPreview` prints `pr.Title` and `pr.Body` unsanitized to `io.Out`, whereas the analogous test `Test_sanitizedReader` for `pr diff` and `TestUntrusted_String_sanitizes` for the `Untrusted` type confirm the expected sanitized behavior elsewhere in the codebase [7](#0-6) [8](#0-7) .

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

**File:** pkg/cmd/pr/diff/diff.go (L196-207)
```go
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

**File:** pkg/cmd/pr/diff/diff_test.go (L638-646)
```go
func Test_sanitizedReader(t *testing.T) {
	input := strings.NewReader("\t hello \x1B[m world! ăѣ𝔠ծề\r\n")
	expected := "\t hello ^[[m world! ăѣ𝔠ծề\r\n"

	err := iotest.TestReader(sanitizedReader(input), []byte(expected))
	if err != nil {
		t.Error(err)
	}
}
```

**File:** pkg/iostreams/untrusted_test.go (L14-17)
```go
func TestUntrusted_String_sanitizes(t *testing.T) {
	u := NewUntrusted("hello" + esc + "[31mRED" + esc + "[0m")
	assert.NotContains(t, u.String(), esc)
}
```
