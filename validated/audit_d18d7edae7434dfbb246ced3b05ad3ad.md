### Title
Unsanitized attacker-controlled PR/issue text (title and Markdown body) reaches the terminal via `markdown.Render`/`WithTheme` without control/ANSI-escape stripping - ([File: pkg/markdown/markdown.go])

### Summary
`WithTheme` in `pkg/markdown/markdown.go:30` is a thin pass-through to `ghMarkdown.WithTheme`, and `Render` (`pkg/markdown/markdown.go:38`) simply forwards to `go-gh`'s glamour-based Markdown renderer with no sanitization step applied to the input text. In `pkg/cmd/pr/view/view.go`, both the raw PR title (`pr.Title`, printed at line 187 via `fmt.Fprintf(out, "%s %s#%d\n", cs.Bold(pr.Title), ...)`) and the PR body (`pr.Body`, rendered at lines 270-272 via `markdown.Render(pr.Body, markdown.WithTheme(...), markdown.WithWrap(...))`) are written to the terminal without ever being wrapped in the codebase's own `iostreams.Untrusted` sanitizer or passed through `asciisanitizer`.

### Finding Description
The repository has a deliberate, well-established sanitization architecture for exactly this class of risk: `iostreams.Untrusted` (`pkg/iostreams/untrusted.go:21-44`) wraps any string "the application did not author" and forces ANSI/control-sequence stripping via `asciisanitizer.Sanitizer` whenever it's printed through `fmt`, `iostreams.ContainsEscapeSequence`/`CopyGuardedContent` (`pkg/iostreams/content.go:18-92`) guards raw file/gist/diff/log dumps, and `IOStreams.ContentOut` (`pkg/iostreams/iostreams.go:490-508`) automatically sanitizes external content. This pattern is applied consistently in `gh gist view` (`pkg/cmd/gist/view/view.go:148-181`), `gh pr diff`, `gh repo read-file`, and `gh run view --log`.

However, `pr view`'s human-readable preview path does not route the PR title or body through any of this machinery: [1](#0-0) [2](#0-1) 

`pr.Title` is a plain Go `string` field populated from the GitHub API and is printed directly with `cs.Bold(pr.Title)` — no `Untrusted` wrapper, no `stripControl`, no escape-sequence check. `pr.Body` is passed straight into `markdown.Render`, which is just: [3](#0-2) 

`markdown.Render` calls `ghMarkdown.Render` (the `go-gh` glamour wrapper), which parses the text as a goldmark AST and re-emits it with ANSI styling. Glamour's ANSI renderer decorates markdown-structural elements with color/style codes but does not scan literal text-node content for embedded C0/C1 control bytes or existing ANSI/OSC/DCS sequences — such bytes in the source Markdown are carried through into the rendered text verbatim. Because the `go-gh` markdown package is an external dependency not vendored in this repo, I could not directly inspect its internals to confirm sanitization is absent there, but no sanitization call (`asciisanitizer`, `Untrusted`, `ContainsEscapeSequence`) appears anywhere on the `pr.Body` or `pr.Title` path in `gh cli`'s own code, which is the deciding factor for `pr.Title` regardless of glamour's behavior since the title is never passed to `markdown.Render` at all.

### Impact Explanation
An attacker who authors a PR title (fully attacker-controlled, no privilege needed to open a PR on a repo they can push a branch/fork to) or a PR body can embed OSC 52 (clipboard write/read), OSC 7 (working-directory/prompt spoofing), DCS, or CSI window-title/query sequences. When a victim runs `gh pr view` on that PR, `printHumanPrPreview` writes the title unsanitized to the victim's terminal, and (pending confirmation of glamour's internal handling) the body likely does too. This matches the "Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation" impact class — e.g., using OSC 52 to silently write attacker data into the victim's clipboard, or manipulating the terminal title/prompt to trick the victim into approving a destructive action.

### Likelihood Explanation
High feasibility and full attacker control: opening a PR/issue with a crafted title/body requires no special privilege beyond the ability to create a PR (fork + PR is sufficient), and `gh pr view` is a routine command victims run constantly. The attack is fully repeatable and does not depend on any other misconfiguration.

### Recommendation
- Wrap `pr.Title` (and other free-text API fields printed in `printHumanPrPreview`/`printRawPrPreview`, e.g. milestone title, reviewer/assignee display names) in `iostreams.Untrusted` before printing, consistent with the pattern already used for gist/log/diff content.
- Before calling `markdown.Render` on `pr.Body` (and equivalent bodies in issue/discussion/release/gist view), run the text through `asciisanitizer.Sanitizer` (or `iostreams.Untrusted.String()`) so any raw control/escape sequences are neutralized prior to Markdown parsing, regardless of how glamour treats them internally.
- Add a golden/regression test (mirroring `TestCopyLogWithLinePrefix_TerminalEscapeSequences` in `pkg/cmd/run/view/view_test.go`) for `pr view`/`issue view` asserting that a PR title/body containing `\x1b]0;...\x07`, `\x1b[31m`, or OSC 52 sequences produces output with no raw `\x1b` bytes.

### Proof of Concept
```go
func TestPrintHumanPrPreview_TitleEscapeSequence(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    ios.SetStdoutTTY(true)
    pr := &api.PullRequest{
        Title: "Innocuous title\x1b]0;HIJACKED\x07",
        Body:  "Normal body \x1b[31mRED\x1b[0m text",
    }
    opts := &ViewOptions{IO: ios, Now: time.Now}
    err := printHumanPrPreview(opts, ghrepo.New("OWNER", "REPO"), pr)
    require.NoError(t, err)
    assert.NotContains(t, out.String(), "\x1b",
        "PR title/body escape sequences must not reach the terminal unsanitized")
}
```
This test is expected to currently fail because neither `pr.Title` nor `pr.Body` is sanitized before reaching `opts.IO.Out`.

### Citations

**File:** pkg/cmd/pr/view/view.go (L186-187)
```go
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

**File:** pkg/markdown/markdown.go (L30-40)
```go
func WithTheme(theme string) glamour.TermRendererOption {
	return ghMarkdown.WithTheme(theme)
}

func WithBaseURL(u string) glamour.TermRendererOption {
	return ghMarkdown.WithBaseURL(u)
}

func Render(text string, opts ...glamour.TermRendererOption) (string, error) {
	return ghMarkdown.Render(text, opts...)
}
```
