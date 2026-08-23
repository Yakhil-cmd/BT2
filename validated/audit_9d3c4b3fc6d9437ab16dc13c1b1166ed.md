### Title
Terminal escape sequence injection in `gh skill preview` via unsanitized SKILL.md/extra-file content - ([File: pkg/cmd/skills/preview/preview.go])

### Finding Description
`renderMarkdownPreview` (pkg/cmd/skills/preview/preview.go:392-409) passes attacker-controlled `SKILL.md` content straight into `markdown.Render` (which wraps `github.com/cli/go-gh/v2/pkg/markdown` / `glamour`), and returns the resulting string unmodified [1](#0-0) . That string is then written verbatim to the victim's terminal with `fmt.Fprint(out, rendered)` in `renderAllFiles` and `renderInteractive` [2](#0-1) [3](#0-2) . Neither `markdown.Render` nor the surrounding code calls any escape-sequence stripping routine before the write.

Non-markdown extra files fare worse: the fetched blob content is assigned to a variable literally named `sanitized` but no sanitization function is ever invoked on it — it is just `fileContent.String()` — before being written with `fmt.Fprint(out, sanitized)` [4](#0-3) . The misleading variable name suggests sanitization was intended but not implemented for this path.

The codebase already has a dedicated mechanism for handling untrusted terminal output — `pkg/iostreams/untrusted.go` — which other commands that render attacker-controlled repository content (`pkg/cmd/gist/view/view.go`, `pkg/cmd/pr/diff/diff.go`, `pkg/cmd/run/view/logs.go`, `pkg/cmd/repo/read-file/read_file.go`) reference. `pkg/cmd/skills/preview/preview.go` does not call into that sanitization path for either the `SKILL.md` markdown render or the raw "extra file" content, so both attacker inputs (a malicious `SKILL.md` fetched via `discovery.FetchBlob`, and any non-`SKILL.md` file in the skill's tree) reach the terminal with raw ANSI/OSC sequences intact.

An attacker who publishes a public repo/skill can embed sequences such as OSC 8 hyperlinks with deceptive/hidden targets, cursor-repositioning or screen-clearing codes to overwrite/hide prior pager output, or OSC window-title/clipboard manipulation sequences, all of which execute in the victim's terminal emulator when they run `gh skill preview owner/repo skill-name`.

### Impact Explanation
This falls under terminal escape sequence injection / spoofing impact — it does not grant code execution on the host, but it can be used to: hide malicious OSC 8 hyperlink targets behind benign-looking anchor text (phishing via the pager), manipulate terminal title/clipboard (e.g., OSC 52 to write attacker text to the victim's clipboard if the terminal supports it), or corrupt the victim's visible terminal state to hide or forge portions of the rendered preview. This maps to a low/moderate "spoofing"-class impact rather than RCE or credential theft, since no file write outside intended path, no auth bypass, and no direct credential exfiltration path was found.

### Likelihood Explanation
High feasibility and full attacker control: any unprivileged GitHub user can publish a public repo containing a `SKILL.md` or arbitrary extra file with raw escape bytes, and the victim simply needs to run `gh skill preview <that-repo>` — a documented, intended use case of the feature. No authentication, no social engineering beyond normal skill discovery, and it is fully repeatable.

### Recommendation
Route both the `markdown.Render` output in `renderMarkdownPreview` and the raw extra-file content in `renderAllFiles`/`renderInteractive` through the existing untrusted-content sanitization helpers in `pkg/iostreams/untrusted.go` (or equivalent ANSI/OSC-stripping logic already used by `gist/view`, `pr/diff`, `run/view/logs`, and `repo/read-file`) before writing to `opts.IO.Out`. Actually implement sanitization for the variable currently named `sanitized` at preview.go:307 rather than passing it through unchanged.

### Proof of Concept
```go
func TestRenderMarkdownPreview_StripsANSIEscape(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    malicious := "Click [here](x)\n\n\x1b]8;;file:///etc/passwd\x07malicious\x1b]8;;\x07\n"
    rendered := renderMarkdownPreview(ios, "SKILL.md", malicious)

    if strings.Contains(rendered, "\x1b]8;;file:///etc/passwd") {
        t.Fatalf("expected OSC 8 escape sequence to be stripped/escaped, got: %q", rendered)
    }
    fmt.Fprint(out, rendered)
    if strings.Contains(out.String(), "\x1b]8;") {
        t.Fatalf("raw OSC 8 sequence reached opts.IO.Out unsanitized")
    }
}
```
Expected (failing) result today: the raw `\x1b]8;;file:///etc/passwd\x07` sequence passes through unchanged in `rendered` and in `out.String()`, demonstrating the missing output-safety invariant.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L285-286)
```go
	fmt.Fprintf(out, "%s\n\n", cs.Bold("── SKILL.md ──"))
	fmt.Fprint(out, rendered)
```

**File:** pkg/cmd/skills/preview/preview.go (L307-313)
```go
		sanitized := fileContent.String()
		totalBytes += len(sanitized)
		fmt.Fprintf(out, "\n%s\n\n", cs.Bold("── "+f.Path+" ──"))
		fmt.Fprint(out, sanitized)
		if !strings.HasSuffix(sanitized, "\n") {
			fmt.Fprintln(out)
		}
```

**File:** pkg/cmd/skills/preview/preview.go (L368-372)
```go
		if err := opts.IO.StartPager(); err != nil {
			fmt.Fprintf(opts.IO.ErrOut, "starting pager failed: %v\n", err)
		}
		fmt.Fprint(opts.IO.Out, content)
		opts.IO.StopPager()
```

**File:** pkg/cmd/skills/preview/preview.go (L392-409)
```go
func renderMarkdownPreview(io *iostreams.IOStreams, filePath, content string) string {
	if filePath == "SKILL.md" {
		parsed, err := frontmatter.Parse(content)
		if err == nil {
			content = parsed.Body
		}
	}

	rendered, err := markdown.Render(content,
		markdown.WithTheme(io.TerminalTheme()),
		markdown.WithWrap(io.TerminalWidth()),
		markdown.WithoutIndentation())
	if err != nil {
		return content
	}

	return rendered
}
```
