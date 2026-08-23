### Title
Unsanitized attacker-controlled file paths passed to interactive file-picker prompt - (File: pkg/cmd/skills/preview/preview.go)

### Finding Description
`renderInteractive` builds the `choices` slice directly from `extraFiles[i].Path`, which originates from `discovery.ListSkillFiles`/the GitHub Git Trees API and reflects raw file paths in the attacker's published repository [1](#0-0) . Those strings are passed unmodified into `opts.Prompter.Select("View a file (Esc to exit):", "", choices)` [2](#0-1) . Unlike other places in this codebase that explicitly sanitize attacker-controlled/frontmatter text before it reaches the terminal — e.g. `sanitizeForTerminal` in `pkg/cmd/skills/list/list.go` [3](#0-2)  and the `iostreams.Untrusted` wrapper that neutralizes ANSI escapes for any fmt-printed untrusted content [4](#0-3)  — no such sanitization is applied to `f.Path` before it is placed in `choices` here. Git allows filenames to contain arbitrary bytes other than `/` and NUL, including control characters, ANSI escape sequences, and OSC 8 hyperlink sequences, so an attacker publishing a skill repo can name a file to embed such sequences.

The underlying prompt implementations are `survey` (`internal/prompter/prompter.go`, `surveyPrompter.Select`) or `huh` (`internal/prompter/huh_prompter.go`, `huhPrompter.Select`/`accessiblePrompter.Select`) [5](#0-4) [6](#0-5) . These libraries render option labels as terminal text; embedded escape sequences (e.g., OSC 8 hyperlinks, cursor-movement, or newline sequences) are not stripped by `preview.go` or by the prompter wrappers before being handed to the underlying list-rendering widgets.

### Impact Explanation
This falls under output/terminal safety rather than direct code execution: a malicious file name can visually spoof menu entries (e.g., inject a fake extra "menu item" via a newline, or use OSC 8 to make the entry render as different clickable/misleading text), potentially tricking the user into selecting or trusting unintended content in the file picker. There is no arbitrary file read/write, credential exfiltration, or code execution demonstrated — the impact is confined to a terminal-rendering/prompt-forgery/spoofing effect on the local victim terminal, and only affects the interactive preview session initiated by the victim against attacker-controlled content.

### Likelihood Explanation
The precondition is straightforward and fully attacker-controlled: publish a public repo containing a valid `SKILL.md` plus at least one extra file whose git path embeds control/escape sequences, and have the victim run `gh skill preview <attacker-repo>` interactively (a normal, expected usage pattern for this feature). No special privileges are required beyond publishing a repository, matching the assumed attacker model.

### Recommendation
Sanitize `f.Path` (and any other attacker-controlled string surfaced in `choices`, the file tree rendering, and pager headers such as `"── "+f.Path+" ──"`) using the same mechanism already used elsewhere in the codebase — e.g., wrap it in `iostreams.NewUntrusted(...)` before formatting, or run it through the existing `asciisanitizer`-based sanitizer (as in `sanitizeForTerminal` in `pkg/cmd/skills/list/list.go`) — before adding it to `choices` in `renderInteractive`, and before using it in `renderFileTree`/`renderAllFiles` file headers.

### Proof of Concept
Go test sketch:
```go
func TestRenderInteractive_SanitizesFilePathsInChoices(t *testing.T) {
    malicious := "safe.txt\n\x1b]8;;http://evil\x07EVIL-ENTRY\x1b]8;;\x07"
    extraFiles := []discovery.SkillFile{{Path: malicious, SHA: "abc"}}

    var capturedChoices []string
    mockPrompter := &prompter.PrompterMock{
        SelectFunc: func(prompt, def string, choices []string) (int, error) {
            capturedChoices = choices
            return 0, errors.New("esc") // exit immediately
        },
    }
    opts := &PreviewOptions{IO: iostreams.Test(), Prompter: mockPrompter}

    renderInteractive(opts, opts.IO.ColorScheme(), discovery.Skill{}, nil, "rendered", extraFiles, nil, "", "", "")

    for _, c := range capturedChoices {
        require.NotContains(t, c, "\x1b]8;")
        require.NotContains(t, c, "\n")
    }
}
```
Expected (current, failing) result: `capturedChoices[1]` contains the raw `\n` and OSC 8 escape sequence unmodified, confirming the unsanitized pass-through into the prompter's `choices` argument.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L327-332)
```go
	// Build choices: SKILL.md first, then extra files
	choices := make([]string, 0, len(extraFiles)+1)
	choices = append(choices, "SKILL.md")
	for _, f := range extraFiles {
		choices = append(choices, f.Path)
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L344-344)
```go
		idx, err := opts.Prompter.Select("View a file (Esc to exit):", "", choices)
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

**File:** internal/prompter/prompter.go (L353-355)
```go
func (p *surveyPrompter) Select(prompt, defaultValue string, options []string) (int, error) {
	return p.prompter.Select(prompt, defaultValue, options)
}
```

**File:** internal/prompter/huh_prompter.go (L67-71)
```go
func (p *huhPrompter) Select(prompt, defaultValue string, options []string) (int, error) {
	form, result := p.buildSelectForm(prompt, defaultValue, options)
	err := p.runForm(form)
	return *result, err
}
```
