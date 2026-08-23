### Title
Unsanitized attacker-controlled skill file paths passed to interactive `Select` prompt permit terminal/menu spoofing - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`renderInteractive` builds the `choices` slice by directly appending `f.Path` from `discovery.SkillFile` (sourced from the GitHub git tree API for an attacker-controlled repository) without any sanitization, then passes it straight into `opts.Prompter.Select`. Similar untrusted path values elsewhere in the same skills feature (`pkg/cmd/skills/list/list.go`) are explicitly passed through `sanitizeForTerminal` before display, showing the codebase already recognizes this class of file-path is untrusted and needs sanitization, but that treatment is missing here.

### Finding Description
The call chain is `previewRun` → `renderInteractive` → `opts.Prompter.Select("...", "", choices)`.
`files, err = discovery.ListSkillFiles(...)` returns `[]discovery.SkillFile` whose `Path` field is taken verbatim from the GitHub git tree API response for the attacker's repo/ref. [1](#0-0) 
In `renderInteractive`, extra file paths are appended unmodified to `choices`: [2](#0-1) 
No newline/control-character/ANSI stripping is applied to `f.Path` before it becomes a `huh.Option` label rendered by the underlying `charm.land/huh/v2` select widget: [3](#0-2) 

By contrast, the sibling `skills list` command explicitly treats similarly-sourced skill path values (`github-path`, `local-path` from frontmatter) as untrusted and neutralizes control characters via `sanitizeForTerminal` before printing: [4](#0-3) 
That defense is absent for `renderInteractive`'s `choices` list, so a repository containing a file whose git-tree path embeds a newline, carriage return, or ANSI/CSI escape sequence would have that raw content handed to the terminal-rendering prompt library.

### Impact Explanation
This would fall under output/terminal-injection-style spoofing (misleading UI text, not code execution) — matching a low-severity "spoofing / UI redress" class rather than credential theft or code execution. Concretely it could let a malicious repo owner display a bogus/deceptive extra menu entry or otherwise garble the file-picker so a victim misreads which file they are viewing/selecting when running `gh skill preview`.

However, this claim could not be conclusively validated within the available context:
- I was not able to confirm the actual terminal rendering behavior of the `charm.land/huh/v2` library (a Bubble Tea/Lip Gloss based TUI framework) for option labels containing embedded newlines or ANSI escapes. TUI frameworks in this family generally render each option within a styled, bounded row and often strip or visually contain embedded control sequences/newlines rather than naively echoing them to the raw terminal like a simple `fmt.Printf` would, which is a materially different (and typically much safer) rendering path than a naive prompt built from string concatenation.
- No test in the repo (including `preview_test.go`, `huh_prompter_test.go`) exercises a crafted `f.Path` containing `\n` or ANSI sequences to demonstrate the resulting rendered output actually reproduces a forged "[2] Install now"-style entry.
- I could not verify whether `huh`/Bubble Tea itself already sanitizes/escapes such input at the rendering layer (which would fully mitigate this even without CLI-side sanitization).

### Likelihood Explanation
Preconditions are attacker-controlled and unprivileged: publishing a public repo with a skill directory containing a file whose name/path embeds a newline or ANSI sequence, then having a victim run `gh skill preview owner/repo` interactively. This is easy to construct as a git tree entry path. Feasibility of causing a *convincing* forged menu, however, depends entirely on the unverified rendering behavior of the `huh` TUI library, which is the key unresolved uncertainty.

### Recommendation
Apply the same untrusted-path sanitization used in `pkg/cmd/skills/list/list.go` (`sanitizeForTerminal` / `asciisanitizer`) to `f.Path` before appending it to `choices` in `renderInteractive`, and also to the `renderFileTree` display path, for defense-in-depth consistency across the skills feature regardless of the underlying prompt library's own protections.

### Proof of Concept
Not fully reproducible with current evidence. A conclusive PoC would require:
1. A unit test in `pkg/cmd/skills/preview/preview_test.go` that stubs a git tree response with an extra file `{"path": "scripts/x\n[2] Install now", ...}` (paralleling the existing `TestPreviewRun_ShowsFileTree` interactive-picker test at `pkg/cmd/skills/preview/preview_test.go:577-618`), capturing the `options` slice passed into `prompter.PrompterMock.SelectFunc` and asserting it still contains the raw `\n`/ANSI bytes (proving no sanitization occurs at the `gh` layer).
2. Separately, an inspection or test of `charm.land/huh/v2`'s actual terminal output for such an option label, to determine whether the TUI framework itself neutralizes the embedded control characters — this second part is required to establish exploitable end-user impact and was not verifiable within this review.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L197-205)
```go
	opts.IO.StartProgressIndicatorWithLabel("Fetching skill content")
	var files []discovery.SkillFile
	if skill.TreeSHA != "" {
		files, err = discovery.ListSkillFiles(apiClient, hostname, owner, repoName, skill.TreeSHA)
		if err != nil {
			fmt.Fprintf(opts.IO.ErrOut, "warning: could not list skill files: %v\n", err)
			files = nil
		}
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L327-344)
```go
	// Build choices: SKILL.md first, then extra files
	choices := make([]string, 0, len(extraFiles)+1)
	choices = append(choices, "SKILL.md")
	for _, f := range extraFiles {
		choices = append(choices, f.Path)
	}

	// Save original stdout. StopPager closes IO.Out, so we need to
	// restore a working writer before each StartPager call.
	originalOut := opts.IO.Out

	for {
		// Restore original Out before each pager cycle. StartPager replaces
		// IO.Out with a pipe; StopPager closes that pipe but does not
		// restore the original. The original writer remains valid.
		opts.IO.Out = originalOut

		idx, err := opts.Prompter.Select("View a file (Esc to exit):", "", choices)
```

**File:** internal/prompter/huh_prompter.go (L41-65)
```go
func (p *huhPrompter) buildSelectForm(prompt, defaultValue string, options []string) (*huh.Form, *int) {
	var result int

	if !slices.Contains(options, defaultValue) {
		defaultValue = ""
	}

	formOptions := make([]huh.Option[int], len(options))
	for i, o := range options {
		if defaultValue == o {
			result = i
		}
		formOptions[i] = huh.NewOption(o, i)
	}

	form := p.newForm(
		huh.NewGroup(
			huh.NewSelect[int]().
				Title(prompt).
				Value(&result).
				Options(formOptions...),
		),
	)
	return form, &result
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
