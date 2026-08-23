### Title
Raw ANSI/terminal escape sequences in skill files are written directly to the terminal without sanitization - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`renderAllFiles` in `pkg/cmd/skills/preview/preview.go` fetches every non-`SKILL.md` file belonging to an attacker-published skill and writes its raw bytes straight to `opts.IO.Out` with no escape-sequence stripping, despite the local variable being misleadingly named `sanitized`. The Markdown path for `SKILL.md` is not much better: `renderMarkdownPreview` pipes content through `markdown.Render` (a thin wrapper around `github.com/cli/go-gh/v2/pkg/markdown` / `glamour`), and neither `pkg/markdown/markdown.go` nor `renderAllFiles`/`renderInteractive` perform any post-render ANSI/OSC allowlisting before the bytes reach the terminal.

### Finding Description
`renderAllFiles` ( [1](#0-0) ) is reached from `previewRun` whenever the command is non-interactive or the skill has only one file ( [2](#0-1) ). It iterates `extraFiles`, fetches each blob with `discovery.FetchBlob`, assigns it to a variable named `sanitized`, and immediately writes it verbatim to stdout: [3](#0-2) 

There is no call to any sanitizer, ANSI stripper, or escape-sequence filter anywhere in this function or in `pkg/markdown/markdown.go` ( [4](#0-3) ) — `Render` simply delegates to `ghMarkdown.Render`/glamour and returns whatever bytes come out, which are then `fmt.Fprint`'d directly ( [5](#0-4) ). The same unsanitized-passthrough pattern exists in the interactive picker path, `renderInteractive`, where selected non-markdown file content is written raw to the pager ( [6](#0-5) ).

Because `extraFiles` and `SKILL.md` content originate entirely from the attacker-controlled repository (`discovery.FetchBlob` over attacker's tree/blob SHAs) ( [7](#0-6) ), any bytes an attacker places in a published skill archive — including raw ANSI CSI sequences, OSC 8 hyperlink escapes, or terminal title/clipboard escapes embedded in a script file, a code fence, or reference-link target — flow unmodified to the victim's terminal emulator when they run `gh skills preview`. Terminal emulators that support these controls will interpret them (e.g., rendering a fake hyperlink whose displayed text differs from its underlying URI, repainting the screen, or injecting a spoofed prompt), independent of what `glamour` does with Markdown syntax itself.

### Impact Explanation
This matches "Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation." An attacker who publishes a skill repository can craft a non-markdown extra file (or content inside a code fence in `SKILL.md`, which is preserved literally by Markdown renderers) containing OSC 8 (`\x1b]8;;URL\x07TEXT\x1b]8;;\x07`) or other escape sequences to display misleading link text, overwrite prior terminal content, or fake a `y/N` confirmation prompt that tricks the victim into typing sensitive input or approving a destructive action in a follow-up command.

### Likelihood Explanation
The attacker only needs to publish a public repository (or fork/branch) containing a `skills/...` directory with a crafted extra file or `SKILL.md`, and get a victim to run `gh skills preview owner/repo skill-name`, which is the intended/normal usage of this feature. No elevated privileges, tokens, or social engineering beyond "get victim to preview your public skill" are required, making this highly feasible and repeatable.

### Recommendation
Before writing any fetched blob (both `SKILL.md`/extra-file raw content and the final rendered Markdown output) to `opts.IO.Out`, strip or neutralize non-display-affecting terminal escape sequences (e.g., using an ANSI/OSC allowlist limited to the color/style codes glamour itself emits, or a dedicated sanitizer such as stripping `\x1b]`, `\x1b[` sequences not produced by the renderer) at the single point where bytes leave the process, so extraFiles content and SKILL.md code-fence/autolink content cannot inject arbitrary terminal control sequences.

### Proof of Concept
Golden-test plan (Go):
1. Stub `discovery.FetchBlob` (via httpmock/git-stub) to return, for one `extraFiles` entry, content containing a raw OSC 8 escape sequence, e.g. `"\x1b]8;;https://evil.example\x07https://github.com/legit\x1b]8;;\x07\n"`.
2. Call `renderAllFiles` with an `iostreams.IOStreams` backed by a `bytes.Buffer` for `Out`.
3. Assert that the raw escape bytes (`\x1b]8;;`) are present unmodified in the buffer — demonstrating no sanitization occurs (expected assertion for a fixed version: the escape bytes should be stripped/escaped, e.g. rendered as literal `^[]8;;` or removed entirely).
4. Repeat with `SKILL.md` content containing a fenced code block with the same escape sequence, verifying `markdown.Render` output also retains the raw bytes end-to-end through `renderAllFiles`.

Note: I could not verify the internal behavior of the vendored `glamour`/`github.com/cli/go-gh/v2/pkg/markdown` renderer regarding escape-sequence handling from within this index (its source is outside this repo and not indexed here), so the Markdown-fence sub-claim is based on the absence of any local sanitization call in `pkg/markdown/markdown.go`; the extra-file raw-passthrough finding at lines 301-313, however, is directly confirmed in this repository's source.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L196-220)
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
	content, err := discovery.FetchBlob(apiClient, hostname, owner, repoName, skill.BlobSHA)
	opts.IO.StopProgressIndicator()
	if err != nil {
		return err
	}

	rendered := opts.renderFile("SKILL.md", content.String())

	// Collect extra files (everything that isn't SKILL.md)
	var extraFiles []discovery.SkillFile
	for _, f := range files {
		if f.Path != "SKILL.md" {
			extraFiles = append(extraFiles, f)
		}
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L224-230)
```go
	// Non-interactive or skill has only SKILL.md: dump through pager
	if !canPrompt || len(extraFiles) == 0 {
		renderAllFiles(opts, cs, skill, files, rendered, extraFiles, apiClient, hostname, owner, repoName)
	} else {
		// Interactive with multiple files: show tree, then file picker
		renderInteractive(opts, cs, skill, files, rendered, extraFiles, apiClient, hostname, owner, repoName)
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L266-269)
```go
// renderAllFiles dumps the tree, SKILL.md, and all extra files through the pager.
func renderAllFiles(opts *PreviewOptions, cs *iostreams.ColorScheme, skill discovery.Skill,
	files []discovery.SkillFile, rendered string, extraFiles []discovery.SkillFile,
	apiClient *api.Client, hostname, owner, repo string) {
```

**File:** pkg/cmd/skills/preview/preview.go (L285-286)
```go
	fmt.Fprintf(out, "%s\n\n", cs.Bold("── SKILL.md ──"))
	fmt.Fprint(out, rendered)
```

**File:** pkg/cmd/skills/preview/preview.go (L301-313)
```go
		fileContent, fetchErr := discovery.FetchBlob(apiClient, hostname, owner, repo, f.SHA)
		if fetchErr != nil {
			fmt.Fprintf(out, "\n%s\n\n%s\n", cs.Bold("── "+f.Path+" ──"), cs.Muted("(could not fetch file)"))
			continue
		}
		fetched++
		sanitized := fileContent.String()
		totalBytes += len(sanitized)
		fmt.Fprintf(out, "\n%s\n\n", cs.Bold("── "+f.Path+" ──"))
		fmt.Fprint(out, sanitized)
		if !strings.HasSuffix(sanitized, "\n") {
			fmt.Fprintln(out)
		}
```

**File:** pkg/cmd/skills/preview/preview.go (L349-371)
```go
		var content string

		if idx == 0 {
			content = renderedSkillMD
		} else {
			selectedFile := extraFiles[idx-1]

			// Fetch on demand; don't hold blob data in memory
			fileContent, fetchErr := discovery.FetchBlob(apiClient, hostname, owner, repo, selectedFile.SHA)
			if fetchErr != nil {
				fmt.Fprintf(opts.IO.ErrOut, "%s could not fetch %s: %v\n", cs.Red("!"), selectedFile.Path, fetchErr)
				continue
			}
			content = renderSelectedFilePreview(opts, selectedFile.Path, fileContent.String())
			if !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
		}

		if err := opts.IO.StartPager(); err != nil {
			fmt.Fprintf(opts.IO.ErrOut, "starting pager failed: %v\n", err)
		}
		fmt.Fprint(opts.IO.Out, content)
```

**File:** pkg/markdown/markdown.go (L38-40)
```go
func Render(text string, opts ...glamour.TermRendererOption) (string, error) {
	return ghMarkdown.Render(text, opts...)
}
```
