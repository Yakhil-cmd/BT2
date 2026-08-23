### Title
Unsanitized attacker-controlled file paths from git tree written raw to terminal in `renderFileTree`/`renderAllFiles` - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`gh skill preview` fetches a repository's git tree via `discovery.ListSkillFiles` and prints each `SkillFile.Path` directly to the terminal through `fmt.Fprintf` in `renderFileTree`/`printTree` and `renderAllFiles`, without passing it through the codebase's `iostreams.Untrusted` sanitizer. Blob content fetched from the same untrusted repo (e.g. via `discovery.FetchBlob`) is deliberately wrapped and sanitized before printing, but file path strings are not, creating an inconsistent sanitization boundary.

### Finding Description
`previewRun` calls `discovery.ListSkillFiles(apiClient, hostname, owner, repoName, skill.TreeSHA)` [1](#0-0)  to obtain `[]discovery.SkillFile` whose `Path` field originates from the attacker-controlled git tree API response. This slice is passed into `renderFileTree`/`renderAllFiles`/`renderInteractive`.

In `renderFileTree` → `buildTree` → `printTree`, each path segment (`node.name`, derived from `strings.Split(f.Path, "/")`) is written with plain `fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)` [2](#0-1) , with no ANSI-escape stripping.

Similarly, in `renderAllFiles`, the file path is interpolated directly into section headers: `fmt.Fprintf(out, "\n%s\n\n%s\n", cs.Bold("── "+f.Path+" ──"), cs.Muted("(could not fetch file)"))` and `fmt.Fprintf(out, "\n%s\n\n", cs.Bold("── "+f.Path+" ──"))` [3](#0-2) . The same unsanitized `f.Path` is echoed to `opts.IO.ErrOut` in `renderInteractive` (tree render and error messages) [4](#0-3) .

By contrast, the actual blob content fetched from the same untrusted repository is deliberately routed through the `iostreams.Untrusted` type, whose `String()` method sanitizes ANSI escape sequences before it reaches `fmt.Fprint`/`fmt.Fprintf` [5](#0-4) . The comment `sanitized := fileContent.String()` at line 307 in `preview.go` confirms this is the intended sanitization path for content, but no equivalent call exists for `f.Path`. This confirms `Path` values are plain, unsanitized `string`s carried straight from the API response into terminal output, bypassing the repo's own `Untrusted` sanitization convention that is otherwise applied to remote content in this exact code path.

### Impact Explanation
An attacker who controls a public repository (or a fork/branch a victim is instructed to preview) can name a file with embedded ANSI escape sequences, e.g. terminal title-setting (`\x1b]0;pwned\x07`), screen-clearing, or cursor-repositioning codes. When a victim runs `gh skill preview owner/repo`, these bytes are written verbatim to the victim's terminal via `renderFileTree`/`renderAllFiles`, enabling terminal title spoofing, screen clutter/clearing, or (in vulnerable terminal emulators) more exotic escape-sequence side effects. This matches a terminal-injection / output-neutralization class impact — not remote code execution, but a genuine violation of the project's own untrusted-output-sanitization invariant.

### Likelihood Explanation
The only precondition is that the victim runs `gh skill preview` against an attacker-published repository — a very ordinary flow for this feature (skill discovery encourages browsing/previewing skills from arbitrary repos). No privileged access, token, or MITM is required; the attacker merely needs to create file names in a repository they control. This is straightforward and repeatable.

### Recommendation
Wrap `SkillFile.Path` (and any other externally-sourced display strings used in `printTree`/`renderAllFiles`/`renderInteractive`) with `iostreams.NewUntrusted(...)` and use its `String()` method (or an equivalent sanitizing call) before interpolating into `fmt.Fprintf`/`cs.Bold`/`cs.Muted`, consistent with how blob content is already handled via `fileContent.String()`.

### Proof of Concept
Integration test outline:
1. Use `httpmock` to stub the git tree API response (`discovery.ListSkillFiles`'s underlying REST call) so that one tree entry's `path` field is `"a\x1b]0;pwned\x07b"`.
2. Call `previewRun` (or directly `renderFileTree`/`renderAllFiles`) with an `iostreams.IOStreams` backed by a `bytes.Buffer` for `Out`.
3. Assert that the captured stdout bytes do **not** contain the raw `\x1b]0;` OSC sequence — i.e. that they equal the output of `iostreams.NewUntrusted(path).String()` rather than the raw path — analogous to existing tests for `Untrusted.String()` in `pkg/iostreams/untrusted.go`.
4. Currently this assertion fails: the buffer contains the raw escape bytes, confirming the gap.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L199-205)
```go
	if skill.TreeSHA != "" {
		files, err = discovery.ListSkillFiles(apiClient, hostname, owner, repoName, skill.TreeSHA)
		if err != nil {
			fmt.Fprintf(opts.IO.ErrOut, "warning: could not list skill files: %v\n", err)
			files = nil
		}
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L301-309)
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
```

**File:** pkg/cmd/skills/preview/preview.go (L322-359)
```go
	// Show the file tree to stderr so it persists above the prompt
	fmt.Fprintf(opts.IO.ErrOut, "\n%s\n", cs.Bold(skill.DisplayName()+"/"))
	renderFileTree(opts.IO.ErrOut, cs, files)
	fmt.Fprintln(opts.IO.ErrOut)

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
		if err != nil {
			return // Prompter returns error on Esc/Ctrl-C; treat as graceful exit
		}

		var content string

		if idx == 0 {
			content = renderedSkillMD
		} else {
			selectedFile := extraFiles[idx-1]

			// Fetch on demand; don't hold blob data in memory
			fileContent, fetchErr := discovery.FetchBlob(apiClient, hostname, owner, repo, selectedFile.SHA)
			if fetchErr != nil {
				fmt.Fprintf(opts.IO.ErrOut, "%s could not fetch %s: %v\n", cs.Red("!"), selectedFile.Path, fetchErr)
```

**File:** pkg/cmd/skills/preview/preview.go (L541-556)
```go
func printTree(w io.Writer, cs *iostreams.ColorScheme, nodes []*treeNode, indent string) {
	for i, node := range nodes {
		isLast := i == len(nodes)-1
		connector := "├── "
		childIndent := "│   "
		if isLast {
			connector = "└── "
			childIndent = "    "
		}
		if node.isDir {
			fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), cs.Bold(node.name+"/"))
			printTree(w, cs, node.children, indent+cs.Muted(childIndent))
		} else {
			fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)
		}
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
