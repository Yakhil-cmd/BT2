### Title
Unsanitized attacker-controlled git tree paths written raw to terminal in `renderFileTree`/`renderAllFiles` - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`discovery.SkillFile.Path` values, which originate from the git tree API response for an attacker-controlled repository, are printed to the terminal via `fmt.Fprintf` in `printTree` (called from `renderFileTree`) and directly in `renderAllFiles`/`renderInteractive` without being wrapped in the `iostreams.Untrusted` sanitizer used elsewhere in the codebase for untrusted content. This allows terminal escape sequences embedded in file/directory names to reach the victim's terminal verbatim.

### Finding Description
`previewRun` fetches `files, err = discovery.ListSkillFiles(apiClient, hostname, owner, repoName, skill.TreeSHA)` [1](#0-0)  where each `discovery.SkillFile.Path` is a plain `string` field populated straight from the GitHub tree API JSON (attacker-controlled since they own the repo/tree). This is then passed to `renderFileTree`/`renderAllFiles`:

- `buildTree` splits `f.Path` on `/` and stores each path segment as `node.name`, a plain string [2](#0-1) .
- `printTree` writes `node.name` directly with `fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)`, with no escaping [3](#0-2) .
- `renderAllFiles` also concatenates `f.Path` directly into header strings: `fmt.Fprintf(out, "\n%s\n\n", cs.Bold("── "+f.Path+" ──"))` [4](#0-3)  and similarly in the error branch [5](#0-4) .
- `renderInteractive` writes `f.Path` into the file picker's choice list and also calls `renderFileTree(opts.IO.ErrOut, cs, files)` directly [6](#0-5) .

By contrast, the codebase has an explicit sanitization mechanism, `iostreams.Untrusted`, whose doc comment states it exists precisely for "HTTP response bodies, file contents fetched from a remote, anything that originates outside the CLI" and that its `String()` method neutralizes ANSI escape sequences via `asciisanitizer.Sanitizer` before any `fmt` print path [7](#0-6) . File *contents* fetched via `discovery.FetchBlob(...).String()` appear to go through this sanitized-string path (referenced as `content.String()` / `fileContent.String()` in `preview.go`), but file *paths* (`f.Path`, `node.name`) are plain `string` values never passed through `Untrusted`/`asciisanitizer`, so no existing control stops raw escape bytes embedded in a tree entry name from being written to `opts.IO.Out` or `opts.IO.ErrOut`.

### Impact Explanation
An attacker who controls a git tree (by publishing a repo with a skill directory) can name a file or directory with embedded ANSI/OSC escape sequences (e.g., `\x1b]0;pwned\x07`, cursor-movement/clear-screen codes). When a victim runs `gh skill preview owner/repo` against that repo, the file tree listing (`renderFileTree`) and the extra-file section headers (`renderAllFiles`) print these bytes verbatim to the victim's terminal. This enables terminal title spoofing, screen clearing/obscuring of subsequent legitimate output, or other terminal-escape-sequence-based UI spoofing (impact class: terminal escape sequence / output injection leading to UI spoofing). It does not achieve code execution or credential exfiltration on its own, but it is a genuine violation of the project's own output-safety invariant enforced elsewhere via `Untrusted`.

### Likelihood Explanation
Fully attacker-controlled and trivially reproducible: any user can create/rename files in their own repository's skills directory to their choosing paths, and any victim invoking `gh skill preview <attacker>/<repo>` will trigger the vulnerable code path with no other precondition. No elevated privileges, tokens, or special repo configuration required beyond simply naming files in a publicly viewable git tree.

### Recommendation
Wrap `f.Path`/tree-derived names in `iostreams.NewUntrusted(...)` (or run them through the same `asciisanitizer` transform) before interpolating them into any `fmt.Fprintf`/`fmt.Fprint` call that targets `opts.IO.Out` or `opts.IO.ErrOut`, in `printTree`, `renderAllFiles` (both the success and `could not fetch file` branches), and `renderInteractive`'s choice list construction.

### Proof of Concept
Integration test sketch:
1. Use `httpmock` to stub the git tree API response (`discovery.ListSkillFiles`'s underlying REST call) so one tree entry's `path` field is `"scripts/\x1b]0;pwned\x07evil.sh"` and another is `"\x1b[2Jcleared/README.md"`.
2. Stub the blob-fetch endpoint to return a normal `SKILL.md` blob.
3. Run `previewRun` (or `NewCmdPreview` with `runF`) with a non-interactive `IOStreams` test double (`iostreams.Test()`), capturing stdout.
4. Assert that the raw ESC (`\x1b`) / OSC bytes appear unescaped in the captured stdout buffer as printed by `renderFileTree`/`renderAllFiles`, i.e. `strings.Contains(stdoutBuf.String(), "\x1b]0;pwned\x07")` is `true`.
5. Expected (fixed) behavior: after wrapping `f.Path` in `iostreams.Untrusted`, the same assertion should fail — the escape bytes should be stripped/neutralized, matching the sanitization already verified for file content via existing `asciisanitizer`-based tests.

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

**File:** pkg/cmd/skills/preview/preview.go (L303-303)
```go
			fmt.Fprintf(out, "\n%s\n\n%s\n", cs.Bold("── "+f.Path+" ──"), cs.Muted("(could not fetch file)"))
```

**File:** pkg/cmd/skills/preview/preview.go (L309-309)
```go
		fmt.Fprintf(out, "\n%s\n\n", cs.Bold("── "+f.Path+" ──"))
```

**File:** pkg/cmd/skills/preview/preview.go (L323-331)
```go
	fmt.Fprintf(opts.IO.ErrOut, "\n%s\n", cs.Bold(skill.DisplayName()+"/"))
	renderFileTree(opts.IO.ErrOut, cs, files)
	fmt.Fprintln(opts.IO.ErrOut)

	// Build choices: SKILL.md first, then extra files
	choices := make([]string, 0, len(extraFiles)+1)
	choices = append(choices, "SKILL.md")
	for _, f := range extraFiles {
		choices = append(choices, f.Path)
```

**File:** pkg/cmd/skills/preview/preview.go (L500-525)
```go
// buildTree constructs a tree structure from flat file paths.
func buildTree(files []discovery.SkillFile) *treeNode {
	root := &treeNode{isDir: true}
	for _, f := range files {
		parts := strings.Split(f.Path, "/")
		current := root
		for i, part := range parts {
			isLast := i == len(parts)-1
			found := false
			for _, child := range current.children {
				if child.name == part {
					current = child
					found = true
					break
				}
			}
			if !found {
				node := &treeNode{name: part, isDir: !isLast}
				current.children = append(current.children, node)
				current = node
			}
		}
	}
	sortTree(root)
	return root
}
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

**File:** pkg/iostreams/untrusted.go (L11-44)
```go
// Untrusted wraps string content the application did not author: HTTP response
// bodies, file contents fetched from a remote, anything that originates outside
// the CLI. The raw bytes are unexported so the only ways out are the methods
// below.
//
// Untrusted satisfies fmt.Stringer, and String sanitizes, so any fmt print path
// (Fprint, Fprintf with %s or %v, Sprint) renders the content with ANSI escape
// sequences neutralized. The only way to reach the raw bytes is Raw, which is
// deliberately easy to grep for and is intended for non-terminal uses such as
// hashing, writing to a file, or piping to another program.
type Untrusted struct {
	raw string
}

// NewUntrusted labels a string as untrusted external content.
func NewUntrusted(s string) Untrusted {
	return Untrusted{raw: s}
}

// NewUntrustedBytes labels a byte slice as untrusted external content.
func NewUntrustedBytes(b []byte) Untrusted {
	return Untrusted{raw: string(b)}
}

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
