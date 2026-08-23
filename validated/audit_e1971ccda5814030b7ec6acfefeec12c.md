### Title
Skill preview writes attacker-controlled file names and raw file content directly to the pager without ANSI sanitization - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`printTree` and `renderAllFiles` in `pkg/cmd/skills/preview/preview.go` write file/directory names from the skill's git tree and raw fetched blob content directly to `opts.IO.Out` via `fmt.Fprintf`/`fmt.Fprint`, instead of routing through `opts.IO.ContentOut` (the ANSI-sanitizing writer) or wrapping the bytes in `iostreams.Untrusted` as other commands (`gist view`, `pr diff`, `repo read-file`, `api`) do. Both the tree entry names and the extra-file contents are attacker-controlled via a published skill repository, so escape sequences in either can reach the terminal/pager unmodified.

### Finding Description
`renderFileTree` builds a tree from `discovery.SkillFile.Path` values (attacker-controlled git blob/tree paths from the published repo) and calls `printTree(w, cs, root.children, "")`, which does: [1](#0-0) 
writing `node.name` directly with `fmt.Fprintf`. `node.name` is a raw path segment split from `f.Path` in `buildTree`, never passed through `iostreams.Untrusted` or `asciisanitizer`: [2](#0-1) 

Similarly, in `renderAllFiles`, the tree is rendered to `out := opts.IO.Out` (line 277) and extra-file content fetched via `discovery.FetchBlob` is printed with `fmt.Fprint(out, sanitized)` where `sanitized` is merely `fileContent.String()` — no sanitizer is actually applied despite the variable name: [3](#0-2) 

This contrasts with the codebase's established pattern for untrusted remote content, where raw non-markdown content is explicitly wrapped in `iostreams.Untrusted` or written through `opts.IO.ContentOut`, which wraps the underlying writer with an `asciisanitizer.Sanitizer` transform unless explicitly disabled: [4](#0-3) [5](#0-4) 

`printTree`/`renderAllFiles` bypass this entirely: they write straight to `opts.IO.Out`, not `opts.IO.ContentOut`, so file names and non-markdown file contents carry through any embedded ANSI/OSC escape sequences (0x1B) to whatever consumes `IO.Out` — the pager process started via `opts.IO.StartPager()` (line 272) or the terminal directly when not paging. A published skill can include file names (or extra files) containing OSC 0; title-set sequences, CSI cursor-position codes, or terminal query sequences (as seen exploited in `run-view-log-escape-sequences.txtar` and `TestCopyLogWithLinePrefix_TerminalEscapeSequences`), which are interpreted differently — or not at all — by gh's own rendering vs. by an external pager (e.g., `less`, `more`) that has its own escape-handling rules (e.g. `less -R` passes ANSI/OSC through verbatim to the terminal).

### Impact Explanation
An attacker who publishes a skill repository with crafted file/directory names or additional (non-`SKILL.md`) file content containing terminal escape sequences can cause terminal output spoofing when a victim runs `gh skills preview` — including fake prompts, hidden/altered text, or terminal title-bar hijacking — matching the "Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation" impact class (High).

### Likelihood Explanation
Fully attacker-controlled and requires no privilege beyond publishing a public repository that the victim previews with `gh skills preview <repo>`. The default preview path (`renderAllFiles`, used when non-interactive or when the skill only has a `SKILL.md`) and the tree header shown in both `renderAllFiles` and `renderInteractive` are always exercised, making this reliably reproducible for any victim who previews the attacker's skill.

### Recommendation
Route all attacker-controlled strings written in `printTree` and `renderAllFiles` through the same sanitization used elsewhere: wrap `node.name` and fetched blob content in `iostreams.Untrusted` (or write via `opts.IO.ContentOut` instead of `opts.IO.Out`) so escape sequences are neutralized before reaching the pager, consistent with the pattern in `pkg/cmd/gist/view/view.go` and `pkg/cmd/pr/diff/diff.go`.

### Proof of Concept
```go
// pkg/cmd/skills/preview/preview_test.go
func TestPrintTree_SanitizesFileNames(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    cs := ios.ColorScheme()
    files := []discovery.SkillFile{
        {Path: "safe.txt\x1b]0;HIJACKED\x07"}, // attacker-controlled path with OSC sequence
    }
    renderFileTree(out, cs, files)
    assert.NotContains(t, out.String(), "\x1b",
        "tree output written to pager must not contain raw ESC bytes")
}

func TestRenderAllFiles_SanitizesExtraFileContent(t *testing.T) {
    // stub discovery.FetchBlob to return content: "hello\x1b[31mDANGER\x1b[0m"
    // call renderAllFiles with a stub pager writer (opts.IO.Out captured)
    // assert.NotContains(t, capturedOut, "\x1b")
}
```
Both assertions currently fail against the existing `printTree`/`renderAllFiles` implementation because neither routes through `iostreams.Untrusted`/`ContentOut`.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L300-314)
```go
		}
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
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L500-522)
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
```

**File:** pkg/cmd/skills/preview/preview.go (L550-555)
```go
		if node.isDir {
			fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), cs.Bold(node.name+"/"))
			printTree(w, cs, node.children, indent+cs.Muted(childIndent))
		} else {
			fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)
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
