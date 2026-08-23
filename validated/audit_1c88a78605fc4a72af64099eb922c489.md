### Title
Terminal escape-sequence injection via unsanitized file/directory names in `printTree` - ([File: pkg/cmd/skills/preview/preview.go])

### Finding Description
`printTree` renders the skill's file tree by writing `node.name` directly into the terminal with `fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)` for files and `cs.Bold(node.name+"/")` for directories. [1](#0-0) 

`node.name` originates from `treeNode` entries built in `buildTree`, which splits `discovery.SkillFile.Path` on `/`. [2](#0-1) 

`SkillFile.Path` values come from the git tree of the attacker's own repository (via `ListSkillFiles`/tree API), so an attacker publishing a skill fully controls file and directory names, including embedding raw control bytes such as OSC 8 hyperlink sequences (`ESC ] 8 ; ; <uri> ST <text> ESC ] 8 ; ; ST`) with a non-http URI scheme, bracketed-paste toggles (`ESC [ 200~` / `ESC [ 201~`), or title-set-then-report sequences (`ESC ] 2 ; ... BEL`) in a file name.

Elsewhere in the same package, remote blob content fetched via `discovery.FetchBlob` is handled through the `iostreams.Untrusted` type, whose `String()` method runs the content through `asciisanitizer.Sanitizer` (or a `stripControl` fallback) to neutralize ANSI/OSC escape sequences before any `fmt` print path renders it. [3](#0-2) 

However, `printTree` never routes `node.name` through `Untrusted` (or any other sanitizer) before writing it to `w`. `cs.Muted`/`cs.Bold` only wrap the string in SGR color codes; they do not strip or validate embedded control sequences. This means the file-tree rendering path — which is the very first thing shown to the user in both `renderAllFiles` and `renderInteractive` — bypasses the sanitization invariant that the rest of the preview pipeline relies on.

### Impact Explanation
An attacker who publishes a skill repository can name a file/directory to embed terminal control sequences that: open an OSC 8 hyperlink pointing at a `file://` or other non-http URI later "clicked" by terminal auto-report/click-to-open behavior, toggle bracketed-paste mode off so that a later paste is interpreted as keystrokes, or set the window title and query the terminal to echo cursor-position/answerback data back into the tty input buffer. Depending on the victim's terminal emulator, this can be leveraged to plant characters into the shell's input stream, corrupt shell state, or otherwise influence subsequent user interaction — a stepping stone toward remote code execution on the victim's machine, matching the "arbitrary code execution" bug bounty impact class for a maliciously crafted, unprivileged repo/skill.

### Likelihood Explanation
This requires only that an attacker publish a skill repository with a crafted file/directory name — no special permissions, tokens, or victim interaction beyond running `gh skill preview <attacker-repo>`, which is the documented entrypoint for previewing third-party skills. The tree is always rendered (both interactive and non-interactive/pager paths call `renderFileTree` → `printTree`), so the payload triggers on every preview, making this highly repeatable.

### Recommendation
Wrap `node.name` (and any other externally-derived path segment) in `iostreams.Untrusted` before printing in `printTree`, e.g. `fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), iostreams.NewUntrusted(node.name))`, consistent with how blob content is already protected elsewhere in this package. Alternatively, sanitize file/directory names at tree-build time using the same `asciisanitizer`/`stripControl` logic so raw control bytes can never reach `fmt.Fprintf`.

### Proof of Concept
```go
func TestPrintTree_SanitizesControlSequences(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    cs := ios.ColorScheme()

    malicious := "\x1b]8;;file:///etc/passwd\x1b\\click-me\x1b]8;;\x1b\\"
    nodes := []*treeNode{{name: malicious, isDir: false}}

    printTree(out, cs, nodes, "")

    got := out.String()
    if strings.Contains(got, "\x1b]8;;file://") {
        t.Fatalf("printTree emitted unsanitized OSC 8 hyperlink escape sequence: %q", got)
    }
}
```
Expected (current) result: the test fails because `printTree` writes `node.name` verbatim, proving the raw OSC 8 escape sequence (with a `file://` URI) reaches the terminal writer unsanitized.

### Citations

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

**File:** pkg/cmd/skills/preview/preview.go (L541-557)
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
