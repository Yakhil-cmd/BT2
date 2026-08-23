`SkillFile.Path` is populated directly from the GitHub tree API's `entry.Path` field [1](#0-0) , and it's a plain `string`, not the `iostreams.Untrusted` type used elsewhere in this codebase for remote content [2](#0-1) . This path is fully attacker-controlled: any published repository can contain a file whose name embeds ANSI escape sequences (e.g. `\x1b]0;evil title\x07innocent.txt`), since GitHub's tree API does not filter file names.

`printTree` then writes `node.name` (derived from `SkillFile.Path` via `buildTree`) straight into the writer with `fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)` and `cs.Bold(node.name+"/")` for directories [3](#0-2) . There is no call to `iostreams.NewUntrusted(...).String()`, `sanitizeForTerminal`, or any other sanitizer on this value — unlike every other untrusted-content path in this file, which explicitly routes through `Untrusted.String()` (e.g. `content.String()` for `SKILL.md` and extra files, both fed by `discovery.FetchBlob` which explicitly returns `iostreams.Untrusted`) [4](#0-3) [5](#0-4) [6](#0-5) .

`renderFileTree`/`printTree` is called from two places: `renderAllFiles`, which writes to `opts.IO.Out` while a pager is active (`opts.IO.StartPager()`) [7](#0-6) , and `renderInteractive`, which writes the tree to `opts.IO.ErrOut` before the prompt [8](#0-7) . In the pager case, the raw, unsanitized bytes (including any ANSI/OSC escape sequences embedded in a file name) are handed to whatever program the user's `PAGER`/`GH_PAGER` environment variable points to (see `pagerCommand: os.Getenv("PAGER")` in `iostreams.System()`) [9](#0-8) . Because this text never passes through `asciisanitizer.Sanitizer` or `Untrusted.String()`, escape sequences reach the pager verbatim, matching the concern in the question: gh's own sanitization is bypassed for this particular sink even though the same file's `content` (SKILL.md body) is sanitized.

This is consistent with the general design pattern documented throughout the repo — `Untrusted.String()` sanitizes ANSI escapes before printing [10](#0-9) , and other view commands (`gist view`, `repo read-file`) explicitly guard raw/escape content before writing to a terminal or pager [11](#0-10) [12](#0-11)  — but `SkillFile.Path`/`node.name` in `printTree` was never wrapped in `Untrusted` or otherwise sanitized before being printed.

### Title
Unsanitized attacker-controlled file names from the skill tree are printed to the pager/terminal by `printTree`, allowing terminal escape sequence injection - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`printTree` in `pkg/cmd/skills/preview/preview.go` writes `treeNode.name`, which originates from GitHub tree API `path` fields (`SkillFile.Path`) populated in `internal/skills/discovery/discovery.go`, directly to the pager/terminal writer without passing through the codebase's standard `iostreams.Untrusted` sanitization. An attacker who publishes a repository with a maliciously-named file (embedding ANSI/OSC escape sequences in the file or directory name) can have those raw escape bytes delivered to the victim's pager/terminal when running `gh skills preview`.

### Finding Description
`ListSkillFiles`/`walkTree` populate `SkillFile.Path` directly from the untyped `entry.Path` field returned by the GitHub trees API, with no escape-sequence filtering [1](#0-0) . `buildTree` splits these paths into `treeNode.name` values [13](#0-12) , and `printTree` prints them verbatim via `fmt.Fprintf` [14](#0-13) . Unlike blob content in the same file, which is wrapped in `iostreams.Untrusted` by `discovery.FetchBlob` and sanitized via `.String()` before printing [15](#0-14) [16](#0-15) , file/directory names never pass through this sanitization layer. Both call sites forward this raw text to a sink outside gh's own text renderer — `renderAllFiles` writes it to `opts.IO.Out` while the pager is active [7](#0-6) , and `renderInteractive` writes it to `opts.IO.ErrOut` prior to prompting [8](#0-7) .

### Impact Explanation
An attacker-published repository containing a file whose name embeds ANSI/OSC escape sequences can manipulate the victim's pager or terminal (e.g. altering displayed text, terminal title, or attempting a spoofed prompt) purely by having the victim run `gh skills preview <attacker-repo>`. This matches the "Terminal output/prompt spoofing" impact class named in the question, since the escapes reach the pager unsanitized while equivalent blob content in the same command is sanitized — an inconsistency exploitable to spoof output that a victim might otherwise trust as sanitized by gh.

### Likelihood Explanation
No special privileges are required: any GitHub user can publish a public repository, name a file with control characters, and reference it via `gh skills preview owner/repo`. The path travels through the standard discovery flow (`ListSkillFiles`/`walkTree`) reachable from a normal `gh skills preview` invocation, with no interactive confirmation gating the tree display step. This is highly feasible and repeatable.

### Recommendation
Route `SkillFile.Path` (or the derived `treeNode.name`) through `iostreams.Untrusted`/`asciisanitizer.Sanitizer` (or the `sanitizeForTerminal` helper already used in `pkg/cmd/skills/list/list.go`) before printing in `printTree`, consistent with how blob content is handled elsewhere in the same file.

### Proof of Concept
Go test sketch:
```go
func TestPrintTree_SanitizesEscapesInFileNames(t *testing.T) {
    files := []discovery.SkillFile{
        {Path: "innocent\x1b]0;pwned\x07.txt"},
    }
    root := buildTree(files)
    var buf bytes.Buffer
    io, _, _, _ := iostreams.Test()
    cs := io.ColorScheme()
    printTree(&buf, cs, root.children, "")
    assert.NotContains(t, buf.String(), "\x1b")
}
```
This test currently fails because `printTree` writes `node.name` unsanitized; the fix should make it pass by sanitizing before write.

### Citations

**File:** internal/skills/discovery/discovery.go (L861-871)
```go
	var files []SkillFile
	for _, entry := range tree.Tree {
		if entry.Type == "blob" {
			files = append(files, SkillFile{
				Path: entry.Path,
				SHA:  entry.SHA,
				Size: entry.Size,
			})
		}
	}
	return files, nil
```

**File:** internal/skills/discovery/discovery.go (L914-944)
```go
// FetchBlob retrieves the content of a blob by SHA. The blob is base64-encoded
// inside the JSON response and decoded here, so it is returned as
// iostreams.Untrusted and callers must choose sanitized display or raw
// round-tripping.
func FetchBlob(client *api.Client, host, owner, repo, sha string) (iostreams.Untrusted, error) {
	apiPath, err := safeurl.JoinPath("repos", owner, repo, "git", "blobs", sha)
	if err != nil {
		return iostreams.Untrusted{}, err
	}
	var resp struct {
		SHA      string `json:"sha"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := client.REST(host, "GET", apiPath.String(), nil, &resp); err != nil {
		return iostreams.Untrusted{}, fmt.Errorf("could not fetch blob: %w", err)
	}

	if resp.Encoding != "base64" {
		return iostreams.Untrusted{}, fmt.Errorf("unexpected blob encoding: %s", resp.Encoding)
	}

	// GitHub API returns base64 with embedded newlines; use the StdEncoding
	// decoder via a reader to handle them transparently.
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(resp.Content)))
	if err != nil {
		return iostreams.Untrusted{}, fmt.Errorf("could not decode blob content: %w", err)
	}

	return iostreams.NewUntrustedBytes(decoded), nil
}
```

**File:** pkg/iostreams/untrusted.go (L21-23)
```go
type Untrusted struct {
	raw string
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

**File:** pkg/cmd/skills/preview/preview.go (L206-212)
```go
	content, err := discovery.FetchBlob(apiClient, hostname, owner, repoName, skill.BlobSHA)
	opts.IO.StopProgressIndicator()
	if err != nil {
		return err
	}

	rendered := opts.renderFile("SKILL.md", content.String())
```

**File:** pkg/cmd/skills/preview/preview.go (L271-283)
```go
	opts.IO.DetectTerminalTheme()
	if err := opts.IO.StartPager(); err != nil {
		fmt.Fprintf(opts.IO.ErrOut, "starting pager failed: %v\n", err)
	}
	defer opts.IO.StopPager()

	out := opts.IO.Out

	if len(files) > 0 {
		fmt.Fprintf(out, "%s\n", cs.Bold(skill.DisplayName()+"/"))
		renderFileTree(out, cs, files)
		fmt.Fprintln(out)
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L301-310)
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
```

**File:** pkg/cmd/skills/preview/preview.go (L322-325)
```go
	// Show the file tree to stderr so it persists above the prompt
	fmt.Fprintf(opts.IO.ErrOut, "\n%s\n", cs.Bold(skill.DisplayName()+"/"))
	renderFileTree(opts.IO.ErrOut, cs, files)
	fmt.Fprintln(opts.IO.ErrOut)
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

**File:** pkg/iostreams/iostreams.go (L535-542)
```go
	io := &IOStreams{
		In:              os.Stdin,
		Out:             stdout,
		ErrOut:          stderr,
		pagerCommand:    os.Getenv("PAGER"),
		term:            &terminal,
		sanitizeContent: true,
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

**File:** pkg/cmd/repo/read-file/read_file.go (L196-200)
```go
	// Refuse terminal escape sequences unless --allow-escape-sequences, in both TTY and non-TTY modes,
	// so a malicious file cannot manipulate a downstream terminal.
	if !opts.AllowEscapeSequences && iostreams.ContainsEscapeSequence(file.Content) {
		return errors.New("file contains terminal escape sequences; use --allow-escape-sequences to read anyway")
	}
```
