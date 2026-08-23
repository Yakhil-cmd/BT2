### Title
Unsanitized skill frontmatter `description` printed via `listAvailableSkills` allows ANSI/OSC escape injection - (File: pkg/cmd/skills/install/install.go)

### Summary
`listAvailableSkills` renders each skill's `Description` field directly into a terminal table without any control-character or ANSI/OSC stripping. The description text originates from the attacker-controlled `SKILL.md` frontmatter of a published skill, fetched via the "raw" (unsanitized) accessor of an `iostreams.Untrusted` blob, bypassing the sanitization mechanism the codebase provides for exactly this purpose.

### Finding Description
`listAvailableSkills` builds a table and writes `s.Description` straight into a row: `desc := s.Description; if isTTY { desc = text.Truncate(descWidth, desc) }; table.AddField(desc)` [1](#0-0) . Neither `text.Truncate` nor `text.RemoveExcessiveWhitespace` strip C0/C1 control bytes or ANSI/OSC sequences — `Truncate` only limits display width and `RemoveExcessiveWhitespace` only collapses `\s+` [2](#0-1) .

`Skill.Description` is populated by `fetchDescription`, which fetches the `SKILL.md` blob and parses frontmatter: `content, err := FetchBlob(...); result, err := frontmatter.Parse(content.Raw())` [3](#0-2) . `FetchBlob`'s own doc comment states the blob is returned as `iostreams.Untrusted` specifically "so...callers must choose sanitized display or raw round-tripping" [4](#0-3) , implying a sanitized accessor exists as an alternative to `Raw()`. `fetchDescription` chooses `.Raw()`, discarding any sanitization, and the resulting `Metadata.Description` is assigned unmodified to `Skill.Description` [5](#0-4) .

By contrast, `Skill.Name`/`Namespace` are constrained by `specNamePattern`/`safeNamePattern` regexes (alphanumeric, hyphen, underscore, dot, space only) [6](#0-5) , so `DisplayName()` is safe, but `Description` has no such restriction — it is free-form text from an attacker-controlled repository's `SKILL.md` frontmatter `description:` field.

This same unsanitized `Description` also reaches the interactive picker via `skillSearchFunc`, which only applies `text.RemoveExcessiveWhitespace` and `text.Truncate`, neither of which strips escapes [7](#0-6) .

### Impact Explanation
An attacker who publishes a skill repository (no privileges required) can embed OSC 52 (clipboard write), OSC 7 (working-directory spoof), or other C0/C1/ANSI sequences in the `description:` frontmatter field. When a victim runs `gh skills install` (or an equivalent flow reaching `listAvailableSkills`/the interactive selector) against that repository without specifying an exact skill name, the raw escape bytes are written to the victim's terminal, enabling terminal/prompt spoofing, hidden text injection, or clipboard exfiltration — matching the "Terminal output/prompt spoofing" impact class described in the question.

### Likelihood Explanation
This requires only that the victim run `gh skill install <owner>/<repo>` (or similar) without a specific skill name against an attacker-published skills repository, or interactively browse skills from it — an ordinary, expected usage pattern. No special repo permissions, MITM, or social engineering beyond publishing a public repo/skill are needed, making this straightforward and repeatable.

### Recommendation
Sanitize `Skill.Description` before display: strip C0/C1 control characters and ANSI/OSC escape sequences either when parsing frontmatter (`frontmatter.Parse`) or immediately before rendering in `listAvailableSkills` and `skillSearchFunc`. Prefer using the sanitized accessor of `iostreams.Untrusted` (rather than `.Raw()`) when extracting text destined for the frontmatter description, consistent with the pattern already implied by the `FetchBlob` documentation.

### Proof of Concept
Add a test in `internal/skills/discovery` or `pkg/cmd/skills/install` that constructs a `Skill{Description: "safe\x1b]52;c;ZXZpbA==\x07text"}` (OSC 52 clipboard-write payload) and asserts that after passing through the `listAvailableSkills` rendering path (or `text.Truncate`/`text.RemoveExcessiveWhitespace`), the output still contains the raw `\x1b]52;` bytes — demonstrating no sanitization occurs. A full end-to-end PoC would use `httpmock` to serve a `git/blobs` response whose base64 content decodes to a `SKILL.md` with a frontmatter `description` containing the OSC payload, run `gh skills install owner/repo` non-interactively, and capture stdout to confirm the escape sequence is emitted verbatim.

### Citations

**File:** pkg/cmd/skills/install/install.go (L789-799)
```go
	table := tableprinter.New(opts.IO, tableprinter.WithHeader("SKILL", "DESCRIPTION"))
	for _, s := range skills {
		table.AddField(s.DisplayName())
		desc := s.Description
		if isTTY {
			desc = text.Truncate(descWidth, desc)
		}
		table.AddField(desc)
		table.EndRow()
	}
	return table.Render()
```

**File:** pkg/cmd/skills/install/install.go (L866-874)
```go
		labels := make([]string, len(matched))
		for i, s := range matched {
			keys[i] = s.DisplayName()
			label := s.DisplayName()
			if s.Description != "" {
				label = fmt.Sprintf("%s - %s", label, text.RemoveExcessiveWhitespace(s.Description))
			}
			labels[i] = text.Truncate(labelWidth, label)
		}
```

**File:** internal/text/text.go (L29-40)
```go
// RemoveExcessiveWhitespace returns a copy of the string s with excessive whitespace removed.
func RemoveExcessiveWhitespace(s string) string {
	return whitespaceRE.ReplaceAllString(strings.TrimSpace(s), " ")
}

func DisplayWidth(s string) int {
	return text.DisplayWidth(s)
}

func Truncate(maxWidth int, s string) string {
	return text.Truncate(maxWidth, s)
}
```

**File:** internal/skills/discovery/discovery.go (L24-42)
```go
// specNamePattern matches the strict agentskills.io name spec:
// 1-64 chars, lowercase alphanumeric + hyphens, no leading/trailing/consecutive hyphens.
var specNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// TreeTooLargeError is returned when a repository's git tree exceeds the
// GitHub API truncation limit and full skill discovery is not possible.
type TreeTooLargeError struct {
	Owner string
	Repo  string
}

func (e *TreeTooLargeError) Error() string {
	return fmt.Sprintf("repository tree for %s/%s is too large for full discovery", e.Owner, e.Repo)
}

// safeNamePattern matches names that are safe for filesystem use during discovery.
// Allows letters (any case), numbers, hyphens, underscores, dots, and spaces.
// Must start with a letter or number. This matches copilot-agent-runtime's SKILL_NAME_REGEX.
var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\- ]*$`)
```

**File:** internal/skills/discovery/discovery.go (L647-661)
```go
// fetchDescription fetches and parses the frontmatter description for a skill.
func fetchDescription(client *api.Client, host, owner, repo string, skill *Skill) string {
	if skill.BlobSHA == "" {
		return ""
	}
	content, err := FetchBlob(client, host, owner, repo, skill.BlobSHA)
	if err != nil {
		return ""
	}
	result, err := frontmatter.Parse(content.Raw())
	if err != nil {
		return ""
	}
	return result.Metadata.Description
}
```

**File:** internal/skills/discovery/discovery.go (L914-918)
```go
// FetchBlob retrieves the content of a blob by SHA. The blob is base64-encoded
// inside the JSON response and decoded here, so it is returned as
// iostreams.Untrusted and callers must choose sanitized display or raw
// round-tripping.
func FetchBlob(client *api.Client, host, owner, repo, sha string) (iostreams.Untrusted, error) {
```
