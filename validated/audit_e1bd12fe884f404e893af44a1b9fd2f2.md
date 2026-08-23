### Title
Attacker-controlled SKILL.md `description` frontmatter bypasses terminal sanitization in `gh skill search` - ([File: pkg/cmd/skills/search/search.go])

### Finding Description
`gh skill list`'s `renderTable` correctly wraps every attacker-influenced field (`skillName`, `source`) in `sanitizeForTerminal`, which strips ASCII control/escape bytes via `asciisanitizer.Sanitizer` before writing to the table. [1](#0-0) [2](#0-1) 

However, `gh skill search` has a separate, unrelated `renderTable` implementation that never sanitizes attacker-controlled data. The `Description` field is populated directly from the raw YAML frontmatter of a `SKILL.md` blob fetched from an arbitrary (attacker-owned) repository via `fetchDescriptions`, which calls `frontmatter.Parse(content.Raw())` and stores `result.Metadata.Description` verbatim: [3](#0-2) 

`frontmatter.Parse` performs a plain `yaml.Unmarshal` with no character filtering, so a double-quoted YAML scalar such as `description: "\x1b]0;pwned\x07"` decodes into a Go string containing raw ESC/OSC bytes. [4](#0-3) 

That raw string is then written straight into the table with `table.AddField(desc)` — the only transformation applied is an optional width truncation, not sanitization: [5](#0-4) 

The same unsanitized `Description` value is also used in the interactive picker (`promptInstall`), embedded into option strings shown by the prompter UI: [6](#0-5) 

Because `pkg/cmd/skills/search` never imports or calls `sanitizeForTerminal` (that function is private to the `list` package), there is no path-independent enforcement that "every displayed frontmatter field" gets neutralized — the sanitizer only protects `list.go`, not `search.go`, even though both surface raw, attacker-authored `SKILL.md` content to the terminal.

### Impact Explanation
An attacker who publishes any public repository containing a `SKILL.md` with a crafted `description` field can inject arbitrary terminal escape/control sequences into the victim's terminal output when the victim runs `gh skill search <query>` and the malicious skill appears in the (attacker-influenced, since the attacker controls the file that is matched by GitHub Code Search) result set. This enables classic terminal escape injection impacts: title-bar spoofing, output obfuscation/spoofing (hiding or rewriting displayed text), and in vulnerable terminal emulators, more severe effects (e.g., clipboard writes via OSC 52, malicious OSC 8 hyperlinks). This matches the "terminal escape injection" scoped impact class called out in the question.

### Likelihood Explanation
Fully attacker-controlled and requires no special privileges: the attacker only needs to publish a public repo with a `SKILL.md` matched by GitHub Code Search for some query term, and get a victim to run `gh skill search <term>`, which is an ordinary discovery command with no install step required. This is highly feasible and repeatable — no fork/PR interaction with the victim needed.

### Recommendation
Sanitize all attacker-derived display fields in `pkg/cmd/skills/search/search.go`'s `renderTable` (and the `promptInstall` option strings), specifically `Description` (and defensively `Repo`/`SkillName`/`Namespace`), using the same control-character stripping approach as `sanitizeForTerminal` in `pkg/cmd/skills/list/list.go`. Consider moving `sanitizeForTerminal` into a shared internal package (e.g. under `internal/skills` or `internal/text`) so both `list` and `search` commands — and any future skill-display code — are forced to use one consistent, tested sanitizer.

### Proof of Concept
```go
// pkg/cmd/skills/search/search_test.go
func TestRenderTable_SanitizesDescription(t *testing.T) {
    ios, _, stdout, _ := iostreams.Test()
    ios.SetStdoutTTY(false)

    skills := []skillResult{{
        Repo:        "attacker/evil-skill",
        SkillName:   "evil-skill",
        Description: "\x1b]0;pwned\x07innocuous-looking desc",
        Stars:       0,
    }}

    err := renderTable(ios, skills)
    require.NoError(t, err)

    out := stdout.String()
    require.NotContains(t, out, "\x1b", "ESC byte must not reach terminal output")
    require.NotContains(t, out, "\x07", "BEL byte must not reach terminal output")
}
```
Expected today: this test **fails** because `renderTable` in `pkg/cmd/skills/search/search.go` writes `desc` (from `frontmatter.Parse`'s raw `Description`) unmodified via `table.AddField(desc)`, so the ESC/BEL bytes appear verbatim in `stdout`. A companion `httpmock`-based integration test can drive `searchRun` end-to-end with a mocked Code Search + blob-fetch response containing the same malicious `description:` frontmatter to confirm the full attacker-to-terminal path.

### Citations

**File:** pkg/cmd/skills/list/list.go (L509-514)
```go
	for _, skill := range skills {
		table.AddField(sanitizeForTerminal(skill.skillName))
		table.AddField(formatAgentHosts(skill.agentHostIDs))
		table.AddField(displayOrDash(skill.scope))
		table.AddField(displayOrDash(sanitizeForTerminal(skill.source)))
		table.EndRow()
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

**File:** pkg/cmd/skills/search/search.go (L502-514)
```go
	table := tableprinter.New(io, tableprinter.WithHeader("REPOSITORY", "SKILL", "DESCRIPTION", "STARS"))
	for _, s := range skills {
		table.AddField(s.Repo)
		table.AddField(s.qualifiedName())
		desc := s.Description
		if isTTY {
			desc = text.Truncate(descWidth, desc)
		}
		table.AddField(desc)
		table.AddField(formatStars(s.Stars))
		table.EndRow()
	}
	return table.Render()
```

**File:** pkg/cmd/skills/search/search.go (L538-543)
```go
		descStr := ""
		if s.Description != "" {
			desc := strings.Join(strings.Fields(s.Description), " ")
			descStr = "\n       " + cs.Muted(text.Truncate(descWidth, desc))
		}
		options[i] = s.qualifiedName() + "  " + cs.Muted(s.Repo) + starStr + descStr
```

**File:** pkg/cmd/skills/search/search.go (L860-871)
```go
			content, err := discovery.FetchBlob(client, host, skills[idx].Owner, skills[idx].RepoName, skills[idx].BlobSHA)
			if err != nil {
				return
			}
			result, err := frontmatter.Parse(content.Raw())
			if err != nil {
				return
			}

			mu.Lock()
			descs[idx] = result.Metadata.Description
			mu.Unlock()
```

**File:** internal/skills/frontmatter/frontmatter.go (L48-56)
```go
	var rawYAML map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &rawYAML); err != nil {
		return nil, fmt.Errorf("invalid frontmatter YAML: %w", err)
	}

	var meta Metadata
	if err := yaml.Unmarshal([]byte(yamlContent), &meta); err != nil {
		return nil, fmt.Errorf("invalid frontmatter YAML: %w", err)
	}
```
