### Title
Unsanitized remote codespace fields (branch ref, display name, owner login, repo name) rendered into interactive `survey.Select` prompt allow terminal/prompt spoofing - (File: pkg/cmd/codespace/common.go)

### Summary
`chooseCodespaceFromList` builds a `survey.Select` prompt whose option strings are produced by `codespace.displayName` [1](#0-0) , which directly `fmt.Sprintf`s `Repository.FullName`, `GitStatus.Ref` (via `branchWithGitStatus`), `DisplayName`, and `Owner.Login` from the API-returned `api.Codespace` struct into the terminal-rendered option list [2](#0-1) . None of these values pass through the codebase's existing `iostreams.Untrusted` sanitizer, which is precisely designed to strip ANSI escape sequences from "HTTP response bodies... anything that originates outside the CLI" before it reaches a terminal [3](#0-2) .

### Finding Description
`GitStatus.Ref` reflects the git branch/status reported by the codespace-side agent running in the (possibly attacker-influenced) devcontainer environment, and `DisplayName`/`Owner.Login`/`Repository.FullName` are populated straight from the Codespaces API response with no length bound or escape-sequence stripping. `formatCodespacesForSelect` feeds these strings as `survey.Select.Options` [4](#0-3) , and `survey` writes them to the terminal essentially verbatim. The codebase already recognizes this exact hazard class elsewhere — `iostreams.Untrusted.String()` exists specifically to neutralize ANSI escape sequences in remote-originated strings before they reach a terminal writer [5](#0-4)  — but `displayName`/`chooseCodespaceFromList` never wraps or sanitizes these fields with it, nor does it bound their length. A crafted value containing ANSI cursor-movement/clear-line/color escape codes or embedded newlines could rewrite what appears on screen (e.g., hide the real list entries, fabricate a fake confirmation line, or make an attacker-labeled codespace visually resemble a different, legitimate one), influencing which codespace the user selects to connect/attach to.

### Impact Explanation
This matches the "Terminal output/prompt spoofing" impact class: an attacker who can influence codespace metadata reaching this API (e.g., via a compromised/malicious devcontainer environment reporting `GitStatus`, or via `DisplayName`/repository fields associated with a shared/org codespace) can manipulate the on-screen selection prompt the victim uses to choose which codespace to connect to, potentially leading them to select or trust the wrong codespace. It does not achieve code execution or credential exfiltration by itself — the impact is confined to visual manipulation of the interactive picker.

### Likelihood Explanation
Exploitability depends on the attacker's ability to control one of these Codespace fields as seen by the victim's `gh codespace` commands (e.g., shared org codespaces, or a devcontainer/codespace agent under attacker influence reporting `GitStatus`). This is a narrower precondition than a fully unauthenticated remote attacker manipulating an arbitrary victim, since most fields (`Repository.FullName`, `Owner.Login`) are constrained by GitHub's own naming rules, and `DisplayName` is typically set by the codespace's own owner. The most plausible attacker-controlled field is `GitStatus.Ref`, sourced from the codespace-side process.

### Recommendation
Wrap remote-originated fields (`DisplayName`, `GitStatus.Ref`, `Repository.FullName`, `Owner.Login`) with `iostreams.Untrusted` (or equivalent ANSI-stripping/length-bounding) before formatting them into `codespace.displayName`, consistent with existing usage patterns in `pkg/cmd/gist/view/view.go` and `internal/skills/discovery/discovery.go`.

### Proof of Concept
Golden test extending `Test_codespace_displayName` in `pkg/cmd/codespace/common_test.go`: construct an `api.Codespace` with `GitStatus.Ref` (or `DisplayName`) containing `"\x1b[2K\x1b[1A\x1b[32mFAKE ENTRY\x1b[0m"` and assert that `displayName()` output either matches the raw (unsafe) string — demonstrating the escape sequence passes through unsanitized — or, after a fix, is stripped/escaped. Currently, per the reviewed code, the escape bytes would flow through unmodified into the `survey.Select` options, confirming the lack of sanitization.

### Citations

**File:** pkg/cmd/codespace/common.go (L107-116)
```go
	csSurvey := []*survey.Question{
		{
			Name: "codespace",
			Prompt: &survey.Select{
				Message: "Choose codespace:",
				Options: formatCodespacesForSelect(sortedCodespaces, includeOwner),
			},
			Validate: survey.Required,
		},
	}
```

**File:** pkg/cmd/codespace/common.go (L129-138)
```go
func formatCodespacesForSelect(codespaces []*api.Codespace, includeOwner bool) []string {
	names := make([]string, len(codespaces))

	for i, apiCodespace := range codespaces {
		cs := codespace{apiCodespace}
		names[i] = cs.displayName(includeOwner)
	}

	return names
}
```

**File:** pkg/cmd/codespace/common.go (L193-209)
```go
// displayName formats the codespace name for the interactive selector prompt.
func (c codespace) displayName(includeOwner bool) string {
	branch := c.branchWithGitStatus()
	displayName := c.DisplayName

	if displayName == "" {
		displayName = c.Name
	}

	description := fmt.Sprintf("%s [%s]: %s", c.Repository.FullName, branch, displayName)

	if includeOwner {
		description = fmt.Sprintf("%-15s %s", c.Owner.Login, description)
	}

	return description
}
```

**File:** pkg/iostreams/untrusted.go (L11-20)
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
