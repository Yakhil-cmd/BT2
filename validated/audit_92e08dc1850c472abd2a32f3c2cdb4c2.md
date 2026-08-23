### Title
Unsanitized skill/repo names in `buildInstallPlans` and overwrite prompts allow terminal output/prompt spoofing via CR/control characters - (File: pkg/cmd/skills/install/install.go)

### Summary
`buildInstallPlans` and its helpers (`checkOverwrite`, `existingSkillPrompt`) print attacker-controlled skill names (`discovery.Skill.DisplayName()`/`Name`) and repository/ref strings directly into `fmt.Fprintf` calls on `opts.IO.ErrOut`/`opts.IO.Out` and into `opts.Prompter.Confirm` prompt text, with no escaping of control characters such as `\r`, `\n`, or ANSI cursor-movement sequences. A skill name is derived from a directory path segment in the attacker's own published repository, so it is fully attacker-controlled and can contain any byte except `/` and NUL.

### Finding Description
The relevant sinks are all inside/adjacent to `buildInstallPlans`:
- `fmt.Fprintf(opts.IO.ErrOut, "No skills to install in %s for %s.\n", friendlyDir(plan.dir), formatPlanHosts(plan.hosts))` [1](#0-0) 
- `fmt.Fprintf(opts.IO.ErrOut, "Skipping %s\n", s.DisplayName())` inside `checkOverwrite` [2](#0-1) 
- `existingSkillPrompt` builds the confirmation text shown by `opts.Prompter.Confirm`, embedding `incoming.DisplayName()` and the source repo/ref string parsed from frontmatter metadata, with no sanitization: `fmt.Sprintf("Skill %q already installed from %s. Overwrite?", incoming.DisplayName(), sourceName)` [3](#0-2) 
- The same unsanitized pattern appears in the calling function `installRun`, e.g. the "Installed %s (from %s@%s) in %s" success line [4](#0-3)  and the naming-convention warning [5](#0-4) .

`discovery.Skill.Name`/`DisplayName()` originate from directory names discovered in the attacker's git tree (via `discovery.DiscoverSkillsWithOptions`/`DiscoverSkillByPath`), and frontmatter-derived fields (`github-repo`, `github-ref`) come from the skill's own `SKILL.md` metadata written by the publisher. Git tree/blob entry names may contain arbitrary bytes other than `/` and NUL, including `\r`, `\n`, and ANSI escape sequences (e.g., cursor-position or line-clear codes). I was not able to find any sanitization/escaping utility (e.g., a `StripAnsi`/control-character filter) applied to these fields before they reach `fmt.Fprintf`/`Prompter.Confirm`/`Prompter.Select`/`Prompter.MultiSelect` in this code path — searches for such helpers only turned up unrelated test-file matches. `discovery.IsSpecCompliant` is used only to emit a *warning* about naming convention, not to block installation of non-compliant names, so a crafted name with `\r` would still proceed through selection, confirmation, and printing.

### Impact Explanation
If a crafted skill name/frontmatter value contains `\r` followed by fabricated text (e.g., `? Paste your GitHub token: `), the terminal will overwrite the currently rendered line, and combined with ANSI cursor codes it can reposition text anywhere on screen. This can be used to disguise a destructive confirmation prompt (`checkOverwrite`'s `Confirm`), trick the user into typing a token or confirming an unintended action, or forge trusted-looking `gh` output (e.g., a fake "Installed ..." success line) to mask malicious behavior. This matches "Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation."

### Likelihood Explanation
The attacker only needs to publish a public repository with a `skills/*/SKILL.md` structure where the skill's directory name (or `github-repo`/`github-ref` frontmatter metadata used for provenance display) contains control characters — well within the capability of an "unprivileged remote GitHub user who publishes repos." Any victim running `gh skill install owner/repo` (or `gh skill update`) against that repository, interactively or non-interactively, would trigger the spoofed rendering. This requires no special repo permissions and is fully repeatable.

### Recommendation
Sanitize all attacker-controlled strings (`Skill.Name`, `Skill.DisplayName()`, description text, and `github-repo`/`github-ref` metadata pulled from frontmatter) before they are passed to `fmt.Fprintf`, `Prompter.Confirm`, `Prompter.Select`, or `Prompter.MultiSelect`. Strip or escape all C0/C1 control characters (in particular `\r`, `\n` inside single-line messages, and ESC-prefixed sequences) at the point these values are parsed from git tree entries/frontmatter (e.g., in `discovery.DiscoverSkillsWithOptions`, `frontmatter.Parse`, and `source.ParseMetadataRepo`), or centrally via a shared "safe for terminal" sanitizer applied at every print/prompt boundary in `pkg/cmd/skills/install/install.go`.

### Proof of Concept
Go test sketch (to be added under `pkg/cmd/skills/install`):
```go
func TestBuildInstallPlans_SanitizesControlCharsInPrompt(t *testing.T) {
    malicious := "legit-name\r? Paste your GitHub token: "
    skill := discovery.Skill{Name: malicious, Path: "skills/" + malicious}

    ios, _, _, errBuf := iostreams.Test()
    opts := &InstallOptions{IO: ios, Prompter: &prompter.PrompterMock{
        ConfirmFunc: func(prompt string, _ bool) (bool, error) {
            if strings.ContainsAny(prompt, "\r") {
                t.Fatalf("prompt contains raw CR, spoofing possible: %q", prompt)
            }
            return false, nil
        },
    }}
    // create a pre-existing dir to force the overwrite-confirmation path
    _ = os.MkdirAll(filepath.Join(t.TempDir(), malicious), 0o755)

    _, err := buildInstallPlans(opts, []discovery.Skill{skill}, someHosts, registry.ScopeProject, "", "", true)
    require.NoError(t, err)
    require.NotContains(t, errBuf.String(), "\r")
}
```
Expected (current, vulnerable) behavior: the raw `\r` reaches `existingSkillPrompt`/`fmt.Fprintf` unmodified, so the assertion `strings.ContainsAny(prompt, "\r")` fails the test, proving unsanitized control-character propagation into a trusted-looking prompt/output line.

### Citations

**File:** pkg/cmd/skills/install/install.go (L419-422)
```go
			for _, name := range result.Installed {
				fmt.Fprintf(opts.IO.Out, "%s Installed %s (from %s@%s) in %s\n",
					cs.SuccessIcon(), name, repoSource, discovery.ShortRef(resolved.Ref), friendlyDir(result.Dir))
			}
```

**File:** pkg/cmd/skills/install/install.go (L652-656)
```go
	for _, s := range skills {
		if !discovery.IsSpecCompliant(s.Name) {
			fmt.Fprintf(opts.IO.ErrOut, "Warning: skill %q does not follow the agentskills.io naming convention\n", s.DisplayName())
		}
	}
```

**File:** pkg/cmd/skills/install/install.go (L1020-1020)
```go
			fmt.Fprintf(opts.IO.ErrOut, "No skills to install in %s for %s.\n", friendlyDir(plan.dir), formatPlanHosts(plan.hosts))
```

**File:** pkg/cmd/skills/install/install.go (L1082-1082)
```go
			fmt.Fprintf(opts.IO.ErrOut, "Skipping %s\n", s.DisplayName())
```

**File:** pkg/cmd/skills/install/install.go (L1107-1113)
```go
	if repoInfo != nil {
		sourceName := ghrepo.FullName(repoInfo)
		if ref != "" {
			sourceName += "@" + ref
		}
		return fmt.Sprintf("Skill %q already installed from %s. Overwrite?", incoming.DisplayName(), sourceName)
	}
```
