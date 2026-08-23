## Title
Attacker-controlled skill repository can hide malicious file content from the `gh skill preview` security review by exceeding hard file-count/size caps - (File: `pkg/cmd/skills/preview/preview.go`)

### Summary
The `gh skill preview` command, which `gh skill install` explicitly recommends users run to inspect untrusted skill content before installation, silently truncates the files it renders once a hard cap (`maxFiles = 20` files or `maxTotalBytes = 512KB`) is reached. Because the attacker fully controls the ordering and size of files in their own published skill repository, they can pad the tree with enough files/bytes to push a malicious payload past this cap, making it invisible to a reviewer relying on `preview`, while `gh skill install` still fetches and writes every file to disk, including the hidden malicious one.

### Finding Description
`gh` treats skill repositories as fundamentally untrusted content: `printPreInstallDisclaimer` and `printReviewHint` explicitly warn that "Skills are not verified by GitHub and may contain prompt injections, hidden instructions, or malicious scripts" and direct users to run `gh skill preview` first. [1](#0-0) 

The `previewRun` -> `renderAllFiles` code path, however, enforces hard caps on how many extra files (beyond `SKILL.md`) it will fetch and display: [2](#0-1) 

Once `maxFiles` (20) files have been shown, or once `totalBytes` would exceed `maxTotalBytes` (512 KB), the loop breaks and prints only a generic "(skipped remaining files...)" notice, giving the reviewer no visibility into what was skipped. This is confirmed by the test suite, which explicitly validates that files beyond the caps are never fetched or shown: [3](#0-2) [4](#0-3) 

Crucially, the same repository content is not subject to any equivalent cap during actual installation — `installSkill` iterates over *all* discovered files and writes every one of them to disk verbatim, with no file-count or size limit: [5](#0-4) 

Because the attacker (the publisher of the skill repository) fully controls the number, ordering, and size of files under their own `skills/<name>/` path, they can trivially arrange for a small number of large "decoy" files (or 20+ filler files) to precede a malicious file (e.g. a script, or a secondary Markdown file containing hidden prompt-injection instructions for an agent) in the tree ordering returned by the GitHub Trees API. This guarantees the malicious file is dropped from `preview` output by the cap, while `install` still writes it to disk unconditionally.

### Impact Explanation
This defeats the tool's own documented safety mechanism for reviewing untrusted skill content before installation. A user who follows the CLI's own guidance (`gh skill preview <repo> <skill>` before `gh skill install`) will not see the malicious content because it silently falls outside the 20-file/512KB rendering budget, yet `gh skill install` will still install it to disk where it becomes available to an AI agent (e.g. GitHub Copilot) as instructions/scripts. This can lead to prompt injection or execution of attacker-supplied instructions/scripts by the consuming agent without the user's knowledge, despite having performed the recommended review step.

### Likelihood Explanation
Any unprivileged, unauthenticated third party can publish a public GitHub repository containing a "skill" (per the documented discovery conventions) and get it indexed via `gh skill search`/`gh skill publish`. Crafting a tree with padding files to push a malicious file past a fixed, publicly-known cap (20 files / 512KB) requires no special access or timing — it is fully within the attacker's control at publish time. The victim only needs to follow the officially recommended `preview`-then-`install` workflow.

### Recommendation
- Do not silently truncate the preview: instead of just skipping remaining files, explicitly enumerate (by name/path) every file that was *not* rendered so the reviewer knows exactly what was skipped and can decide whether to trust the skill.
- Consider capping the number of files fetched during `install` similarly, or refusing to install skills whose tree exceeds the size that can be reasonably previewed, and require an explicit `--force`/opt-in for oversized skills.
- Alternatively, make `preview`'s truncation limits large enough (or configurable) to always cover everything that `install` would write, so preview and install operate on the exact same content set.

### Proof of Concept
1. Attacker creates and publishes a public GitHub repo skill at `skills/evil-skill/SKILL.md` per the documented conventions, and adds 20 small decoy files (`file000.txt` ... `file019.txt`) plus a 21st file `payload.sh` containing malicious instructions, ordered so `payload.sh` sorts after the first 20 in the git tree.
2. Victim runs `gh skill preview attacker/evil-skill evil-skill` as instructed by `gh skill install`'s review hint; output shows `(skipped remaining files, showing first 20)` and never displays `payload.sh`'s content, matching the exact truncation behavior validated in `preview_test.go`'s "maxFiles cap truncates at 20" case. [3](#0-2) 
3. Believing the skill reviewed clean, the victim runs `gh skill install attacker/evil-skill evil-skill`; `installSkill` fetches and writes *all* files including `payload.sh` to the local skills directory with no cap. [6](#0-5) 
4. The agent host later reads/executes the installed skill directory contents, including the previously-hidden `payload.sh`/injected instructions.

### Citations

**File:** pkg/cmd/skills/install/install.go (L1187-1220)
```go
// printPreInstallDisclaimer prints a warning that installed skills are unverified
// and should be inspected before use.
func printPreInstallDisclaimer(w io.Writer, cs *iostreams.ColorScheme) {
	fmt.Fprintf(w, "\n%s Skills are not verified by GitHub and may contain prompt injections, hidden instructions, or malicious scripts. Always review skill contents before use.\n\n", cs.WarningIcon())
}

// printReviewHint warns the user to review installed skills and suggests preview commands.
// When sha is non-empty the suggested commands include @SHA so the user previews
// exactly the version that was installed. When allowHiddenDirs is true, the
// suggested commands include --allow-hidden-dirs so previewing hidden-dir
// skills works without an extra manual step.
func printReviewHint(w io.Writer, cs *iostreams.ColorScheme, repo, sha string, skillNames []string, allowHiddenDirs bool) {
	if len(skillNames) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s Skills may contain prompt injections or malicious scripts.\n", cs.WarningIcon())
	if repo == "" {
		fmt.Fprintln(w, "  Review the installed files before use.")
		return
	}
	fmt.Fprintln(w, "  Review installed content before use:")
	fmt.Fprintln(w)
	hiddenFlag := ""
	if allowHiddenDirs {
		hiddenFlag = " --allow-hidden-dirs"
	}
	for _, name := range skillNames {
		if sha != "" {
			fmt.Fprintf(w, "    gh skill preview %s %s@%s%s\n", repo, name, sha, hiddenFlag)
		} else {
			fmt.Fprintf(w, "    gh skill preview %s %s%s\n", repo, name, hiddenFlag)
		}
	}
	fmt.Fprintln(w)
```

**File:** pkg/cmd/skills/preview/preview.go (L286-315)
```go
	fmt.Fprint(out, rendered)

	const maxFiles = 20
	const maxTotalBytes = 512 * 1024
	fetched := 0
	totalBytes := 0
	for _, f := range extraFiles {
		if fetched >= maxFiles {
			fmt.Fprintf(out, "\n%s\n", cs.Muted(fmt.Sprintf("(skipped remaining files, showing first %d)", maxFiles)))
			break
		}
		if totalBytes+f.Size > maxTotalBytes {
			fmt.Fprintf(out, "\n%s\n", cs.Muted("(skipped remaining files, size limit reached)"))
			break
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
}
```

**File:** pkg/cmd/skills/preview/preview_test.go (L797-835)
```go
	t.Run("maxFiles cap truncates at 20", func(t *testing.T) {
		reg := &httpmock.Registry{}
		defer reg.Verify(t)

		n := 22
		treeJSON := buildTree(n)
		subtreeJSON := buildSubtree(n, nil)
		registerBase(reg, treeJSON, subtreeJSON)

		// Register blob stubs for files 0-19 (first 20 get fetched)
		tinyContent := base64.StdEncoding.EncodeToString([]byte("tiny"))
		for i := range 20 {
			reg.Register(
				httpmock.REST("GET", fmt.Sprintf("repos/monalisa/skills-repo/git/blobs/blob%03d", i)),
				httpmock.StringResponse(fmt.Sprintf(`{"sha": "blob%03d", "content": "%s", "encoding": "base64"}`, i, tinyContent)),
			)
		}
		// Files 20 and 21 should NOT be fetched

		ios, _, stdout, _ := iostreams.Test()
		ios.SetStdoutTTY(false)
		ios.SetStdinTTY(false)

		opts := &PreviewOptions{
			IO:         ios,
			HttpClient: func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
			Prompter:   &prompter.PrompterMock{},
			repo:       ghrepo.New("monalisa", "skills-repo"),
			SkillName:  "my-skill",
			Telemetry:  &telemetry.NoOpService{},
		}

		err := previewRun(opts)
		require.NoError(t, err)

		out := stdout.String()
		assert.Contains(t, out, "showing first 20")
		assert.Contains(t, out, "file019.txt") // last fetched
	})
```

**File:** pkg/cmd/skills/preview/preview_test.go (L837-872)
```go
	t.Run("maxBytes cap stops fetching", func(t *testing.T) {
		reg := &httpmock.Registry{}
		defer reg.Verify(t)

		// Two files: first is 500KB, second would exceed 512KB cap
		sizes := []int{500 * 1024, 100 * 1024}
		treeJSON := buildTree(2)
		subtreeJSON := buildSubtree(2, sizes)
		registerBase(reg, treeJSON, subtreeJSON)

		bigContent := base64.StdEncoding.EncodeToString(make([]byte, 500*1024))
		reg.Register(
			httpmock.REST("GET", "repos/monalisa/skills-repo/git/blobs/blob000"),
			httpmock.StringResponse(fmt.Sprintf(`{"sha": "blob000", "content": "%s", "encoding": "base64"}`, bigContent)),
		)
		// blob001 should NOT be fetched (size limit reached)

		ios, _, stdout, _ := iostreams.Test()
		ios.SetStdoutTTY(false)
		ios.SetStdinTTY(false)

		opts := &PreviewOptions{
			IO:         ios,
			HttpClient: func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
			Prompter:   &prompter.PrompterMock{},
			repo:       ghrepo.New("monalisa", "skills-repo"),
			SkillName:  "my-skill",
			Telemetry:  &telemetry.NoOpService{},
		}

		err := previewRun(opts)
		require.NoError(t, err)

		out := stdout.String()
		assert.Contains(t, out, "size limit reached")
	})
```

**File:** internal/skills/installer/installer.go (L251-309)
```go
func installSkill(opts *Options, skill discovery.Skill, baseDir string) error {
	// Use skill.Name (not InstallName) for a flat directory layout.
	skillDir := filepath.Join(baseDir, skill.Name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return fmt.Errorf("could not create directory %s: %w", skillDir, err)
	}

	files, err := discovery.DiscoverSkillFiles(opts.Client, opts.Host, opts.Owner, opts.Repo, skill.TreeSHA, skill.Path)
	if err != nil {
		return fmt.Errorf("could not list skill files: %w", err)
	}

	safeSkillDir, err := safepaths.ParseAbsolute(skillDir)
	if err != nil {
		return fmt.Errorf("could not resolve skill directory path: %w", err)
	}

	for _, file := range files {
		fetchedContent, err := discovery.FetchBlob(opts.Client, opts.Host, opts.Owner, opts.Repo, file.SHA)
		if err != nil {
			return fmt.Errorf("could not fetch %s: %w", file.Path, err)
		}

		// Install path: the blob is written to disk verbatim, so the raw bytes
		// must be preserved.
		content := fetchedContent.Raw()

		relPath := strings.TrimPrefix(file.Path, skill.Path+"/")

		safeDest, err := safeSkillDir.Join(relPath)
		if err != nil {
			var traversalErr safepaths.PathTraversalError
			if errors.As(err, &traversalErr) {
				return fmt.Errorf("blocked path traversal in %q", relPath)
			}
			return fmt.Errorf("could not resolve destination path: %w", err)
		}
		destPath := safeDest.String()

		if dir := filepath.Dir(destPath); dir != skillDir {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("could not create directory: %w", err)
			}
		}

		if filepath.Base(relPath) == "SKILL.md" {
			content, err = frontmatter.InjectGitHubMetadata(content, opts.Host, opts.Owner, opts.Repo, opts.Ref, skill.TreeSHA, opts.PinnedRef, skill.Path)
			if err != nil {
				return fmt.Errorf("could not inject metadata: %w", err)
			}
		}

		if err := os.WriteFile(destPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("could not write %s: %w", destPath, err)
		}
	}

	return nil
}
```
