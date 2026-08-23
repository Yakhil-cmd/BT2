### Title
Case-insensitive path collision allows attacker blob to silently overwrite SKILL.md content post-metadata-injection - ([File: internal/skills/installer/installer.go])

### Summary
`installSkill` writes each blob returned by `DiscoverSkillFiles` to disk sequentially using `os.WriteFile`, keyed only by the byte-exact `relPath` derived from the tree entry's `Path`. Neither `safepaths.Absolute.Join` nor `installSkill` performs case-folding or Unicode normalization, so on case-insensitive filesystems (macOS default, Windows) two distinct tree entries such as `SKILL.md` and `skill.md` resolve to the same underlying file, and whichever is processed last wins in the write order controlled by the attacker's tree.

### Finding Description
In `installSkill` (internal/skills/installer/installer.go:268-306), the file loop iterates over `files` returned from `discovery.DiscoverSkillFiles`, which simply reflects the order of `tree.Tree` entries in GitHub's git-trees API JSON response — fully attacker-controlled since the attacker publishes the repository/tree. For each entry: [1](#0-0) 
`relPath` is computed via `strings.TrimPrefix`, joined with `safeSkillDir.Join(relPath)`, which calls into `safepaths.Absolute.Join` (internal/safepaths/absolute.go:38-57). That function only does `filepath.Join` + `filepath.Rel` traversal checks — no case-folding, no Unicode NFC/NFD normalization. [2](#0-1) 
Only when `filepath.Base(relPath) == "SKILL.md"` (exact, case-sensitive string comparison) is `frontmatter.InjectGitHubMetadata` applied to stamp provenance. If the attacker's tree contains both `SKILL.md` (which gets metadata injected) and a case-variant such as `skill.md` (which is written verbatim, bypassing the `== "SKILL.md"` check and thus the metadata injection), and the entries are processed in an order where `skill.md` is written after `SKILL.md`, then on a case-insensitive filesystem both writes target the identical inode, and the final on-disk content is the attacker's uninjected/attacker-controlled bytes rather than the provenance-stamped content the safeguard is meant to guarantee.

### Impact Explanation
This defeats the "provenance stamping" safeguard (`InjectGitHubMetadata`) that annotates installed skills with source/pin metadata, letting an attacker's raw payload end up at the exact `SKILL.md` path that agent tooling reads and trusts as vetted/injected content — a file overwrite bypassing an intended safeguard within the confined install directory. It does not escape the target directory (path confinement itself holds — both destinations resolve inside `skillDir`), so this is not a directory-traversal write; it is a same-directory collision that undermines the metadata-injection guarantee, not classic arbitrary file write outside intended path.

### Likelihood Explanation
Requires: (1) a case-insensitive filesystem (default macOS, default Windows — not default Linux); (2) the attacker to publish a repo/tree with two case-variant filenames both matching the `SKILL.md` pattern loosely, one of which is literally `SKILL.md` and the other differs only in case; (3) the GitHub tree API to return them as two distinct blob entries in an order where the non-`SKILL.md`-cased one is last. GitHub's tree/git API generally allows two blobs differing only by case to coexist in a tree object (git itself is case-sensitive; only the checkout/filesystem is not), so this precondition is plausible but not verified against live GitHub API behavior in this investigation. I was unable to directly test/observe how GitHub's `git/trees` endpoint or git object model treats attacker-supplied case-colliding blob paths within a single tree, since that is outside the indexed codebase.

### Recommendation
Track destination paths using a filesystem-aware collision check, e.g., normalize `relPath` (Unicode NFC and case-fold on case-insensitive platforms) and detect/reject duplicate resolved destinations before writing, and apply `InjectGitHubMetadata` based on a normalized comparison against `"SKILL.md"` rather than exact case-sensitive string equality — or explicitly reject skill trees containing multiple blobs whose paths collide after normalization.

### Proof of Concept
Go test sketch using `discovery` package with an `httpmock` git-trees response returning:
```json
{"sha":"...","tree":[
  {"path":"SKILL.md","mode":"100644","type":"blob","sha":"blobA"},
  {"path":"skill.md","mode":"100644","type":"blob","sha":"blobB"}
],"truncated":false}
```
then run `installSkill` on a simulated case-insensitive path resolver (or on an actual macOS/Windows runner) with `blobA` content containing legitimate frontmatter and `blobB` content containing attacker payload without frontmatter. Assert:
- `DiscoverSkillFiles` returns two `SkillFile` entries with distinct `Path` values (`skills/x/SKILL.md`, `skills/x/skill.md`).
- After `installSkill` completes, `os.ReadFile(destPath)` for `.../SKILL.md` (case-insensitive lookup) equals `blobB`'s raw content (attacker payload), not the `InjectGitHubMetadata`-stamped `blobA` content — confirming the safeguard was bypassed by write order.

### Citations

**File:** internal/skills/installer/installer.go (L278-288)
```go
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
```

**File:** internal/skills/installer/installer.go (L296-305)
```go
		if filepath.Base(relPath) == "SKILL.md" {
			content, err = frontmatter.InjectGitHubMetadata(content, opts.Host, opts.Owner, opts.Repo, opts.Ref, skill.TreeSHA, opts.PinnedRef, skill.Path)
			if err != nil {
				return fmt.Errorf("could not inject metadata: %w", err)
			}
		}

		if err := os.WriteFile(destPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("could not write %s: %w", destPath, err)
		}
```
