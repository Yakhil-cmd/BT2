# Q3055: cached response written world-readable - findForRefs in finder.go

## Question
Does the on-disk cache used by `findForRefs` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L386) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:386](pkg/cmd/pr/shared/finder.go#L386) - `findForRefs`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
