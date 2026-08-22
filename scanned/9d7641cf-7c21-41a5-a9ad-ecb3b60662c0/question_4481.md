# Q4481: sync/push targets attacker remote - ParseFullReference in finder.go

## Question
Can `ParseFullReference` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L335) be steered by repo metadata into pushing the victim's local branches (possibly containing private code) to a remote the attacker controls?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:335](pkg/cmd/pr/shared/finder.go#L335) - `ParseFullReference`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose upstream/parent metadata points at the attacker.
- Invariant to test: Push targets are confirmed and host-validated.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the push remote for hostile metadata.
