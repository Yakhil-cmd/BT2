# Q3642: external-file-url via StyledBaseLink 3642

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `StyledBaseLink` (packages/core/src/components/Link/Link.tsx) control oversized or polyglot import file with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/Link/Link.tsx` / `StyledBaseLink`
- Entrypoint: embedded iframe render path
- Attacker controls: oversized or polyglot import file; with a delayed metadata fetch
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
