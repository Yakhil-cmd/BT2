# Q1361: external-file-url via LinkAPI 1361

## Question
Can an unprivileged attacker entering through the imported file parse path in `LinkAPI` (packages/gui/src/electron/constants/LinkAPI.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion with case-normalized identifiers and drive the sequence import -> parse -> preview -> submit so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/constants/LinkAPI.ts` / `LinkAPI`
- Entrypoint: imported file parse path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; with case-normalized identifiers
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
