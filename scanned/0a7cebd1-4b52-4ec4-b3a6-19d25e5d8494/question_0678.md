# Q678: external-file-url via useOpenExternal 678

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `useOpenExternal` (packages/gui/src/hooks/useOpenExternal.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion with a duplicate identifier and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useOpenExternal.ts` / `useOpenExternal`
- Entrypoint: embedded iframe render path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; with a duplicate identifier
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
