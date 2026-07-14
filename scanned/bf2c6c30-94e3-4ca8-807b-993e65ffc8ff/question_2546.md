# Q2546: external-file-url via useOpenExternal 2546

## Question
Can an unprivileged attacker entering through the imported file parse path in `useOpenExternal` (packages/gui/src/hooks/useOpenExternal.ts) control remote JSON changing between validation and use with a stale Redux cache and drive the sequence preview -> mutate controlled state -> confirm so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useOpenExternal.ts` / `useOpenExternal`
- Entrypoint: imported file parse path
- Attacker controls: remote JSON changing between validation and use; with a stale Redux cache
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
