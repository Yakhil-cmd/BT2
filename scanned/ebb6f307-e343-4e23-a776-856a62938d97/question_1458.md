# Q1458: external-file-url via index 1458

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `index` (packages/gui/src/electron/components/SandboxedIframe/index.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion after a profile switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would fetch private/local resources during normal GUI use, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/components/SandboxedIframe/index.ts` / `index`
- Entrypoint: embedded iframe render path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; after a profile switch
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
