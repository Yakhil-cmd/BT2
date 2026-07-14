# Q1360: external-file-url via LinkAPI 1360

## Question
Can an unprivileged attacker entering through the external link click in `LinkAPI` (packages/gui/src/electron/constants/LinkAPI.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion with case-normalized identifiers and drive the sequence import -> parse -> preview -> submit so the GUI would fetch private/local resources during normal GUI use, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/constants/LinkAPI.ts` / `LinkAPI`
- Entrypoint: external link click
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; with case-normalized identifiers
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
